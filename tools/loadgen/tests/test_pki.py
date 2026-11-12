"""Key views, revocation material and broker configuration."""

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography import x509

import pki
from broker import Broker


class KeyViews(unittest.TestCase):
    def setUp(self):
        self.keys = pki.make_keys([1, 2], epoch=0)

    def test_gateway_never_holds_sensor_private_keys(self):
        gw = pki.gateway_view(self.keys)
        self.assertEqual(set(gw.aead), {0, 1, 2})
        self.assertEqual(set(gw.sign_public), {0, 1, 2})
        self.assertEqual(set(gw.sign_private), {0})  # only its own

    def test_device_holds_own_keys_and_gateway_public_material(self):
        dev = pki.device_view(self.keys, [1])
        self.assertEqual(set(dev.aead), {0, 1})          # own + downlink group key
        self.assertEqual(set(dev.sign_private), {1})
        self.assertEqual(set(dev.sign_public), {0})      # verifies the gateway only
        self.assertNotIn(2, dev.owners)

    def test_epochs_never_reuse_key_ids(self):
        later = pki.make_keys([1, 2], epoch=1)
        self.assertFalse(set(self.keys.aead) & set(later.aead))
        self.assertEqual(later.owners[pki.key_id(1, 1)], "sensor-1")


class Revocation(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)

    @unittest.skipUnless(shutil.which("mosquitto_passwd"), "needs mosquitto_passwd")
    def test_generate_crl_and_passwd(self):
        ca = pki.CertificateAuthority.create()
        p, keys = pki.generate(self.dir, ca, [1, 2], [1, 2], ["localhost"])
        self.assertTrue(p.keys.exists() and p.device_keys.exists())
        pki.write_crl(p, ca, {"sensor-2"})
        crl = x509.load_pem_x509_crl(p.crl.read_bytes())
        cert = x509.load_pem_x509_certificate(p.issued("sensor-2").read_bytes())
        self.assertIsNotNone(crl.get_revoked_certificate_by_serial_number(cert.serial_number))
        passwords = pki.read_credentials(p.credentials)
        pki.write_passwd(p, passwords, {"sensor-2"})
        users = {line.split(":")[0] for line in p.passwd.read_text().splitlines()}
        self.assertEqual(users, {"gateway", "sensor-1"})

    def test_crl_covers_every_certificate_of_a_device(self):
        # The stand-in the lab issues to an attacker for sensor-1 (cluster mode:
        # the device's own key stays on its agent) is revoked with sensor-1,
        # and sensor-1 does not pull in sensor-10's certificates.
        ca = pki.CertificateAuthority.create()
        p = pki.Pki(self.dir)
        serials = {}
        for name, tag in (("sensor-1", ""), ("sensor-1", "stolen"), ("sensor-10", "")):
            cert = ca.issue(name, pki.new_key().public_key())
            p.record_issued(name, pki.cert_pem(cert), tag=tag)
            serials[(name, tag)] = cert.serial_number
        self.assertEqual(len(p.issued_all("sensor-1")), 2)
        p.crl.parent.mkdir(parents=True, exist_ok=True)
        pki.write_crl(p, ca, {"sensor-1"})
        crl = x509.load_pem_x509_crl(p.crl.read_bytes())
        revoked = {r.serial_number for r in crl}
        self.assertEqual(revoked, {serials[("sensor-1", "")], serials[("sensor-1", "stolen")]})


class BrokerConfig(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.broker = Broker(self.dir, pki.Pki(self.dir), "127.0.0.1", 18999)
        self.addCleanup(self.broker._log.close)

    def conf(self, **settings):
        self.broker.settings.update(settings)
        self.broker._write()
        return self.broker.conf.read_text().splitlines()

    def test_listener_options_follow_the_listener(self):
        lines = self.conf(clientid_binding=True, max_connections=5, mode="mtls")
        listener = next(i for i, l in enumerate(lines) if l.startswith("listener"))
        for option in ("use_username_as_clientid", "max_connections", "crlfile", "tls_version"):
            self.assertGreater(next(i for i, l in enumerate(lines) if l.startswith(option)),
                               listener, option)

    def test_acl_off_means_no_acl_file(self):
        self.assertFalse(any(l.startswith("acl_file") for l in self.conf(acl=False)))
        self.assertTrue(any(l.startswith("acl_file") for l in self.conf(acl=True)))

    def test_tls12_is_capped_by_openssl_config(self):
        # Mosquitto's tls_version is only a minimum; the broker caps the maximum.
        self.conf(mode="tls", tls_version="1.2")
        env = self.broker._env()
        self.assertEqual(env["OPENSSL_CONF"], str(self.broker.openssl_conf))
        self.assertIn("MaxProtocol = TLSv1.2", self.broker.openssl_conf.read_text())
        self.conf(tls_version="1.3")
        self.assertNotIn("OPENSSL_CONF", self.broker._env())
        self.conf(mode="plain", tls_version="1.2")
        self.assertNotIn("OPENSSL_CONF", self.broker._env())

    def test_apply_reloads_or_restarts(self):
        self.broker.proc = mock.Mock(pid=os.getpid())
        with mock.patch.object(Broker, "restart") as restart, mock.patch("os.kill") as kill:
            self.assertEqual(self.broker.apply(auth=True), "reload")
            kill.assert_called_once()
            self.assertEqual(self.broker.apply(clientid_binding=True), "restart")
            self.assertEqual(self.broker.apply(clientid_binding=True), "")
            self.broker.settings["mode"] = "mtls"
            self.assertEqual(self.broker.apply(revoked=frozenset({"sensor-1"})), "restart")
            self.assertEqual(restart.call_count, 2)


if __name__ == "__main__":
    unittest.main()
