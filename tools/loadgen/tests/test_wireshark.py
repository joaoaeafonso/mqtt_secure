"""Wireshark tooling: the Lua dissector and TLS decryption with logged secrets.

Needs tshark (set TSHARK=/path/to/tshark to use a non-system one); the TLS
test also needs mosquitto and the key-log shim from the bench build
(build/bench/tools/wireshark/libmsec_sslkeylog.so, or MSEC_SSLKEYLOG_LIB).
Skipped when they are missing.
"""

import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import broker
import capture
import pcapgen
import pki

REPO = Path(__file__).resolve().parents[3]
DISSECTOR = REPO / "tools" / "wireshark" / "msec.lua"
VECTORS = REPO / "tests" / "vectors" / "envelope_vectors.txt"
TSHARK = os.environ.get("TSHARK") or shutil.which("tshark")
SHIM = Path(os.environ.get("MSEC_SSLKEYLOG_LIB",
                           REPO / "build" / "bench" / "tools" / "wireshark" / "libmsec_sslkeylog.so"))


def tshark(capture: Path, *args: str) -> str:
    out = subprocess.run([TSHARK, "-r", str(capture), "-X", f"lua_script:{DISSECTOR}", *args],
                         capture_output=True, text=True, check=True, timeout=60)
    return out.stdout


def fields(capture: Path, display_filter: str, *names: str, extra: tuple = ()) -> list[list[str]]:
    args = [*extra, "-Y", display_filter, "-T", "fields", "-E", "separator=|"]
    for n in names:
        args += ["-e", n]
    return [line.split("|") for line in tshark(capture, *args).splitlines() if line]


@unittest.skipUnless(TSHARK, "needs tshark")
class Dissector(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = Path(tempfile.mkdtemp())
        cls.capture = pcapgen.sample(cls.dir / "sample.pcap", VECTORS)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir)

    def test_every_mode_is_decoded_with_its_overhead(self):
        rows = fields(self.capture, "msec.mode && !msec.replay_of && tcp.dstport == 18830",
                      "msec.mode", "msec.key_id", "msec.seq", "msec.overhead", "msec.lab.owner")
        self.assertEqual(sorted(r[0] for r in rows), ["1", "2", "3"])
        overhead = {r[0]: r[3] for r in rows}
        self.assertEqual(overhead, {"1": "53", "2": "53", "3": "89"})
        self.assertTrue(all(r[1] == "7" and r[2] == "1" and r[4] == "sensor-7" for r in rows))

    def test_replay_is_flagged_and_linked_to_the_original(self):
        original = fields(self.capture, "msec.mode == 1 && tcp.dstport == 18830 && !msec.replay_of",
                          "frame.number")
        replays = fields(self.capture, "msec.replay_of", "frame.number", "msec.replay_of")
        self.assertEqual(len(replays), 1)
        self.assertEqual(replays[0][1], original[0][0])

    def test_broker_deliveries_are_not_replays(self):
        delivered = fields(self.capture, "msec.published_in", "frame.number")
        self.assertEqual(len(delivered), 6)  # 3 envelopes x (gateway + eavesdropper)

    def test_forgery_unprotected_and_malformed(self):
        self.assertEqual(len(fields(self.capture, 'msec.lab.forged == "FORGED!!"', "frame.number")), 1)
        experts = tshark(self.capture, "-q", "-z", "expert")
        self.assertIn("Unprotected payload", experts)
        self.assertIn("Envelope truncated", experts)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@unittest.skipUnless(TSHARK and shutil.which("mosquitto") and shutil.which("mosquitto_passwd")
                     and SHIM.exists(),
                     "needs tshark, mosquitto and the bench build's libmsec_sslkeylog.so")
class TlsDecryption(unittest.TestCase):
    """A real TLS session to the lab's broker (broker.Broker), decrypted with the
    secrets only the BROKER logged through the LD_PRELOAD shim. Proves that the
    shim works, that the configured TLS version is the one on the wire, and that
    the envelope is still there inside the tunnel."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        ca = pki.CertificateAuthority.create()
        self.pki, _ = pki.generate(self.dir, ca, [7], [7], ["127.0.0.1"])

    def session(self, tls_version: str) -> tuple[Path, Path, str]:
        port = free_port()
        keys = self.dir / f"keys-{tls_version}.log"
        with mock.patch.dict(os.environ, {"SSLKEYLOGFILE": str(keys)}):
            b = broker.Broker(self.dir, self.pki, "127.0.0.1", port, SHIM)
            b.start(mode="tls", tls_version=tls_version, acl=False)
        self.addCleanup(b._log.close)
        self.addCleanup(b.stop)

        recorder = pcapgen.Recorder(("127.0.0.1", port))
        self.addCleanup(recorder.close)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # no keylog: only the broker logs
        context.load_verify_locations(self.pki.ca)
        topic, envelope = next((f[3], bytes.fromhex(f[5])) for f in
                               (line.split() for line in VECTORS.read_text().splitlines())
                               if len(f) == 6 and f[0] == "encrypt_short")
        with socket.create_connection(("127.0.0.1", recorder.port)) as raw, \
                context.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
            negotiated = tls.version()
            tls.sendall(pcapgen.mqtt_connect("sensor-7"))
            self.assertEqual(tls.recv(4)[:1], b"\x20")  # CONNACK
            tls.sendall(pcapgen.mqtt_publish(topic, envelope))
            tls.sendall(b"\xe0\x00")                      # DISCONNECT
            time.sleep(0.2)
        time.sleep(0.2)

        cap = pcapgen.Capture()
        conn = pcapgen.TcpConnection(cap, ("127.0.0.1", 42000), ("127.0.0.1", 18830))
        recorder.replay_into(conn)
        conn.close()
        return cap.write(self.dir / f"tls-{tls_version}.pcap"), keys, negotiated

    def check(self, tls_version: str):
        capture, keys, negotiated = self.session(tls_version)
        self.assertEqual(negotiated, f"TLSv{tls_version}")
        labels = {line.split()[0] for line in keys.read_text().splitlines()}
        self.assertEqual("CLIENT_RANDOM" in labels, tls_version == "1.2")
        decrypted = fields(capture, "msec", "mqtt.topic", "msec.mode", "msec.ciphertext",
                           extra=("-o", f"tls.keylog_file:{keys}"))
        self.assertEqual(decrypted, [["restricted/sensors/sensor-7/temp", "1", "7533f82e86"]])
        # Without the secrets: TLS records only, no MQTT, no envelope.
        self.assertEqual(fields(capture, "mqtt || msec", "frame.number"), [])
        self.assertTrue(fields(capture, "tls.app_data", "frame.number"))

    @unittest.skipUnless(TSHARK and Path(TSHARK).with_name("editcap").exists(), "needs editcap")
    def test_capture_finish_embeds_secrets_and_event_comments(self):
        raw, keys, _ = self.session("1.3")
        cap_file = self.dir / "run.pcapng"
        editcap = str(Path(TSHARK).with_name("editcap"))
        subprocess.run([editcap, "-F", "pcapng", str(raw), str(cap_file)], check=True)
        times = capture.frame_times(cap_file)
        epochs = [float(r[0]) for r in fields(cap_file, "frame", "frame.time_epoch")]
        self.assertEqual(len(times), len(epochs))
        self.assertTrue(all(abs(a - b) < 1e-5 for a, b in zip(times, epochs)))

        with mock.patch.dict(os.environ, {"SSLKEYLOGFILE": str(self.dir / "unused")}):
            c = capture.Capture(cap_file, "lo", [18830], log=lambda m: None, keys=keys)
        c.events = [(times[4], "transport.mode: plain → tls"), (times[-1] + 60, "after the end")]
        with mock.patch.object(capture, "find_tool", return_value=editcap):
            c._finish()
        # Opens decrypted with no key file, and the comment sits on frame 5.
        self.assertEqual(fields(cap_file, "msec", "msec.mode"), [["1"]])
        self.assertEqual(fields(cap_file, "frame.comment", "frame.number", "frame.comment"),
                         [["5", "lab: transport.mode: plain → tls"]])
        self.assertIn("after the end", (self.dir / "run.events.tsv").read_text())

    def test_tls12_is_really_tls12(self):
        self.check("1.2")

    def test_tls13(self):
        self.check("1.3")


if __name__ == "__main__":
    unittest.main()
