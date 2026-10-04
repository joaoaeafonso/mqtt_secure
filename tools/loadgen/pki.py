"""Test credentials for the load lab: a CA, certificates, passwords and payload keys.

Everything is generated fresh per run into one directory:

    pki/ca.crt                       trust anchor (public: every client gets it)
    pki/server.{crt,key}             broker, SAN localhost + 127.0.0.1
    pki/clients/<name>.{crt,key}     gateway, sensor-<n> (CN = MQTT username)
    credentials.txt                  "<user> <password>" for gateway and sensors
    passwd                           the same, hashed for mosquitto (mosquitto_passwd -U)
    keys.txt                         "<key id> <hex>" payload keys, key id n = sensor-<n>

The attacker ("mallory") deliberately gets nothing but the public CA certificate.
ECDSA P-256 keeps generating hundreds of certificates fast. TEST USE ONLY:
private keys and passwords are stored unencrypted.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import secrets
import subprocess
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from msec_envelope import KEY_SIZE

VALIDITY = dt.timedelta(days=2)


@dataclass(frozen=True)
class Pki:
    root: Path

    @property
    def ca(self) -> Path:
        return self.root / "pki" / "ca.crt"

    @property
    def server_cert(self) -> Path:
        return self.root / "pki" / "server.crt"

    @property
    def server_key(self) -> Path:
        return self.root / "pki" / "server.key"

    def client_cert(self, name: str) -> Path:
        return self.root / "pki" / "clients" / f"{name}.crt"

    def client_key(self, name: str) -> Path:
        return self.root / "pki" / "clients" / f"{name}.key"

    @property
    def credentials(self) -> Path:
        return self.root / "credentials.txt"

    @property
    def passwd(self) -> Path:
        return self.root / "passwd"

    @property
    def keys(self) -> Path:
        return self.root / "keys.txt"


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(mode=0o600, exist_ok=True)
    path.chmod(0o600)
    path.write_bytes(data)


def _key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _issue(subject_cn: str, key, issuer_name, issuer_key, *, ca=False, server=False):
    now = dt.datetime.now(dt.timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
               .issuer_name(issuer_name)
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - dt.timedelta(minutes=5))
               .not_valid_after(now + VALIDITY)
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if ca:
        builder = builder.add_extension(
            x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                          content_commitment=False, key_encipherment=False,
                          data_encipherment=False, key_agreement=False, encipher_only=False,
                          decipher_only=False), critical=True)
    else:
        usage = ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH
        builder = builder.add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
    if server:
        builder = builder.add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]), critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


def generate(root: Path, sensors: int) -> Pki:
    pki = Pki(root)
    curve = ec.SECP256R1()

    ca_key = ec.generate_private_key(curve)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "msec-loadtest-ca")])
    ca_cert = _issue("msec-loadtest-ca", ca_key, ca_name, ca_key, ca=True)
    pki.ca.parent.mkdir(parents=True, exist_ok=True)
    pki.ca.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    server_key = ec.generate_private_key(curve)
    pki.server_cert.write_bytes(
        _issue("localhost", server_key, ca_name, ca_key, server=True)
        .public_bytes(serialization.Encoding.PEM))
    _write_private(pki.server_key, _key_pem(server_key))

    names = ["gateway"] + [f"sensor-{n}" for n in range(1, sensors + 1)]
    for name in names:
        key = ec.generate_private_key(curve)
        cert = pki.client_cert(name)
        cert.parent.mkdir(parents=True, exist_ok=True)
        cert.write_bytes(_issue(name, key, ca_name, ca_key)
                         .public_bytes(serialization.Encoding.PEM))
        _write_private(pki.client_key(name), _key_pem(key))

    passwords = {name: secrets.token_urlsafe(16) for name in names}
    _write_private(pki.credentials,
                   "".join(f"{u} {p}\n" for u, p in passwords.items()).encode())
    _write_private(pki.passwd, "".join(f"{u}:{p}\n" for u, p in passwords.items()).encode())
    subprocess.run(["mosquitto_passwd", "-U", str(pki.passwd)], check=True)
    pki.passwd.chmod(0o600)

    lines = ["# key id, 32-byte AES key (hex). Test keys only.\n"]
    lines += [f"{n} {secrets.token_hex(KEY_SIZE)}\n" for n in range(1, sensors + 1)]
    _write_private(pki.keys, "".join(lines).encode())
    return pki


def read_credentials(path: Path) -> dict[str, str]:
    users = {}
    for line in path.read_text().splitlines():
        fields = line.split()
        if len(fields) == 2:
            users[fields[0]] = fields[1]
    return users
