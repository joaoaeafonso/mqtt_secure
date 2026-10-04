"""Test credentials for the load lab: a CA, certificates, passwords and payload keys.

One CertificateAuthority signs everything. Per run, generate() writes:

    pki/ca.crt                       trust anchor (public: every client gets it)
    pki/server.{crt,key}             broker; SAN localhost, 127.0.0.1 + advertised names
    pki/clients/<name>.{crt,key}     gateway and local sensors (CN = MQTT username)
    credentials.txt                  "<user> <password>" for gateway and every sensor
    passwd                           the same, hashed for mosquitto (mosquitto_passwd -U)
    keys.txt                         "<key id> <hex>" payload keys, key id n = sensor-<n>

Remote sensors (on agent machines) generate their own private keys; the CA only
signs their CSRs (issue_from_csr), so those keys never leave the agent.
The attacker gets nothing but the public CA certificate. ECDSA P-256 keeps
issuing hundreds of certificates fast. TEST USE ONLY: keys and passwords are
stored unencrypted (files are 0600).
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

LEAF_VALIDITY = dt.timedelta(days=2)
CA_VALIDITY = dt.timedelta(days=365)


def new_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def cert_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def write_private(path: Path, data: bytes) -> None:
    """Writes a file only its owner can read (created 0600, never world-readable)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(mode=0o600, exist_ok=True)
    path.chmod(0o600)
    path.write_bytes(data)


def subject_alt_names(names: list[str]) -> list[x509.GeneralName]:
    out: list[x509.GeneralName] = []
    for name in dict.fromkeys(names):  # dedupe, keep order
        try:
            out.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            out.append(x509.DNSName(name))
    return out


class CertificateAuthority:
    def __init__(self, key: ec.EllipticCurvePrivateKey, cert: x509.Certificate) -> None:
        self.key = key
        self.cert = cert

    @classmethod
    def create(cls, name: str = "msec-loadtest-ca") -> CertificateAuthority:
        key = new_key()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (x509.CertificateBuilder()
                .subject_name(subject).issuer_name(subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(minutes=5))
                .not_valid_after(now + CA_VALIDITY)
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    content_commitment=False, key_encipherment=False, data_encipherment=False,
                    key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
                .sign(key, hashes.SHA256()))
        return cls(key, cert)

    @classmethod
    def load(cls, key_path: Path, cert_path: Path) -> CertificateAuthority:
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        return cls(key, x509.load_pem_x509_certificate(cert_path.read_bytes()))

    def save(self, key_path: Path, cert_path: Path) -> None:
        write_private(key_path, key_pem(self.key))
        cert_path.write_bytes(cert_pem(self.cert))

    @property
    def pem(self) -> bytes:
        return cert_pem(self.cert)

    def issue(self, common_name: str, public_key, *, server: bool = False,
              names: list[str] | None = None) -> x509.Certificate:
        now = dt.datetime.now(dt.timezone.utc)
        usage = ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH
        builder = (x509.CertificateBuilder()
                   .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
                   .issuer_name(self.cert.subject)
                   .public_key(public_key)
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(now - dt.timedelta(minutes=5))
                   .not_valid_after(now + LEAF_VALIDITY)
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .add_extension(x509.ExtendedKeyUsage([usage]), critical=False))
        if names:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(subject_alt_names(names)), critical=False)
        return builder.sign(self.key, hashes.SHA256())

    def issue_from_csr(self, csr_pem: str, expected_cn: str) -> x509.Certificate:
        """Signs a client CSR, but only for the identity the controller assigned."""
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        if not csr.is_signature_valid:
            raise ValueError(f"CSR for {expected_cn}: bad signature")
        cns = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(cns) != 1 or cns[0].value != expected_cn:
            raise ValueError(f"CSR subject must be CN={expected_cn}")
        return self.issue(expected_cn, csr.public_key())


def make_csr(common_name: str) -> tuple[ec.EllipticCurvePrivateKey, str]:
    key = new_key()
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
           .sign(key, hashes.SHA256()))
    return key, csr.public_bytes(serialization.Encoding.PEM).decode()


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

    @property
    def clients_dir(self) -> Path:
        return self.root / "pki" / "clients"

    def client_cert(self, name: str) -> Path:
        return self.clients_dir / f"{name}.crt"

    def client_key(self, name: str) -> Path:
        return self.clients_dir / f"{name}.key"

    @property
    def credentials(self) -> Path:
        return self.root / "credentials.txt"

    @property
    def passwd(self) -> Path:
        return self.root / "passwd"

    @property
    def keys(self) -> Path:
        return self.root / "keys.txt"


def generate(root: Path, ca: CertificateAuthority, sensor_ids: list[int],
             local_sensor_ids: list[int], server_names: list[str]) -> Pki:
    """Credentials for one lab run. Certificates (with private keys) are made here
    only for the gateway and local sensors; remote sensors enrol via CSR."""
    pki = Pki(root)
    pki.ca.parent.mkdir(parents=True, exist_ok=True)
    pki.ca.write_bytes(ca.pem)

    server_key = new_key()
    pki.server_cert.write_bytes(cert_pem(ca.issue(
        "localhost", server_key.public_key(), server=True,
        names=["localhost", "127.0.0.1", *server_names])))
    write_private(pki.server_key, key_pem(server_key))

    for name in ["gateway"] + [f"sensor-{n}" for n in local_sensor_ids]:
        key = new_key()
        pki.clients_dir.mkdir(parents=True, exist_ok=True)
        pki.client_cert(name).write_bytes(cert_pem(ca.issue(name, key.public_key())))
        write_private(pki.client_key(name), key_pem(key))

    users = ["gateway"] + [f"sensor-{n}" for n in sensor_ids]
    passwords = {name: secrets.token_urlsafe(16) for name in users}
    write_private(pki.credentials, "".join(f"{u} {p}\n" for u, p in passwords.items()).encode())
    write_private(pki.passwd, "".join(f"{u}:{p}\n" for u, p in passwords.items()).encode())
    subprocess.run(["mosquitto_passwd", "-U", str(pki.passwd)], check=True)
    pki.passwd.chmod(0o600)

    lines = ["# key id, 32-byte AES key (hex). Test keys only.\n"]
    lines += [f"{n} {secrets.token_hex(KEY_SIZE)}\n" for n in sensor_ids]
    write_private(pki.keys, "".join(lines).encode())
    return pki


def read_credentials(path: Path) -> dict[str, str]:
    users = {}
    for line in path.read_text().splitlines():
        fields = line.split()
        if len(fields) == 2:
            users[fields[0]] = fields[1]
    return users
