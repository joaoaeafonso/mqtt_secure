"""Test credentials for the load lab: a CA, certificates, passwords and payload keys.

One CertificateAuthority signs everything. Per run, generate() writes:

    pki/ca.crt                       trust anchor (public: every client gets it)
    pki/server.{crt,key}             broker; SAN localhost, 127.0.0.1 + advertised names
    pki/clients/<name>.{crt,key}     gateway and local sensors (CN = MQTT username)
    pki/issued/<name>.crt            every client certificate issued (for revocation)
    pki/crl.pem                      revoked client certificates (mtls)
    credentials.txt                  "<user> <password>" for gateway and every sensor
    passwd                           the same minus revoked users, hashed for mosquitto
    keys.txt                         the gateway's payload keys (see below)
    device-keys.txt                  the local sensors' payload keys

Payload keys (msec_envelope.KeySet, "<id> <kind> <hex> <owner>"): per device an
AEAD key and an Ed25519 key pair. The AEAD key's algorithm (AES-256-GCM, kind
"aead", or ChaCha20-Poly1305, kind "aead-chacha20") is chosen per epoch, so
switching algorithms is a key rotation; key id = epoch * EPOCH_STRIDE + device,
device 0 = the gateway. The gateway gets every aead key and public key but
only its own private key: a signature then proves a sensor made the message,
which a shared AES key cannot. A device gets its own aead + private key plus
the gateway's aead key (the downlink "group key" every actuator shares) and the
gateway's public key.

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

from msec_envelope import AEAD, AES_GCM, KEY_SIZE, SIGN_PRIVATE, SIGN_PUBLIC, KeySet, public_key

EPOCH_STRIDE = 1_000_000
GATEWAY = 0
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

    def crl(self, revoked: list[x509.Certificate]) -> bytes:
        """A CRL listing these certificates (PEM), valid for the lab's lifetime."""
        now = dt.datetime.now(dt.timezone.utc)
        builder = (x509.CertificateRevocationListBuilder()
                   .issuer_name(self.cert.subject)
                   .last_update(now - dt.timedelta(minutes=5))
                   .next_update(now + LEAF_VALIDITY))
        for cert in revoked:
            builder = builder.add_revoked_certificate(
                x509.RevokedCertificateBuilder().serial_number(cert.serial_number)
                .revocation_date(now - dt.timedelta(minutes=1)).build())
        return builder.sign(self.key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)

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

    @property
    def device_keys(self) -> Path:
        return self.root / "device-keys.txt"

    @property
    def epoch_state(self) -> Path:
        """The gateway's durable record of the newest key epoch it accepted."""
        return self.root / "gateway-epoch"

    @property
    def crl(self) -> Path:
        return self.root / "pki" / "crl.pem"

    def issued(self, name: str) -> Path:
        return self.root / "pki" / "issued" / f"{name}.crt"

    def record_issued(self, name: str, pem: bytes) -> None:
        self.issued(name).parent.mkdir(parents=True, exist_ok=True)
        self.issued(name).write_bytes(pem)


def key_id(device: int, epoch: int) -> int:
    return epoch * EPOCH_STRIDE + device


def owner(device: int) -> str:
    return "gateway" if device == GATEWAY else f"sensor-{device}"


def make_keys(sensor_ids: list[int], epoch: int, algorithm: str = AES_GCM) -> KeySet:
    """Fresh payload keys for the gateway and these sensors; `algorithm` is the
    AEAD algorithm of this epoch's aead keys."""
    keys = KeySet()
    for device in [GATEWAY, *sensor_ids]:
        kid, name = key_id(device, epoch), owner(device)
        signing = secrets.token_bytes(KEY_SIZE)
        keys.add(kid, AEAD, secrets.token_bytes(KEY_SIZE), name, algorithm)
        keys.add(kid, SIGN_PRIVATE, signing, name)
        keys.add(kid, SIGN_PUBLIC, public_key(signing), name)
    return keys


def gateway_view(keys: KeySet) -> KeySet:
    """Every aead and public key; the private signing key of the gateway only."""
    out = KeySet()
    for kid in keys.aead:
        out.add(kid, AEAD, keys.aead[kid], keys.owners.get(kid), keys.algorithm(kid))
    for kid in keys.sign_public:
        out.add(kid, SIGN_PUBLIC, keys.sign_public[kid], keys.owners.get(kid))
    for kid, key in keys.sign_private.items():
        if keys.owners.get(kid) == "gateway":
            out.add(kid, SIGN_PRIVATE, key, "gateway")
    return out


def device_view(keys: KeySet, sensor_ids: list[int]) -> KeySet:
    """What these sensors hold: their own keys, the gateway's aead and public key."""
    names = {owner(n) for n in sensor_ids}
    out = KeySet()
    for kid, name in keys.owners.items():
        if name in names:
            out.merge(keys.subset([kid], (AEAD, SIGN_PRIVATE)))
        elif name == "gateway":
            out.merge(keys.subset([kid], (AEAD, SIGN_PUBLIC)))
    return out


def write_keys(path: Path, keys: KeySet) -> None:
    write_private(path, ("# key id, kind, 32-byte key (hex), owner. Test keys only.\n"
                         + "".join(line + "\n" for line in keys.lines())).encode())


def write_passwd(pki: Pki, passwords: dict[str, str], revoked: set[str]) -> None:
    """mosquitto's password file, without revoked users."""
    write_private(pki.passwd, "".join(f"{u}:{p}\n" for u, p in passwords.items()
                                      if u not in revoked).encode())
    subprocess.run(["mosquitto_passwd", "-U", str(pki.passwd)], check=True)
    pki.passwd.chmod(0o600)


def write_crl(pki: Pki, ca: CertificateAuthority, revoked: set[str]) -> None:
    certs = [x509.load_pem_x509_certificate(pki.issued(name).read_bytes())
             for name in sorted(revoked) if pki.issued(name).exists()]
    pki.crl.write_bytes(ca.crl(certs))


def generate(root: Path, ca: CertificateAuthority, sensor_ids: list[int],
             local_sensor_ids: list[int], server_names: list[str],
             algorithm: str = AES_GCM) -> tuple[Pki, KeySet]:
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
        pem = cert_pem(ca.issue(name, key.public_key()))
        pki.client_cert(name).write_bytes(pem)
        pki.record_issued(name, pem)
        write_private(pki.client_key(name), key_pem(key))

    users = ["gateway"] + [f"sensor-{n}" for n in sensor_ids]
    passwords = {name: secrets.token_urlsafe(16) for name in users}
    write_private(pki.credentials, "".join(f"{u} {p}\n" for u, p in passwords.items()).encode())
    write_passwd(pki, passwords, set())
    write_crl(pki, ca, set())

    keys = make_keys(sensor_ids, epoch=0, algorithm=algorithm)
    write_keys(pki.keys, gateway_view(keys))
    write_keys(pki.device_keys, device_view(keys, local_sensor_ids))
    return pki, keys


def read_credentials(path: Path) -> dict[str, str]:
    users = {}
    for line in path.read_text().splitlines():
        fields = line.split()
        if len(fields) == 2:
            users[fields[0]] = fields[1]
    return users
