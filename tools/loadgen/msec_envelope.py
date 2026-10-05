"""Python implementation of the msec::security envelope, both directions.

Must stay byte-compatible with modules/security/src/envelope.cpp and
SecurityLayer (tests/vectors/envelope_vectors.txt is checked by both):

    offset size  field
    0      2     magic "MS"
    2      1     version (2)
    3      1     protection mode              1 encrypt, 2 auth_only, 3 sign
    4      4     key id                       big-endian
    8      8     sequence number              big-endian, starts at 1
    16     8     timestamp, ms since epoch    big-endian, signed
    24     1     nonce length N               0 for sign
    25     N     nonce
    25+N   ...   encrypt:    ciphertext || tag          AEAD(payload, AAD)
                 auth_only:  payload    || tag          AEAD(empty, AAD || payload)
                 sign:       payload    || signature    Ed25519(AAD || payload)

    AAD = bytes[0 : 25+N] || u16 topic length || topic

Protector seals (sensors, attacker); Verifier opens (actuators receiving
gateway commands), with the same policy checks as the C++ receiver: accepted
modes, freshness, key → sender binding and a 64-entry replay window.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"MS"
VERSION = 2
NONCE_SIZE = 12
KEY_SIZE = 32
TAG_SIZE = 16
SIGNATURE_SIZE = 64
FIXED_HEADER = 25
REPLAY_WINDOW = 64

NONE = "none"
AUTH_ONLY = "auth_only"
ENCRYPT = "encrypt"
SIGN = "sign"
MODES = {ENCRYPT: 1, AUTH_ONLY: 2, SIGN: 3}
MODE_NAMES = {v: k for k, v in MODES.items()}

# Lab / gateway --protection values -> sender mode.
SENDER_PROTECTION_MODES = {"none": NONE, "auth_only": AUTH_ONLY, "encrypt": ENCRYPT,
                           "sign": SIGN}

# Gateway profile -> what the sender has to do. Freshness and replay checks are
# receiver-side only, so every AEAD profile looks the same on the wire.
SENDER_PROTECTION = {
    "none": NONE,
    "auth_only": AUTH_ONLY,
    "aead": ENCRYPT,
    "aead_freshness": ENCRYPT,
    "aead_replay": ENCRYPT,
    "full": ENCRYPT,
}

# Key kinds in key files: "<id> <kind> <hex> [owner]".
AEAD = "aead"
SIGN_PRIVATE = "sign-private"
SIGN_PUBLIC = "sign-public"
KINDS = (AEAD, SIGN_PRIVATE, SIGN_PUBLIC)
GATEWAY_OWNER = "gateway"


class Rejected(Exception):
    """A message the Verifier refused; `reason` uses the C++ ErrorCode names."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


@dataclass
class KeySet:
    """Keys by kind and id, plus the device each key id belongs to."""

    aead: dict[int, bytes] = field(default_factory=dict)
    sign_private: dict[int, bytes] = field(default_factory=dict)
    sign_public: dict[int, bytes] = field(default_factory=dict)
    owners: dict[int, str] = field(default_factory=dict)

    def store(self, kind: str) -> dict[int, bytes]:
        return {AEAD: self.aead, SIGN_PRIVATE: self.sign_private,
                SIGN_PUBLIC: self.sign_public}[kind]

    def add(self, key_id: int, kind: str, key: bytes, owner: str | None = None) -> None:
        if kind not in KINDS:
            raise ValueError(f"unknown key kind {kind!r}")
        if len(key) != KEY_SIZE:
            raise ValueError(f"key {key_id} ({kind}) must be {KEY_SIZE} bytes")
        self.store(kind)[key_id] = key
        if owner:
            self.owners[key_id] = owner

    def remove(self, key_id: int) -> None:
        for kind in KINDS:
            self.store(kind).pop(key_id, None)
        self.owners.pop(key_id, None)

    def lines(self) -> list[str]:
        out = []
        for kind in KINDS:
            for key_id, key in sorted(self.store(kind).items()):
                owner = self.owners.get(key_id)
                out.append(f"{key_id} {kind} {key.hex()}" + (f" {owner}" if owner else ""))
        return out

    def subset(self, key_ids, kinds=KINDS) -> KeySet:
        out = KeySet()
        for kind in kinds:
            for key_id in key_ids:
                if key_id in self.store(kind):
                    out.add(key_id, kind, self.store(kind)[key_id], self.owners.get(key_id))
        return out

    def merge(self, other: KeySet) -> None:
        for line in other.lines():
            add_line(self, line)


def add_line(keys: KeySet, line: str) -> None:
    fields = line.split()
    if len(fields) == 2:
        fields.insert(1, AEAD)
    if len(fields) not in (3, 4):
        raise ValueError(f"bad key line {line!r}")
    keys.add(int(fields[0]), fields[1], bytes.fromhex(fields[2]),
             fields[3] if len(fields) == 4 else None)


def read_keys(path: str) -> KeySet:
    """Parses a key file shared with msec_load_gateway."""
    keys = KeySet()
    with open(path, encoding="ascii") as f:
        for line in f:
            if line.strip() and not line.lstrip().startswith("#"):
                add_line(keys, line)
    return keys


def public_key(private_key: bytes) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return Ed25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _prefix(mode: str, key_id: int, sequence: int, timestamp_ms: int, nonce: bytes) -> bytes:
    return b"".join((
        MAGIC,
        bytes((VERSION, MODES[mode])),
        key_id.to_bytes(4, "big"),
        sequence.to_bytes(8, "big"),
        timestamp_ms.to_bytes(8, "big", signed=True),
        bytes((len(nonce),)),
        nonce,
    ))


def _aad(prefix: bytes, topic: bytes) -> bytes:
    return prefix + len(topic).to_bytes(2, "big") + topic


class Protector:
    """Seals payloads for one sender (one key id, one sequence counter).

    `clock_ns`, `random` and `sequence` are injectable for test vectors.
    """

    def __init__(self, protection: str, key_id: int = 0, key: bytes | None = None,
                 signing_key: bytes | None = None, *,
                 clock_ns: Callable[[], int] = time.time_ns,
                 random: Callable[[int], bytes] = os.urandom,
                 sequence: int | None = None) -> None:
        self.key_id = key_id
        self._aead = AESGCM(key) if key else None
        self._signer = Ed25519PrivateKey.from_private_bytes(signing_key) if signing_key else None
        self._clock_ns = clock_ns
        self._random = random
        # Start from the current time in µs rather than 0: a sensor that restarts
        # (new process, agent reconnect) keeps moving forward through the
        # receiver's replay window instead of falling behind it. Stays monotonic
        # as long as a sensor sends < 1M msg/s and the clock doesn't step back.
        self.sequence = time.time_ns() // 1000 if sequence is None else sequence
        self.protection = NONE
        self.set_protection(protection)

    def set_protection(self, protection: str) -> None:
        """Switches mode at runtime; the sequence number keeps counting up, so the
        receiver's replay window stays valid across switches."""
        if protection not in (NONE, AUTH_ONLY, ENCRYPT, SIGN):
            raise ValueError(f"unknown protection {protection!r}")
        if protection in (AUTH_ONLY, ENCRYPT) and self._aead is None:
            raise ValueError(f"protection {protection!r} needs a {KEY_SIZE}-byte AEAD key")
        if protection == SIGN and self._signer is None:
            raise ValueError("protection 'sign' needs a signing key")
        self.protection = protection

    def rekey(self, key_id: int, key: bytes | None, signing_key: bytes | None) -> None:
        """Key rotation: continue with a new key id (and a fresh sequence space)."""
        self.key_id = key_id
        self._aead = AESGCM(key) if key else None
        self._signer = Ed25519PrivateKey.from_private_bytes(signing_key) if signing_key else None

    def protect(self, topic: bytes, payload: bytes) -> bytes:
        if self.protection == NONE:
            return payload
        self.sequence += 1
        nonce = b"" if self.protection == SIGN else self._random(NONCE_SIZE)
        prefix = _prefix(self.protection, self.key_id, self.sequence,
                         self._clock_ns() // 1_000_000, nonce)
        aad = _aad(prefix, topic)
        if self.protection == ENCRYPT:
            return prefix + self._aead.encrypt(nonce, payload, aad)
        if self.protection == SIGN:
            return prefix + payload + self._signer.sign(aad + payload)
        return prefix + payload + self._aead.encrypt(nonce, b"", aad + payload)


@dataclass
class _Window:
    highest: int
    bitmap: int


class Verifier:
    """Opens envelopes with the same checks, in the same order, as SecurityLayer."""

    def __init__(self, keys: KeySet, accept: set[str], *, freshness: bool = True,
                 replay: bool = True, allowed_senders: set[int] | None = None,
                 max_age_ms: int = 60_000, max_skew_ms: int = 5_000,
                 clock_ns: Callable[[], int] = time.time_ns) -> None:
        self.keys = keys
        self.accept = set(accept)
        self.freshness = freshness
        self.replay = replay
        # None: any known key; otherwise only these key ids (the binding check).
        self.allowed_senders = allowed_senders
        self.max_age_ms = max_age_ms
        self.max_skew_ms = max_skew_ms
        self._clock_ns = clock_ns
        self._windows: dict[int, _Window] = {}

    def open(self, topic: bytes, data: bytes) -> bytes:
        if len(data) < FIXED_HEADER or data[:2] != MAGIC:
            raise Rejected("MalformedMessage", "not an envelope")
        if data[2] != VERSION:
            raise Rejected("MalformedMessage", "unsupported envelope version")
        mode = MODE_NAMES.get(data[3])
        if mode is None:
            raise Rejected("MalformedMessage", "unknown protection mode")
        key_id = int.from_bytes(data[4:8], "big")
        sequence = int.from_bytes(data[8:16], "big")
        timestamp_ms = int.from_bytes(data[16:24], "big", signed=True)
        nonce_len = data[24]
        if sequence == 0 or len(data) <= FIXED_HEADER + nonce_len:
            raise Rejected("MalformedMessage", "truncated envelope")
        if mode not in self.accept:
            raise Rejected("ProtectionNotAccepted", f"mode {mode}")
        if nonce_len != (0 if mode == SIGN else NONCE_SIZE):
            raise Rejected("MalformedMessage", "nonce size does not match algorithm")
        if self.freshness:
            now = self._clock_ns() // 1_000_000
            if timestamp_ms < now - self.max_age_ms or timestamp_ms > now + self.max_skew_ms:
                raise Rejected("MessageExpired")
        prefix = data[:FIXED_HEADER + nonce_len]
        nonce = data[FIXED_HEADER:FIXED_HEADER + nonce_len]
        body = data[FIXED_HEADER + nonce_len:]
        aad = _aad(prefix, topic)
        payload = self._unprotect(mode, key_id, nonce, body, aad)
        if self.allowed_senders is not None and key_id not in self.allowed_senders:
            raise Rejected("PermissionDenied", f"key {key_id} may not send here")
        if self.replay:
            self._check_replay(key_id, sequence)
        return payload

    def _unprotect(self, mode: str, key_id: int, nonce: bytes, body: bytes, aad: bytes) -> bytes:
        store = self.keys.sign_public if mode == SIGN else self.keys.aead
        key = store.get(key_id)
        if key is None:
            raise Rejected("AuthenticationFailed", "unknown key id")
        try:
            if mode == ENCRYPT:
                return AESGCM(key).decrypt(nonce, body, aad)
            tag_size = SIGNATURE_SIZE if mode == SIGN else TAG_SIZE
            if len(body) < tag_size:
                raise Rejected("AuthenticationFailed")
            payload, tag = body[:-tag_size], body[-tag_size:]
            if mode == SIGN:
                Ed25519PublicKey.from_public_bytes(key).verify(tag, aad + payload)
            else:
                AESGCM(key).decrypt(nonce, tag, aad + payload)
            return payload
        except (InvalidTag, InvalidSignature, ValueError) as e:
            raise Rejected("AuthenticationFailed") from e

    def _check_replay(self, key_id: int, sequence: int) -> None:
        w = self._windows.get(key_id)
        if w is None:
            self._windows[key_id] = _Window(sequence, 1)
            return
        if sequence > w.highest:
            shift = sequence - w.highest
            w.bitmap = 1 if shift >= REPLAY_WINDOW else ((w.bitmap << shift) | 1) & ((1 << 64) - 1)
            w.highest = sequence
            return
        offset = w.highest - sequence
        if offset >= REPLAY_WINDOW or w.bitmap & (1 << offset):
            raise Rejected("ReplayDetected")
        w.bitmap |= 1 << offset

    def forget(self, key_id: int) -> None:
        self._windows.pop(key_id, None)
