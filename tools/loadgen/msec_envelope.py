"""Python implementation of the msec::security envelope (sender side only).

Must stay byte-compatible with modules/security/src/envelope.cpp and
SecurityLayer::protect():

    offset size  field
    0      2     magic "MS"
    2      1     version (1)
    3      4     key id                       big-endian
    7      8     sequence number              big-endian, starts at 1
    15     8     timestamp, ms since epoch    big-endian, signed
    23     1     nonce length N
    24     N     nonce
    24+N   ...   Encrypt:          ciphertext || tag
                 AuthenticateOnly: payload    || tag

    AAD = bytes[0 : 24+N] || u16 topic length || topic          (Encrypt)
        = same || payload                                       (AuthenticateOnly)
"""

from __future__ import annotations

import os
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"MS"
VERSION = 1
NONCE_SIZE = 12
KEY_SIZE = 32

NONE = "none"
AUTH_ONLY = "auth_only"
ENCRYPT = "encrypt"

# Lab / gateway --protection values -> sender mode.
SENDER_PROTECTION_MODES = {"none": NONE, "auth_only": AUTH_ONLY, "encrypt": ENCRYPT}

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


class Protector:
    """Seals payloads for one sensor (one key id, one sequence counter)."""

    def __init__(self, protection: str, key_id: int = 0, key: bytes | None = None) -> None:
        if protection not in (NONE, AUTH_ONLY, ENCRYPT):
            raise ValueError(f"unknown protection {protection!r}")
        if protection != NONE and (key is None or len(key) != KEY_SIZE):
            raise ValueError(f"protection {protection!r} needs a {KEY_SIZE}-byte key")
        self.protection = protection
        self.key_id = key_id
        # Start from the current time in µs rather than 0: a sensor that restarts
        # (new process, agent reconnect) keeps moving forward through the
        # receiver's replay window instead of falling behind it. Stays monotonic
        # as long as a sensor sends < 1M msg/s and the clock doesn't step back.
        self.sequence = time.time_ns() // 1000
        self._aead = AESGCM(key) if key else None
        self._key_id_bytes = key_id.to_bytes(4, "big")

    def set_protection(self, protection: str) -> None:
        """Switches mode at runtime; the sequence number keeps counting up, so the
        receiver's replay window stays valid across switches."""
        if protection != NONE and self._aead is None:
            raise ValueError("this protector has no key")
        self.protection = protection

    def protect(self, topic: bytes, payload: bytes) -> bytes:
        if self.protection == NONE:
            return payload
        self.sequence += 1
        nonce = os.urandom(NONCE_SIZE)
        prefix = b"".join((
            MAGIC,
            bytes((VERSION,)),
            self._key_id_bytes,
            self.sequence.to_bytes(8, "big"),
            (time.time_ns() // 1_000_000).to_bytes(8, "big", signed=True),
            bytes((NONCE_SIZE,)),
            nonce,
        ))
        aad = prefix + len(topic).to_bytes(2, "big") + topic
        if self.protection == ENCRYPT:
            return prefix + self._aead.encrypt(nonce, payload, aad)
        tag = self._aead.encrypt(nonce, b"", aad + payload)
        return prefix + payload + tag


def read_keys(path: str) -> dict[int, bytes]:
    """Parses the key file shared with msec_load_gateway: "<id> <hex>" per line."""
    keys: dict[int, bytes] = {}
    with open(path, encoding="ascii") as f:
        for line in f:
            fields = line.split()
            if not fields or fields[0].startswith("#"):
                continue
            keys[int(fields[0])] = bytes.fromhex(fields[1])
    return keys
