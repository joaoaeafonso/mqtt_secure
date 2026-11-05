"""msec_envelope: byte compatibility with C++ (shared vectors) and Verifier policy."""

import unittest
from pathlib import Path

from msec_envelope import (AES_GCM, AUTH_ONLY, CHACHA20, ENCRYPT, SIGN, KeySet, Protector,
                           Rejected, Verifier, public_key, read_keys)

VECTORS = Path(__file__).resolve().parents[3] / "tests" / "vectors" / "envelope_vectors.txt"
NOW_MS = 1_700_000_000_000


def load_vectors():
    params, vectors = {}, []
    for line in VECTORS.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        f = line.split()
        if len(f) == 2:
            params[f[0]] = f[1]
        else:
            vectors.append(f)
    return params, vectors


class Vectors(unittest.TestCase):
    def test_python_reproduces_every_vector(self):
        params, vectors = load_vectors()
        self.assertGreaterEqual(len(vectors), 5)
        aead, sign = bytes.fromhex(params["aead_key"]), bytes.fromhex(params["sign_key"])
        nonce, ts = bytes.fromhex(params["nonce"]), int(params["timestamp_ms"])
        for name, mode, key_id, topic, payload_hex, envelope_hex in vectors:
            with self.subTest(name):
                payload = b"" if payload_hex == "-" else bytes.fromhex(payload_hex)
                mode, _, alg = mode.partition(":")
                p = Protector(mode, int(key_id), aead, sign,
                              algorithm=CHACHA20 if alg == "chacha20" else AES_GCM,
                              clock_ns=lambda: ts * 1_000_000, random=lambda n: nonce, sequence=0)
                self.assertEqual(p.protect(topic.encode(), payload).hex(), envelope_hex)


class VerifierPolicy(unittest.TestCase):
    def setUp(self):
        self.aead, self.signing = bytes(range(32)), bytes(range(32, 64))
        self.keys = KeySet()
        self.keys.add(1, "aead", self.aead, "sensor-1")
        self.keys.add(1, "sign-public", public_key(self.signing), "sensor-1")
        self.clock = lambda: NOW_MS * 1_000_000

    def sender(self, mode):
        return Protector(mode, 1, self.aead, self.signing, clock_ns=self.clock, sequence=0)

    def verifier(self, accept, **kw):
        return Verifier(self.keys, accept, clock_ns=self.clock, **kw)

    def reason(self, verifier, topic, data):
        with self.assertRaises(Rejected) as ctx:
            verifier.open(topic, data)
        return ctx.exception.reason

    def test_round_trip_every_mode(self):
        for mode in (ENCRYPT, AUTH_ONLY, SIGN):
            with self.subTest(mode):
                env = self.sender(mode).protect(b"t", b"21.5C")
                self.assertEqual(self.verifier({mode}).open(b"t", env), b"21.5C")

    def test_tampering_topic_rebinding_and_unknown_keys_fail(self):
        for mode in (ENCRYPT, AUTH_ONLY, SIGN):
            with self.subTest(mode):
                env = bytearray(self.sender(mode).protect(b"t", b"21.5C"))
                v = self.verifier({mode})
                self.assertEqual(self.reason(v, b"other", bytes(env)), "AuthenticationFailed")
                env[-1] ^= 1
                self.assertEqual(self.reason(v, b"t", bytes(env)), "AuthenticationFailed")
        unknown = Protector(ENCRYPT, 9, bytes(32), clock_ns=self.clock, sequence=0).protect(b"t", b"x")
        self.assertEqual(self.reason(self.verifier({ENCRYPT}), b"t", unknown),
                         "AuthenticationFailed")

    def test_mode_policy_and_plaintext(self):
        env = self.sender(AUTH_ONLY).protect(b"t", b"x")
        self.assertEqual(self.reason(self.verifier({ENCRYPT}), b"t", env), "ProtectionNotAccepted")
        self.assertEqual(self.reason(self.verifier({ENCRYPT}), b"t", b"plain"), "MalformedMessage")

    def test_replay_window(self):
        s, v = self.sender(ENCRYPT), self.verifier({ENCRYPT})
        first, second = s.protect(b"t", b"a"), s.protect(b"t", b"b")
        v.open(b"t", second)
        v.open(b"t", first)  # reordering inside the window is fine
        self.assertEqual(self.reason(v, b"t", first), "ReplayDetected")
        self.assertEqual(self.verifier({ENCRYPT}, replay=False).open(b"t", first), b"a")

    def test_freshness(self):
        old = Protector(ENCRYPT, 1, self.aead, clock_ns=lambda: (NOW_MS - 61_000) * 1_000_000,
                        sequence=0).protect(b"t", b"x")
        self.assertEqual(self.reason(self.verifier({ENCRYPT}), b"t", old), "MessageExpired")
        self.assertEqual(self.verifier({ENCRYPT}, freshness=False).open(b"t", old), b"x")

    def test_only_allowed_senders(self):
        env = self.sender(ENCRYPT).protect(b"t", b"x")
        self.assertEqual(self.reason(self.verifier({ENCRYPT}, allowed_senders={0}), b"t", env),
                         "PermissionDenied")


class ChaCha20Keys(unittest.TestCase):
    """The AEAD algorithm is an attribute of the key; the envelope is unchanged."""

    def setUp(self):
        self.key = bytes(range(32))
        self.clock = lambda: NOW_MS * 1_000_000

    def keys(self, algorithm):
        keys = KeySet()
        keys.add(1, "aead", self.key, "sensor-1", algorithm)
        return keys

    def test_round_trip_and_cross_algorithm_failure(self):
        for mode in (ENCRYPT, AUTH_ONLY):
            with self.subTest(mode):
                env = Protector(mode, 1, self.key, algorithm=CHACHA20, clock_ns=self.clock,
                                sequence=0).protect(b"t", b"21.5C")
                ok = Verifier(self.keys(CHACHA20), {mode}, clock_ns=self.clock)
                self.assertEqual(ok.open(b"t", env), b"21.5C")
                # Same key bytes registered as AES-GCM: the receiver must not open it.
                aes = Verifier(self.keys(AES_GCM), {mode}, clock_ns=self.clock)
                with self.assertRaises(Rejected) as ctx:
                    aes.open(b"t", env)
                self.assertEqual(ctx.exception.reason, "AuthenticationFailed")

    def test_key_file_kind_carries_the_algorithm(self):
        keys = self.keys(CHACHA20)
        keys.add(2, "aead", self.key, "sensor-2")
        self.assertIn(f"1 aead-chacha20 {self.key.hex()} sensor-1", keys.lines())
        self.assertIn(f"2 aead {self.key.hex()} sensor-2", keys.lines())
        back = KeySet()
        back.merge(keys)
        self.assertEqual((back.algorithm(1), back.algorithm(2)), (CHACHA20, AES_GCM))
        self.assertEqual(keys.subset([1]).algorithm(1), CHACHA20)
        keys.remove(1)
        self.assertEqual(keys.algorithm(1), AES_GCM)


class KeyFiles(unittest.TestCase):
    def test_lines_round_trip(self):
        keys = KeySet()
        keys.add(3, "aead", bytes(32), "sensor-3")
        keys.add(3, "sign-private", bytes(range(32)), "sensor-3")
        path = Path(self.id().replace(".", "_") + ".txt")
        try:
            path.write_text("\n".join(keys.lines()) + "\n# comment\n")
            back = read_keys(str(path))
        finally:
            path.unlink(missing_ok=True)
        self.assertEqual(back.lines(), keys.lines())
        self.assertEqual(back.owners[3], "sensor-3")


if __name__ == "__main__":
    unittest.main()
