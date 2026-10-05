"""Lab configuration validation (no processes started)."""

import unittest

from lab import DEFAULTS, PACKET_OVERHEAD, PRESETS, merged, parse_revoked, validate


class Validate(unittest.TestCase):
    def test_defaults_are_valid(self):
        self.assertEqual(merged(DEFAULTS, {})["payload"]["protection"], "encrypt")

    def test_choices_accept_numbers_or_text(self):
        cfg = merged(DEFAULTS, {"transport": {"protocol": 5, "tls_version": 1.3}})
        self.assertEqual(cfg["transport"]["protocol"], "5")
        self.assertEqual(cfg["transport"]["tls_version"], "1.3")
        self.assertEqual(merged(DEFAULTS, {"load": {"qos": "2"}})["load"]["qos"], 2)

    def test_rejects_bad_values(self):
        for patch in ({"payload": {"protection": "rot13"}}, {"transport": {"bogus": 1}},
                      {"nope": {}}, {"payload": {"rate_limit": -1}},
                      {"payload": {"key_binding": "yes"}}, {"load": {"payload": 4}}):
            with self.subTest(patch), self.assertRaises(ValueError):
                merged(DEFAULTS, patch)

    def test_revoked_list(self):
        self.assertEqual(parse_revoked("3, 7,3"), {3, 7})
        self.assertEqual(parse_revoked(""), set())
        self.assertEqual(merged(DEFAULTS, {"response": {"revoked": "7,3"}})["response"]["revoked"],
                         "3,7")
        with self.assertRaises(ValueError):
            parse_revoked("x")
        with self.assertRaises(ValueError):
            merged(DEFAULTS, {"response": {"revoked": "999"}})  # only 50 sensors

    def test_validate_flattens(self):
        self.assertEqual(validate({"downlink": {"rate": 5}}), [("downlink", "rate", 5)])


class HardenedPreset(unittest.TestCase):
    def test_turns_every_defence_on(self):
        cfg = merged(DEFAULTS, PRESETS["hardened"](DEFAULTS))
        t, p = cfg["transport"], cfg["payload"]
        self.assertEqual((t["mode"], t["tls_version"], t["protocol"]), ("mtls", "1.3", "5"))
        self.assertTrue(t["auth"] and t["acl"] and t["clientid_binding"])
        self.assertFalse(t["sys_topics"])
        self.assertEqual(p["protection"], "sign")
        self.assertTrue(p["freshness"] and p["replay"] and p["key_binding"])
        self.assertEqual(cfg["load"]["zone"], "restricted")

    def test_limits_follow_the_load(self):
        base = merged(DEFAULTS, {"load": {"sensors": 200, "rate": 50.0, "payload": 4096}})
        cfg = merged(base, PRESETS["hardened"](base))
        self.assertEqual(cfg["transport"]["max_connections"], 216)
        self.assertEqual(cfg["transport"]["max_packet"], 4096 + PACKET_OVERHEAD)
        self.assertGreaterEqual(cfg["payload"]["rate_limit"], 100)  # never below the real rate

    def test_packet_limit_must_fit_the_payload(self):
        with self.assertRaises(ValueError):
            merged(DEFAULTS, {"transport": {"max_packet": 100}})


if __name__ == "__main__":
    unittest.main()
