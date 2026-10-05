"""Lab configuration validation (no processes started)."""

import unittest

from lab import DEFAULTS, merged, parse_revoked, validate


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


if __name__ == "__main__":
    unittest.main()
