"""Lab configuration validation (no processes started)."""

import unittest

from lab import (DEFAULTS, LEVELS, PACKET_OVERHEAD, PRESETS, current_level, merged, parse_accept,
                 parse_revoked, validate)
from msec_envelope import AES_GCM, CHACHA20


class Validate(unittest.TestCase):
    def test_defaults_are_valid(self):
        self.assertEqual(merged(DEFAULTS, {})["payload"]["protection"], "none")

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

    def test_checks_need_the_envelope(self):
        """§7.7 req. 1: a check that needs the envelope cannot be on without it."""
        for key in ("freshness", "replay", "key_binding"):
            with self.subTest(key), self.assertRaises(ValueError):
                merged(DEFAULTS, {"payload": {key: True}})
        with self.assertRaises(ValueError):
            merged(DEFAULTS, {"payload": {"accept": "encrypt"}})
        ok = merged(DEFAULTS, {"payload": {"protection": "encrypt", "freshness": True}})
        self.assertTrue(ok["payload"]["freshness"])
        with self.assertRaises(ValueError):  # and turning the envelope off alone is refused
            merged(ok, {"payload": {"protection": "none"}})

    def test_accept_list(self):
        self.assertEqual(parse_accept(" encrypt, auth_only,encrypt"), ["encrypt", "auth_only"])
        with self.assertRaises(ValueError):
            parse_accept("encrypt,none")

    def test_attacker_settings_need_their_prerequisites(self):
        for patch in ({"stolen_rate": 5.0}, {"forge_commands_rate": 5.0}, {"tamper": "alter"},
                      {"stolen_key": 999}):
            with self.subTest(patch), self.assertRaises(ValueError):
                merged(DEFAULTS, {"attacker": patch})
        cfg = merged(DEFAULTS, {"attacker": {"stolen_key": 1, "stolen_rate": 5.0}})
        self.assertEqual(cfg["attacker"]["stolen_key"], 1)

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


class SecurityLevels(unittest.TestCase):
    """K0..K11 follow the report's configuration table (Section 7)."""

    def apply(self, level_id, base=DEFAULTS):
        return merged(base, PRESETS[level_id](base))

    def test_ids_match_the_report(self):
        self.assertEqual([lv.id for lv in LEVELS], [f"K{i}" for i in range(12)])

    def test_every_level_is_valid_and_recognised(self):
        for lv in LEVELS:
            with self.subTest(lv.id):
                self.assertEqual(current_level(self.apply(lv.id)), lv.id)

    def test_k9_is_hardened(self):
        self.assertEqual(PRESETS["K9"](DEFAULTS), PRESETS["hardened"](DEFAULTS))

    def test_each_step_adds_one_thing(self):
        table = {  # transport, protection, freshness, replay, key binding, limits
            "K0": (False, "none", False, False, False, False),
            "K1": (True, "none", False, False, False, False),
            "K2": (True, "auth_only", False, False, False, False),
            "K3": (True, "encrypt", False, False, False, False),
            "K4": (True, "encrypt", True, False, False, False),
            "K5": (True, "encrypt", False, True, False, False),
            "K6": (True, "encrypt", True, True, False, False),
            "K7": (True, "encrypt", True, True, True, False),
            "K8": (True, "encrypt", True, True, True, True),
            "K9": (True, "sign", True, True, True, True),
            "K10": (False, "encrypt", True, True, True, False),
            "K11": (True, "encrypt", True, True, True, True),
        }
        for level_id, (on, protection, fresh, replay, binding, limits) in table.items():
            with self.subTest(level_id):
                cfg = self.apply(level_id)
                t, p = cfg["transport"], cfg["payload"]
                self.assertEqual(t["mode"], "mtls" if on else "plain")
                self.assertEqual((t["auth"], t["acl"], t["clientid_binding"]), (on, on, on))
                self.assertEqual((p["protection"], p["freshness"], p["replay"],
                                  p["key_binding"]), (protection, fresh, replay, binding))
                self.assertEqual(p["rate_limit"] > 0, limits)
                self.assertEqual(t["max_packet"] > 0 and t["max_connections"] > 0, limits)

    def test_k11_is_k8_with_chacha20(self):
        k8, k11 = self.apply("K8"), self.apply("K11")
        self.assertEqual(k8["payload"]["cipher"], AES_GCM)
        self.assertEqual(k11["payload"]["cipher"], CHACHA20)
        k11["payload"]["cipher"] = AES_GCM
        self.assertEqual(k11, k8)
        self.assertEqual(current_level(self.apply("K11")), "K11")

    def test_defaults_are_k0(self):
        self.assertEqual(current_level(merged(DEFAULTS, {})), "K0")
        self.assertEqual(self.apply("K0"), merged(DEFAULTS, {}))  # picking K0 changes nothing

    def test_level_survives_a_load_change(self):
        cfg = self.apply("K8")
        cfg = merged(cfg, {"load": {"rate": 80.0}})  # rate limit no longer derived from it
        self.assertEqual(current_level(cfg), "K8")

    def test_any_other_change_is_custom(self):
        cfg = merged(self.apply("K6"), {"payload": {"replay": False, "freshness": False}})
        self.assertEqual(current_level(cfg), "K3")
        self.assertIsNone(current_level(merged(cfg, {"transport": {"acl": False}})))


if __name__ == "__main__":
    unittest.main()
