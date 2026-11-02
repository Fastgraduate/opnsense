import unittest

from backend.security_policy import evaluate_auto_block, ip_in_allowlist, ml_risk_component, risk_level


class SecurityPolicyTests(unittest.TestCase):
    def setUp(self):
        self.settings = {
            "enabled": True,
            "dry_run": True,
            "risk_threshold": 90,
            "confidence_threshold": 85,
            "min_occurrences": 3,
            "allowed_classes": ["SQL_Injection"],
            "allowlist": [],
            "allow_private": False,
            "require_suricata_confirmation": True,
        }
        self.ml = {
            "available": True,
            "prediction": "SQL_Injection",
            "confidence_percent": 96.0,
        }

    def test_risk_levels(self):
        self.assertEqual(risk_level(20)["level"], "low")
        self.assertEqual(risk_level(40)["level"], "medium")
        self.assertEqual(risk_level(70)["level"], "high")
        self.assertEqual(risk_level(90)["level"], "critical")

    def test_ml_risk_increases_with_repetition(self):
        first = ml_risk_component(self.ml, 1)["score"]
        repeated = ml_risk_component(self.ml, 5)["score"]
        self.assertGreater(repeated, first)

    def test_eligible_event_stays_dry_run_by_default(self):
        result = evaluate_auto_block(
            settings=self.settings,
            risk={"score": 96},
            ml=self.ml,
            source_ip="8.8.8.8",
            occurrences=3,
            corroborated=True,
            private_or_reserved=False,
        )
        self.assertTrue(result["eligible"])
        self.assertEqual(result["action"], "auto_block_dry_run")

    def test_all_safety_gates_are_required(self):
        result = evaluate_auto_block(
            settings=self.settings,
            risk={"score": 96},
            ml=self.ml,
            source_ip="10.0.0.8",
            occurrences=1,
            corroborated=False,
            private_or_reserved=True,
        )
        self.assertFalse(result["eligible"])
        joined = " / ".join(result["reasons"])
        self.assertIn("not enough repeated events", joined)
        self.assertIn("confirmation missing", joined)
        self.assertIn("private/reserved/local IP", joined)

    def test_allowlist_accepts_ip_and_cidr(self):
        self.assertTrue(ip_in_allowlist("203.0.113.8", ["203.0.113.8"]))
        self.assertTrue(ip_in_allowlist("192.0.2.25", ["192.0.2.0/24"]))
        self.assertFalse(ip_in_allowlist("8.8.8.8", ["192.0.2.0/24"]))


if __name__ == "__main__":
    unittest.main()
