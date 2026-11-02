import unittest

from backend.ml_v32_service import model_status, predict_event


class V32ModelServiceTests(unittest.TestCase):
    def test_model_loads_and_hash_matches(self):
        status = model_status(load_model=True)
        self.assertTrue(status["ready"], status.get("load_error"))
        self.assertTrue(status["model_hash_ok"])

    def test_http_event_returns_one_of_seven_classes(self):
        result = predict_event(
            {
                "destination_ip": "198.51.100.20",
                "raw": {
                    "http": {
                        "http_method": "GET",
                        "url": "/search?q=<script>alert(1)</script>",
                        "hostname": "example.test",
                    }
                },
            }
        )
        self.assertTrue(result["available"], result.get("reason"))
        self.assertIn(
            result["prediction"],
            {
                "Normal",
                "HOST_Scan",
                "Vulnerability_Scan",
                "Cross_Site_Scripting",
                "SQL_Injection",
                "Path_Disclosure",
                "System_Cmd_Execution",
            },
        )
        self.assertGreaterEqual(float(result["confidence_percent"]), 0.0)
        self.assertLessEqual(float(result["confidence_percent"]), 100.0)


if __name__ == "__main__":
    unittest.main()
