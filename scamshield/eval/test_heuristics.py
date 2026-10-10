import unittest

from heuristics import analyze


class HeuristicsTests(unittest.TestCase):
    def test_detects_obfuscated_lookalike_link(self):
        result = analyze(
            "Your SBI account is blocked. Update now: "
            "hxxp://sbi-kyc-update[.]xyz/login"
        )

        self.assertEqual(result["urls"][0]["host"], "sbi-kyc-update.xyz")
        self.assertGreaterEqual(result["score"], 60)

    def test_does_not_flag_legitimate_otp_warning_as_a_request(self):
        result = analyze("Your OTP for login is 123456. Do not share this with anyone.")

        self.assertNotIn("Asks for money or card details", result["tactics"])
        self.assertLess(result["score"], 30)

    def test_does_not_treat_completed_upi_alert_as_a_request(self):
        result = analyze(
            "Bank alert: your UPI payment of Rs 899 to a local shop was successful. "
            "If you did not do this, call the number on your card."
        )

        self.assertNotIn("Asks for money or card details", result["tactics"])
        self.assertLess(result["score"], 30)

    def test_detects_romanized_hindi_credential_phishing(self):
        result = analyze(
            "Your account updation karna jaroori hai. "
            "Link par click karke details bhar do."
        )

        self.assertGreaterEqual(result["score"], 30)

    def test_detects_job_fee_scam(self):
        result = analyze(
            "We are hiring remote agents. Pay a refundable security deposit "
            "of Rs 1500 and we will recruit you."
        )

        self.assertGreaterEqual(result["score"], 30)


if __name__ == "__main__":
    unittest.main()
