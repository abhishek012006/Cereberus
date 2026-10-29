"""Offline tests for the isolated claim extraction component."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.claim_extractor import extract_claims


class TestClaimExtractor(unittest.TestCase):
    def test_multiple_claims_and_cybersecurity_types(self):
        result = extract_claims(
            "CVE-2024-3094 affected XZ Utils 5.6.0 [1]. "
            "Attackers exploited the backdoor [2]. "
            "Users should downgrade to 5.4.6 [3]."
        )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(result["claims"]), 3)
        self.assertEqual(
            [claim["claim_type"] for claim in result["claims"]],
            ["affected_versions", "exploitation", "mitigation"],
        )

    def test_identifiers_versions_and_citations_are_preserved(self):
        result = extract_claims(
            "CVE-2024-3094 affected XZ Utils 5.6.0 and 5.6.1 [1][2]."
        )
        claim = result["claims"][0]

        self.assertEqual(claim["claim_text"], "CVE-2024-3094 affected XZ Utils 5.6.0 and 5.6.1 [1][2].")
        self.assertEqual(claim["related_identifiers"], ["CVE-2024-3094", "5.6.0", "5.6.1"])
        self.assertEqual(claim["source_citation_markers"], [1, 2])

    def test_injected_extractor_output_is_normalized_without_verdicts(self):
        def fake_extractor(_report):
            return [{"claim_text": "CVE-2024-3094 is exploitable [7]."}]

        result = extract_claims("ignored", extractor=fake_extractor)
        claim = result["claims"][0]

        self.assertEqual(claim["claim_id"], "claim-1")
        self.assertEqual(claim["source_citation_markers"], [7])
        self.assertNotIn("truth", claim)
        self.assertNotIn("verdict", claim)
        self.assertNotIn("confidence", claim)

    def test_empty_report(self):
        result = extract_claims(" \n ")

        self.assertEqual(result, {
            "status": "empty",
            "claims": [],
            "error": "Report is empty.",
        })

    def test_malformed_model_output(self):
        result = extract_claims("A report.", extractor=lambda _report: {"claims": []})

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["claims"], [])
        self.assertIn("must be a list", result["error"])

    def test_model_extractor_error_is_explicit(self):
        def failing_extractor(_report):
            raise RuntimeError("model unavailable")

        result = extract_claims("A report.", extractor=failing_extractor)

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["claims"], [])
        self.assertIn("model unavailable", result["error"])

    def test_no_claims_or_evidence_are_invented(self):
        result = extract_claims("This is a general note.")
        claim = result["claims"][0]

        self.assertEqual(claim["related_identifiers"], [])
        self.assertEqual(claim["source_citation_markers"], [])
        self.assertEqual(claim["claim_type"], "other")
        self.assertNotIn("evidence", claim)
        self.assertNotIn("confidence", claim)
        self.assertNotIn("verdict", claim)


if __name__ == "__main__":
    unittest.main()
