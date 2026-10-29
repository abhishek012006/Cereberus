"""Offline tests for conservative deterministic evidence assessment."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.evidence_assessor import assess_claim_evidence


def claim(text, claim_id="c1", claim_type="other", identifiers=None, markers=None):
    return {
        "claim_id": claim_id,
        "claim_text": text,
        "claim_type": claim_type,
        "related_identifiers": identifiers or [],
        "source_citation_markers": markers or [],
    }


def evidence(url, passage, citation=None, final_url=None, method="identifier"):
    return {
        "url": url,
        "final_url": final_url,
        "passage": passage,
        "start": 0,
        "end": len(passage),
        "match_method": method,
        "citation_number": citation,
    }


def matcher(claim_id, evidence_items, status="matched"):
    return {
        "status": "completed",
        "matches": [{
            "claim_id": claim_id,
            "claim_text": "original claim",
            "match_status": status,
            "evidence": evidence_items,
        }],
        "unresolved_citations": [],
        "errors": [],
    }


class TestEvidenceAssessor(unittest.TestCase):
    def test_empty_and_malformed_inputs(self):
        self.assertEqual(
            assess_claim_evidence([], {"matches": []})["status"],
            "empty",
        )
        self.assertEqual(
            assess_claim_evidence([claim("x")], {})["status"],
            "error",
        )
        result = assess_claim_evidence([{"claim_id": "bad"}], {"matches": []})
        self.assertEqual(result["status"], "error")
        self.assertTrue(result["errors"])

    def test_exact_cve_and_mismatched_or_longer_lookalike(self):
        for passage in ("CVE-2024-3095 is discussed.", "CVE-2024-30940 is discussed."):
            result = assess_claim_evidence(
                [claim("CVE-2024-3094", identifiers=["CVE-2024-3094"])],
                matcher("c1", [evidence("https://a.example", passage)]),
            )
            self.assertEqual(result["assessments"][0]["assessment"], "inconclusive")

        result = assess_claim_evidence(
            [claim("CVE-2024-3094", identifiers=["CVE-2024-3094"])],
            matcher("c1", [evidence("https://a.example", "cve-2024-3094 is referenced.")]),
        )
        self.assertEqual(result["assessments"][0]["assessment"], "identifier_match_only")

    def test_cve_mention_does_not_support_affected_version(self):
        result = assess_claim_evidence(
            [claim(
                "CVE-2024-3094 affects XZ Utils 5.6.0.",
                claim_type="affected_versions",
                identifiers=["CVE-2024-3094", "5.6.0"],
            )],
            matcher("c1", [evidence("https://a.example", "CVE-2024-3094 is a vulnerability.")]),
        )
        self.assertIn(result["assessments"][0]["assessment"], {"inconclusive", "partially_supported", "identifier_match_only"})
        self.assertTrue(any("CVE" in reason or "insufficient" in reason for reason in result["assessments"][0]["reasons"]))

    def test_explicit_product_version_and_affected_relation(self):
        passage = "XZ Utils version 5.6.0 is affected by CVE-2024-3094."
        result = assess_claim_evidence(
            [claim(
                "CVE-2024-3094 affects XZ Utils 5.6.0.",
                claim_type="affected_versions",
                identifiers=["CVE-2024-3094", "5.6.0"],
            )],
            matcher("c1", [evidence("https://a.example", passage)]),
        )
        self.assertEqual(result["assessments"][0]["assessment"], "candidate_only")
        self.assertTrue(any(item["status"] == "matched" for item in result["assessments"][0]["detail_assessments"]))

    def test_fixed_unaffected_and_negation_are_not_affirmative(self):
        for passage in (
            "XZ Utils 5.6.0 is not affected by CVE-2024-3094.",
            "XZ Utils 5.6.0 is fixed and not vulnerable.",
        ):
            result = assess_claim_evidence(
                [claim(
                    "CVE-2024-3094 affects XZ Utils 5.6.0.",
                    claim_type="affected_versions",
                    identifiers=["CVE-2024-3094", "5.6.0"],
                )],
                matcher("c1", [evidence("https://a.example", passage)]),
            )
            self.assertEqual(result["assessments"][0]["assessment"], "conflicting")

    def test_ambiguous_negation_is_inconclusive(self):
        result = assess_claim_evidence(
            [claim(
                "CVE-2024-3094 affects XZ Utils 5.6.0.",
                claim_type="affected_versions",
                identifiers=["CVE-2024-3094", "5.6.0"],
            )],
            matcher("c1", [evidence("https://a.example", "Some reports discuss whether 5.6.0 may be affected.")]),
        )
        self.assertEqual(result["assessments"][0]["assessment"], "inconclusive")

    def test_compound_claim_partial_coverage(self):
        result = assess_claim_evidence(
            [claim(
                "CVE-2024-3094 affects XZ Utils 5.6.0 and attackers exploited it.",
                claim_type="affected_versions",
                identifiers=["CVE-2024-3094", "5.6.0"],
            )],
            matcher("c1", [evidence("https://a.example", "CVE-2024-3094 affects XZ Utils 5.6.0.")]),
        )
        assessment = result["assessments"][0]
        self.assertEqual(assessment["assessment"], "partially_supported")
        self.assertTrue(any(item["detail_type"] == "exploitation" for item in assessment["detail_assessments"]))

    def test_conflicting_explicit_statements_are_preserved(self):
        items = [
            evidence("https://a.example", "Version 5.6.0 is affected by CVE-2024-3094."),
            evidence("https://b.example", "Version 5.6.0 is not affected by CVE-2024-3094."),
        ]
        result = assess_claim_evidence(
            [claim(
                "CVE-2024-3094 affects version 5.6.0.",
                claim_type="affected_versions",
                identifiers=["CVE-2024-3094", "5.6.0"],
            )],
            matcher("c1", items),
        )
        assessment = result["assessments"][0]
        self.assertEqual(assessment["assessment"], "conflicting")
        self.assertEqual(assessment["evidence"], items)
        self.assertIn("disagree", " ".join(assessment["reasons"]))

    def test_multiple_sources_and_provenance_are_preserved(self):
        item = evidence("https://a.example/original", "CVE-2024-3094 is referenced.", 3, "https://a.example/final")
        result = assess_claim_evidence(
            [claim("CVE-2024-3094", identifiers=["CVE-2024-3094"], markers=[3])],
            matcher("c1", [item]),
        )
        returned = result["assessments"][0]["evidence"][0]
        self.assertEqual(returned, item)
        self.assertEqual(returned["url"], "https://a.example/original")
        self.assertEqual(returned["final_url"], "https://a.example/final")
        self.assertEqual(returned["citation_number"], 3)

    def test_unresolved_ambiguous_and_failed_evidence(self):
        for status in ("citation_unresolved", "citation_ambiguous"):
            result = assess_claim_evidence(
                [claim("CVE-2024-3094", identifiers=["CVE-2024-3094"])],
                matcher("c1", [], status=status),
            )
            self.assertEqual(result["assessments"][0]["assessment"], status)

        result = assess_claim_evidence(
            [claim("CVE-2024-3094", identifiers=["CVE-2024-3094"])],
            matcher("c1", []),
        )
        self.assertEqual(result["assessments"][0]["assessment"], "no_retrieved_evidence")

    def test_historical_claim_without_current_context_is_inconclusive(self):
        result = assess_claim_evidence(
            [claim("CVE-2024-3094 currently affects version 5.6.0.", identifiers=["CVE-2024-3094", "5.6.0"], claim_type="affected_versions")],
            matcher("c1", [evidence("https://a.example", "Historically, version 5.6.0 was affected by CVE-2024-3094.")]),
        )
        self.assertEqual(result["assessments"][0]["assessment"], "inconclusive")

    def test_no_fabrication_or_truth_verdict(self):
        result = assess_claim_evidence(
            [claim("CVE-2024-3094", identifiers=["CVE-2024-3094"])],
            matcher("c1", [evidence("https://a.example", "No matching content.")]),
        )
        serialized = repr(result)
        self.assertNotIn("verified", result)
        self.assertNotIn("confidence", serialized)
        self.assertNotIn("true", serialized.lower())
        self.assertEqual(result["assessments"][0]["evidence"][0]["url"], "https://a.example")

    def test_wrapped_claim_extractor_result_and_optional_retrieval_input(self):
        result = assess_claim_evidence(
            {
                "status": "completed",
                "claims": [claim("CVE-2024-3094", identifiers=["CVE-2024-3094"])],
                "error": None,
            },
            matcher("c1", [evidence("https://a.example", "CVE-2024-3094 is referenced.")]),
            retrieval_results=[],
        )
        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(result["assessments"]), 1)


if __name__ == "__main__":
    unittest.main()
