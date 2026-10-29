"""Offline tests for deterministic claim-to-source candidate matching."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.evidence_matcher import match_claims_to_evidence


def claim(text, claim_id="claim-1", markers=None, identifiers=None):
    return {
        "claim_id": claim_id,
        "claim_text": text,
        "claim_type": "vulnerability",
        "related_identifiers": identifiers if identifiers is not None else [],
        "source_citation_markers": markers if markers is not None else [],
    }


def source(url, citation_number=None):
    record = {"url": url}
    if citation_number is not None:
        record["citation_number"] = citation_number
    return record


def retrieval(url, text, final_url=None, status="retrieved"):
    return {
        "url": url,
        "final_url": final_url,
        "status_code": 200,
        "title": None,
        "text": text,
        "retrieval_status": status,
        "error": None,
    }


class TestEvidenceMatcher(unittest.TestCase):
    def test_explicit_citation_resolution_and_url_provenance(self):
        result = match_claims_to_evidence(
            [claim("CVE-2024-3094 is vulnerable [7].", markers=[7], identifiers=["CVE-2024-3094"])],
            [source("https://source.example/a", 7)],
            [retrieval("https://source.example/a", "CVE-2024-3094 is vulnerable.", "https://source.example/final")],
        )
        evidence = result["matches"][0]["evidence"][0]
        self.assertEqual(result["matches"][0]["match_status"], "matched")
        self.assertEqual(evidence["url"], "https://source.example/a")
        self.assertEqual(evidence["final_url"], "https://source.example/final")
        self.assertEqual(evidence["citation_number"], 7)

    def test_citation_does_not_fall_back_to_source_order(self):
        result = match_claims_to_evidence(
            [claim("CVE-2024-3094 [1].", markers=[1], identifiers=["CVE-2024-3094"])],
            [source("https://source.example/a"), source("https://source.example/b")],
            [retrieval("https://source.example/a", "CVE-2024-3094")],
        )
        self.assertEqual(result["matches"][0]["match_status"], "citation_unresolved")
        self.assertEqual(result["matches"][0]["evidence"], [])

    def test_unresolved_and_duplicate_citations_are_explicit(self):
        result = match_claims_to_evidence(
            [
                claim("CVE-2024-3094 [9].", markers=[9], identifiers=["CVE-2024-3094"]),
                claim("CVE-2024-3094 [2].", "claim-2", [2], ["CVE-2024-3094"]),
            ],
            [source("https://source.example/a", 2), source("https://source.example/b", 2)],
            [retrieval("https://source.example/a", "CVE-2024-3094")],
        )
        self.assertEqual(result["matches"][0]["match_status"], "citation_unresolved")
        self.assertEqual(result["matches"][1]["match_status"], "citation_ambiguous")
        self.assertEqual(result["unresolved_citations"][0]["citation_number"], 9)
        self.assertEqual(result["unresolved_citations"][1]["urls"], [
            "https://source.example/a", "https://source.example/b"
        ])

    def test_multiple_citations_resolve_independently(self):
        result = match_claims_to_evidence(
            [claim("CVE-2024-3094 affects 5.6.0 [1][2].", markers=[1, 2], identifiers=["CVE-2024-3094", "5.6.0"])],
            [source("https://source.example/a", 1), source("https://source.example/b", 2)],
            [
                retrieval("https://source.example/a", "CVE-2024-3094 affects 5.6.0."),
                retrieval("https://source.example/b", "CVE-2024-3094 affects 5.6.0."),
            ],
        )
        self.assertEqual(len(result["matches"][0]["evidence"]), 2)
        self.assertEqual({item["citation_number"] for item in result["matches"][0]["evidence"]}, {1, 2})

    def test_exact_cve_matching_rejects_lookalikes_and_versions_have_boundaries(self):
        result = match_claims_to_evidence(
            [
                claim("CVE-2024-3094", "cve", identifiers=["CVE-2024-3094"]),
                claim("Version 5.6.0", "version", identifiers=["5.6.0"]),
            ],
            [],
            [
                retrieval("https://source.example/cve", "CVE-2024-30940 is here."),
                retrieval("https://source.example/version", "Versions 5.6.01 and 15.6.0 are here."),
            ],
        )
        self.assertEqual(result["matches"][0]["match_status"], "unmatched")
        self.assertEqual(result["matches"][1]["match_status"], "unmatched")

    def test_case_insensitive_identifier_matching(self):
        result = match_claims_to_evidence(
            [claim("CVE-2024-3094", identifiers=["CVE-2024-3094"])],
            [],
            [retrieval("https://source.example/a", "cve-2024-3094 details")],
        )
        self.assertEqual(result["matches"][0]["match_status"], "matched")
        self.assertEqual(result["matches"][0]["evidence"][0]["match_method"], "identifier")

    def test_lexical_overlap_and_generic_word_rejection(self):
        result = match_claims_to_evidence(
            [
                claim("XZ Utils backdoor affects version 5.6.0", "specific"),
                claim("The vulnerability affects software", "generic"),
            ],
            [],
            [
                retrieval("https://source.example/a", "The XZ Utils backdoor affects version 5.6.0."),
                retrieval("https://source.example/b", "The software is available."),
            ],
            min_overlap=2,
        )
        self.assertEqual(result["matches"][0]["match_status"], "matched")
        self.assertTrue(any(item["match_method"] == "phrase_overlap" for item in result["matches"][0]["evidence"]))
        self.assertEqual(result["matches"][1]["match_status"], "unmatched")

    def test_multiple_sources_and_failed_retrieval_exclusion(self):
        result = match_claims_to_evidence(
            [claim("CVE-2024-3094", identifiers=["CVE-2024-3094"])],
            [],
            [
                retrieval("https://source.example/a", "CVE-2024-3094"),
                retrieval("https://source.example/b", "CVE-2024-3094", status="http_error"),
                retrieval("https://source.example/c", "CVE-2024-3094"),
            ],
        )
        self.assertEqual(
            {item["url"] for item in result["matches"][0]["evidence"]},
            {"https://source.example/a", "https://source.example/c"},
        )

    def test_passage_integrity_and_offsets(self):
        text = "Intro.\nCVE-2024-3094 affects XZ Utils 5.6.0."
        result = match_claims_to_evidence(
            [claim("CVE-2024-3094", identifiers=["CVE-2024-3094"])],
            [],
            [retrieval("https://source.example/a", text)],
        )
        evidence = result["matches"][0]["evidence"][0]
        self.assertEqual(text[evidence["start"]:evidence["end"]], evidence["passage"])
        self.assertEqual(evidence["passage"], "CVE-2024-3094 affects XZ Utils 5.6.0.")

    def test_empty_and_malformed_inputs_are_explicit(self):
        self.assertEqual(
            match_claims_to_evidence([], [], [])["status"],
            "empty",
        )
        result = match_claims_to_evidence(
            [{"claim_id": "bad"}],
            [{"url": ""}, "bad-source"],
            [{"url": "https://source.example/a", "retrieval_status": "retrieved"}],
        )
        self.assertEqual(result["status"], "error")
        self.assertTrue(result["errors"])
        self.assertEqual(result["matches"], [])

    def test_no_verdict_confidence_or_fabricated_fields(self):
        result = match_claims_to_evidence(
            [claim("CVE-2024-3094", identifiers=["CVE-2024-3094"])],
            [],
            [retrieval("https://source.example/a", "No matching text.")],
        )
        self.assertNotIn("verified", result)
        self.assertNotIn("confidence", result)
        self.assertNotIn("verdict", result)
        self.assertEqual(result["matches"][0]["evidence"], [])
        self.assertNotIn("fabricated-url", str(result))


if __name__ == "__main__":
    unittest.main()
