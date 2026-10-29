"""Unit tests for the BlackBox Agent (agents/blackbox.py).

These tests run entirely offline with simulated inputs, verifying deterministic
evidence checks, domain recognition heuristics, input validation, and failure handling.
"""

import sys
from pathlib import Path
import unittest

# Ensure root directory is on sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from agents.blackbox import (
    verify_research,
    validate_input_structure,
    parse_source_url,
    is_domain_recognized,
    classify_domain,
    extract_query_identifiers,
    DEFAULT_RECOGNIZED_DOMAINS,
    DEFAULT_SECURITY_VENDOR_DOMAINS,
)


class TestBlackBoxAgent(unittest.TestCase):
    """Test suite for BlackBox verification logic and helper functions."""

    def test_validate_input_structure(self):
        """Verify input structure validation rejects malformed dictionaries and types."""
        # Non-dict inputs
        is_val, err = validate_input_structure("not a dict")
        self.assertFalse(is_val)
        self.assertIn("Expected a dictionary", err)

        # Missing required key
        incomplete = {
            "success": True,
            "status": "completed",
            "query": "CVE-2024-3094",
            # missing report, sources, run_id, error
        }
        is_val, err = validate_input_structure(incomplete)
        self.assertFalse(is_val)
        self.assertIn("Missing required fields", err)

        # Invalid type
        bad_types = {
            "success": "yes",  # should be bool
            "status": "completed",
            "query": "CVE-2024-3094",
            "report": "Analysis",
            "sources": [],
            "run_id": None,
            "error": None,
        }
        is_val, err = validate_input_structure(bad_types)
        self.assertFalse(is_val)
        self.assertIn("must be of type bool", err)

        # Invalid source item type
        bad_source_item = {
            "success": True,
            "status": "completed",
            "query": "CVE-2024-3094",
            "report": "Analysis",
            "sources": [12345],  # item is int instead of str
            "run_id": None,
            "error": None,
        }
        is_val, err = validate_input_structure(bad_source_item)
        self.assertFalse(is_val)
        self.assertIn("expected str", err)

    def test_parse_source_url(self):
        """Verify URL syntax parsing and domain extraction."""
        # Valid URLs
        valid, domain, _ = parse_source_url("https://nvd.nist.gov/vuln/detail/CVE-2024-3094")
        self.assertTrue(valid)
        self.assertEqual(domain, "nvd.nist.gov")

        valid, domain, _ = parse_source_url("http://example.com:8080/path")
        self.assertTrue(valid)
        self.assertEqual(domain, "example.com")

        # Invalid schemes
        valid, _, err = parse_source_url("ftp://files.example.com/file.txt")
        self.assertFalse(valid)
        self.assertIn("Invalid or missing scheme", err)

        # Missing scheme
        valid, _, err = parse_source_url("nvd.nist.gov/path")
        self.assertFalse(valid)
        self.assertIn("Invalid or missing scheme", err)

        # Not a string
        valid, _, err = parse_source_url(None)
        self.assertFalse(valid)
        self.assertIn("not a string", err)

    def test_is_domain_recognized(self):
        """Verify domain recognition heuristic and subdomain matching."""
        # Exact match
        rec, matched = is_domain_recognized("cisa.gov", DEFAULT_RECOGNIZED_DOMAINS)
        self.assertTrue(rec)
        self.assertEqual(matched, "cisa.gov")

        # Subdomain match
        rec, matched = is_domain_recognized("nvd.nist.gov", DEFAULT_RECOGNIZED_DOMAINS)
        self.assertTrue(rec)
        self.assertEqual(matched, "nist.gov")

        # www prefix stripping
        rec, matched = is_domain_recognized("www.github.com", DEFAULT_RECOGNIZED_DOMAINS)
        self.assertTrue(rec)
        self.assertEqual(matched, "github.com")

        # Unrecognized domain
        rec, _ = is_domain_recognized("random-exploit-blog.xyz", DEFAULT_RECOGNIZED_DOMAINS)
        self.assertFalse(rec)

        # Spoofing prevention: domain ending with string but not a subdomain
        rec, _ = is_domain_recognized("fakemediterraneancisa.gov", DEFAULT_RECOGNIZED_DOMAINS)
        self.assertFalse(rec)

        # A deceptive nested domain must not match the real organization.
        rec, _ = is_domain_recognized("cisa.gov.example.com", DEFAULT_RECOGNIZED_DOMAINS)
        self.assertFalse(rec)

    def test_domain_categories_are_distinct_and_configurable(self):
        category, matched = classify_domain(
            "nvd.nist.gov",
            DEFAULT_RECOGNIZED_DOMAINS,
            DEFAULT_SECURITY_VENDOR_DOMAINS,
        )
        self.assertEqual(category, "authoritative")
        self.assertEqual(matched, "nist.gov")

        category, matched = classify_domain(
            "research.microsoft.com",
            DEFAULT_RECOGNIZED_DOMAINS,
            DEFAULT_SECURITY_VENDOR_DOMAINS,
        )
        self.assertEqual(category, "security_vendor")
        self.assertEqual(matched, "microsoft.com")

        category, matched = classify_domain(
            "cisa.gov.example.com",
            DEFAULT_RECOGNIZED_DOMAINS,
            DEFAULT_SECURITY_VENDOR_DOMAINS,
        )
        self.assertEqual(category, "unrecognized")
        self.assertEqual(matched, "")

        category, matched = classify_domain(
            "security.example.org",
            ["example.org"],
            [],
        )
        self.assertEqual(category, "authoritative")
        self.assertEqual(matched, "example.org")

    def test_extract_query_identifiers(self):
        """Verify CVE identifier and keyword extraction from queries."""
        # Standard CVE query
        ids = extract_query_identifiers("Investigate CVE-2024-3094 in relation to XZ Utils.")
        self.assertIn("CVE-2024-3094", ids)

        # Named threat query
        ids2 = extract_query_identifiers("Explain Log4Shell impact")
        self.assertIn("Log4Shell", ids2)

    def test_successful_research_with_authoritative_sources(self):
        """Verify standard successful research result with recognized sources."""
        simulated_result = {
            "success": True,
            "status": "completed",
            "query": "CVE-2024-3094 in XZ Utils",
            "report": (
                "# CVE-2024-3094 Investigation Report\n\n"
                "A sophisticated backdoor was identified in upstream XZ Utils 5.6.0 and 5.6.1. "
                "The vulnerability allows unauthorized remote access via SSH."
            ),
            "sources": [
                "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
                "https://www.cisa.gov/news-events/alerts/2024/03/29/open-source-software-security-alert",
            ],
            "run_id": "test-run-101",
            "error": None,
        }

        analysis = verify_research(simulated_result)

        self.assertTrue(analysis["verified"])
        self.assertEqual(analysis["verdict"], "RESEARCH_VALID_WITH_RECOGNIZED_SOURCES_CLAIMS_UNVERIFIED")
        self.assertTrue(analysis["checks"]["input_valid"])
        self.assertTrue(analysis["checks"]["research_successful"])
        self.assertTrue(analysis["checks"]["report_present"])
        self.assertTrue(analysis["checks"]["identifier_detected"])
        self.assertTrue(analysis["checks"]["sources_valid"])
        self.assertFalse(analysis["checks"]["claims_verified"])
        self.assertEqual(analysis["source_analysis"]["recognized_count"], 2)
        self.assertEqual(analysis["source_analysis"]["unrecognized_count"], 0)
        self.assertEqual(analysis["source_analysis"]["malformed_count"], 0)

        # Verify claim verification boundaries
        self.assertEqual(analysis["claim_verification"]["status"], "NOT_IMPLEMENTED")
        self.assertFalse(analysis["claim_verification"]["claims_verified"])
        self.assertEqual(analysis["claim_verification"]["supported_claims_count"], 0)
        self.assertIn("claim-level verification is not yet implemented", analysis["summary"])

    def test_successful_research_with_unrecognized_sources_only(self):
        """Verify that valid research with non-whitelisted sources is marked structurally verified with note."""
        simulated_result = {
            "success": True,
            "status": "completed",
            "query": "CVE-2024-3094",
            "report": "CVE-2024-3094 was analyzed based on independent research blog posts.",
            "sources": ["https://independent-security-blog.org/xz-analysis"],
            "run_id": "test-run-102",
            "error": None,
        }

        analysis = verify_research(simulated_result)

        self.assertTrue(analysis["verified"])
        self.assertEqual(analysis["verdict"], "RESEARCH_VALID_UNRECOGNIZED_SOURCES_CLAIMS_UNVERIFIED")
        self.assertFalse(analysis["checks"]["claims_verified"])
        self.assertEqual(analysis["claim_verification"]["status"], "NOT_IMPLEMENTED")
        self.assertFalse(analysis["claim_verification"]["claims_verified"])
        self.assertEqual(analysis["source_analysis"]["recognized_count"], 0)
        self.assertEqual(analysis["source_analysis"]["unrecognized_count"], 1)

    def test_custom_vendor_domains(self):
        """Verify that optional vendor domains can be recognized."""
        simulated_result = {
            "success": True,
            "status": "completed",
            "query": "CVE-2024-3094",
            "report": "CVE-2024-3094 details from the official vendor repository.",
            "sources": ["https://tukaani.org/xz-backdoor/"],
            "run_id": "test-run-103",
            "error": None,
        }

        # Without vendor domain: unrecognized
        base_analysis = verify_research(simulated_result)
        self.assertEqual(base_analysis["source_analysis"]["recognized_count"], 0)

        # With vendor domain: recognized
        vendor_analysis = verify_research(simulated_result, vendor_domains=["tukaani.org"])
        self.assertEqual(vendor_analysis["source_analysis"]["recognized_count"], 1)
        self.assertEqual(vendor_analysis["verdict"], "RESEARCH_VALID_WITH_RECOGNIZED_SOURCES_CLAIMS_UNVERIFIED")

    def test_source_analysis_separates_authoritative_vendor_unknown_and_malformed(self):
        simulated_result = {
            "success": True,
            "status": "completed",
            "query": "CVE-2024-3094",
            "report": "CVE-2024-3094 report content.",
            "sources": [
                "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
                "https://research.microsoft.com/advisory",
                "https://unknown.example.org/report",
                "not-a-url",
            ],
            "run_id": "run-categories",
            "error": None,
        }

        analysis = verify_research(simulated_result)
        source_analysis = analysis["source_analysis"]

        self.assertEqual(source_analysis["authoritative_count"], 1)
        self.assertEqual(source_analysis["security_vendor_count"], 1)
        self.assertEqual(source_analysis["unrecognized_count"], 1)
        self.assertEqual(source_analysis["malformed_count"], 1)
        self.assertEqual(source_analysis["recognized_count"], 2)
        self.assertFalse(analysis["checks"]["claims_verified"])
        self.assertIn(
            "claim-level factual verification is not yet implemented",
            analysis["claim_verification"]["note"].lower(),
        )

    def test_malformed_sources_fail_verification(self):
        """Verify that malformed source URLs prevent verification and request review."""
        simulated_result = {
            "success": True,
            "status": "completed",
            "query": "CVE-2024-3094",
            "report": "CVE-2024-3094 report content.",
            "sources": [
                "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
                "not_a_valid_url_at_all",
            ],
            "run_id": "test-run-104",
            "error": None,
        }

        analysis = verify_research(simulated_result)

        self.assertFalse(analysis["verified"])
        self.assertEqual(analysis["verdict"], "NEEDS_REVIEW_MALFORMED_SOURCES")
        self.assertEqual(analysis["source_analysis"]["malformed_count"], 1)
        self.assertIn("not_a_valid_url_at_all", analysis["source_analysis"]["malformed_sources"])

    def test_failed_nightwatch_execution_never_verified(self):
        """Verify that HTTP/API errors are never marked verified."""
        simulated_result = {
            "success": False,
            "status": "error",
            "query": "CVE-2024-3094",
            "report": "",
            "sources": [],
            "run_id": None,
            "error": "Authentication failed (401 Unauthorized).",
        }

        analysis = verify_research(simulated_result)

        self.assertFalse(analysis["verified"])
        self.assertEqual(analysis["verdict"], "UNVERIFIED_ERROR")
        self.assertFalse(analysis["checks"]["research_successful"])

    def test_timeout_never_verified(self):
        """Verify that timeouts are never marked verified."""
        simulated_result = {
            "success": False,
            "status": "timeout",
            "query": "CVE-2024-3094",
            "report": "",
            "sources": [],
            "run_id": None,
            "error": "Research request timed out after 300.0 seconds.",
        }

        analysis = verify_research(simulated_result)

        self.assertFalse(analysis["verified"])
        self.assertEqual(analysis["verdict"], "UNVERIFIED_TIMEOUT")

    def test_incomplete_stream_never_verified(self):
        """Verify that disconnected/incomplete streams are never marked verified."""
        simulated_result = {
            "success": False,
            "status": "incomplete",
            "query": "CVE-2024-3094",
            "report": "Partial report notes...",
            "sources": ["https://nvd.nist.gov/vuln/detail/CVE-2024-3094"],
            "run_id": "run-cut-short",
            "error": "The research stream disconnected before receiving the completion event.",
        }

        analysis = verify_research(simulated_result)

        self.assertFalse(analysis["verified"])
        self.assertEqual(analysis["verdict"], "UNVERIFIED_INCOMPLETE")

    def test_empty_result_never_verified(self):
        """Verify that completed research with empty report text is never marked verified."""
        simulated_result = {
            "success": False,
            "status": "empty_result",
            "query": "CVE-2024-3094",
            "report": "",
            "sources": ["https://nvd.nist.gov/vuln/detail/CVE-2024-3094"],
            "run_id": "run-empty",
            "error": "Research stream completed, but no report content was generated.",
        }

        analysis = verify_research(simulated_result)

        self.assertFalse(analysis["verified"])
        self.assertEqual(analysis["verdict"], "UNVERIFIED_EMPTY_RESULT")
        self.assertFalse(analysis["checks"]["report_present"])

    def test_zero_sources_flagged_for_review(self):
        """Verify that a report with zero sources is flagged for review."""
        simulated_result = {
            "success": True,
            "status": "completed",
            "query": "CVE-2024-3094",
            "report": "Detailed CVE-2024-3094 analysis with no cited URLs.",
            "sources": [],
            "run_id": "run-105",
            "error": None,
        }

        analysis = verify_research(simulated_result)

        self.assertFalse(analysis["verified"])
        self.assertEqual(analysis["verdict"], "NEEDS_REVIEW_NO_SOURCES")
        self.assertFalse(analysis["checks"]["sources_valid"])

    def test_target_identifier_missing_flagged_for_review(self):
        """Verify that missing query identifier in report is flagged for review without being declared false."""
        simulated_result = {
            "success": True,
            "status": "completed",
            "query": "CVE-2024-3094",
            "report": (
                "# General Cybersecurity Summary\n\n"
                "A general advisory was released about open-source security hygiene."
            ),
            "sources": ["https://www.cisa.gov/news-events/alerts/2024/03/29"],
            "run_id": "run-106",
            "error": None,
        }

        analysis = verify_research(simulated_result)

        self.assertFalse(analysis["verified"])
        self.assertEqual(analysis["verdict"], "NEEDS_REVIEW_IDENTIFIER_MISSING")
        self.assertFalse(analysis["checks"]["identifier_detected"])
        # Finding explicitly notes the review recommendation
        identifier_finding = any("was not detected in report text" in f for f in analysis["findings"])
        self.assertTrue(identifier_finding)

    def test_claims_remain_unverified_despite_recognized_sources(self):
        """Verify that factual claims remain unverified even when all structural checks pass with recognized domains."""
        simulated_result = {
            "success": True,
            "status": "completed",
            "query": "CVE-2024-3094",
            "report": "CVE-2024-3094 affected XZ Utils 5.6.0. Remediation is to downgrade to 5.4.6.",
            "sources": [
                "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
                "https://cve.org/CVERecord?id=CVE-2024-3094",
            ],
            "run_id": "run-claims-test",
            "error": None,
        }

        analysis = verify_research(simulated_result)

        # Research quality / structure is verified
        self.assertTrue(analysis["verified"])

        # BUT factual claims MUST NOT be marked verified
        self.assertFalse(analysis["checks"]["claims_verified"])
        self.assertEqual(analysis["claim_verification"]["status"], "NOT_IMPLEMENTED")
        self.assertFalse(analysis["claim_verification"]["claims_verified"])
        self.assertEqual(analysis["claim_verification"]["supported_claims_count"], 0)
        self.assertIn("CLAIMS_UNVERIFIED", analysis["verdict"])
        self.assertIn("factual claims remain unverified", analysis["summary"].lower())

        # Assert limitation explicitly warns about claim verification
        limitation_mentions_claims = any("Claim-level factual verification is not yet implemented" in lim for lim in analysis["limitations"])
        self.assertTrue(limitation_mentions_claims)


if __name__ == "__main__":
    unittest.main()
