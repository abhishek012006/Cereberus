"""Offline interaction tests for the CERBERUS research-to-evidence workflow."""

import unittest
from unittest.mock import MagicMock, patch

import httpx

from agents.evidence_pipeline import build_evidence_pipeline
from agents.source_retriever import retrieve_source


def _research(report, source_records):
    return {
        "success": True,
        "status": "completed",
        "query": "CVE-2024-3094",
        "report": report,
        "sources": [record["url"] for record in source_records],
        "source_records": source_records,
        "run_id": "offline-run",
        "error": None,
    }


def _claim(text, markers=None):
    return {
        "claim_id": "claim-1",
        "claim_text": text,
        "claim_type": "affected_versions",
        "related_identifiers": ["CVE-2024-3094", "5.6.0"],
        "source_citation_markers": markers or [],
    }


def _retrieval(url, text, *, final_url=None, status="retrieved", error=None):
    return {
        "url": url,
        "final_url": final_url or url,
        "status_code": 200 if status == "retrieved" else None,
        "title": None,
        "text": text if status == "retrieved" else "",
        "retrieval_status": status,
        "error": error,
    }


class TestEndToEndWorkflow(unittest.TestCase):
    def test_valid_and_unresolved_citations_preserve_both_outcomes(self):
        sources = [
            {"url": "https://valid.example", "citation_number": 1},
        ]
        result = build_evidence_pipeline(
            _research("CVE-2024-3094 affects XZ Utils 5.6.0 [1] [9].", sources),
            claim_extractor=lambda report: {
                "status": "completed",
                "claims": [_claim(report, [1, 9])],
                "error": None,
            },
            source_retriever=lambda url: _retrieval(
                url, "CVE-2024-3094 affects XZ Utils 5.6.0."
            ),
        )
        match = result["evidence_matches"]["matches"][0]
        self.assertEqual(match["match_status"], "citation_unresolved")
        self.assertTrue(match["evidence"])
        self.assertEqual(
            result["evidence_matches"]["unresolved_citations"][0]["citation_number"],
            9,
        )

    def test_ambiguous_and_resolvable_citations_remain_distinct(self):
        sources = [
            {"url": "https://one.example", "citation_number": 1},
            {"url": "https://two.example", "citation_number": 1},
            {"url": "https://valid.example", "citation_number": 2},
        ]
        result = build_evidence_pipeline(
            _research("CVE-2024-3094 [1] [2].", sources),
            claim_extractor=lambda report: {
                "status": "completed",
                "claims": [_claim(report, [1, 2])],
                "error": None,
            },
            source_retriever=lambda url: _retrieval(
                url, "CVE-2024-3094 affects XZ Utils 5.6.0."
            ),
        )
        match = result["evidence_matches"]["matches"][0]
        self.assertEqual(match["match_status"], "citation_ambiguous")
        self.assertTrue(any(item["citation_number"] == 1 for item in result["evidence_matches"]["unresolved_citations"]))
        self.assertTrue(any(item["citation_number"] == 2 for item in match["evidence"]))

    def test_successful_workflow_preserves_provenance(self):
        source_records = [
            {
                "url": "https://advisory.example/original",
                "title": "Advisory",
                "source_id": "source-7",
                "citation_number": 7,
            }
        ]
        result = build_evidence_pipeline(
            _research(
                "CVE-2024-3094 affects XZ Utils 5.6.0 [7].",
                source_records,
            ),
            source_retriever=lambda url: _retrieval(
                url,
                "CVE-2024-3094 affects XZ Utils 5.6.0.",
                final_url="https://advisory.example/final",
            ),
        )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["research_result"]["source_records"], source_records)
        self.assertEqual(result["retrieval_results"][0]["url"], source_records[0]["url"])
        self.assertEqual(
            result["retrieval_results"][0]["final_url"],
            "https://advisory.example/final",
        )
        evidence = result["evidence_assessment"]["assessments"][0]["evidence"]
        self.assertEqual(evidence[0]["url"], source_records[0]["url"])
        self.assertEqual(evidence[0]["final_url"], "https://advisory.example/final")
        self.assertEqual(evidence[0]["citation_number"], 7)
        self.assertNotIn(
            "verified",
            repr(result["evidence_assessment"]).lower(),
        )

    def test_identifier_only_evidence_is_not_confirmation(self):
        result = build_evidence_pipeline(
            _research(
                "CVE-2024-3094 affects XZ Utils 5.6.0.",
                [{"url": "https://catalog.example", "citation_number": 1}],
            ),
            source_retriever=lambda url: _retrieval(
                url, "Catalog entry: CVE-2024-3094."
            ),
        )

        assessment = result["evidence_assessment"]["assessments"][0]
        self.assertIn(
            assessment["assessment"],
            {"identifier_match_only", "inconclusive", "partially_supported"},
        )
        self.assertNotEqual(assessment["assessment"], "verified")
        self.assertTrue(any("does not establish" in reason.lower()
                            for reason in assessment["reasons"]))

    def test_conflicting_sources_remain_visible(self):
        sources = [
            {"url": "https://one.example"},
            {"url": "https://two.example"},
        ]
        texts = {
            "https://one.example": "XZ Utils 5.6.0 is affected by CVE-2024-3094.",
            "https://two.example": "XZ Utils 5.6.0 is not affected by CVE-2024-3094.",
        }
        result = build_evidence_pipeline(
            _research(
                "CVE-2024-3094 affects XZ Utils 5.6.0.",
                sources,
            ),
            claim_extractor=lambda report: {
                "status": "completed",
                "claims": [_claim(report)],
                "error": None,
            },
            source_retriever=lambda url: _retrieval(url, texts[url]),
        )

        assessment = result["evidence_assessment"]["assessments"][0]
        self.assertEqual(assessment["assessment"], "conflicting")
        self.assertEqual(len(assessment["evidence"]), 2)
        self.assertIn("disagree", " ".join(assessment["reasons"]).lower())

    def test_partial_source_failure_preserves_successful_evidence(self):
        sources = [
            {"url": "https://good.example", "citation_number": 1},
            {"url": "https://bad.example", "citation_number": 2},
        ]

        def retriever(url):
            if url == "https://bad.example":
                raise RuntimeError("private implementation detail")
            return _retrieval(url, "CVE-2024-3094 affects XZ Utils 5.6.0.")

        result = build_evidence_pipeline(
            _research("CVE-2024-3094 affects XZ Utils 5.6.0 [1] [2].", sources),
            source_retriever=retriever,
        )

        self.assertEqual(result["status"], "completed_with_errors")
        self.assertEqual(len(result["retrieval_results"]), 2)
        self.assertEqual(result["retrieval_results"][1]["retrieval_status"], "pipeline_error")
        self.assertEqual(result["retrieval_results"][1]["text"], "")
        self.assertTrue(result["evidence_assessment"]["assessments"][0]["evidence"])
        self.assertNotIn(
            "bad.example",
            repr(result["evidence_assessment"]["assessments"][0]["evidence"]),
        )
        evidence = result["evidence_assessment"]["assessments"][0]["evidence"][0]
        self.assertEqual(evidence["url"], "https://good.example")
        self.assertEqual(evidence["citation_number"], 1)
        reasons = result["evidence_assessment"]["assessments"][0]["reasons"]
        self.assertTrue(any("not a truth verdict" in reason.lower() for reason in reasons))

    def test_citation_integrity_never_uses_source_order(self):
        source_records = [
            {"url": "https://second.example", "citation_number": 2},
            {"url": "https://first.example", "citation_number": 1},
        ]
        seen = []

        def retriever(url):
            seen.append(url)
            return _retrieval(url, f"Source text for {url}.")

        result = build_evidence_pipeline(
            _research("A claim about CVE-2024-3094 [1].", source_records),
            claim_extractor=lambda report: {
                "status": "completed",
                "claims": [_claim(report, [1])],
                "error": None,
            },
            source_retriever=retriever,
        )

        self.assertEqual(
            seen,
            ["https://second.example", "https://first.example"],
        )
        evidence = result["evidence_matches"]["matches"][0]["evidence"]
        self.assertTrue(all(item["url"] == "https://first.example" for item in evidence))

        duplicate = build_evidence_pipeline(
            _research("A claim [1].", [
                {"url": "https://one.example", "citation_number": 1},
                {"url": "https://two.example", "citation_number": 1},
            ]),
            claim_extractor=lambda report: {
                "status": "completed",
                "claims": [_claim(report, [1])],
                "error": None,
            },
            source_retriever=lambda url: _retrieval(url, "CVE-2024-3094 text."),
        )
        self.assertEqual(
            duplicate["evidence_matches"]["matches"][0]["match_status"],
            "citation_ambiguous",
        )

    def test_ineligible_research_is_skipped(self):
        for status in ("incomplete", "timeout", "error", "empty_result"):
            result = build_evidence_pipeline({
                "success": status == "empty_result",
                "status": status,
                "report": "partial report",
            })
            self.assertEqual(result["status"], "skipped")
            self.assertIsNone(result["claim_extraction"])
            self.assertEqual(result["retrieval_results"], [])

    def test_malformed_stage_outputs_are_explicit_and_stop_dependents(self):
        calls = []
        result = build_evidence_pipeline(
            _research("CVE-2024-3094.", []),
            claim_extractor=lambda report: {"status": "completed", "claims": "bad"},
            evidence_matcher=lambda *args: calls.append("matcher"),
            evidence_assessor=lambda *args, **kwargs: calls.append("assessor"),
        )
        self.assertEqual(result["status"], "error")
        self.assertEqual(calls, [])
        self.assertTrue(result["errors"])

        result = build_evidence_pipeline(
            _research("CVE-2024-3094.", [{"url": "https://source.example"}]),
            source_retriever=lambda url: "not a retrieval record",
            evidence_assessor=lambda *args, **kwargs: (
                calls.append("assessor")
                or {"status": "completed", "assessments": [], "errors": []}
            ),
        )
        self.assertEqual(result["status"], "completed_with_errors")
        self.assertEqual(calls, ["assessor"])
        self.assertEqual(
            result["retrieval_results"][0]["retrieval_status"],
            "pipeline_error",
        )

    def test_ui_keeps_report_when_pipeline_fails_and_uses_conservative_wording(self):
        import app

        result = _research(
            "# Durable report",
            [{"url": "https://source.example", "citation_number": 1}],
        )
        blackbox = {
            "verified": True,
            "verdict": "QUALITY_PASS",
            "summary": "Structural checks only.",
            "report_analysis": {
                "word_count": 2,
                "identifier_in_report": True,
            },
            "source_analysis": {
                "total_sources": 1,
                "recognized_count": 1,
                "authoritative_count": 1,
                "security_vendor_count": 0,
                "unrecognized_count": 0,
                "malformed_count": 0,
                "authoritative_sources": [],
                "security_vendor_sources": [],
                "unrecognized_sources": [],
                "malformed_sources": [],
            },
            "claim_verification": {"note": "Claims remain unverified."},
            "limitations": [],
        }
        with patch("streamlit.spinner") as spinner, \
             patch("streamlit.markdown") as markdown, \
             patch("streamlit.expander") as expander, \
             patch("streamlit.warning"), \
             patch("streamlit.success"), \
             patch("streamlit.caption"), \
             patch("streamlit.subheader"), \
             patch("streamlit.error"), \
             patch("streamlit.info"):
            spinner.return_value.__enter__ = MagicMock(return_value=None)
            spinner.return_value.__exit__ = MagicMock(return_value=False)
            expander.return_value.__enter__ = MagicMock(return_value=None)
            expander.return_value.__exit__ = MagicMock(return_value=False)
            app.handle_investigation(
                "CVE-2024-3094",
                research_func=MagicMock(return_value=result),
                blackbox_func=MagicMock(return_value=blackbox),
                evidence_pipeline_func=MagicMock(side_effect=RuntimeError("failed")),
            )

        rendered = " ".join(str(call) for call in markdown.call_args_list)
        self.assertIn("# Durable report", rendered)
        self.assertNotIn("factual verification", rendered.lower())


class TestSourceRetrieverBoundaries(unittest.TestCase):
    PUBLIC_IP = "93.184.216.34"

    def resolver(self, host):
        return [self.PUBLIC_IP]

    def client(self, handler):
        return httpx.Client(
            transport=httpx.MockTransport(handler),
            follow_redirects=False,
        )

    def test_security_boundaries_are_enforced_offline(self):
        self.assertEqual(
            retrieve_source("ftp://example.com", resolver=self.resolver)["retrieval_status"],
            "unsupported_url",
        )
        self.assertEqual(
            retrieve_source("https://", resolver=self.resolver)["retrieval_status"],
            "malformed_url",
        )
        self.assertEqual(
            retrieve_source(
                "http://127.0.0.1/",
                resolver=lambda host: ["127.0.0.1"],
            )["retrieval_status"],
            "blocked_destination",
        )

    def test_redirect_block_limit_size_and_content_type(self):
        def redirect_handler(request):
            return httpx.Response(
                302,
                headers={"location": "http://internal.example/"},
                request=request,
            )

        with self.client(redirect_handler) as client:
            blocked = retrieve_source(
                "https://public.example/start",
                client=client,
                resolver=lambda host: ["10.0.0.5"] if host == "internal.example"
                else [self.PUBLIC_IP],
            )
        self.assertEqual(blocked["retrieval_status"], "blocked_destination")

        def loop_handler(request):
            return httpx.Response(
                302,
                headers={"location": "/next"},
                request=request,
            )

        with self.client(loop_handler) as client:
            limited = retrieve_source(
                "https://public.example/start",
                client=client,
                resolver=self.resolver,
                max_redirects=1,
            )
        self.assertEqual(limited["retrieval_status"], "redirect_limit_exceeded")

        def large_handler(request):
            return httpx.Response(
                200,
                headers={"content-type": "text/plain"},
                content=b"123456",
                request=request,
            )

        with self.client(large_handler) as client:
            large = retrieve_source(
                "https://public.example/",
                client=client,
                resolver=self.resolver,
                max_bytes=5,
            )
        self.assertEqual(large["retrieval_status"], "response_too_large")

        def binary_handler(request):
            return httpx.Response(
                200,
                headers={"content-type": "application/pdf"},
                content=b"pdf",
                request=request,
            )

        with self.client(binary_handler) as client:
            binary = retrieve_source(
                "https://public.example/",
                client=client,
                resolver=self.resolver,
            )
        self.assertEqual(binary["retrieval_status"], "unsupported_content_type")


if __name__ == "__main__":
    unittest.main()
