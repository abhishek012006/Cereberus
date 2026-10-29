"""Offline tests for the standalone evidence pipeline."""

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.evidence_pipeline import build_evidence_pipeline


def research_result(**overrides):
    result = {
        "success": True,
        "status": "completed",
        "query": "CVE-2024-3094",
        "report": "CVE-2024-3094 affects XZ Utils 5.6.0 [7].",
        "sources": ["https://a.example", "https://a.example"],
        "source_records": [
            {"url": "https://a.example", "citation_number": 7, "title": "A"},
        ],
        "run_id": "run-1",
        "error": None,
    }
    result.update(overrides)
    return result


def claim_result(claims=None, status="completed", error=None):
    return {
        "status": status,
        "claims": claims if claims is not None else [{
            "claim_id": "c1",
            "claim_text": "CVE-2024-3094 affects XZ Utils 5.6.0 [7].",
            "claim_type": "affected_versions",
            "related_identifiers": ["CVE-2024-3094", "5.6.0"],
            "source_citation_markers": [7],
        }],
        "error": error,
    }


def retrieval(url, status="retrieved"):
    return {
        "url": url,
        "final_url": url + "/final",
        "status_code": 200,
        "title": None,
        "text": "CVE-2024-3094 affects XZ Utils 5.6.0.",
        "retrieval_status": status,
        "error": None if status == "retrieved" else "failed",
    }


def matcher_result():
    return {
        "status": "completed",
        "matches": [],
        "unresolved_citations": [],
        "errors": [],
    }


def assessor_result():
    return {"status": "completed", "assessments": [], "errors": []}


class TestEvidencePipeline(unittest.TestCase):
    def test_mixed_source_outcomes_preserve_successful_evidence(self):
        result = build_evidence_pipeline(
            research_result(source_records=[
                {"url": "https://good.example", "citation_number": 7},
                {"url": "https://bad.example", "citation_number": 8},
            ]),
            source_retriever=lambda url: (
                retrieval(url)
                if url.endswith("good.example")
                else {
                    **retrieval(url, status="network_error"),
                    "text": "",
                }
            ),
        )
        self.assertEqual(result["status"], "completed_with_errors")
        evidence = result["evidence_matches"]["matches"][0]["evidence"]
        self.assertTrue(evidence)
        self.assertTrue(all(item["url"] == "https://good.example" for item in evidence))
        self.assertTrue(any("bad.example" in error for error in result["errors"]))

    def test_downstream_exceptions_and_malformed_results_stop_cleanly(self):
        scenarios = (
            ("extractor", lambda: build_evidence_pipeline(
                research_result(),
                claim_extractor=lambda _report: (_ for _ in ()).throw(RuntimeError()),
            )),
            ("matcher", lambda: build_evidence_pipeline(
                research_result(),
                evidence_matcher=lambda *_args: (_ for _ in ()).throw(RuntimeError()),
            )),
            ("assessor", lambda: build_evidence_pipeline(
                research_result(),
                evidence_assessor=lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError()),
            )),
            ("matcher malformed", lambda: build_evidence_pipeline(
                research_result(),
                evidence_matcher=lambda *_args: {"status": "error", "matches": [], "unresolved_citations": [], "errors": ["bad"]},
            )),
            ("assessor malformed", lambda: build_evidence_pipeline(
                research_result(),
                evidence_assessor=lambda *_args, **_kwargs: {"status": "error", "assessments": [], "errors": ["bad"]},
            )),
        )
        for stage, run in scenarios:
            with self.subTest(stage=stage):
                result = run()
                self.assertEqual(result["status"], "error")
                if stage == "matcher":
                    self.assertIsNone(result["evidence_matches"])
                elif stage == "matcher malformed":
                    self.assertEqual(result["evidence_matches"]["status"], "error")
                elif stage == "assessor malformed":
                    self.assertEqual(result["evidence_assessment"]["status"], "error")
                else:
                    self.assertIsNone(result["evidence_assessment"])

    def test_error_lists_from_empty_claim_stages_are_propagated(self):
        result = build_evidence_pipeline(
            research_result(),
            claim_extractor=lambda _report: claim_result(claims=[], status="empty"),
            evidence_matcher=lambda *_args: {
                "status": "completed_with_errors",
                "matches": [],
                "unresolved_citations": [],
                "errors": ["matcher warning"],
            },
            evidence_assessor=lambda *_args, **_kwargs: {
                "status": "completed_with_errors",
                "assessments": [],
                "errors": ["assessor warning"],
            },
        )
        self.assertEqual(result["status"], "completed_with_errors")
        self.assertIn("Evidence matcher: matcher warning", result["errors"])
        self.assertIn("Evidence assessor: assessor warning", result["errors"])

    def test_duplicate_claim_ids_and_extra_fields_are_preserved_without_verdicts(self):
        claims = [
            {**claim_result()["claims"][0], "extra": "ignored"},
            {**claim_result()["claims"][0], "claim_text": "Same claim again."},
        ]
        result = build_evidence_pipeline(
            research_result(),
            claim_extractor=lambda _report: claim_result(claims=claims),
        )
        self.assertEqual(result["status"], "completed_with_errors")
        self.assertEqual(len(result["claim_extraction"]["claims"]), 2)
        self.assertTrue(result["errors"])
        self.assertNotIn("verified", repr(result["evidence_assessment"]).lower())

    def test_malformed_source_records_are_reported_and_do_not_stop_other_sources(self):
        result = build_evidence_pipeline(
            research_result(source_records=[
                "not a record",
                {"url": ""},
                {"url": "https://good.example"},
            ]),
            source_retriever=lambda url: retrieval(url),
        )
        self.assertEqual(result["status"], "completed_with_errors")
        self.assertEqual(len(result["retrieval_results"]), 1)
        self.assertEqual(result["retrieval_results"][0]["url"], "https://good.example")
        self.assertGreaterEqual(len(result["errors"]), 2)

    def test_invalid_retriever_outputs_are_structured_and_excluded(self):
        invalid_results = (
            "not a result",
            {"url": "https://a.example", "text": ""},
            {
                **retrieval("https://a.example"),
                "text": 42,
            },
            {
                **retrieval("https://a.example"),
                "retrieval_status": "unknown",
            },
        )
        for invalid in invalid_results:
            with self.subTest(invalid=invalid):
                result = build_evidence_pipeline(
                    research_result(),
                    source_retriever=lambda _url, value=invalid: value,
                )
                self.assertEqual(result["status"], "completed_with_errors")
                self.assertEqual(
                    result["retrieval_results"][0]["retrieval_status"],
                    "pipeline_error",
                )
                self.assertEqual(result["retrieval_results"][0]["text"], "")
                self.assertFalse(result["evidence_matches"]["matches"][0]["evidence"])

    def test_retriever_url_mismatch_cannot_change_provenance(self):
        result = build_evidence_pipeline(
            research_result(),
            source_retriever=lambda _url: retrieval("https://other.example"),
        )
        self.assertEqual(result["status"], "completed_with_errors")
        self.assertEqual(result["retrieval_results"][0]["url"], "https://a.example")
        self.assertEqual(result["retrieval_results"][0]["retrieval_status"], "pipeline_error")
        self.assertFalse(result["evidence_matches"]["matches"][0]["evidence"])

    def test_successful_empty_text_never_becomes_evidence(self):
        result = build_evidence_pipeline(
            research_result(),
            source_retriever=lambda url: {
                **retrieval(url),
                "text": "",
            },
        )
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["retrieval_results"][0]["retrieval_status"], "retrieved")
        self.assertFalse(result["evidence_matches"]["matches"][0]["evidence"])
        self.assertEqual(
            result["evidence_assessment"]["assessments"][0]["assessment"],
            "no_retrieved_evidence",
        )

    def test_malformed_and_unsupported_urls_use_real_retriever_contract(self):
        for url, expected_status in (
            ("ftp://a.example", "unsupported_url"),
            ("https://", "malformed_url"),
        ):
            with self.subTest(url=url):
                result = build_evidence_pipeline(
                    research_result(
                        source_records=[{"url": url, "citation_number": 7}]
                    )
                )
                self.assertEqual(result["status"], "completed_with_errors")
                self.assertEqual(
                    result["retrieval_results"][0]["retrieval_status"],
                    expected_status,
                )
                self.assertFalse(result["evidence_matches"]["matches"][0]["evidence"])

    def test_completed_runs_stages_in_order_and_passes_exact_report(self):
        calls = []

        def extractor(report):
            calls.append(("extractor", report))
            return claim_result()

        def retriever(url):
            calls.append(("retriever", url))
            return retrieval(url)

        def matcher(claims, records, retrievals):
            calls.append(("matcher", claims, records, retrievals))
            return matcher_result()

        def assessor(claims, matches, *, retrieval_results):
            calls.append(("assessor", claims, matches, retrieval_results))
            return assessor_result()

        result = build_evidence_pipeline(
            research_result(),
            claim_extractor=extractor,
            source_retriever=retriever,
            evidence_matcher=matcher,
            evidence_assessor=assessor,
        )

        self.assertEqual(result["status"], "completed")
        self.assertEqual([call[0] for call in calls], [
            "extractor", "retriever", "matcher", "assessor"
        ])
        self.assertEqual(calls[0][1], research_result()["report"])

    def test_exact_duplicate_urls_retrieved_once(self):
        urls = []

        def retriever(url):
            urls.append(url)
            return retrieval(url)

        result = build_evidence_pipeline(
            research_result(source_records=[
                {"url": " https://a.example "},
                {"url": "https://a.example"},
                {"url": "https://b.example"},
            ]),
            source_retriever=retriever,
            evidence_matcher=lambda *args: matcher_result(),
            evidence_assessor=lambda *args, **kwargs: assessor_result(),
        )
        self.assertEqual(urls, ["https://a.example", "https://b.example"])
        self.assertEqual(len(result["retrieval_results"]), 2)

    def test_distinct_url_variants_remain_distinct(self):
        urls = []
        result = build_evidence_pipeline(
            research_result(source_records=[
                {"url": "https://a.example"},
                {"url": "https://a.example/"},
                {"url": "HTTPS://a.example"},
            ]),
            source_retriever=lambda url: (urls.append(url) or retrieval(url)),
            evidence_matcher=lambda *args: matcher_result(),
            evidence_assessor=lambda *args, **kwargs: assessor_result(),
        )
        self.assertEqual(urls, [
            "https://a.example", "https://a.example/", "HTTPS://a.example"
        ])
        self.assertEqual(len(result["retrieval_results"]), 3)

    def test_original_records_and_citation_metadata_reach_matcher(self):
        records = [
            {"url": "https://a.example", "citation_number": 7, "source_id": "s7"}
        ]
        received = []

        def matcher(claims, source_records, retrievals):
            received.append(source_records)
            return matcher_result()

        build_evidence_pipeline(
            research_result(source_records=records),
            evidence_matcher=matcher,
            evidence_assessor=lambda *args, **kwargs: assessor_result(),
        )
        self.assertIs(received[0], records)
        self.assertEqual(received[0][0]["citation_number"], 7)
        self.assertEqual(received[0][0]["source_id"], "s7")

    def test_retrieval_failures_are_preserved_and_other_urls_continue(self):
        def retriever(url):
            if url == "https://bad.example":
                raise RuntimeError("secret should not be exposed")
            return retrieval(url)

        result = build_evidence_pipeline(
            research_result(source_records=[
                {"url": "https://bad.example"},
                {"url": "https://good.example"},
            ]),
            source_retriever=retriever,
            evidence_matcher=lambda *args: matcher_result(),
            evidence_assessor=lambda *args, **kwargs: assessor_result(),
        )
        self.assertEqual(result["status"], "completed_with_errors")
        self.assertEqual(result["retrieval_results"][0]["retrieval_status"], "pipeline_error")
        self.assertEqual(result["retrieval_results"][0]["url"], "https://bad.example")
        self.assertNotIn("secret", result["retrieval_results"][0]["error"])
        self.assertEqual(result["retrieval_results"][1]["url"], "https://good.example")

    def test_missing_source_records_does_not_infer_sources(self):
        received = []
        result = build_evidence_pipeline(
            research_result(source_records=None),
            source_retriever=lambda url: self.fail("source order inference occurred"),
            evidence_matcher=lambda claims, records, retrievals: (
                received.append((records, retrievals)) or matcher_result()
            ),
            evidence_assessor=lambda *args, **kwargs: assessor_result(),
        )
        self.assertEqual(result["status"], "completed")
        self.assertEqual(received, [([], [])])

    def test_duplicate_and_missing_citations_are_not_repaired(self):
        records = [
            {"url": "https://a.example", "citation_number": 2},
            {"url": "https://b.example", "citation_number": 2},
        ]
        received = []
        build_evidence_pipeline(
            research_result(source_records=records),
            evidence_matcher=lambda claims, source_records, retrievals: (
                received.append(source_records) or matcher_result()
            ),
            evidence_assessor=lambda *args, **kwargs: assessor_result(),
        )
        self.assertEqual(received[0], records)
        self.assertEqual([record["citation_number"] for record in received[0]], [2, 2])

    def test_extractor_failure_or_malformed_output_stops_downstream(self):
        calls = []
        for extractor_result in (
            {"status": "error", "claims": [], "error": "failed"},
            {"status": "completed", "claims": "bad", "error": None},
        ):
            result = build_evidence_pipeline(
                research_result(),
                claim_extractor=lambda report, value=extractor_result: value,
                source_retriever=lambda url: calls.append("retriever"),
                evidence_matcher=lambda *args: calls.append("matcher"),
                evidence_assessor=lambda *args, **kwargs: calls.append("assessor"),
            )
            self.assertEqual(result["status"], "error")
            self.assertEqual(calls, [])

    def test_matcher_and_assessor_errors_are_preserved_and_surfaced(self):
        matcher_output = {
            "status": "completed",
            "matches": [],
            "unresolved_citations": [],
            "errors": ["citation issue"],
        }
        assessor_output = {"status": "completed", "assessments": [], "errors": ["assessment issue"]}
        result = build_evidence_pipeline(
            research_result(),
            evidence_matcher=lambda *args: matcher_output,
            evidence_assessor=lambda *args, **kwargs: assessor_output,
        )
        self.assertEqual(result["status"], "completed_with_errors")
        self.assertIs(result["evidence_matches"], matcher_output)
        self.assertIs(result["evidence_assessment"], assessor_output)
        self.assertTrue(any("citation issue" in error for error in result["errors"]))
        self.assertTrue(any("assessment issue" in error for error in result["errors"]))

    def test_empty_claims_and_sources_do_not_fabricate(self):
        calls = []
        result = build_evidence_pipeline(
            research_result(source_records=[]),
            claim_extractor=lambda report: claim_result(claims=[]),
            evidence_matcher=lambda claims, records, retrievals: (
                calls.append(("matcher", claims, records, retrievals)) or matcher_result()
            ),
            evidence_assessor=lambda claims, matches, **kwargs: (
                calls.append(("assessor", claims)) or assessor_result()
            ),
        )
        self.assertEqual(result["status"], "completed")
        self.assertEqual(calls, [("matcher", [], [], []), ("assessor", [])])
        self.assertEqual(result["retrieval_results"], [])

    def test_ineligible_research_is_skipped_without_stage_calls(self):
        for status in ("incomplete", "timeout", "empty_result", "error"):
            with self.subTest(status=status):
                calls = []
                result = build_evidence_pipeline(
                    research_result(success=False, status=status, report="partial"),
                    claim_extractor=lambda report: calls.append("extractor"),
                    source_retriever=lambda url: calls.append("retriever"),
                    evidence_matcher=lambda *args: calls.append("matcher"),
                    evidence_assessor=lambda *args, **kwargs: calls.append("assessor"),
                )
                self.assertEqual(result["status"], "skipped")
                self.assertEqual(calls, [])

    def test_malformed_research_inputs_are_safe(self):
        for value in (None, [], "bad", {"success": True, "status": "completed"}):
            result = build_evidence_pipeline(value)
            self.assertEqual(result["status"], "skipped")
            self.assertIs(result["research_result"], value)

    def test_input_and_component_outputs_are_not_mutated(self):
        research = research_result()
        original = copy.deepcopy(research)
        claim_output = claim_result()
        match_output = matcher_result()
        assess_output = assessor_result()

        result = build_evidence_pipeline(
            research,
            claim_extractor=lambda report: claim_output,
            source_retriever=lambda url: retrieval(url),
            evidence_matcher=lambda *args: match_output,
            evidence_assessor=lambda *args, **kwargs: assess_output,
        )
        self.assertEqual(research, original)
        self.assertIs(result["claim_extraction"], claim_output)
        self.assertIs(result["evidence_matches"], match_output)
        self.assertIs(result["evidence_assessment"], assess_output)

    def test_stage_exception_stops_only_dependent_downstream_stage(self):
        calls = []
        result = build_evidence_pipeline(
            research_result(),
            evidence_matcher=lambda *args: (_ for _ in ()).throw(RuntimeError("matcher")),
            evidence_assessor=lambda *args, **kwargs: calls.append("assessor"),
        )
        self.assertEqual(result["status"], "error")
        self.assertIsNone(result["evidence_matches"])
        self.assertIsNone(result["evidence_assessment"])
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
