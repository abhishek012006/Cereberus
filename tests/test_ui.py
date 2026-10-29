"""Unit tests for the CERBERUS Streamlit UI logic (app.py).

These tests verify input validation, query formulation, and result rendering
by mocking Streamlit functions and Nightwatch research calls. No live API requests are made.
"""

import sys
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch

# Ensure the root directory is on sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from app import (
    _render_evidence_assessment,
    _retrieval_issue_explanation,
    construct_query,
    handle_investigation,
)


class TestStreamlitUILogic(unittest.TestCase):
    """Test suite for app.py helper functions and investigation handler."""

    def test_construct_query_without_software(self):
        """Verify that query without software info uses the clean vulnerability input."""
        q = construct_query("CVE-2024-3094")
        self.assertEqual(q, "CVE-2024-3094")

        # Whitespace handling
        q2 = construct_query("  Log4Shell   ", "   ")
        self.assertEqual(q2, "Log4Shell")

    @patch("streamlit.markdown")
    @patch("streamlit.caption")
    @patch("streamlit.subheader")
    def test_ambiguous_citation_label_is_rendered(self, mock_subheader, mock_caption, mock_markdown):
        _render_evidence_assessment({
            "status": "completed_with_errors",
            "errors": ["citation number is ambiguous."],
            "evidence_assessment": {
                "assessments": [{
                    "claim_id": "claim-1",
                    "claim_text": "CVE-2024-3094 [1].",
                    "assessment": "citation_ambiguous",
                    "detail_assessments": [],
                    "evidence": [],
                    "reasons": ["The cited source could not be resolved unambiguously."],
                }],
                "errors": [],
            },
        })
        rendered = " ".join(str(call.args[0]) for call in mock_markdown.call_args_list)
        self.assertIn("citation_ambiguous", rendered)

    @patch("streamlit.markdown")
    @patch("streamlit.caption")
    @patch("streamlit.subheader")
    def test_candidate_evidence_disclaimer_is_rendered(
        self, mock_subheader, mock_caption, mock_markdown
    ):
        _render_evidence_assessment({
            "status": "completed_with_errors",
            "errors": ["One source failed retrieval."],
            "evidence_assessment": {
                "assessments": [{
                    "claim_id": "claim-1",
                    "claim_text": "CVE-2024-3094 affects XZ Utils 5.6.0.",
                    "assessment": "citation_unresolved",
                    "detail_assessments": [],
                    "evidence": [{
                        "url": "https://good.example",
                        "citation_number": 1,
                        "passage": "CVE-2024-3094 affects XZ Utils 5.6.0.",
                    }],
                    "reasons": ["This is a deterministic text-level assessment, not a truth verdict."],
                }],
                "errors": [],
            },
        })
        captions = " ".join(str(call.args[0]) for call in mock_caption.call_args_list)
        self.assertIn("do not establish factual truth", captions)

    def test_retrieval_issue_explanations_are_sanitized(self):
        cases = (
            (
                {"retrieval_status": "http_error", "status_code": 403,
                 "error": "secret response body"},
                "HTTP status 403",
            ),
            (
                {"retrieval_status": "network_error", "error": "secret TLS details"},
                "network request",
            ),
            (
                {"retrieval_status": "timeout", "error": "secret timeout details"},
                "retrieval deadline",
            ),
            (
                {"retrieval_status": "response_too_large", "error": "secret body"},
                "configured size limit",
            ),
        )
        for retrieval, expected in cases:
            with self.subTest(status=retrieval["retrieval_status"]):
                explanation = _retrieval_issue_explanation(retrieval)
                self.assertIn(expected, explanation)
                self.assertNotIn("secret", explanation)

        self.assertIn(
            "TLS or certificate verification failed",
            _retrieval_issue_explanation({
                "retrieval_status": "network_error",
                "error": "TLS or certificate verification failed.",
            }),
        )
        self.assertIn(
            "transferring data",
            _retrieval_issue_explanation({
                "retrieval_status": "network_error",
                "error": "Read/write transport failure.",
            }),
        )

    @patch("streamlit.warning")
    @patch("streamlit.markdown")
    @patch("streamlit.caption")
    @patch("streamlit.subheader")
    def test_retrieval_issues_show_safe_status_and_provenance(
        self, mock_subheader, mock_caption, mock_markdown, mock_warning
    ):
        _render_evidence_assessment({
            "status": "completed_with_errors",
            "research_result": {
                "source_records": [
                    {"url": "https://denied.example", "citation_number": 4},
                    {"url": "https://good.example", "citation_number": 5},
                ],
            },
            "retrieval_results": [
                {
                    "url": "https://denied.example",
                    "retrieval_status": "http_error",
                    "status_code": 403,
                    "error": "Authorization header and response body must not appear.",
                    "text": "",
                },
                {
                    "url": "https://good.example",
                    "retrieval_status": "retrieved",
                    "status_code": 200,
                    "text": "candidate",
                },
            ],
            "errors": [],
            "evidence_assessment": {"assessments": [], "errors": []},
        })

        rendered = " ".join(str(call.args[0]) for call in mock_warning.call_args_list)
        self.assertIn("denied.example", rendered)
        self.assertIn("citation 4", rendered)
        self.assertIn("HTTP status 403", rendered)
        self.assertNotIn("Authorization header", rendered)
        self.assertNotIn("response body", rendered)

    def test_construct_query_with_software_neutrality(self):
        """Verify that query with software info includes software context without assuming vulnerability."""
        q = construct_query("CVE-2024-3094", "XZ Utils 5.6.0")
        self.assertIn("CVE-2024-3094", q)
        self.assertIn("XZ Utils 5.6.0", q)
        self.assertIn("Evaluate whether this software version is affected", q)

    @patch("streamlit.warning")
    def test_empty_vulnerability_shows_warning(self, mock_warning):
        """Verify that an empty or whitespace vulnerability input displays a warning and stops."""
        mock_research = MagicMock()

        handle_investigation("", "", research_func=mock_research)
        mock_warning.assert_called_with("Please enter a vulnerability name or CVE identifier.")
        mock_research.assert_not_called()

        mock_warning.reset_mock()
        handle_investigation("   \t  ", "", research_func=mock_research)
        mock_warning.assert_called_with("Please enter a vulnerability name or CVE identifier.")
        mock_research.assert_not_called()

    @patch("streamlit.error")
    @patch("streamlit.spinner")
    def test_malformed_research_result_is_reported_without_crashing(
        self, mock_spinner, mock_error
    ):
        mock_research = MagicMock(return_value=None)

        handle_investigation("CVE-2024-3094", research_func=mock_research)

        mock_error.assert_called_once_with(
            "Investigation failed because the research engine returned an invalid result "
            "(NoneType). Please retry."
        )

    @patch("streamlit.warning")
    @patch("streamlit.spinner")
    def test_blackbox_failure_preserves_report_and_continues_pipeline(
        self, mock_spinner, mock_warning
    ):
        report = "# Research report remains visible"
        mock_research = MagicMock(return_value={
            "success": True,
            "status": "completed",
            "query": "CVE-2024-3094",
            "report": report,
            "sources": [],
            "run_id": None,
            "error": None,
        })
        mock_pipeline = MagicMock(return_value={
            "status": "completed",
            "errors": [],
            "evidence_assessment": {"assessments": []},
        })

        with patch("streamlit.markdown") as mock_markdown:
            handle_investigation(
                "CVE-2024-3094",
                research_func=mock_research,
                blackbox_func=MagicMock(side_effect=RuntimeError("secret details")),
                evidence_pipeline_func=mock_pipeline,
            )

        rendered = " ".join(str(call.args[0]) for call in mock_markdown.call_args_list)
        self.assertIn(report, rendered)
        mock_pipeline.assert_called_once_with(mock_research.return_value)
        warning = mock_warning.call_args.args[0]
        self.assertIn("RuntimeError", warning)
        self.assertNotIn("secret details", warning)

    @patch("app.handle_investigation")
    @patch("streamlit.button", side_effect=[True, False])
    @patch(
        "streamlit.text_input",
        side_effect=["CVE-2024-3094", "", "CVE-2024-3094", ""],
    )
    @patch("streamlit.markdown")
    @patch("streamlit.title")
    @patch("streamlit.set_page_config")
    def test_button_event_does_not_duplicate_investigation_on_rerun(
        self,
        mock_set_page_config,
        mock_title,
        mock_markdown,
        mock_text_input,
        mock_button,
        mock_handle,
    ):
        from app import render_ui

        render_ui()
        render_ui()

        mock_handle.assert_called_once_with("CVE-2024-3094", "")

    @patch("app.handle_investigation")
    @patch("streamlit.button", return_value=False)
    @patch("streamlit.text_input", side_effect=["", ""])
    @patch("streamlit.caption")
    @patch("streamlit.markdown")
    @patch("streamlit.subheader")
    @patch("streamlit.title")
    @patch("streamlit.set_page_config")
    def test_opening_ui_explains_research_and_evidence_limits(
        self,
        mock_set_page_config,
        mock_title,
        mock_subheader,
        mock_markdown,
        mock_caption,
        mock_text_input,
        mock_button,
        mock_handle,
    ):
        from app import render_ui

        render_ui()

        opening = " ".join(str(call.args[0]) for call in mock_markdown.call_args_list)
        captions = " ".join(str(call.args[0]) for call in mock_caption.call_args_list)
        self.assertIn("TinyFish", opening)
        self.assertIn("Candidate evidence", captions)
        self.assertIn("not a factual verification verdict", captions)
        mock_handle.assert_not_called()

    @patch("streamlit.caption")
    @patch("streamlit.subheader")
    @patch("streamlit.markdown")
    @patch("streamlit.success")
    @patch("streamlit.spinner")
    def test_successful_investigation_rendering(
        self,
        mock_spinner,
        mock_success,
        mock_markdown,
        mock_subheader,
        mock_caption,
    ):
        """Verify report, run ID, and clickable sources are rendered on successful investigation."""
        mock_research = MagicMock(return_value={
            "success": True,
            "status": "completed",
            "query": "CVE-2024-3094",
            "report": "# Analysis of CVE-2024-3094\nMalicious code was found in upstream tarballs.",
            "sources": ["https://nvd.nist.gov/vuln/detail/CVE-2024-3094"],
            "run_id": "test-run-ui-456",
            "error": None,
        })

        handle_investigation("CVE-2024-3094", "", research_func=mock_research)

        mock_research.assert_called_once_with(query="CVE-2024-3094")
        mock_success.assert_called_with("Investigation complete.")
        # st.caption is now called for BOTH the run ID and the BlackBox summary,
        # so we use assert_any_call rather than assert_called_with.
        mock_caption.assert_any_call("Research Run ID: `test-run-ui-456`")

        # Verify report was rendered via markdown
        markdown_calls = [c[0][0] for c in mock_markdown.call_args_list]
        self.assertIn("# Analysis of CVE-2024-3094\nMalicious code was found in upstream tarballs.", markdown_calls)

        # Verify source URL was formatted as a clickable markdown link
        expected_link = "1. [https://nvd.nist.gov/vuln/detail/CVE-2024-3094](https://nvd.nist.gov/vuln/detail/CVE-2024-3094)"
        self.assertIn(expected_link, markdown_calls)

    @patch("streamlit.spinner")
    def test_software_info_passed_to_nightwatch(self, mock_spinner):
        """Verify that optional software context is incorporated into the Nightwatch query."""
        mock_research = MagicMock(return_value={
            "success": True,
            "status": "completed",
            "query": "test query",
            "report": "Findings text",
            "sources": [],
            "run_id": "run-1",
            "error": None,
        })

        handle_investigation("CVE-2021-44228", "Apache Log4j 2.14.1", research_func=mock_research)

        called_query = mock_research.call_args[1]["query"]
        self.assertIn("CVE-2021-44228", called_query)
        self.assertIn("Apache Log4j 2.14.1", called_query)
        self.assertIn("Evaluate whether this software version is affected", called_query)

    @patch("streamlit.error")
    @patch("streamlit.spinner")
    def test_error_handling_in_ui(self, mock_spinner, mock_error):
        """Verify that API errors display a safe message without leaking details."""
        mock_research = MagicMock(return_value={
            "success": False,
            "status": "error",
            "query": "CVE-2024-3094",
            "report": "",
            "sources": [],
            "run_id": None,
            "error": "SECRET_GENERAL_ERROR response body and Authorization header",
        })

        handle_investigation("CVE-2024-3094", "", research_func=mock_research)

        mock_error.assert_called_once_with(
            "Investigation failed before research completed. "
            "Please retry or check the research service configuration."
        )
        self.assertNotIn("SECRET_GENERAL_ERROR", repr(mock_error.call_args_list))

    @patch("streamlit.subheader")
    @patch("streamlit.markdown")
    @patch("streamlit.warning")
    @patch("streamlit.spinner")
    def test_empty_result_handling_in_ui(
        self,
        mock_spinner,
        mock_warning,
        mock_markdown,
        mock_subheader,
    ):
        """Verify that empty research results display a warning rather than fabricated reports."""
        mock_research = MagicMock(return_value={
            "success": False,
            "status": "empty_result",
            "query": "CVE-2024-3094",
            "report": "",
            "sources": ["https://example.com/visited-site"],
            "run_id": "run-empty",
            "error": "Research stream completed, but no report content was generated.",
        })

        handle_investigation("CVE-2024-3094", "", research_func=mock_research)

        mock_warning.assert_called_with(
            "Research concluded, but no report content was generated by the research engine. "
            "No findings are available to assess."
        )
        # Visited sources are still surfaced
        mock_subheader.assert_called_with("Discovered Sources")
        markdown_calls = [c[0][0] for c in mock_markdown.call_args_list]
        self.assertIn("1. [https://example.com/visited-site](https://example.com/visited-site)", markdown_calls)

    @patch("streamlit.error")
    @patch("streamlit.spinner")
    def test_timeout_handling_in_ui(self, mock_spinner, mock_error):
        """Verify that timeouts display a safe timeout message."""
        mock_research = MagicMock(return_value={
            "success": False,
            "status": "timeout",
            "query": "CVE-2024-3094",
            "report": "",
            "sources": [],
            "run_id": None,
            "error": "SECRET_TIMEOUT_ERROR raw exception and response body",
        })

        handle_investigation("CVE-2024-3094", "", research_func=mock_research)

        mock_error.assert_called_once_with(
            "Investigation timed out before research completed. "
            "Please retry with the same or a narrower query."
        )
        self.assertNotIn("SECRET_TIMEOUT_ERROR", repr(mock_error.call_args_list))

    @patch("streamlit.markdown")
    @patch("streamlit.warning")
    @patch("streamlit.spinner")
    def test_incomplete_stream_handling_in_ui(self, mock_spinner, mock_warning, mock_markdown):
        """Verify interrupted streams display safe messaging and partial findings."""
        mock_research = MagicMock(return_value={
            "success": False,
            "status": "incomplete",
            "query": "CVE-2024-3094",
            "report": "Partial report text gathered so far...",
            "sources": [],
            "run_id": "run-inc",
            "error": "SECRET_INCOMPLETE_ERROR traceback and response body",
        })

        handle_investigation("CVE-2024-3094", "", research_func=mock_research)

        mock_warning.assert_called_with(
            "Research stream disconnected before completion. "
            "Any partial findings are shown below."
        )
        self.assertNotIn("SECRET_INCOMPLETE_ERROR", repr(mock_warning.call_args_list))
        markdown_calls = [c[0][0] for c in mock_markdown.call_args_list]
        self.assertIn("### Partial Findings Gathered Prior to Disconnect", markdown_calls)
        self.assertIn("Partial report text gathered so far...", markdown_calls)


class TestBlackBoxUIIntegration(unittest.TestCase):
    """Tests verifying that the BlackBox section renders correctly inside the Streamlit UI.

    All tests use mock objects so no live API calls or real BlackBox logic are executed.
    The blackbox_func parameter is injected directly into handle_investigation() to
    keep tests isolated from the real verify_research() implementation.
    """

    # ── Shared helpers ────────────────────────────────────────────────────────

    def _make_nightwatch_success(self, report="CVE-2024-3094 backdoor details.", sources=None):
        """Return a minimal but complete successful Nightwatch result dict."""
        return {
            "success": True,
            "status": "completed",
            "query": "CVE-2024-3094",
            "report": report,
            "sources": sources if sources is not None else ["https://nvd.nist.gov/vuln/detail/CVE-2024-3094"],
            "run_id": "run-bb-test-1",
            "error": None,
        }

    def _make_blackbox_result(
        self,
        verified=True,
        verdict="RESEARCH_VALID_WITH_RECOGNIZED_SOURCES_CLAIMS_UNVERIFIED",
        word_count=5,
        identifier_in_report=True,
        recognized_count=1,
        unrecognized_count=0,
        malformed_count=0,
        recognized_sources=None,
        unrecognized_sources=None,
        malformed_sources=None,
        cv_note="Claim-level factual verification is not yet implemented in BlackBox.",
    ):
        """Return a minimal but complete BlackBox verification result dict."""
        return {
            "verified": verified,
            "verdict": verdict,
            "summary": "Research-quality validation passed.",
            "checks": {
                "input_valid": True,
                "research_successful": True,
                "report_present": True,
                "identifier_detected": True,
                "sources_valid": True,
                "claims_verified": False,  # Always False in v1
            },
            "report_analysis": {
                "character_count": 50,
                "word_count": word_count,
                "has_content": True,
                "query_target": "CVE-2024-3094",
                "identifier_in_report": identifier_in_report,
            },
            "source_analysis": {
                "total_sources": recognized_count + unrecognized_count + malformed_count,
                "valid_count": recognized_count + unrecognized_count,
                "malformed_count": malformed_count,
                "recognized_count": recognized_count,
                "unrecognized_count": unrecognized_count,
                "recognized_sources": recognized_sources or [
                    {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
                     "domain": "nvd.nist.gov",
                     "matched_domain": "nist.gov"}
                ],
                "unrecognized_sources": unrecognized_sources or [],
                "malformed_sources": malformed_sources or [],
            },
            "claim_verification": {
                "status": "NOT_IMPLEMENTED",
                "claims_verified": False,
                "supported_claims_count": 0,
                "total_claims_count": 0,
                "note": cv_note,
            },
            "limitations": [
                "Claim-level factual verification is not yet implemented.",
                "Source URLs evaluated for syntax and domain heuristics only.",
            ],
            "findings": [],
        }

    # ── Test: BlackBox section renders on successful investigation ────────────

    @patch("streamlit.expander")
    @patch("streamlit.caption")
    @patch("streamlit.subheader")
    @patch("streamlit.markdown")
    @patch("streamlit.success")
    @patch("streamlit.spinner")
    def test_blackbox_section_called_on_success(
        self, mock_spinner, mock_success, mock_markdown, mock_subheader, mock_caption, mock_expander
    ):
        """BlackBox must be invoked exactly once when Nightwatch returns a successful result."""
        mock_research = MagicMock(return_value=self._make_nightwatch_success())
        mock_blackbox = MagicMock(return_value=self._make_blackbox_result())

        # Simulate the expander context manager (used twice: outer + limitations)
        mock_expander.return_value.__enter__ = MagicMock(return_value=None)
        mock_expander.return_value.__exit__ = MagicMock(return_value=False)

        handle_investigation(
            "CVE-2024-3094", "",
            research_func=mock_research,
            blackbox_func=mock_blackbox,
        )

        # BlackBox must have been called with the Nightwatch result
        mock_blackbox.assert_called_once_with(mock_research.return_value)

    @patch("streamlit.error")
    @patch("streamlit.expander")
    @patch("streamlit.caption")
    @patch("streamlit.info")
    @patch("streamlit.markdown")
    @patch("streamlit.success")
    @patch("streamlit.spinner")
    def test_blackbox_verdict_rendered_as_info_when_verified(
        self, mock_spinner, mock_success, mock_markdown, mock_info,
        mock_caption, mock_expander, mock_error
    ):
        """When BlackBox verified=True, the verdict should appear via st.info."""
        mock_research = MagicMock(return_value=self._make_nightwatch_success())
        bb_result = self._make_blackbox_result(verified=True)
        mock_blackbox = MagicMock(return_value=bb_result)

        mock_expander.return_value.__enter__ = MagicMock(return_value=None)
        mock_expander.return_value.__exit__ = MagicMock(return_value=False)

        handle_investigation(
            "CVE-2024-3094", "",
            research_func=mock_research,
            blackbox_func=mock_blackbox,
        )

        # st.info should have been called with a string containing the verdict
        info_calls = [str(c) for c in mock_info.call_args_list]
        self.assertTrue(
            any("RESEARCH_VALID_WITH_RECOGNIZED_SOURCES_CLAIMS_UNVERIFIED" in c for c in info_calls),
            "Expected verdict to appear in st.info call."
        )

    @patch("streamlit.error")
    @patch("streamlit.expander")
    @patch("streamlit.caption")
    @patch("streamlit.warning")
    @patch("streamlit.markdown")
    @patch("streamlit.success")
    @patch("streamlit.spinner")
    def test_blackbox_verdict_rendered_as_warning_when_not_verified(
        self, mock_spinner, mock_success, mock_markdown, mock_warning,
        mock_caption, mock_expander, mock_error
    ):
        """When BlackBox verified=False, the verdict should appear via st.warning."""
        mock_research = MagicMock(return_value=self._make_nightwatch_success())
        bb_result = self._make_blackbox_result(
            verified=False,
            verdict="NEEDS_REVIEW_IDENTIFIER_MISSING",
        )
        mock_blackbox = MagicMock(return_value=bb_result)

        mock_expander.return_value.__enter__ = MagicMock(return_value=None)
        mock_expander.return_value.__exit__ = MagicMock(return_value=False)

        handle_investigation(
            "CVE-2024-3094", "",
            research_func=mock_research,
            blackbox_func=mock_blackbox,
        )

        warning_calls = [str(c) for c in mock_warning.call_args_list]
        self.assertTrue(
            any("NEEDS_REVIEW_IDENTIFIER_MISSING" in c for c in warning_calls),
            "Expected verdict to appear in st.warning call."
        )

    @patch("streamlit.error")
    @patch("streamlit.expander")
    @patch("streamlit.caption")
    @patch("streamlit.info")
    @patch("streamlit.markdown")
    @patch("streamlit.success")
    @patch("streamlit.spinner")
    def test_claims_verified_always_false_in_blackbox_output(
        self, mock_spinner, mock_success, mock_markdown, mock_info,
        mock_caption, mock_expander, mock_error
    ):
        """Verify that the BlackBox result passed to the UI always has claims_verified=False.

        This guards against a future regression where claim verification is partially
        implemented but the disclaimer is accidentally removed from the UI.
        """
        mock_research = MagicMock(return_value=self._make_nightwatch_success())
        bb_result = self._make_blackbox_result()
        mock_blackbox = MagicMock(return_value=bb_result)

        mock_expander.return_value.__enter__ = MagicMock(return_value=None)
        mock_expander.return_value.__exit__ = MagicMock(return_value=False)

        handle_investigation(
            "CVE-2024-3094", "",
            research_func=mock_research,
            blackbox_func=mock_blackbox,
        )

        # The return value that the UI consumed must have claims_verified=False
        consumed_bb_result = mock_blackbox.return_value
        self.assertFalse(
            consumed_bb_result["checks"]["claims_verified"],
            "claims_verified must always be False in BlackBox v1."
        )
        self.assertFalse(
            consumed_bb_result["claim_verification"]["claims_verified"],
            "claim_verification.claims_verified must always be False in BlackBox v1."
        )

    @patch("streamlit.error")
    @patch("streamlit.expander")
    @patch("streamlit.caption")
    @patch("streamlit.info")
    @patch("streamlit.markdown")
    @patch("streamlit.success")
    @patch("streamlit.spinner")
    def test_claim_verification_disclaimer_shown(
        self, mock_spinner, mock_success, mock_markdown, mock_info,
        mock_caption, mock_expander, mock_error
    ):
        """The claim verification disclaimer (st.error) must always appear in the BlackBox section."""
        disclaimer_note = "Claim-level factual verification is not yet implemented in BlackBox."
        mock_research = MagicMock(return_value=self._make_nightwatch_success())
        bb_result = self._make_blackbox_result(cv_note=disclaimer_note)
        mock_blackbox = MagicMock(return_value=bb_result)

        mock_expander.return_value.__enter__ = MagicMock(return_value=None)
        mock_expander.return_value.__exit__ = MagicMock(return_value=False)

        handle_investigation(
            "CVE-2024-3094", "",
            research_func=mock_research,
            blackbox_func=mock_blackbox,
        )

        error_calls = [str(c) for c in mock_error.call_args_list]
        self.assertTrue(
            any(disclaimer_note in c for c in error_calls),
            "Claim verification disclaimer must appear via st.error in the BlackBox section."
        )

    @patch("streamlit.warning")
    @patch("streamlit.expander")
    @patch("streamlit.caption")
    @patch("streamlit.subheader")
    @patch("streamlit.markdown")
    @patch("streamlit.success")
    @patch("streamlit.spinner")
    def test_completed_research_invokes_pipeline_once(
        self, mock_spinner, mock_success, mock_markdown, mock_subheader,
        mock_caption, mock_expander, mock_warning
    ):
        mock_research = MagicMock(return_value=self._make_nightwatch_success())
        mock_blackbox = MagicMock(return_value=self._make_blackbox_result())
        mock_pipeline = MagicMock(return_value={
            "status": "completed",
            "evidence_assessment": {"assessments": [], "errors": []},
            "errors": [],
        })
        mock_expander.return_value.__enter__ = MagicMock(return_value=None)
        mock_expander.return_value.__exit__ = MagicMock(return_value=False)

        handle_investigation(
            "CVE-2024-3094",
            research_func=mock_research,
            blackbox_func=mock_blackbox,
            evidence_pipeline_func=mock_pipeline,
        )

        mock_pipeline.assert_called_once_with(mock_research.return_value)
        mock_blackbox.assert_called_once_with(mock_research.return_value)

    @patch("streamlit.error")
    @patch("streamlit.warning")
    @patch("streamlit.spinner")
    def test_incomplete_or_failed_research_does_not_invoke_pipeline(
        self, mock_spinner, mock_warning, mock_error
    ):
        for status in ("incomplete", "error"):
            with self.subTest(status=status):
                mock_research = MagicMock(return_value={
                    "success": False,
                    "status": status,
                    "query": "CVE-2024-3094",
                    "report": "partial" if status == "incomplete" else "",
                    "sources": [],
                    "run_id": None,
                    "error": "failed",
                })
                mock_pipeline = MagicMock()

                handle_investigation(
                    "CVE-2024-3094",
                    research_func=mock_research,
                    evidence_pipeline_func=mock_pipeline,
                )

                mock_pipeline.assert_not_called()

    @patch("streamlit.warning")
    @patch("streamlit.error")
    @patch("streamlit.expander")
    @patch("streamlit.caption")
    @patch("streamlit.subheader")
    @patch("streamlit.markdown")
    @patch("streamlit.success")
    @patch("streamlit.spinner")
    def test_evidence_assessment_and_provenance_are_rendered(
        self, mock_spinner, mock_success, mock_markdown, mock_subheader,
        mock_caption, mock_expander, mock_error, mock_warning
    ):
        mock_research = MagicMock(return_value=self._make_nightwatch_success())
        mock_blackbox = MagicMock(return_value=self._make_blackbox_result())
        mock_pipeline = MagicMock(return_value={
            "status": "completed",
            "evidence_assessment": {
                "assessments": [{
                    "claim_id": "claim-1",
                    "claim_text": "CVE-2024-3094 is referenced.",
                    "assessment": "identifier_match_only",
                    "detail_assessments": [{
                        "detail_type": "cve",
                        "detail_text": "CVE-2024-3094",
                        "status": "matched",
                    }],
                    "evidence": [{
                        "url": "https://source.example/original",
                        "final_url": "https://source.example/final",
                        "passage": "CVE-2024-3094 is referenced.",
                        "citation_number": 7,
                    }],
                    "reasons": ["Deterministic text-level observation."],
                }],
                "errors": [],
            },
            "errors": [],
        })
        mock_expander.return_value.__enter__ = MagicMock(return_value=None)
        mock_expander.return_value.__exit__ = MagicMock(return_value=False)

        handle_investigation(
            "CVE-2024-3094",
            research_func=mock_research,
            blackbox_func=mock_blackbox,
            evidence_pipeline_func=mock_pipeline,
        )

        markdown_calls = [call.args[0] for call in mock_markdown.call_args_list]
        self.assertIn("**Assessment:** `identifier_match_only`", markdown_calls)
        self.assertTrue(any("source.example/original" in call for call in markdown_calls))
        self.assertTrue(any("CVE-2024-3094 is referenced." in call for call in markdown_calls))
        self.assertTrue(any("Evidence Assessment" in call.args for call in mock_subheader.call_args_list))
        self.assertTrue(any(
            "does not mean the source supports the full claim" in str(call)
            for call in mock_caption.call_args_list
        ))

    @patch("streamlit.info")
    @patch("streamlit.warning")
    @patch("streamlit.expander")
    @patch("streamlit.caption")
    @patch("streamlit.subheader")
    @patch("streamlit.markdown")
    @patch("streamlit.success")
    @patch("streamlit.spinner")
    def test_empty_assessments_render_gracefully(
        self, mock_spinner, mock_success, mock_markdown, mock_subheader,
        mock_caption, mock_expander, mock_warning, mock_info
    ):
        mock_expander.return_value.__enter__ = MagicMock(return_value=None)
        mock_expander.return_value.__exit__ = MagicMock(return_value=False)

        handle_investigation(
            "CVE-2024-3094",
            research_func=MagicMock(return_value=self._make_nightwatch_success()),
            blackbox_func=MagicMock(return_value=self._make_blackbox_result()),
            evidence_pipeline_func=MagicMock(return_value={
                "status": "completed",
                "evidence_assessment": {"assessments": [], "errors": []},
                "errors": [],
            }),
        )

        mock_info.assert_called_with(
            "No claims were available for deterministic evidence assessment."
        )

    @patch("streamlit.warning")
    @patch("streamlit.expander")
    @patch("streamlit.caption")
    @patch("streamlit.subheader")
    @patch("streamlit.markdown")
    @patch("streamlit.success")
    @patch("streamlit.spinner")
    def test_pipeline_exception_warns_and_preserves_report(
        self, mock_spinner, mock_success, mock_markdown, mock_subheader,
        mock_caption, mock_expander, mock_warning
    ):
        report = "# Research report remains visible"
        mock_expander.return_value.__enter__ = MagicMock(return_value=None)
        mock_expander.return_value.__exit__ = MagicMock(return_value=False)

        handle_investigation(
            "CVE-2024-3094",
            research_func=MagicMock(return_value=self._make_nightwatch_success(report=report)),
            blackbox_func=MagicMock(return_value=self._make_blackbox_result()),
            evidence_pipeline_func=MagicMock(side_effect=RuntimeError("internal detail")),
        )

        markdown_calls = [call.args[0] for call in mock_markdown.call_args_list]
        self.assertIn(report, markdown_calls)
        self.assertTrue(any("Evidence Assessment is unavailable" in str(call)
                            for call in mock_warning.call_args_list))

    @patch("streamlit.warning")
    @patch("streamlit.expander")
    @patch("streamlit.caption")
    @patch("streamlit.subheader")
    @patch("streamlit.markdown")
    @patch("streamlit.success")
    @patch("streamlit.spinner")
    def test_missing_source_records_does_not_crash_or_infer_citations(
        self, mock_spinner, mock_success, mock_markdown, mock_subheader,
        mock_caption, mock_expander, mock_warning
    ):
        mock_expander.return_value.__enter__ = MagicMock(return_value=None)
        mock_expander.return_value.__exit__ = MagicMock(return_value=False)
        mock_pipeline = MagicMock(return_value={
            "status": "completed",
            "evidence_assessment": {
                "assessments": [{
                    "claim_id": "claim-1",
                    "claim_text": "CVE-2024-3094.",
                    "assessment": "citation_unresolved",
                    "detail_assessments": [],
                    "evidence": [],
                    "reasons": ["No explicit citation mapping."],
                }],
                "errors": [],
            },
            "errors": [],
        })
        result = self._make_nightwatch_success()
        self.assertNotIn("source_records", result)

        handle_investigation(
            "CVE-2024-3094",
            research_func=MagicMock(return_value=result),
            blackbox_func=MagicMock(return_value=self._make_blackbox_result()),
            evidence_pipeline_func=mock_pipeline,
        )

        mock_pipeline.assert_called_once_with(result)
        self.assertTrue(any("citation_unresolved" in str(call)
                            for call in mock_markdown.call_args_list))

    @patch("streamlit.warning")
    @patch("streamlit.expander")
    @patch("streamlit.caption")
    @patch("streamlit.subheader")
    @patch("streamlit.markdown")
    @patch("streamlit.success")
    @patch("streamlit.spinner")
    def test_evidence_labels_are_not_presented_as_verification(
        self, mock_spinner, mock_success, mock_markdown, mock_subheader,
        mock_caption, mock_expander, mock_warning
    ):
        mock_expander.return_value.__enter__ = MagicMock(return_value=None)
        mock_expander.return_value.__exit__ = MagicMock(return_value=False)
        mock_pipeline = MagicMock(return_value={
            "status": "completed",
            "evidence_assessment": {
                "assessments": [{
                    "claim_id": "claim-1",
                    "claim_text": "A claim.",
                    "assessment": "partially_supported",
                    "detail_assessments": [],
                    "evidence": [],
                    "reasons": ["Partial evidence coverage."],
                }],
                "errors": [],
            },
            "errors": [],
        })

        handle_investigation(
            "CVE-2024-3094",
            research_func=MagicMock(return_value=self._make_nightwatch_success()),
            blackbox_func=MagicMock(return_value=self._make_blackbox_result()),
            evidence_pipeline_func=mock_pipeline,
        )

        rendered = " ".join(str(call) for call in mock_markdown.call_args_list)
        self.assertNotIn("verified", rendered.lower())
        captions = " ".join(str(call) for call in mock_caption.call_args_list)
        self.assertIn("not a final vulnerability verdict", captions)

    # ── Test: BlackBox must NOT be called on failed/incomplete results ────────

    @patch("streamlit.error")
    @patch("streamlit.spinner")
    def test_blackbox_not_called_on_api_error(self, mock_spinner, mock_error):
        """BlackBox must not be invoked when Nightwatch returns an API error."""
        mock_research = MagicMock(return_value={
            "success": False, "status": "error",
            "query": "CVE-2024-3094", "report": "",
            "sources": [], "run_id": None,
            "error": "Authentication failed (401 Unauthorized).",
        })
        mock_blackbox = MagicMock()

        handle_investigation(
            "CVE-2024-3094", "",
            research_func=mock_research,
            blackbox_func=mock_blackbox,
        )

        mock_blackbox.assert_not_called()

    @patch("streamlit.error")
    @patch("streamlit.spinner")
    def test_blackbox_not_called_on_timeout(self, mock_spinner, mock_error):
        """BlackBox must not be invoked when Nightwatch times out."""
        mock_research = MagicMock(return_value={
            "success": False, "status": "timeout",
            "query": "CVE-2024-3094", "report": "",
            "sources": [], "run_id": None,
            "error": "Research request timed out after 300.0 seconds.",
        })
        mock_blackbox = MagicMock()

        handle_investigation(
            "CVE-2024-3094", "",
            research_func=mock_research,
            blackbox_func=mock_blackbox,
        )

        mock_blackbox.assert_not_called()

    @patch("streamlit.subheader")
    @patch("streamlit.markdown")
    @patch("streamlit.warning")
    @patch("streamlit.spinner")
    def test_blackbox_not_called_on_empty_result(
        self, mock_spinner, mock_warning, mock_markdown, mock_subheader
    ):
        """BlackBox must not be invoked when Nightwatch returns an empty_result status."""
        mock_research = MagicMock(return_value={
            "success": False, "status": "empty_result",
            "query": "CVE-2024-3094", "report": "",
            "sources": [], "run_id": "run-empty", "error": "No content.",
        })
        mock_blackbox = MagicMock()

        handle_investigation(
            "CVE-2024-3094", "",
            research_func=mock_research,
            blackbox_func=mock_blackbox,
        )

        mock_blackbox.assert_not_called()

    @patch("streamlit.markdown")
    @patch("streamlit.warning")
    @patch("streamlit.spinner")
    def test_blackbox_not_called_on_incomplete_stream(
        self, mock_spinner, mock_warning, mock_markdown
    ):
        """BlackBox must not be invoked when the Nightwatch stream disconnects before completion."""
        mock_research = MagicMock(return_value={
            "success": False, "status": "incomplete",
            "query": "CVE-2024-3094",
            "report": "Partial findings so far...",
            "sources": [], "run_id": "run-inc",
            "error": "Stream disconnected.",
        })
        mock_blackbox = MagicMock()

        handle_investigation(
            "CVE-2024-3094", "",
            research_func=mock_research,
            blackbox_func=mock_blackbox,
        )

        mock_blackbox.assert_not_called()

    @patch("streamlit.warning")
    def test_blackbox_not_called_on_empty_vulnerability_input(self, mock_warning):
        """BlackBox must not be invoked when the user submits an empty vulnerability query."""
        mock_research = MagicMock()
        mock_blackbox = MagicMock()

        handle_investigation("", "", research_func=mock_research, blackbox_func=mock_blackbox)

        mock_research.assert_not_called()
        mock_blackbox.assert_not_called()


if __name__ == "__main__":
    unittest.main()
