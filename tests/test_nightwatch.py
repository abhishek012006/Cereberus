"""Unit tests for the Nightwatch Agent (agents/nightwatch.py).

These tests use mocked HTTP streaming responses via unittest.mock, ensuring
fast, deterministic test execution without needing live API calls or consuming credits.
"""

import sys
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch

# Ensure root directory is on sys.path for direct script execution
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx
from agents.nightwatch import research_vulnerability, get_api_key


class TestNightwatchAgent(unittest.TestCase):
    """Test suite for research_vulnerability and helper functions."""

    def test_empty_query_returns_error(self):
        """Verify that an empty or whitespace-only query returns an immediate error."""
        result = research_vulnerability("")
        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error"], "Query cannot be empty.")
        self.assertEqual(result["sources"], [])
        self.assertEqual(result["source_records"], [])
        self.assertEqual(result["report"], "")

        # Whitespace only
        result_ws = research_vulnerability("   \t\n  ")
        self.assertFalse(result_ws["success"])
        self.assertEqual(result_ws["status"], "error")
        self.assertEqual(result_ws["error"], "Query cannot be empty.")

    @patch("agents.nightwatch.get_api_key", return_value=None)
    def test_missing_api_key_returns_error(self, _mock_key):
        """Verify that missing API key returns a clear error without crashing."""
        result = research_vulnerability("CVE-2024-3094")
        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "error")
        self.assertIn("TINYFISH_API_KEY is not configured", result["error"])
        self.assertEqual(result["source_records"], [])

    @patch("agents.nightwatch.get_api_key", return_value="dummy-key-for-test")
    @patch("httpx.stream")
    def test_successful_research_stream(self, mock_stream, _mock_key):
        """Verify full end-to-end assembly of a successful research stream."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.iter_lines.return_value = [
            'data: {"event": "created", "research_run_id": "run-test-abc-123"}',
            'data: {"event": "plan_updated", "plan": "Searching NIST and GitHub"}',
            'data: {"event": "source_fetched", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-3094"}',
            'data: {"event": "source_fetched", "url": "https://www.cisa.gov/news-events/alerts/2024/03/29"}',
            'data: {"event": "synthesis_delta", "delta": "# CVE-2024-3094 Summary\\n\\n"}',
            'data: {"event": "synthesis_delta", "delta": "A backdoor was discovered in upstream XZ Utils."}',
            'data: {"event": "done"}',
        ]
        mock_stream.return_value.__enter__.return_value = mock_response

        result = research_vulnerability("CVE-2024-3094")

        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["query"], "CVE-2024-3094")
        self.assertEqual(result["run_id"], "run-test-abc-123")
        self.assertIn("# CVE-2024-3094 Summary", result["report"])
        self.assertIn("A backdoor was discovered in upstream XZ Utils.", result["report"])
        self.assertEqual(len(result["sources"]), 2)
        self.assertIn("https://nvd.nist.gov/vuln/detail/CVE-2024-3094", result["sources"])
        self.assertIn("https://www.cisa.gov/news-events/alerts/2024/03/29", result["sources"])
        self.assertEqual(
            result["source_records"],
            [
                {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-3094"},
                {"url": "https://www.cisa.gov/news-events/alerts/2024/03/29"},
            ],
        )
        self.assertIsNone(result["error"])

    @patch("agents.nightwatch.get_api_key", return_value="dummy-key-for-test")
    @patch("httpx.stream")
    def test_source_deduplication(self, mock_stream, _mock_key):
        """Verify that duplicate source URLs emitted by TinyFish are deduplicated."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.iter_lines.return_value = [
            'data: {"event": "source_fetched", "url": "https://example.com/advisory"}',
            'data: {"event": "source_fetched", "url": "https://example.com/advisory"}',
            'data: {"event": "source_fetched", "url": "https://example.com/patch"}',
            'data: {"event": "synthesis_delta", "delta": "Report text."}',
            'data: {"event": "done"}',
        ]
        mock_stream.return_value.__enter__.return_value = mock_response

        result = research_vulnerability("Log4Shell")

        self.assertTrue(result["success"])
        self.assertEqual(result["sources"], [
            "https://example.com/advisory",
            "https://example.com/patch",
        ])
        self.assertEqual(len(result["source_records"]), 2)

    def test_url_only_source_event_preserves_backward_compatible_fields(self):
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.iter_lines.return_value = [
            'data: {"event": "source_fetched", "url": "https://example.com/advisory"}',
            'data: {"event": "synthesis_delta", "delta": "Report [1]."}',
            'data: {"event": "done"}',
        ]
        mock_stream = MagicMock()
        mock_stream.__enter__.return_value = mock_response

        with patch("agents.nightwatch.get_api_key", return_value="dummy-key"), patch(
            "httpx.stream", return_value=mock_stream
        ):
            result = research_vulnerability("CVE-2024-3094")

        self.assertEqual(result["sources"], ["https://example.com/advisory"])
        self.assertEqual(result["source_records"], [{"url": "https://example.com/advisory"}])
        self.assertEqual(result["report"], "Report [1].")

    @patch("agents.nightwatch.get_api_key", return_value="dummy-key-for-test")
    @patch("httpx.stream")
    def test_source_metadata_is_preserved(self, mock_stream, _mock_key):
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.iter_lines.return_value = [
            'data: {"event": "source_fetched", "url": "https://example.com/advisory", "title": "Advisory", "snippet": "Summary", "source_id": "src-1", "citation_number": 1}',
            'data: {"event": "synthesis_delta", "delta": "Report text."}',
            'data: {"event": "done"}',
        ]
        mock_stream.return_value.__enter__.return_value = mock_response

        result = research_vulnerability("CVE-2024-3094")

        self.assertEqual(result["source_records"], [{
            "url": "https://example.com/advisory",
            "title": "Advisory",
            "snippet": "Summary",
            "source_id": "src-1",
            "citation_number": 1,
        }])

    @patch("agents.nightwatch.get_api_key", return_value="dummy-key-for-test")
    @patch("httpx.stream")
    def test_duplicate_source_metadata_is_merged(self, mock_stream, _mock_key):
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.iter_lines.return_value = [
            'data: {"event": "source_fetched", "url": "https://example.com/advisory", "title": "Advisory"}',
            'data: {"event": "source_fetched", "url": "https://example.com/advisory", "excerpt": "Evidence", "source_id": "src-1"}',
            'data: {"event": "synthesis_delta", "delta": "Report text."}',
            'data: {"event": "done"}',
        ]
        mock_stream.return_value.__enter__.return_value = mock_response

        result = research_vulnerability("CVE-2024-3094")

        self.assertEqual(result["sources"], ["https://example.com/advisory"])
        self.assertEqual(result["source_records"], [{
            "url": "https://example.com/advisory",
            "title": "Advisory",
            "excerpt": "Evidence",
            "source_id": "src-1",
        }])

    def test_missing_citation_number_is_preserved_as_missing(self):
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.iter_lines.return_value = [
            'data: {"event": "source_fetched", "url": "https://example.com/a"}',
            'data: {"event": "synthesis_delta", "delta": "Report [1]."}',
            'data: {"event": "done"}',
        ]
        mock_stream = MagicMock()
        mock_stream.__enter__.return_value = mock_response

        with patch("agents.nightwatch.get_api_key", return_value="dummy-key"), patch(
            "httpx.stream", return_value=mock_stream
        ):
            result = research_vulnerability("CVE-2024-3094")

        self.assertEqual(result["source_records"], [{"url": "https://example.com/a"}])
        self.assertNotIn("citation_number", result["source_records"][0])

    def test_conflicting_citation_numbers_are_not_rewritten(self):
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.iter_lines.return_value = [
            'data: {"event": "source_fetched", "url": "https://example.com/a", "citation_number": 1}',
            'data: {"event": "source_fetched", "url": "https://example.com/b", "citation_number": 1}',
            'data: {"event": "synthesis_delta", "delta": "Report [1]."}',
            'data: {"event": "done"}',
        ]
        mock_stream = MagicMock()
        mock_stream.__enter__.return_value = mock_response

        with patch("agents.nightwatch.get_api_key", return_value="dummy-key"), patch(
            "httpx.stream", return_value=mock_stream
        ):
            result = research_vulnerability("CVE-2024-3094")

        self.assertEqual(
            [record["citation_number"] for record in result["source_records"]],
            [1, 1],
        )

    @patch("agents.nightwatch.get_api_key", return_value="dummy-key-for-test")
    @patch("httpx.stream")
    def test_final_result_citations_preserve_metadata_and_missing_fields(self, mock_stream, _mock_key):
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.iter_lines.return_value = [
            'data: {"event": "final_result", "report": "Report [1] [2].", "citations": [{"url": "https://example.com/one", "title": "One", "citation_number": 1}, {"url": "https://example.com/two"}]}',
            'data: {"event": "done"}',
        ]
        mock_stream.return_value.__enter__.return_value = mock_response

        result = research_vulnerability("CVE-2024-3094")

        self.assertEqual(result["sources"], [
            "https://example.com/one",
            "https://example.com/two",
        ])
        self.assertEqual(result["source_records"], [
            {"url": "https://example.com/one", "title": "One", "citation_number": 1},
            {"url": "https://example.com/two"},
        ])
        self.assertEqual(result["report"], "Report [1] [2].")

    @patch("agents.nightwatch.get_api_key", return_value="dummy-key-for-test")
    @patch("httpx.stream")
    def test_error_result_includes_source_records(self, mock_stream, _mock_key):
        mock_stream.return_value.__enter__.side_effect = httpx.TimeoutException("Read timed out")

        result = research_vulnerability("CVE-2024-3094")

        self.assertEqual(result["status"], "timeout")
        self.assertIn("source_records", result)
        self.assertEqual(result["source_records"], [])

    @patch("agents.nightwatch.get_api_key", return_value="dummy-key-for-test")
    @patch("httpx.stream")
    def test_unexpected_error_result_includes_source_records(self, mock_stream, _mock_key):
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = RuntimeError("unexpected failure")
        mock_stream.return_value.__enter__.return_value = mock_response

        result = research_vulnerability("CVE-2024-3094")

        self.assertEqual(result["status"], "error")
        self.assertIn("source_records", result)
        self.assertEqual(result["source_records"], [])

    @patch("agents.nightwatch.get_api_key", return_value="dummy-key-for-test")
    @patch("httpx.stream")
    def test_http_401_unauthorized(self, mock_stream, _mock_key):
        """Verify handling of 401 Unauthorized API error."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = '{"error": "Invalid API key"}'
        mock_error = httpx.HTTPStatusError(
            message="401 Unauthorized",
            request=MagicMock(),
            response=mock_response,
        )
        mock_stream.return_value.__enter__.side_effect = mock_error

        result = research_vulnerability("Spring4Shell")

        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "error")
        self.assertIn("401 Unauthorized", result["error"])

    @patch("agents.nightwatch.get_api_key", return_value="dummy-key-for-test")
    @patch("httpx.stream")
    def test_http_429_rate_limit(self, mock_stream, _mock_key):
        """Verify handling of 429 Too Many Requests."""
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.text = '{"error": "Rate limit exceeded"}'
        mock_error = httpx.HTTPStatusError(
            message="429 Too Many Requests",
            request=MagicMock(),
            response=mock_response,
        )
        mock_stream.return_value.__enter__.side_effect = mock_error

        result = research_vulnerability("Log4Shell")

        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "error")
        self.assertIn("429 Too Many Requests", result["error"])

    @patch("agents.nightwatch.get_api_key", return_value="dummy-key-for-test")
    @patch("httpx.stream")
    def test_timeout_exception(self, mock_stream, _mock_key):
        """Verify handling of socket read timeouts."""
        mock_stream.return_value.__enter__.side_effect = httpx.TimeoutException("Read timed out")

        result = research_vulnerability("CVE-2023-4863", timeout=10.0)

        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "timeout")
        self.assertIn("timed out after 10.0 seconds", result["error"])

    @patch("agents.nightwatch.get_api_key", return_value="dummy-key-for-test")
    @patch("httpx.stream")
    def test_network_connection_error(self, mock_stream, _mock_key):
        """Verify handling of network-level connection drops."""
        mock_stream.return_value.__enter__.side_effect = httpx.ConnectError("Failed to connect to host")

        result = research_vulnerability("CVE-2023-4863")

        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "error")
        self.assertIn("Network error connecting to TinyFish", result["error"])

    @patch("agents.nightwatch.get_api_key", return_value="dummy-key-for-test")
    @patch("httpx.stream")
    def test_incomplete_stream_without_done(self, mock_stream, _mock_key):
        """Verify behavior when connection closes prematurely without a 'done' event."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.iter_lines.return_value = [
            'data: {"event": "created", "research_run_id": "run-cut-short"}',
            'data: {"event": "synthesis_delta", "delta": "Partial research notes..."}',
            # Stream disconnects here without emitting 'done'
        ]
        mock_stream.return_value.__enter__.return_value = mock_response

        result = research_vulnerability("Heartbleed")

        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["report"], "Partial research notes...")
        self.assertIn("stream disconnected", result["error"])

    @patch("agents.nightwatch.get_api_key", return_value="dummy-key-for-test")
    @patch("httpx.stream")
    def test_run_id_fallbacks(self, mock_stream, _mock_key):
        """Verify fallback handling for alternative run ID fields (run_id, id, or none)."""
        # Case 1: alternative field 'run_id'
        mock_resp1 = MagicMock()
        mock_resp1.raise_for_status = MagicMock()
        mock_resp1.iter_lines.return_value = [
            'data: {"event": "created", "run_id": "alt-run-id-999"}',
            'data: {"event": "synthesis_delta", "delta": "Analysis text."}',
            'data: {"event": "done"}',
        ]
        mock_stream.return_value.__enter__.return_value = mock_resp1

        res1 = research_vulnerability("CVE-2024-3094")
        self.assertEqual(res1["run_id"], "alt-run-id-999")

        # Case 2: alternative field 'id'
        mock_resp2 = MagicMock()
        mock_resp2.raise_for_status = MagicMock()
        mock_resp2.iter_lines.return_value = [
            'data: {"event": "created", "id": "id-only-555"}',
            'data: {"event": "synthesis_delta", "delta": "Analysis text."}',
            'data: {"event": "done"}',
        ]
        mock_stream.return_value.__enter__.return_value = mock_resp2

        res2 = research_vulnerability("CVE-2024-3094")
        self.assertEqual(res2["run_id"], "id-only-555")

        # Case 3: no ID returned at all (do not invent one)
        mock_resp3 = MagicMock()
        mock_resp3.raise_for_status = MagicMock()
        mock_resp3.iter_lines.return_value = [
            'data: {"event": "created"}',
            'data: {"event": "synthesis_delta", "delta": "Analysis text."}',
            'data: {"event": "done"}',
        ]
        mock_stream.return_value.__enter__.return_value = mock_resp3

        res3 = research_vulnerability("CVE-2024-3094")
        self.assertIsNone(res3["run_id"])

    @patch("agents.nightwatch.get_api_key", return_value="dummy-key-for-test")
    @patch("httpx.stream")
    def test_empty_final_result_falls_back_to_deltas(self, mock_stream, _mock_key):
        """Verify that an empty/whitespace final_result override does not wipe out accumulated deltas."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.iter_lines.return_value = [
            'data: {"event": "synthesis_delta", "delta": "Good content from deltas."}',
            'data: {"event": "final_result", "report": "   "}',
            'data: {"event": "done"}',
        ]
        mock_stream.return_value.__enter__.return_value = mock_response

        result = research_vulnerability("CVE-2024-3094")
        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["report"], "Good content from deltas.")

    @patch("agents.nightwatch.get_api_key", return_value="dummy-key-for-test")
    @patch("httpx.stream")
    def test_non_empty_final_result_takes_precedence(self, mock_stream, _mock_key):
        """Verify that non-empty final_result override takes precedence over draft deltas."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.iter_lines.return_value = [
            'data: {"event": "synthesis_delta", "delta": "Draft deltas."}',
            'data: {"event": "final_result", "report": "# Complete Polished Report"}',
            'data: {"event": "done"}',
        ]
        mock_stream.return_value.__enter__.return_value = mock_response

        result = research_vulnerability("CVE-2024-3094")
        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["report"], "# Complete Polished Report")

    @patch("agents.nightwatch.get_api_key", return_value="dummy-key-for-test")
    @patch("httpx.stream")
    def test_empty_report_returns_empty_result_status(self, mock_stream, _mock_key):
        """Verify that a stream with neither deltas nor final report returns an explicit empty_result status."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.iter_lines.return_value = [
            'data: {"event": "created", "research_run_id": "run-empty-1"}',
            'data: {"event": "source_fetched", "url": "https://example.com"}',
            'data: {"event": "final_result", "report": ""}',
            'data: {"event": "done"}',
        ]
        mock_stream.return_value.__enter__.return_value = mock_response

        result = research_vulnerability("CVE-2024-3094")
        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "empty_result")
        self.assertEqual(result["report"], "")
        self.assertEqual(result["run_id"], "run-empty-1")
        self.assertEqual(result["sources"], ["https://example.com"])
        self.assertIn("no report content was generated", result["error"])


if __name__ == "__main__":
    unittest.main()
