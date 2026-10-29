"""Unit tests for the Phoenix bounded recovery layer."""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.phoenix import phoenix_research


def result(status="error", error="failure", success=False, report="", sources=None, run_id=None):
    return {
        "success": success,
        "status": status,
        "query": "CVE-2024-3094",
        "report": report,
        "sources": sources or [],
        "run_id": run_id,
        "error": error,
    }


class TestPhoenixAgent(unittest.TestCase):
    def test_first_attempt_success(self):
        research = MagicMock(return_value=result("completed", None, True, "report"))
        sleep = MagicMock()

        actual = phoenix_research("CVE-2024-3094", research, sleep)

        self.assertEqual(actual["status"], "completed")
        research.assert_called_once_with(query="CVE-2024-3094")
        sleep.assert_not_called()

    def test_transient_failure_followed_by_success(self):
        research = MagicMock(side_effect=[
            result(error="Network error connecting to TinyFish: connection reset"),
            result("completed", None, True, "final report", ["https://cisa.gov/advisory"], "run-2"),
        ])
        sleep = MagicMock()

        actual = phoenix_research("CVE-2024-3094", research, sleep)

        self.assertEqual(actual["report"], "final report")
        self.assertEqual(research.call_count, 2)
        sleep.assert_called_once_with(1.0)

    def test_retries_exhausted_returns_last_result(self):
        final = result(error="TinyFish server error (503). Please retry shortly.")
        research = MagicMock(return_value=final)
        sleep = MagicMock()

        actual = phoenix_research("CVE-2024-3094", research, sleep, max_attempts=3)

        self.assertIs(actual, final)
        self.assertEqual(research.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_permanent_errors_are_not_retried(self):
        for error in (
            "TINYFISH_API_KEY is not configured.",
            "Invalid request rejected by TinyFish (400): bad request",
            "Authentication failed (401 Unauthorized).",
            "Payment required (402 Payment Required).",
            "Invalid request rejected by TinyFish (422): invalid",
            "Query cannot be empty.",
            "unclassified failure",
        ):
            with self.subTest(error=error):
                research = MagicMock(return_value=result(error=error))
                sleep = MagicMock()

                phoenix_research("CVE-2024-3094", research, sleep)

                research.assert_called_once()
                sleep.assert_not_called()

    def test_retryable_http_statuses(self):
        for error in (
            "Rate limit reached (429 Too Many Requests). Please retry later.",
            "TinyFish server error (500). Please retry shortly.",
            "TinyFish server error (503). Please retry shortly.",
        ):
            with self.subTest(error=error):
                research = MagicMock(side_effect=[
                    result(error=error),
                    result("completed", None, True, "report"),
                ])
                sleep = MagicMock()

                actual = phoenix_research("CVE-2024-3094", research, sleep)

                self.assertTrue(actual["success"])
                self.assertEqual(research.call_count, 2)
                sleep.assert_called_once_with(1.0)

    def test_timeout_and_incomplete_results_are_retried(self):
        for status in ("timeout", "incomplete"):
            with self.subTest(status=status):
                research = MagicMock(side_effect=[
                    result(status=status, error="temporary"),
                    result("completed", None, True, "report"),
                ])
                sleep = MagicMock()

                phoenix_research("CVE-2024-3094", research, sleep)

                self.assertEqual(research.call_count, 2)
                sleep.assert_called_once_with(1.0)

    def test_attempt_limit_and_exponential_backoff(self):
        research = MagicMock(return_value=result(status="timeout", error="temporary"))
        sleep = MagicMock()

        phoenix_research(
            "CVE-2024-3094",
            research,
            sleep,
            max_attempts=4,
            backoff_seconds=2.0,
            max_backoff_seconds=100.0,
        )

        self.assertEqual(research.call_count, 4)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [2.0, 4.0, 8.0])

    def test_backoff_is_capped_and_no_sleep_follows_last_attempt(self):
        research = MagicMock(return_value=result(status="timeout", error="temporary"))
        sleep = MagicMock()

        phoenix_research(
            "CVE-2024-3094",
            research,
            sleep,
            max_attempts=3,
            backoff_seconds=4.0,
            max_backoff_seconds=5.0,
        )

        self.assertEqual([call.args[0] for call in sleep.call_args_list], [4.0, 5.0])
        self.assertEqual(sleep.call_count, research.call_count - 1)

    def test_invalid_attempt_configuration_is_rejected(self):
        with self.assertRaises(ValueError):
            phoenix_research("CVE-2024-3094", max_attempts=0)


if __name__ == "__main__":
    unittest.main()
