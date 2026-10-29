"""Phoenix Agent: bounded failure recovery for CERBERUS research runs."""

import re
import time
from typing import Any, Callable, Dict

from agents.nightwatch import research_vulnerability


DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_BACKOFF_SECONDS = 1.0
MAX_BACKOFF_SECONDS = 30.0

ResearchFunction = Callable[..., Dict[str, Any]]
SleepFunction = Callable[[float], None]


def _is_retryable_result(result: Any) -> bool:
    """Return whether a Nightwatch result represents an observable transient failure."""
    if not isinstance(result, dict):
        return False

    status = result.get("status")
    error = result.get("error")
    error_text = error.lower() if isinstance(error, str) else ""

    if status in {"timeout", "incomplete"}:
        return True

    if status != "error":
        return False

    if "network error connecting to tinyfish" in error_text:
        return True
    if "rate limit reached (429" in error_text:
        return True
    if re.search(r"tinyfish server error \(5\d\d\)", error_text):
        return True

    return False


def phoenix_research(
    query: str,
    research_func: ResearchFunction = research_vulnerability,
    sleep_func: SleepFunction = time.sleep,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    backoff_seconds: float = DEFAULT_BACKOFF_SECONDS,
    max_backoff_seconds: float = MAX_BACKOFF_SECONDS,
) -> Dict[str, Any]:
    """Run Nightwatch with bounded retries for observable transient failures.

    Nightwatch currently does not expose response headers, so Retry-After cannot
    be honored here. Delays use bounded exponential backoff instead.
    """
    if max_attempts < 1:
        raise ValueError("max_attempts must be at least 1.")
    if backoff_seconds < 0:
        raise ValueError("backoff_seconds cannot be negative.")
    if max_backoff_seconds < 0:
        raise ValueError("max_backoff_seconds cannot be negative.")

    for attempt in range(max_attempts):
        result = research_func(query=query)
        if not _is_retryable_result(result) or attempt == max_attempts - 1:
            return result

        delay = min(
            backoff_seconds * (2**attempt),
            max_backoff_seconds,
        )
        sleep_func(delay)

    raise RuntimeError("Phoenix exited without returning a research result.")
