"""Nightwatch Agent: Live-web cybersecurity research component for CERBERUS.

This module provides reusable functions to investigate vulnerabilities and CVEs
by interfacing with the TinyFish Deep Research API. It captures the final synthesized
report and source citations while providing structured error handling and security safeguards.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from dotenv import load_dotenv
import httpx

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
TINYFISH_RESEARCH_ENDPOINT = "https://agent.tinyfish.ai/v1/automation/run-research"
DEFAULT_RESEARCH_MODE = "standard"  # "standard" for fast analysis, "deep" for exhaustive
DEFAULT_TIMEOUT_SECONDS = 300.0     # 5-minute timeout window
SOURCE_METADATA_FIELDS = (
    "title",
    "snippet",
    "excerpt",
    "source_id",
    "citation_number",
)


def _has_source_value(value: Any) -> bool:
    """Return whether a source field contains useful, non-empty metadata."""
    return value is not None and (not isinstance(value, str) or bool(value.strip()))


def _add_source(
    source: Any,
    sources: List[str],
    source_records: List[Dict[str, Any]],
    source_indexes: Dict[str, int],
    event_metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """Add or merge a source while preserving metadata supplied by TinyFish."""
    source_data = dict(source) if isinstance(source, dict) else {}
    if event_metadata:
        for field in SOURCE_METADATA_FIELDS:
            if field not in source_data and field in event_metadata:
                source_data[field] = event_metadata[field]

    url = source_data.get("url") or source_data.get("source")
    if not isinstance(url, str) or not url.strip():
        return

    clean_url = url.strip()
    if clean_url not in source_indexes:
        source_indexes[clean_url] = len(source_records)
        sources.append(clean_url)
        record: Dict[str, Any] = {"url": clean_url}
        for field in SOURCE_METADATA_FIELDS:
            value = source_data.get(field)
            if _has_source_value(value):
                record[field] = value
        source_records.append(record)
        return

    record = source_records[source_indexes[clean_url]]
    for field in SOURCE_METADATA_FIELDS:
        if field not in record and _has_source_value(source_data.get(field)):
            record[field] = source_data[field]


def get_api_key(api_key: Optional[str] = None) -> Optional[str]:
    """Retrieve the TinyFish API key securely.

    Priority order:
    1. Explicit function argument
    2. OS environment variable (`TINYFISH_API_KEY`)
    3. Root `.env` file via `python-dotenv`

    Returns:
        str | None: The API key string, or None if not configured.
    """
    if api_key and api_key.strip():
        return api_key.strip()

    # Check already-loaded environment variables
    env_key = os.getenv("TINYFISH_API_KEY", "").strip()
    if env_key:
        return env_key

    # Attempt to load from the project root .env file
    root_dir = Path(__file__).resolve().parent.parent
    env_file = root_dir / ".env"
    if env_file.exists():
        load_dotenv(dotenv_path=env_file)
        env_key = os.getenv("TINYFISH_API_KEY", "").strip()
        if env_key:
            return env_key

    return None


def research_vulnerability(
    query: str,
    mode: str = DEFAULT_RESEARCH_MODE,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute live-web cybersecurity research on a vulnerability or CVE query.

    Args:
        query: The vulnerability name or CVE identifier (e.g. 'CVE-2024-3094').
        mode: The depth tier ('standard' or 'deep'). Defaults to 'standard'.
        timeout: Maximum duration in seconds to wait for stream completion.
        api_key: Optional API key override. If None, loaded from environment/.env.

    Returns:
        dict: A structured dictionary containing:
            - success (bool): True if completed successfully, False otherwise.
            - status (str): 'completed', 'incomplete', 'empty_result', 'timeout', or 'error'.
            - query (str): The investigated query string.
            - report (str): Full markdown synthesis report.
            - sources (list[str]): List of verified source URLs fetched by the agent.
            - source_records (list[dict]): Source URLs plus metadata emitted by TinyFish.
            - run_id (str | None): TinyFish research run identifier, if emitted.
            - error (str | None): Error description if failure occurred, else None.
    """
    clean_query = query.strip() if query else ""
    if not clean_query:
        return {
            "success": False,
            "status": "error",
            "query": "",
            "report": "",
            "sources": [],
            "source_records": [],
            "run_id": None,
            "error": "Query cannot be empty.",
        }

    resolved_key = get_api_key(api_key)
    if not resolved_key:
        return {
            "success": False,
            "status": "error",
            "query": clean_query,
            "report": "",
            "sources": [],
            "source_records": [],
            "run_id": None,
            "error": "TINYFISH_API_KEY is not configured. Please set it in your .env file.",
        }

    headers = {
        "X-API-Key": resolved_key,
        "Content-Type": "application/json",
    }

    payload = {
        "query": clean_query,
        "mode": mode,
        "stream": True,
    }

    report_chunks: List[str] = []
    sources: List[str] = []
    source_records: List[Dict[str, Any]] = []
    source_indexes: Dict[str, int] = {}
    run_id: Optional[str] = None
    stream_completed = False
    final_report_override: Optional[str] = None

    try:
        with httpx.stream(
            "POST",
            TINYFISH_RESEARCH_ENDPOINT,
            headers=headers,
            json=payload,
            timeout=timeout,
        ) as response:
            response.raise_for_status()

            for line in response.iter_lines():
                if not line or not line.startswith("data: "):
                    continue

                raw_data = line[6:].strip()
                if not raw_data:
                    continue

                try:
                    event_data = json.loads(raw_data)
                except json.JSONDecodeError:
                    continue

                if not isinstance(event_data, dict):
                    continue

                event_type = event_data.get("event")

                if event_type == "created":
                    raw_id = (
                        event_data.get("research_run_id")
                        or event_data.get("run_id")
                        or event_data.get("id")
                    )
                    if raw_id and isinstance(raw_id, str) and raw_id.strip():
                        run_id = raw_id.strip()
                    elif raw_id and isinstance(raw_id, int):
                        run_id = str(raw_id)

                elif event_type == "source_fetched":
                    source = event_data.get("source")
                    source_data = source if isinstance(source, dict) else {}
                    if "url" in event_data:
                        source_data = {**source_data, "url": event_data["url"]}
                    _add_source(
                        source_data or source,
                        sources,
                        source_records,
                        source_indexes,
                        event_data,
                    )

                elif event_type == "synthesis_delta":
                    delta = event_data.get("delta", "")
                    if delta:
                        report_chunks.append(delta)

                elif event_type == "final_result":
                    # Capture full report text from final_result if present
                    if "report" in event_data and isinstance(event_data["report"], str):
                        final_report_override = event_data["report"]
                    elif "markdown" in event_data and isinstance(event_data["markdown"], str):
                        final_report_override = event_data["markdown"]

                    # Capture any citations list emitted in final_result
                    extra_sources = event_data.get("sources") or event_data.get("citations")
                    if isinstance(extra_sources, list):
                        for item in extra_sources:
                            _add_source(
                                item,
                                sources,
                                source_records,
                                source_indexes,
                            )

                elif event_type == "done":
                    stream_completed = True
                    break

        # Select report content: a non-empty, non-whitespace final report override takes precedence;
        # otherwise use the joined accumulated report chunks if non-empty.
        if final_report_override and final_report_override.strip():
            assembled_report = final_report_override.strip()
        else:
            chunks_text = "".join(report_chunks)
            assembled_report = chunks_text if chunks_text.strip() else ""

        if not stream_completed:
            return {
                "success": False,
                "status": "incomplete",
                "query": clean_query,
                "report": assembled_report,
                "sources": sources,
                "source_records": source_records,
                "run_id": run_id,
                "error": "The research stream disconnected before receiving the completion ('done') event.",
            }

        if not assembled_report:
            return {
                "success": False,
                "status": "empty_result",
                "query": clean_query,
                "report": "",
                "sources": sources,
                "source_records": source_records,
                "run_id": run_id,
                "error": "Research stream completed, but no report content was generated.",
            }

        return {
            "success": True,
            "status": "completed",
            "query": clean_query,
            "report": assembled_report,
            "sources": sources,
            "source_records": source_records,
            "run_id": run_id,
            "error": None,
        }

    except httpx.HTTPStatusError as http_err:
        status_code = http_err.response.status_code
        if status_code == 401:
            err_msg = "Authentication failed (401 Unauthorized). Please verify your TINYFISH_API_KEY in .env."
        elif status_code == 429:
            err_msg = "Rate limit reached (429 Too Many Requests). Please retry later."
        elif status_code == 402:
            err_msg = "Payment required (402 Payment Required). TinyFish account credits depleted."
        elif status_code in (400, 422):
            err_msg = f"Invalid request rejected by TinyFish ({status_code}): {http_err.response.text}"
        elif status_code >= 500:
            err_msg = f"TinyFish server error ({status_code}). Please retry shortly."
        else:
            err_msg = f"HTTP error {status_code}: {http_err.response.text}"

        return {
            "success": False,
            "status": "error",
            "query": clean_query,
            "report": "".join(report_chunks),
            "sources": sources,
            "source_records": source_records,
            "run_id": run_id,
            "error": err_msg,
        }

    except httpx.TimeoutException:
        return {
            "success": False,
            "status": "timeout",
            "query": clean_query,
            "report": "".join(report_chunks),
            "sources": sources,
            "source_records": source_records,
            "run_id": run_id,
            "error": f"Research request timed out after {timeout} seconds.",
        }

    except httpx.RequestError as req_err:
        return {
            "success": False,
            "status": "error",
            "query": clean_query,
            "report": "".join(report_chunks),
            "sources": sources,
            "source_records": source_records,
            "run_id": run_id,
            "error": f"Network error connecting to TinyFish: {req_err}",
        }

    except Exception as exc:
        return {
            "success": False,
            "status": "error",
            "query": clean_query,
            "report": "".join(report_chunks),
            "sources": sources,
            "source_records": source_records,
            "run_id": run_id,
            "error": f"Unexpected error: {type(exc).__name__}: {exc}",
        }


if __name__ == "__main__":
    import sys

    # Quick interactive CLI test when executed directly
    sample_query = sys.argv[1] if len(sys.argv) > 1 else "CVE-2024-3094"
    print(f"Running Nightwatch on: {sample_query}...")
    result = research_vulnerability(sample_query)
    print("\nResult Summary:")
    print(f"  Success : {result['success']}")
    print(f"  Status  : {result['status']}")
    print(f"  Run ID  : {result['run_id']}")
    print(f"  Sources : {len(result['sources'])} found")
    if result["error"]:
        print(f"  Error   : {result['error']}")
    if result["report"]:
        print("\nReport Preview:")
        print(result["report"][:400] + ("..." if len(result["report"]) > 400 else ""))
