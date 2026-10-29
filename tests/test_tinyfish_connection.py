"""Test script for verifying connection to the TinyFish Deep Research API.

This script tests the research automation endpoint independently of the Streamlit
frontend, verifying credentials, network connectivity, and streaming response
handling using httpx.
"""

import json
import os
import sys
from pathlib import Path
from dotenv import load_dotenv
import httpx

# ---------------------------------------------------------------------------
# Configuration & Constants
# ---------------------------------------------------------------------------
ENDPOINT = "https://agent.tinyfish.ai/v1/automation/run-research"
TEST_QUERY = "What is CVE-2024-3094, what software does it affect, and what was the remediation?"
RESEARCH_MODE = "standard"  # "standard" provides fast verification; "deep" is exhaustive
TIMEOUT_SECONDS = 300.0     # 5-minute timeout window for standard research test


def load_credentials() -> str:
    """Load and validate the TinyFish API key from the root .env file.

    Returns:
        str: The loaded API key.

    Raises:
        SystemExit: If the .env file is missing or TINYFISH_API_KEY is not set.
    """
    root_dir = Path(__file__).resolve().parent.parent
    env_file = root_dir / ".env"

    if not env_file.exists():
        print(f"[ERROR] .env file not found at: {env_file}", file=sys.stderr)
        print("Please create a .env file with your TINYFISH_API_KEY before running this test.", file=sys.stderr)
        sys.exit(1)

    load_dotenv(dotenv_path=env_file)
    api_key = os.getenv("TINYFISH_API_KEY", "").strip()

    if not api_key:
        print("[ERROR] TINYFISH_API_KEY is empty or missing in .env file.", file=sys.stderr)
        print("Please add 'TINYFISH_API_KEY=your_key_here' to your .env file.", file=sys.stderr)
        sys.exit(1)

    print("[OK] TINYFISH_API_KEY is configured.")
    return api_key


def run_research_test() -> None:
    """Execute a single test query against the TinyFish Deep Research API."""
    api_key = load_credentials()

    headers = {
        "X-API-Key": api_key,
        "Content-Type": "application/json",
    }

    payload = {
        "query": TEST_QUERY,
        "mode": RESEARCH_MODE,
        "stream": True,
    }

    print("\n" + "=" * 60)
    print("CERBERUS — TinyFish Connection Test")
    print("=" * 60)
    print(f"Endpoint : {ENDPOINT}")
    print(f"Mode     : {RESEARCH_MODE}")
    print(f"Query    : {TEST_QUERY}")
    print(f"Streaming: True (Server-Sent Events)")
    print("-" * 60)
    print("[INFO] Submitting research request and awaiting response stream...\n")

    synthesis_started = False

    try:
        with httpx.stream(
            "POST",
            ENDPOINT,
            headers=headers,
            json=payload,
            timeout=TIMEOUT_SECONDS,
        ) as response:
            # Check for non-2xx HTTP status codes before consuming stream
            response.raise_for_status()

            for line in response.iter_lines():
                if not line or not line.startswith("data: "):
                    continue

                raw_data = line[6:].strip()
                if not raw_data:
                    continue

                try:
                    event_data = json.loads(raw_data)
                except json.JSONDecodeError as decode_err:
                    print(f"\n[WARN] Malformed JSON in SSE chunk: {decode_err} (raw: {raw_data[:80]})")
                    continue

                if not isinstance(event_data, dict):
                    continue

                event_type = event_data.get("event")

                # Handle specific documented SSE event types
                if event_type == "created":
                    run_id = event_data.get("research_run_id", "N/A")
                    print(f"[PROGRESS] Research task initiated. Run ID: {run_id}")

                elif event_type == "plan_updated":
                    print("[PROGRESS] Research plan formulated. Gathering web evidence...")

                elif event_type == "source_fetched":
                    source_url = event_data.get("url") or event_data.get("source", "source")
                    print(f"[PROGRESS] Evaluated source: {source_url}")

                elif event_type == "synthesis_delta":
                    if not synthesis_started:
                        print("\n" + "-" * 60)
                        print("[REPORT SYNTHESIS]")
                        print("-" * 60)
                        synthesis_started = True

                    delta_text = event_data.get("delta", "")
                    print(delta_text, end="", flush=True)

                elif event_type == "done":
                    print("\n\n" + "=" * 60)
                    print("[SUCCESS] Research stream concluded ('done' event received).")
                    print("=" * 60)
                    return

    except httpx.HTTPStatusError as http_err:
        status_code = http_err.response.status_code
        print(f"\n[HTTP ERROR] Status Code: {status_code}", file=sys.stderr)

        if status_code == 401:
            print("Resolution : 401 Unauthorized. Verify your TINYFISH_API_KEY in .env.", file=sys.stderr)
        elif status_code == 429:
            print("Resolution : 429 Too Many Requests. Daily limit or concurrency cap reached.", file=sys.stderr)
        elif status_code == 402:
            print("Resolution : 402 Payment Required. Account balance or credits depleted.", file=sys.stderr)
        elif status_code in (400, 422):
            print(f"Resolution : Request rejected. Response body: {http_err.response.text}", file=sys.stderr)
        elif status_code >= 500:
            print("Resolution : 5xx Server Error on TinyFish infrastructure. Retry shortly.", file=sys.stderr)
        else:
            print(f"Response body: {http_err.response.text}", file=sys.stderr)
        sys.exit(1)

    except httpx.TimeoutException:
        print(f"\n[TIMEOUT] Request exceeded {TIMEOUT_SECONDS}s without completion.", file=sys.stderr)
        print("Resolution: Deep research queries may require a higher timeout threshold.", file=sys.stderr)
        sys.exit(1)

    except httpx.RequestError as req_err:
        print(f"\n[NETWORK ERROR] Failed to connect to {ENDPOINT}: {req_err}", file=sys.stderr)
        print("Resolution: Check your internet connection or firewall/proxy settings.", file=sys.stderr)
        sys.exit(1)

    except Exception as err:
        print(f"\n[UNEXPECTED ERROR] {type(err).__name__}: {err}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    run_research_test()
