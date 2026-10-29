"""Live integration test for Nightwatch Agent (agents/nightwatch.py).

This script performs an actual end-to-end integration test against the TinyFish
Deep Research API using credentials loaded from the root .env file.
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Ensure the project root directory is on sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from agents.nightwatch import research_vulnerability, get_api_key

# Target query specified for live research verification
LIVE_QUERY = (
    "Explain the XZ Utils backdoor vulnerability, affected versions, "
    "and official remediation. Prioritize authoritative sources."
)


def verify_credentials() -> str:
    """Check that the API key exists in .env without printing it.

    Returns:
        str: The retrieved API key.

    Raises:
        SystemExit: If .env is missing or the key is not set.
    """
    env_path = ROOT_DIR / ".env"
    if not env_path.exists():
        print(f"[ERROR] Missing .env file at {env_path}", file=sys.stderr)
        print("Please create .env with TINYFISH_API_KEY before running this live test.", file=sys.stderr)
        sys.exit(1)

    load_dotenv(dotenv_path=env_path)
    api_key = get_api_key()

    if not api_key:
        print("[ERROR] TINYFISH_API_KEY is not set or empty in .env.", file=sys.stderr)
        sys.exit(1)

    print("[OK] TINYFISH_API_KEY is configured.")
    return api_key


def run_live_test() -> None:
    """Execute live vulnerability research through Nightwatch and display findings."""
    print("=" * 70)
    print("CERBERUS — Nightwatch Live Integration Test")
    print("=" * 70)

    # 1. Verify credentials securely
    verify_credentials()

    print(f"Query: \"{LIVE_QUERY}\"")
    print("Sending live request to TinyFish research engine (standard mode)...")
    print("Awaiting research synthesis. Please wait...\n")

    # 2. Call the existing research_vulnerability interface
    result = research_vulnerability(
        query=LIVE_QUERY,
        mode="standard",
    )

    status = result.get("status")
    success = result.get("success")
    run_id = result.get("run_id")
    report = result.get("report", "")
    sources = result.get("sources", [])
    error = result.get("error")

    print("\n" + "=" * 70)
    print("RESEARCH OUTCOME")
    print("=" * 70)
    print(f"Status   : {status}")
    print(f"Success  : {success}")
    print(f"Run ID   : {run_id or 'N/A'}")
    print(f"Sources  : {len(sources)} discovered")

    # 3. Clearly distinguish outcome categories
    if status == "completed" and success:
        print("\n[RESULT CATEGORY: SUCCESSFUL RESEARCH COMPLETED]")
        print("-" * 70)
        print("FINAL SYNTHESIS REPORT:")
        print("-" * 70)
        print(report)

        if sources:
            print("\n" + "-" * 70)
            print("AUTHORITATIVE SOURCES & CITATIONS:")
            print("-" * 70)
            for idx, source_url in enumerate(sources, start=1):
                print(f"  [{idx}] {source_url}")
        else:
            print("\n[NOTE] No separate source URLs were parsed in the output structure.")

    elif status == "empty_result":
        print("\n[RESULT CATEGORY: COMPLETED TASK WITH EMPTY RESULT]")
        print("The research task completed, but the engine returned no synthesized report text.")
        if error:
            print(f"Detail: {error}")
        if sources:
            print("\nSources found before empty conclusion:")
            for s in sources:
                print(f" - {s}")

    elif status == "incomplete":
        print("\n[RESULT CATEGORY: INCOMPLETE / INTERRUPTED STREAM]")
        print("The stream disconnected before receiving the completion event.")
        if error:
            print(f"Detail: {error}")
        if report:
            print("\nPartial Report Gathered:")
            print(report)

    elif status == "timeout":
        print("\n[RESULT CATEGORY: REQUEST TIMEOUT]")
        print(f"The request exceeded the timeout threshold without completion.")
        if error:
            print(f"Detail: {error}")

    else:
        # Generic or HTTP failure
        print("\n[RESULT CATEGORY: FAILED REQUEST / API ERROR]")
        print(f"Error Description: {error}")

    print("=" * 70)


if __name__ == "__main__":
    run_live_test()
