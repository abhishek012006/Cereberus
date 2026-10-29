# CERBERUS — AI Cybersecurity Investigation

An AI-powered cybersecurity investigation application designed to analyze vulnerabilities, cross-reference security intelligence, and evaluate software exposure.

> **Status:** Streamlit application with TinyFish-backed research, deterministic BlackBox checks, and local evidence assessment.

---

## Project Structure

```text
CERBERUS/
├── app.py              # Streamlit UI entrypoint
├── requirements.txt    # Project dependencies
├── .gitignore          # Git exclusion rules
├── .env.example        # Placeholder environment configuration
├── README.md           # Setup and usage guide
├── agents/             # Research, retrieval, and evidence pipeline modules
│   └── *.py
├── core/               # Core business logic and shared utilities
│   └── __init__.py
├── tests/              # Offline regression and integration tests
│   └── test_*.py
└── data/               # Local data and cache store
    └── .gitkeep
```

---

## Setup Instructions

### 1. Prerequisites
- Python 3.10 or higher
- PowerShell, Command Prompt, or Bash

### 2. Virtual Environment Setup

A virtual environment (`.venv`) is recommended.

**Windows (PowerShell):**
```powershell
# Create virtual environment (if not already created)
python -m venv .venv

# Activate virtual environment
.venv\Scripts\Activate.ps1
```

*(If script execution is restricted in PowerShell, run `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process` first)*

### 3. Install Dependencies

Install the core dependencies:

```powershell
pip install -r requirements.txt
```

### 4. Environment Configuration

Copy `.env.example` to create your local `.env` file:

```powershell
Copy-Item .env.example .env
```

`TINYFISH_API_KEY` is required to run an investigation. The application can start
without it, but research requests will report a configuration error. The other
keys are reserved configuration placeholders and are not required by the current
launch path.

---

## Launching the Application

Run the Streamlit app:

```powershell
streamlit run app.py
```

The application will launch in your default browser at `http://localhost:8501`.

To verify startup without making a research request, bind Streamlit to loopback:

```powershell
streamlit run app.py --server.address 127.0.0.1 --server.port 8501 --server.headless true
```

### Running tests

Run the established offline test suite from the project root:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py" -v
```

The repository also retains this valid pytest command:

```powershell
python -m pytest -q
```

`tests/test_nightwatch_live.py` and `tests/test_tinyfish_connection.py` are
manual/live checks, not offline tests. They must not run in offline CI and may
require TinyFish credentials and network access.

---

## Hackathon Demo Runbook

This runbook describes the implemented workflow only. CERBERUS does not claim
that a report or candidate passage is a factual vulnerability verdict.

### Pre-demo checks

From the project root, use the project virtual environment:

```powershell
.\.venv\Scripts\Activate.ps1
python --version
python -m pip check
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py" -v
```

The test suite is offline. Do not run `tests/test_nightwatch_live.py` or
`tests/test_tinyfish_connection.py` during a rehearsal or offline CI run.
Those scripts are live checks and should only be used when network access and
the required credentials are explicitly available.

### Configure the API key safely

Create the local configuration file, then edit it without printing its contents:

```powershell
Copy-Item .env.example .env
notepad .env
```

Set `TINYFISH_API_KEY` to the supplied TinyFish key. Keep `.env` local; it is
excluded by `.gitignore`. Do not paste the key into a terminal transcript,
screen share, source file, or issue. A missing key does not prevent the UI from
starting, but an investigation will return a configuration error.

### Start and stop the application

Start Streamlit from the project root:

```powershell
python -m streamlit run app.py
```

Open the displayed local URL, normally `http://localhost:8501`. To bind only
to the local machine and avoid a browser opening automatically:

```powershell
python -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501 --server.headless true
```

Stop the app with `Ctrl+C` in the terminal running Streamlit.

### Suggested demonstration flow

1. Enter a concrete CVE or vulnerability name, such as `CVE-2024-3094`.
2. Optionally enter the affected software and version, such as `XZ Utils 5.6.0`.
3. Select **Investigate** once and wait for the Nightwatch progress indicator.
4. Show the completed research report and its source links.
5. Explain that BlackBox performs structural quality checks and domain
   heuristics; its quality result does not verify factual claims.
6. Open **Evidence Assessment** and show claim-level candidate passages,
   citation numbers, original source URLs, redirects, and any unresolved or
   ambiguous citations.
7. Point out that retrieval failures remain visible and do not become evidence.

### What the workflow does

- Phoenix calls Nightwatch and retries only bounded, observable transient
  failures: timeouts, incomplete streams, network errors, rate limits, and
  recognized TinyFish server errors.
- Nightwatch converts TinyFish stream events into a completed report, source
  records, citation metadata, and a structured status.
- BlackBox checks report structure, source URL syntax, and domain heuristics.
- The evidence pipeline extracts claims, retrieves source text, matches
  candidate passages, and reports conservative text-level assessments.
- Candidate evidence is not proof of factual truth, and BlackBox does not
  implement factual claim verification.

### If the live request fails

- **Missing or invalid key:** confirm `TINYFISH_API_KEY` is set in `.env`
  without displaying it, then restart Streamlit.
- **Timeout or incomplete stream:** Phoenix retries within its configured
  attempt limit. Wait for the final status; do not repeatedly click
  **Investigate**.
- **Rate limit or depleted credits:** stop retrying, wait for the service
  window or restore credits, and use the offline test suite as the fallback
  demonstration.
- **No report or no sources:** explain that the result is surfaced as empty or
  incomplete; CERBERUS does not fabricate findings or citations.
- **Partial source failure:** show that successful candidate evidence remains
  available while the failed source is reported separately.
- **Evidence-pipeline failure:** the original research report and BlackBox
  output remain visible; the UI labels evidence assessment as unavailable.

### Two-minute judge-facing narrative

> CERBERUS helps an analyst investigate a vulnerability without turning a
> search result into an unsupported verdict. The analyst enters a CVE and,
> optionally, a software version. TinyFish is the core research engine:
> Nightwatch streams the research report and source citations, while Phoenix
> provides bounded recovery for transient failures.
>
> Once the report is complete, CERBERUS shows the report and preserves each
> source record and citation. BlackBox then performs deterministic structural
> checks, such as report completeness and source-domain heuristics. Those
> checks describe research quality; they do not prove that the report's claims
> are true.
>
> The evidence pipeline extracts claims, retrieves source text under the
> retriever's security controls, and displays candidate passages linked back to
> their original source URLs and citation numbers. If one source fails, that
> failure remains visible while successful evidence is retained. Unresolved or
> ambiguous citations are not silently inferred.
>
> The important boundary is deliberate: candidate passages and identifier
> matches are text-level observations, not factual vulnerability verification.
> A future milestone could add a separately designed claim-verification
> capability; that capability is not implemented in the current demo.

### Demo risk checklist

- [ ] A valid TinyFish API key is configured locally and has not been exposed.
- [ ] TinyFish account credits and rate limits are sufficient.
- [ ] Network access and service availability have been checked before the demo.
- [ ] The presenter has allowed for live research latency.
- [ ] The presenter can explain timeout, incomplete, and rate-limit outcomes.
- [ ] No-source and partial-source results are treated as expected failure modes.
- [ ] Evidence-pipeline failure behavior is understood.
- [ ] Long reports and source lists can be scrolled during the demo.
- [ ] No credentials, request headers, or `.env` contents are visible on screen.
- [ ] A backup is ready: run the offline pytest suite and show the deterministic
  evidence and failure-path tests instead of claiming a live investigation.
