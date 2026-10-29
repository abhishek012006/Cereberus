import streamlit as st
from agents.blackbox import verify_research
from agents.evidence_pipeline import build_evidence_pipeline
from agents.phoenix import phoenix_research


def construct_query(vulnerability: str, software_info: str = "") -> str:
    """Build a balanced research query without assuming the software is vulnerable."""
    vuln = vulnerability.strip()
    soft = software_info.strip()
    if soft:
        return (
            f"Investigate {vuln} with software context '{soft}'. "
            f"Evaluate whether this software version is affected, describe the vulnerability mechanism, "
            f"and provide official remediation steps."
        )
    return vuln


def handle_investigation(
    vulnerability: str,
    software_info: str = "",
    research_func=phoenix_research,
    blackbox_func=verify_research,
    evidence_pipeline_func=build_evidence_pipeline,
) -> None:
    """Validate input, call Nightwatch, and render the research results in Streamlit.

    Parameters
    ----------
    vulnerability : str
        The vulnerability name or CVE identifier entered by the user.
    software_info : str, optional
        Optional software name and version for exposure context.
    research_func : callable
    The research backend (defaults to Phoenix). Accepts a ``query`` keyword argument.
    blackbox_func : callable
        The verification backend (defaults to BlackBox). Accepts a Nightwatch result dict.
    evidence_pipeline_func : callable
        Optional claim/evidence orchestration backend. Accepts a completed research
        result and returns a standalone evidence-pipeline result.
    """
    clean_vuln = vulnerability.strip()
    if not clean_vuln:
        st.warning("Please enter a vulnerability name or CVE identifier.")
        return

    query = construct_query(clean_vuln, software_info)

    with st.spinner("Nightwatch is conducting live-web cybersecurity research... This may take up to a minute."):
        result = research_func(query=query)

    if not isinstance(result, dict):
        st.error(
            "Investigation failed because the research engine returned an invalid result "
            f"({type(result).__name__}). Please retry."
        )
        return

    status = result.get("status")
    success = result.get("success", False)
    report = result.get("report", "")
    sources = result.get("sources", [])
    error = result.get("error")
    run_id = result.get("run_id")

    if success and status == "completed":
        st.success("Investigation complete.")
        if run_id:
            st.caption(f"Research Run ID: `{run_id}`")

        st.subheader("Research Findings")
        st.markdown(report)

        if sources:
            st.subheader("Authoritative Sources & Citations")
            for idx, source_url in enumerate(sources, start=1):
                st.markdown(f"{idx}. [{source_url}]({source_url})")

        # ── BlackBox Verification ────────────────────────────────────────────
        # Only run verification when Nightwatch produced a completed, non-empty result.
        # BlackBox is a deterministic, local function — no network calls are made here.
        try:
            bb = blackbox_func(result)
            if not isinstance(bb, dict):
                raise TypeError("BlackBox returned a non-object result")
        except Exception as exc:
            st.warning(
                "BlackBox verification is unavailable. The research report remains "
                f"available; diagnostic: {type(exc).__name__}."
            )
        else:
            with st.expander("🔍 BlackBox — Structural Quality Checks", expanded=True):
                # Verdict badge — use st.info for quality-passed, st.warning for review needed
                if bb["verified"]:
                    st.info(f"**Research Quality:** {bb['verdict']}")
                else:
                    st.warning(f"**Review Required:** {bb['verdict']}")

                # Human-readable explanation of the verdict
                st.caption(bb["summary"])

                # Report completeness metrics
                ra = bb["report_analysis"]
                identifier_note = (
                    "Identifier detected ✓"
                    if ra["identifier_in_report"]
                    else "Identifier NOT found in report ⚠️"
                )
                st.markdown(f"**Report:** {ra['word_count']} words — {identifier_note}")

                # Source breakdown
                sa = bb["source_analysis"]
                st.markdown(
                    f"**Sources:** {sa['total_sources']} total — "
                    f"{sa.get('authoritative_count', sa['recognized_count'])} authoritative · "
                    f"{sa.get('security_vendor_count', 0)} security-research/vendor · "
                    f"{sa['unrecognized_count']} unrecognized · "
                    f"{sa['malformed_count']} malformed"
                )

                if sa.get("authoritative_sources"):
                    st.markdown("**Authoritative Sources:**")
                    for s in sa["authoritative_sources"]:
                        st.markdown(f"  - [{s['url']}]({s['url']}) _(matched: {s['matched_domain']})_")

                if sa.get("security_vendor_sources"):
                    st.markdown("**Recognized Security-Research/Vendor Sources:**")
                    for s in sa["security_vendor_sources"]:
                        st.markdown(f"  - [{s['url']}]({s['url']}) _(matched: {s['matched_domain']})_")

                if sa["unrecognized_sources"]:
                    st.markdown("**Unrecognized Domains:**")
                    for s in sa["unrecognized_sources"]:
                        st.markdown(f"  - [{s['url']}]({s['url']})")

                if sa["malformed_sources"]:
                    st.warning("Malformed source URLs detected:")
                    for u in sa["malformed_sources"]:
                        st.markdown(f"  - `{u}`")

                # Claim verification disclaimer — always shown because claims_verified is
                # always False in BlackBox v1.  This must never be hidden or softened.
                cv = bb["claim_verification"]
                st.error(f"⚠️ {cv['note']}")

                # Methodology limitations (collapsed by default to avoid clutter)
                with st.expander("Methodology Limitations"):
                    for lim in bb["limitations"]:
                        st.markdown(f"- {lim}")
        # ── End BlackBox Section ─────────────────────────────────────────────

        try:
            evidence_pipeline = evidence_pipeline_func(result)
        except Exception as exc:
            st.warning(
                "Evidence Assessment is unavailable because the evidence pipeline failed. "
                "The research report and BlackBox results are still available; "
                f"diagnostic: {type(exc).__name__}."
            )
        else:
            _render_evidence_assessment(evidence_pipeline)

    elif status == "empty_result":
        st.warning(
            "Research concluded, but no report content was generated by the research engine. "
            "No findings are available to assess."
        )
        if sources:
            st.subheader("Discovered Sources")
            for idx, source_url in enumerate(sources, start=1):
                st.markdown(f"{idx}. [{source_url}]({source_url})")

    elif status == "incomplete":
        st.warning(
            "Research stream disconnected before completion. "
            "Any partial findings are shown below."
        )
        if report:
            st.markdown("### Partial Findings Gathered Prior to Disconnect")
            st.markdown(report)

    elif status == "timeout":
        st.error(
            "Investigation timed out before research completed. "
            "Please retry with the same or a narrower query."
        )

    else:
        # General error or failure
        st.error(
            "Investigation failed before research completed. "
            "Please retry or check the research service configuration."
        )


def _render_evidence_assessment(pipeline_result) -> None:
    """Render conservative evidence observations without implying factual verification."""
    st.subheader("Evidence Assessment")
    st.caption(
        "These are deterministic, text-level observations. Candidate passages do not "
        "establish factual truth or confirm a vulnerability."
    )

    if not isinstance(pipeline_result, dict):
        st.warning("Evidence Assessment returned an invalid result.")
        return

    status = pipeline_result.get("status")
    if status == "skipped":
        st.info("Evidence assessment was skipped because the research result was not eligible.")
    elif status in {"error", "completed_with_errors"}:
        st.warning("Evidence assessment completed with limitations or errors.")

    _render_retrieval_issues(pipeline_result)

    errors = pipeline_result.get("errors", [])
    if isinstance(errors, list):
        for error in errors:
            if isinstance(error, str) and error:
                st.warning(f"Evidence pipeline: {error}")

    assessment_result = pipeline_result.get("evidence_assessment")
    if not isinstance(assessment_result, dict):
        st.info("No evidence assessments are available.")
        return

    assessments = assessment_result.get("assessments", [])
    if not isinstance(assessments, list) or not assessments:
        st.info("No claims were available for deterministic evidence assessment.")
        return

    for assessment in assessments:
        if not isinstance(assessment, dict):
            continue
        claim_id = assessment.get("claim_id", "unknown")
        claim_text = assessment.get("claim_text", "")
        label = assessment.get("assessment", "inconclusive")
        st.markdown(f"**Claim ({claim_id}):** {claim_text}")
        st.markdown(f"**Assessment:** `{label}`")

        if label == "identifier_match_only":
            st.caption(
                "An identifier was found in retrieved text; this does not mean the "
                "source supports the full claim."
            )
        elif label == "partially_supported":
            st.caption(
                "Some details have text coverage, but this is not a final vulnerability verdict."
            )
        elif label == "conflicting":
            st.caption(
                "Retrieved statements conflict; this does not establish which statement is correct."
            )

        reasons = assessment.get("reasons", [])
        if isinstance(reasons, list):
            for reason in reasons:
                if isinstance(reason, str) and reason:
                    st.markdown(f"- {reason}")

        details = assessment.get("detail_assessments", [])
        if isinstance(details, list) and details:
            st.markdown("**Claim details:**")
            for detail in details:
                if not isinstance(detail, dict):
                    continue
                st.markdown(
                    f"- `{detail.get('detail_type', 'unknown')}`: "
                    f"`{detail.get('status', 'inconclusive')}` — "
                    f"{detail.get('detail_text', '')}"
                )

        evidence = assessment.get("evidence", [])
        if isinstance(evidence, list) and evidence:
            st.markdown("**Candidate evidence passages:**")
            for item in evidence:
                if not isinstance(item, dict):
                    continue
                passage = item.get("passage")
                url = item.get("url")
                if not isinstance(passage, str) or not isinstance(url, str):
                    continue
                citation = item.get("citation_number")
                citation_text = (
                    f" (citation {citation})" if citation is not None else ""
                )
                st.markdown(f"- [{url}]({url}){citation_text}")
                st.markdown(f"  > {passage}")
        else:
            st.caption("No candidate evidence passages were available.")


def _retrieval_issue_explanation(retrieval: dict) -> str:
    """Return a safe, allowlisted explanation for a failed source retrieval."""
    status = retrieval.get("retrieval_status")
    explanations = {
        "http_error": "The source rejected the request.",
        "network_error": "A network request failed.",
        "timeout": "The source did not respond within the retrieval deadline.",
        "response_too_large": "The response exceeded CERBERUS's configured size limit.",
        "blocked_destination": "The destination was blocked by network security policy.",
        "unsupported_content_type": "The source returned an unsupported content type.",
        "redirect_limit_exceeded": "The source exceeded the redirect limit.",
        "invalid_url": "The source URL was invalid.",
        "unsupported_url": "The source URL scheme is unsupported.",
        "malformed_url": "The source URL was malformed.",
        "empty_response": "The source returned an empty response.",
        "parse_error": "The source response could not be processed.",
        "pipeline_error": "The source retrieval pipeline failed before content was accepted.",
    }
    explanation = explanations.get(status, "The source could not be retrieved.")
    if status == "network_error":
        safe_error = retrieval.get("error")
        network_explanations = {
            "DNS resolution failed.": "DNS resolution failed.",
            "TLS or certificate verification failed.": (
                "TLS or certificate verification failed."
            ),
            "Connection failed.": "The connection could not be established.",
            "Read/write transport failure.": "The connection failed while transferring data.",
            "Response decompression failed.": "The compressed response could not be decoded.",
            "Network request failed.": "A network request failed.",
        }
        explanation = network_explanations.get(safe_error, explanation)
    status_code = retrieval.get("status_code")
    if status == "http_error" and isinstance(status_code, int):
        return f"{explanation} HTTP status {status_code}."
    return explanation


def _render_retrieval_issues(pipeline_result: dict) -> None:
    """Render sanitized per-source failures without exposing transport details."""
    retrieval_results = pipeline_result.get("retrieval_results", [])
    if not isinstance(retrieval_results, list):
        return

    source_records = {}
    research_result = pipeline_result.get("research_result")
    if isinstance(research_result, dict):
        records = research_result.get("source_records", [])
        if isinstance(records, list):
            source_records = {
                record.get("url"): record
                for record in records
                if isinstance(record, dict) and isinstance(record.get("url"), str)
            }

    issues = [
        retrieval
        for retrieval in retrieval_results
        if isinstance(retrieval, dict)
        and retrieval.get("retrieval_status") != "retrieved"
    ]
    if not issues:
        return

    st.markdown("**Source retrieval issues:**")
    for retrieval in issues:
        url = retrieval.get("url")
        if not isinstance(url, str) or not url:
            url = "Unknown source"
        record = source_records.get(url, {})
        citation = record.get("citation_number")
        citation_text = f" (citation {citation})" if citation is not None else ""
        st.warning(
            f"[{url}]({url}){citation_text}: "
            f"{_retrieval_issue_explanation(retrieval)}"
        )


def render_ui() -> None:
    """Render the main Streamlit application layout and interactive elements."""
    st.set_page_config(
        page_title="CERBERUS",
        page_icon="🛡️",
        layout="centered",
    )

    st.title("CERBERUS — AI Cybersecurity Investigation")

    st.markdown(
        """
        **CERBERUS** investigates a vulnerability or CVE, gathers live research through
        TinyFish, and presents source-linked findings with deterministic quality and
        evidence observations.
        """
    )
    st.caption(
        "Start with a CVE or vulnerability name. Candidate evidence is a text-level "
        "signal for review, not a factual verification verdict."
    )

    st.subheader("Start an investigation")

    # Required input: vulnerability name or CVE identifier
    vulnerability = st.text_input(
        label="Vulnerability Name or CVE Identifier",
        placeholder="e.g., CVE-2024-3094, Log4Shell, Spring4Shell",
        help="Enter a standard CVE ID or common vulnerability name.",
    )

    # Optional input: software name and installed version
    software_info = st.text_input(
        label="Software Name and Installed Version (Optional)",
        placeholder="e.g., XZ Utils 5.6.0, Apache Log4j 2.14.1",
        help="Optionally provide software context to check for specific exposure.",
    )

    # Action button
    if st.button("Investigate", type="primary"):
        handle_investigation(vulnerability, software_info)


if __name__ == "__main__":
    render_ui()
