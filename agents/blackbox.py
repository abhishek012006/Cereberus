"""BlackBox Agent: Evidence and research-quality verification module for CERBERUS.

This module provides deterministic verification of Nightwatch research outputs.
It evaluates structure, report completeness, URL syntax, and domain authority
heuristics without making live network requests or invoking LLMs.
"""

import re
import urllib.parse
from typing import Any, Dict, List, Optional, Sequence, Tuple

# Default authoritative cybersecurity registries and repositories.
DEFAULT_AUTHORITATIVE_DOMAINS: List[str] = [
    "nist.gov",
    "cisa.gov",
    "cve.org",
    "mitre.org",
    "debian.org",
    "ubuntu.com",
    "redhat.com",
    "archlinux.org",
    "openssf.org",
    "cert.org",
]

# Established security-research and vendor organizations. These are useful
# evidence sources, but are not treated as registries or authoritative records.
DEFAULT_SECURITY_VENDOR_DOMAINS: List[str] = [
    "github.com",
    "microsoft.com",
    "googleprojectzero.blogspot.com",
    "cloud.google.com",
    "cloudflare.com",
    "crowdstrike.com",
    "mandiant.com",
    "paloaltonetworks.com",
    "rapid7.com",
    "tenable.com",
    "sophos.com",
    "eset.com",
    "fortinet.com",
    "checkpoint.com",
    "trendmicro.com",
    "kaspersky.com",
]

# Backwards-compatible name for callers that supplied the original combined list.
DEFAULT_RECOGNIZED_DOMAINS: List[str] = [
    *DEFAULT_AUTHORITATIVE_DOMAINS,
    "github.com",
]

# Required schema for Nightwatch output dictionary
REQUIRED_FIELDS = {
    "success": bool,
    "status": str,
    "query": str,
    "report": str,
    "sources": list,
    "run_id": (str, type(None)),
    "error": (str, type(None)),
}


def validate_input_structure(result: Any) -> Tuple[bool, Optional[str]]:
    """Validate that the input is a dictionary matching Nightwatch output format.

    Returns:
        (is_valid, error_message)
    """
    if not isinstance(result, dict):
        return False, f"Expected a dictionary, got {type(result).__name__}."

    missing_keys = [k for k in REQUIRED_FIELDS if k not in result]
    if missing_keys:
        return False, f"Missing required fields: {', '.join(missing_keys)}."

    for key, expected_type in REQUIRED_FIELDS.items():
        val = result[key]
        if not isinstance(val, expected_type):
            expected_name = (
                "/".join(t.__name__ for t in expected_type)
                if isinstance(expected_type, tuple)
                else expected_type.__name__
            )
            return False, f"Field '{key}' must be of type {expected_name}, got {type(val).__name__}."

    # Validate that every source item is a string
    for idx, item in enumerate(result["sources"]):
        if not isinstance(item, str):
            return False, f"Item at index {idx} in 'sources' is {type(item).__name__}, expected str."

    return True, None


def parse_source_url(url: Any) -> Tuple[bool, str, str]:
    """Parse and validate the syntax of a source URL string.

    Returns:
        (is_valid, domain, error_reason)
    """
    if not isinstance(url, str):
        return False, "", "URL is not a string."

    clean_url = url.strip()
    if not clean_url:
        return False, "", "Empty URL string."

    try:
        parsed = urllib.parse.urlparse(clean_url)
    except Exception as exc:
        return False, "", f"URL parsing error: {exc}"

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        return False, "", f"Invalid or missing scheme '{parsed.scheme}'. Must be http or https."

    netloc = parsed.netloc.lower()
    if not netloc:
        return False, "", "Missing domain host."

    # Strip port if present
    domain = netloc.split(":")[0]

    # Host must contain at least one dot and valid domain characters
    if "." not in domain or domain.startswith(".") or domain.endswith("."):
        return False, domain, f"Invalid domain name format '{domain}'."

    return True, domain, ""


def is_domain_recognized(domain: str, recognized_domains: Sequence[str]) -> Tuple[bool, str]:
    """Check for an exact or boundary-safe subdomain match.

    Returns:
        (is_recognized, matched_rule)
    """
    clean_domain = domain.lower()
    if clean_domain.startswith("www."):
        clean_domain = clean_domain[4:]

    for recognized in recognized_domains:
        rec = recognized.lower().strip()
        if not rec:
            continue
        if rec.startswith("www."):
            rec = rec[4:]
        if clean_domain == rec or clean_domain.endswith("." + rec):
            return True, rec

    return False, ""


def classify_domain(
    domain: str,
    authoritative_domains: Sequence[str],
    security_vendor_domains: Sequence[str],
) -> Tuple[str, str]:
    """Classify a domain as authoritative, security_vendor, or unrecognized."""
    is_authoritative, authoritative_rule = is_domain_recognized(domain, authoritative_domains)
    if is_authoritative:
        return "authoritative", authoritative_rule

    is_vendor, vendor_rule = is_domain_recognized(domain, security_vendor_domains)
    if is_vendor:
        return "security_vendor", vendor_rule

    return "unrecognized", ""


def extract_query_identifiers(query: str) -> List[str]:
    """Extract candidate vulnerability identifiers (e.g. CVE IDs or named CVEs) from a query.

    Returns:
        list[str]: Candidate identifier strings found in query.
    """
    if not query or not query.strip():
        return []

    # 1. Look for CVE patterns (e.g. CVE-2024-3094)
    cve_matches = re.findall(r"\bCVE-\d{4}-\d{4,7}\b", query, re.IGNORECASE)
    if cve_matches:
        seen = set()
        cves = []
        for c in cve_matches:
            c_upper = c.upper()
            if c_upper not in seen:
                seen.add(c_upper)
                cves.append(c_upper)
        return cves

    # 2. Extract notable keywords (excluding common prompt filler words)
    stop_words = {
        "investigate", "explain", "analyze", "evaluate", "with", "software",
        "context", "whether", "this", "version", "is", "affected", "describe",
        "the", "vulnerability", "mechanism", "and", "provide", "official",
        "remediation", "steps", "for", "in", "relation", "to", "what", "of",
        "how", "can", "installed", "target", "about", "detail", "details"
    }

    words = re.findall(r"\b[A-Za-z0-9_-]{3,}\b", query)
    candidates = [w for w in words if w.lower() not in stop_words]
    return candidates


def verify_research(
    result: Any,
    recognized_domains: Optional[Sequence[str]] = None,
    vendor_domains: Optional[Sequence[str]] = None,
    authoritative_domains: Optional[Sequence[str]] = None,
    security_vendor_domains: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Deterministically verify the evidence structure and quality of a Nightwatch research result.

    Args:
        result: The output dictionary from research_vulnerability().
        recognized_domains: Optional list of additional recognized authoritative domains
            retained for backwards compatibility.
        vendor_domains: Optional list of specific vendor domains relevant to the target software.
        authoritative_domains: Optional replacement list for authoritative domains.
        security_vendor_domains: Optional replacement list for security-research/vendor domains.

    Returns:
        dict: A structured dictionary containing:
            - verified (bool): True only if research completed, report has substantive content,
              and all sources have valid URL syntax.
            - verdict (str): Summary categorization code.
            - verified (bool): True if structural research-quality checks pass (report present,
              sources valid). Does NOT imply factual claims are verified.
            - verdict (str): Summary categorization code clearly indicating claim verification status.
            - summary (str): Beginner-friendly explanation of the verification outcome.
            - checks (dict): Boolean results of individual verification checks, including claims_verified=False.
            - report_analysis (dict): Text metrics and query identifier matching.
            - source_analysis (dict): Detailed categorisation of recognized, unrecognized, and malformed URLs.
            - claim_verification (dict): Status explaining that claim-level verification is not yet implemented.
            - limitations (list[str]): Methodological boundaries of this verification step.
            - findings (list[str]): Key takeaways and observations.
    """
    findings: List[str] = []

    # 1. Validate Input Structure
    is_valid_input, input_err = validate_input_structure(result)
    if not is_valid_input:
        return {
            "verified": False,
            "verdict": "INVALID_INPUT",
            "summary": f"Verification aborted: {input_err}",
            "checks": {
                "input_valid": False,
                "research_successful": False,
                "report_present": False,
                "identifier_detected": False,
                "sources_valid": False,
                "claims_verified": False,
            },
            "report_analysis": {
                "character_count": 0,
                "word_count": 0,
                "has_content": False,
                "query_target": "",
                "identifier_in_report": False,
            },
            "source_analysis": {
                "total_sources": 0,
                "valid_count": 0,
                "malformed_count": 0,
                "recognized_count": 0,
                "authoritative_count": 0,
                "security_vendor_count": 0,
                "unrecognized_count": 0,
                "authoritative_sources": [],
                "security_vendor_sources": [],
                "recognized_sources": [],
                "unrecognized_sources": [],
                "malformed_sources": [],
            },
            "claim_verification": {
                "status": "NOT_IMPLEMENTED",
                "claims_verified": False,
                "supported_claims_count": 0,
                "total_claims_count": 0,
                "note": "Input structure is invalid; verification could not proceed.",
            },
            "limitations": [
                "Input did not conform to the expected Nightwatch result dictionary schema.",
            ],
            "findings": [f"Input structure error: {input_err}"],
        }

    # 2. Check Research Completion
    status = result["status"]
    success = result["success"]
    error = result.get("error")

    research_successful = bool(success and status == "completed")
    if not research_successful:
        findings.append(f"Research did not conclude successfully (status='{status}', error='{error or 'None'}').")

    # 3. Analyze Report Content
    report_text = result["report"].strip()
    char_count = len(report_text)
    word_count = len(report_text.split()) if report_text else 0
    report_present = bool(word_count > 0)

    if not report_present:
        findings.append("Research report contains no text content.")
    else:
        findings.append(f"Report contains {word_count} words ({char_count} characters).")

    # 4. Check Identifier Detection in Report
    query_targets = extract_query_identifiers(result["query"])
    identifier_detected = False
    primary_target = query_targets[0] if query_targets else ""

    if primary_target and report_present:
        # Check case-insensitively
        if primary_target.lower() in report_text.lower():
            identifier_detected = True
            findings.append(f"Target identifier '{primary_target}' confirmed in report text.")
        else:
            findings.append(
                f"Target identifier '{primary_target}' was not detected in report text. Flagged for review."
            )
    elif not primary_target and report_present:
        # No clear identifier extracted from query
        identifier_detected = True

    # 5. Build Configurable Recognized Domains List
    authoritative_set = list(
        DEFAULT_AUTHORITATIVE_DOMAINS
        if authoritative_domains is None
        else authoritative_domains
    )
    security_vendor_set = list(
        DEFAULT_SECURITY_VENDOR_DOMAINS
        if security_vendor_domains is None
        else security_vendor_domains
    )
    if recognized_domains:
        authoritative_set.extend(recognized_domains)
    if vendor_domains:
        security_vendor_set.extend(vendor_domains)

    def unique_domains(domains: Sequence[str]) -> List[str]:
        seen = set()
        unique: List[str] = []
        for domain_name in domains:
            clean_domain = domain_name.strip().lower()
            if clean_domain and clean_domain not in seen:
                seen.add(clean_domain)
                unique.append(clean_domain)
        return unique

    authoritative_set = unique_domains(authoritative_set)
    security_vendor_set = unique_domains(security_vendor_set)

    # 6. Source Syntax & Domain Authority Evaluation
    raw_sources = result["sources"]
    recognized_sources: List[Dict[str, str]] = []
    authoritative_sources: List[Dict[str, str]] = []
    security_vendor_sources: List[Dict[str, str]] = []
    unrecognized_sources: List[Dict[str, str]] = []
    malformed_sources: List[str] = []

    for src in raw_sources:
        is_url_valid, domain, err_msg = parse_source_url(src)
        if not is_url_valid:
            malformed_sources.append(src)
            findings.append(f"Malformed source URL detected: '{src}' ({err_msg}).")
            continue

        category, matched_rule = classify_domain(
            domain, authoritative_set, security_vendor_set
        )
        source_details = {
                "url": src,
                "domain": domain,
                "matched_domain": matched_rule,
            }
        if category == "authoritative":
            authoritative_sources.append(source_details)
            recognized_sources.append(source_details)
        elif category == "security_vendor":
            security_vendor_sources.append(source_details)
            recognized_sources.append(source_details)
        else:
            unrecognized_sources.append({"url": src, "domain": domain})

    total_sources = len(raw_sources)
    valid_count = len(recognized_sources) + len(unrecognized_sources)
    malformed_count = len(malformed_sources)
    sources_valid = bool(total_sources > 0 and malformed_count == 0)

    if total_sources == 0:
        findings.append("No source URLs were returned with the research.")
    else:
        findings.append(
            f"Evaluated {total_sources} source URL(s): {len(authoritative_sources)} authoritative, "
            f"{len(security_vendor_sources)} security-research/vendor, "
            f"{len(unrecognized_sources)} unrecognized domain(s), {malformed_count} malformed."
        )

    # 7. Overall Assessment & Verdict Formulation
    checks = {
        "input_valid": True,
        "research_successful": research_successful,
        "report_present": report_present,
        "identifier_detected": identifier_detected,
        "sources_valid": sources_valid,
        "claims_verified": False,
    }

    if not research_successful:
        verified = False
        verdict = f"UNVERIFIED_{status.upper()}"
        summary = f"Investigation unverified: research did not complete successfully ({status}: {error or 'unspecified error'})."

    elif not report_present:
        verified = False
        verdict = "UNVERIFIED_EMPTY_REPORT"
        summary = "Investigation unverified: research task finished, but produced an empty report."

    elif malformed_count > 0:
        verified = False
        verdict = "NEEDS_REVIEW_MALFORMED_SOURCES"
        summary = f"Investigation requires review: {malformed_count} source URL(s) are malformed."

    elif total_sources == 0:
        verified = False
        verdict = "NEEDS_REVIEW_NO_SOURCES"
        summary = "Investigation requires review: report was generated without any source URLs."

    elif primary_target and not identifier_detected:
        verified = False
        verdict = "NEEDS_REVIEW_IDENTIFIER_MISSING"
        summary = f"Investigation requires review: target identifier '{primary_target}' was not found in the report text."

    else:
        # Core structural and syntax checks passed; note that claim-level verification is not yet implemented
        verified = True
        findings.append(
            "Factual claims remain unverified: claim-to-evidence verification is not yet implemented in BlackBox."
        )
        if len(recognized_sources) > 0:
            verdict = "RESEARCH_VALID_WITH_RECOGNIZED_SOURCES_CLAIMS_UNVERIFIED"
            summary = (
                f"Research-quality validation passed ({word_count} words, "
                f"{len(recognized_sources)} authoritative domain(s) cited), "
                f"but factual claims remain unverified (claim-level verification is not yet implemented)."
            )
        else:
            verdict = "RESEARCH_VALID_UNRECOGNIZED_SOURCES_CLAIMS_UNVERIFIED"
            summary = (
                f"Research-quality validation passed ({word_count} words), "
                f"but cited sources ({len(unrecognized_sources)}) are from unrecognized domains, "
                f"and factual claims remain unverified (claim-level verification is not yet implemented)."
            )

    return {
        "verified": verified,
        "verdict": verdict,
        "summary": summary,
        "checks": checks,
        "report_analysis": {
            "character_count": char_count,
            "word_count": word_count,
            "has_content": report_present,
            "query_target": primary_target,
            "identifier_in_report": identifier_detected,
        },
        "source_analysis": {
            "total_sources": total_sources,
            "valid_count": valid_count,
            "malformed_count": malformed_count,
            "recognized_count": len(recognized_sources),
            "authoritative_count": len(authoritative_sources),
            "security_vendor_count": len(security_vendor_sources),
            "unrecognized_count": len(unrecognized_sources),
            "authoritative_sources": authoritative_sources,
            "security_vendor_sources": security_vendor_sources,
            "recognized_sources": recognized_sources,
            "unrecognized_sources": unrecognized_sources,
            "malformed_sources": malformed_sources,
        },
        "claim_verification": {
            "status": "NOT_IMPLEMENTED",
            "claims_verified": False,
            "supported_claims_count": 0,
            "total_claims_count": 0,
            "note": (
                "Claim-level factual verification is not yet implemented in BlackBox. "
                "Domain recognition is a research-quality heuristic only and does not prove "
                "that factual claims in the report are true or supported by evidence."
            ),
        },
        "limitations": [
            "Claim-level factual verification is not yet implemented; BlackBox does not inspect page contents or map claims to sources.",
            "Source URLs are evaluated for syntax and domain authority heuristics only; live HTTP reachability was not tested.",
            "Individual factual claims (such as specific version numbers or exploit mechanisms) cannot be proven true solely from URL presence.",
            "Recognized domains indicate reputable publishing platforms (e.g. nist.gov, cisa.gov), but do not guarantee that the synthesized text accurately reflects their contents.",
        ],
        "findings": findings,
    }
