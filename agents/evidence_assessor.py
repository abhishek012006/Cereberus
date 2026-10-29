"""Conservative deterministic assessment of candidate evidence.

Assessment labels describe text-level observations only.  They are not truth
verdicts, confidence scores, or claims that a source semantically proves a
claim.
"""

import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


_CVE_RE = re.compile(
    r"(?<![A-Za-z0-9])CVE-\d{4}-\d{4,7}(?![A-Za-z0-9])",
    re.IGNORECASE,
)
_VERSION_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:version\s+)?\d+(?:\.\d+)+(?![A-Za-z0-9])",
    re.IGNORECASE,
)
_AFFECTED_RE = re.compile(
    r"\b(?:affect(?:s|ed)?|impact(?:s|ed)?|vulnerable|exposed|"
    r"subject to|at risk)\b",
    re.IGNORECASE,
)
_NEGATED_RE = re.compile(
    r"\b(?:not affected|unaffected|not vulnerable|not exposed|"
    r"does not affect|do not affect|is not affected|are not affected|"
    r"fixed|patched|remediated)\b",
    re.IGNORECASE,
)
_HISTORICAL_RE = re.compile(
    r"\b(?:historically|historical|previously|formerly|at the time|"
    r"was affected|were affected|had been affected)\b",
    re.IGNORECASE,
)
_CURRENT_RE = re.compile(
    r"\b(?:currently|presently|now|today|currently affected)\b",
    re.IGNORECASE,
)
_UNCERTAIN_RE = re.compile(
    r"\b(?:may|might|could|possibly|whether|uncertain|unclear)\b",
    re.IGNORECASE,
)
_EXPLOIT_RE = re.compile(
    r"\b(?:exploited|exploitation|actively exploited|attackers? exploited)\b",
    re.IGNORECASE,
)
_MITIGATION_RE = re.compile(
    r"\b(?:patch(?:ed)?|update|upgrade|downgrade|workaround|mitigat|remediat)\w*\b",
    re.IGNORECASE,
)


def _result(status: str = "completed") -> Dict[str, Any]:
    return {
        "status": status,
        "assessments": [],
        "errors": [],
    }


def _claim_list(claims: Any, errors: List[str]) -> Optional[List[dict]]:
    if isinstance(claims, dict):
        if claims.get("status") == "error":
            errors.append(str(claims.get("error") or "Claim extraction failed."))
            return None
        claims = claims.get("claims")
    if not isinstance(claims, (list, tuple)):
        errors.append("claims must be a claim list or claim-extractor result.")
        return None
    return list(claims)


def _matches_list(evidence_matches: Any, errors: List[str]) -> Optional[List[dict]]:
    if not isinstance(evidence_matches, dict):
        errors.append("evidence_matches must be the matcher result dictionary.")
        return None
    matches = evidence_matches.get("matches")
    if not isinstance(matches, list):
        errors.append("evidence_matches.matches must be a list.")
        return None
    return matches


def _cves(value: str) -> List[str]:
    seen = set()
    result = []
    for match in _CVE_RE.findall(value):
        normalized = match.upper()
        if normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    return result


def _versions(value: str) -> List[str]:
    seen = set()
    result = []
    for match in _VERSION_RE.findall(value):
        normalized = re.sub(r"^version\s+", "", match, flags=re.IGNORECASE)
        if normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    return result


def _evidence_text(evidence: Sequence[dict]) -> str:
    return "\n".join(
        item["passage"]
        for item in evidence
        if isinstance(item, dict) and isinstance(item.get("passage"), str)
    )


def _has_exact_cve(text: str, cve: str) -> bool:
    return bool(
        re.search(
            rf"(?<![A-Za-z0-9]){re.escape(cve)}(?![A-Za-z0-9])",
            text,
            re.IGNORECASE,
        )
    )


def _local_relation(text: str, version: str) -> Tuple[bool, bool]:
    """Return (affirmative, negative) for one version in bounded local text."""
    for match in re.finditer(re.escape(version), text, re.IGNORECASE):
        window = text[max(0, match.start() - 90): match.end() + 90]
        if _NEGATED_RE.search(window):
            return False, True
        if _AFFECTED_RE.search(window):
            return True, False
    return False, False


def _claim_details(claim: dict) -> List[Dict[str, Any]]:
    text = claim["claim_text"]
    details: List[Dict[str, Any]] = []
    for cve in _cves(text):
        details.append({"detail_type": "cve", "detail_text": cve})
    for version in _versions(text):
        details.append({"detail_type": "version", "detail_text": version})
    lowered = text.lower()
    if _AFFECTED_RE.search(text) or "affected_versions" == claim.get("claim_type"):
        details.append({"detail_type": "affected_relation", "detail_text": "affected"})
    if _EXPLOIT_RE.search(text) or claim.get("claim_type") == "exploitation":
        details.append({"detail_type": "exploitation", "detail_text": "exploitation"})
    if _MITIGATION_RE.search(text) or claim.get("claim_type") == "mitigation":
        details.append({"detail_type": "mitigation", "detail_text": "mitigation"})
    if not details and lowered.strip():
        details.append({"detail_type": "claim_text", "detail_text": text})
    return details


def _assess_one(claim: dict, match: dict) -> Dict[str, Any]:
    claim_id = claim["claim_id"]
    claim_text = claim["claim_text"]
    evidence = match.get("evidence", [])
    if not isinstance(evidence, list):
        return {
            "claim_id": claim_id,
            "claim_text": claim_text,
            "assessment": "invalid_input",
            "detail_assessments": [],
            "evidence": [],
            "reasons": ["Matcher evidence must be a list."],
        }

    match_status = match.get("match_status")
    reasons: List[str] = [
        "This is a deterministic text-level assessment, not a truth verdict."
    ]
    if match_status == "citation_ambiguous":
        return {
            "claim_id": claim_id,
            "claim_text": claim_text,
            "assessment": "citation_ambiguous",
            "detail_assessments": [],
            "evidence": evidence,
            "reasons": reasons + ["The citation number maps to multiple source records."],
        }
    if match_status == "citation_unresolved":
        return {
            "claim_id": claim_id,
            "claim_text": claim_text,
            "assessment": "citation_unresolved",
            "detail_assessments": [],
            "evidence": evidence,
            "reasons": reasons + ["The cited source could not be resolved unambiguously."],
        }
    if not evidence:
        return {
            "claim_id": claim_id,
            "claim_text": claim_text,
            "assessment": "no_retrieved_evidence",
            "detail_assessments": [],
            "evidence": [],
            "reasons": reasons + ["No successful retrieved passage was supplied."],
        }

    text = _evidence_text(evidence)
    cves = _cves(claim_text)
    versions = _versions(claim_text)
    details: List[Dict[str, Any]] = []
    positive_details = 0
    missing_details = 0
    conflicting = False

    for detail in _claim_details(claim):
        kind = detail["detail_type"]
        value = detail["detail_text"]
        detail_status = "inconclusive"
        detail_reasons: List[str] = []
        if kind == "cve":
            if any(_has_exact_cve(text, value) for _ in cves):
                detail_status = "matched"
                positive_details += 1
                detail_reasons.append("The exact CVE identifier occurs in retrieved text.")
            else:
                detail_status = "missing"
                missing_details += 1
                detail_reasons.append("The exact claimed CVE identifier was not found.")
        elif kind == "version":
            found = any(version.lower() == value.lower() for version in _versions(text))
            if not found:
                detail_status = "missing"
                missing_details += 1
                detail_reasons.append("The exact version token was not found.")
            else:
                affirmative, negative = _local_relation(text, value)
                if negative and not affirmative:
                    detail_status = "conflicting"
                    conflicting = True
                    detail_reasons.append(
                        "The version is explicitly described as fixed, unaffected, or not vulnerable."
                    )
                elif affirmative:
                    window = next(
                        (
                            text[max(0, item.start() - 90): item.end() + 90]
                            for item in re.finditer(re.escape(value), text, re.I)
                            if _AFFECTED_RE.search(
                                text[max(0, item.start() - 90): item.end() + 90]
                            )
                        ),
                        "",
                    )
                    if _UNCERTAIN_RE.search(window):
                        detail_status = "inconclusive"
                        detail_reasons.append(
                            "Affected language is qualified by uncertain or conditional wording."
                        )
                    else:
                        detail_status = "matched"
                        positive_details += 1
                        detail_reasons.append(
                            "The version occurs with explicit local affected/vulnerability language."
                        )
                else:
                    detail_status = "inconclusive"
                    detail_reasons.append(
                        "The version is mentioned, but no supported affected relation was found."
                    )
        elif kind == "affected_relation":
            affirmative = bool(_AFFECTED_RE.search(text))
            negative = bool(_NEGATED_RE.search(text))
            if affirmative and not negative:
                if _UNCERTAIN_RE.search(text):
                    detail_status = "inconclusive"
                    missing_details += 1
                    detail_reasons.append(
                        "Affected language is qualified by uncertain or conditional wording."
                    )
                else:
                    detail_status = "matched"
                    positive_details += 1
                    detail_reasons.append("Explicit affected/vulnerability language was found.")
            elif negative:
                detail_status = "conflicting"
                conflicting = True
                detail_reasons.append("Explicit negated, fixed, or unaffected language was found.")
            else:
                detail_status = "missing"
                missing_details += 1
                detail_reasons.append("No explicit affected relation was found.")
        elif kind == "exploitation":
            if _EXPLOIT_RE.search(text) and not re.search(r"\bnot\s+(?:actively\s+)?exploited\b", text, re.I):
                detail_status = "matched"
                positive_details += 1
                detail_reasons.append("Explicit exploitation language was found.")
            elif re.search(r"\bnot\s+(?:actively\s+)?exploited\b", text, re.I):
                detail_status = "conflicting"
                conflicting = True
                detail_reasons.append("Explicit negated exploitation language was found.")
            else:
                detail_status = "missing"
                missing_details += 1
                detail_reasons.append("No explicit exploitation language was found.")
        elif kind == "mitigation":
            if _MITIGATION_RE.search(text):
                detail_status = "matched"
                positive_details += 1
                detail_reasons.append("Explicit mitigation language was found.")
            else:
                detail_status = "missing"
                missing_details += 1
                detail_reasons.append("No explicit mitigation language was found.")
        else:
            detail_status = "inconclusive"
            detail_reasons.append("The claim detail cannot be safely decomposed deterministically.")

        details.append(
            {
                "detail_type": kind,
                "detail_text": value,
                "status": detail_status,
                "evidence": evidence,
                "reasons": detail_reasons,
            }
        )

    if _CURRENT_RE.search(claim_text) and _HISTORICAL_RE.search(text) and not _CURRENT_RE.search(text):
        reasons.append("The claim is time-sensitive, but the retrieved text is historical or lacks current context.")
        assessment = "inconclusive"
    elif conflicting:
        assessment = "conflicting"
        reasons.append("Retrieved statements disagree on a narrow detail; the assessor does not resolve which is correct.")
    elif any(item["status"] == "inconclusive" for item in details):
        assessment = "inconclusive"
        reasons.append("At least one claim detail is qualified or cannot be resolved by the narrow deterministic checks.")
    elif positive_details and missing_details:
        assessment = "partially_supported"
        reasons.append("Some claim details have explicit text coverage while others are missing.")
        reasons.append("Partial coverage does not establish that the overall claim is true.")
    elif positive_details:
        if len(cves) == 1 and len(versions) == 0 and not (
            _AFFECTED_RE.search(claim_text)
            or claim.get("claim_type") in {"affected_versions", "exploitation", "mitigation"}
        ):
            assessment = "identifier_match_only"
            reasons.append("The evidence matches an identifier but does not establish a broader proposition.")
        elif len(cves) and not (_AFFECTED_RE.search(text) or _EXPLOIT_RE.search(text) or _MITIGATION_RE.search(text)):
            assessment = "identifier_match_only"
            reasons.append("A CVE mention alone does not establish impact, exploitation, or mitigation.")
        else:
            assessment = "candidate_only"
            reasons.append("Explicit text-level observations exist, but semantic support is not established.")
    else:
        assessment = "inconclusive"
        reasons.append("Retrieved text is insufficient for a deterministic proposition-level assessment.")
    if cves and not (
        _AFFECTED_RE.search(text)
        or _EXPLOIT_RE.search(text)
        or _MITIGATION_RE.search(text)
    ):
        reasons.append(
            "The retrieved text mentions the CVE but does not establish the claim's specific relation."
        )

    return {
        "claim_id": claim_id,
        "claim_text": claim_text,
        "assessment": assessment,
        "detail_assessments": details,
        "evidence": evidence,
        "reasons": reasons,
    }


def assess_claim_evidence(
    claims: Any,
    evidence_matches: Any,
    *,
    retrieval_results: Optional[Sequence[dict]] = None,
) -> Dict[str, Any]:
    """Assess candidate evidence conservatively without external reasoning."""
    result = _result()
    normalized_claims = _claim_list(claims, result["errors"])
    matches = _matches_list(evidence_matches, result["errors"])
    if normalized_claims is None or matches is None:
        result["status"] = "error"
        return result
    if not normalized_claims:
        result["status"] = "empty"
        return result

    if retrieval_results is not None and not isinstance(retrieval_results, (list, tuple)):
        result["errors"].append("retrieval_results must be a sequence when supplied.")

    matches_by_id: Dict[str, dict] = {}
    for index, match in enumerate(matches):
        if not isinstance(match, dict):
            result["errors"].append(f"Evidence match at index {index} must be an object.")
            continue
        claim_id = match.get("claim_id")
        if isinstance(claim_id, str) and claim_id.strip():
            matches_by_id.setdefault(claim_id, match)

    for index, claim in enumerate(normalized_claims):
        if not isinstance(claim, dict):
            result["errors"].append(f"Claim at index {index} must be an object.")
            continue
        claim_id = claim.get("claim_id")
        claim_text = claim.get("claim_text")
        if not isinstance(claim_id, str) or not claim_id.strip():
            result["errors"].append(f"Claim at index {index} is missing claim_id.")
            continue
        if not isinstance(claim_text, str) or not claim_text.strip():
            result["errors"].append(f"Claim '{claim_id}' is missing claim_text.")
            continue
        match = matches_by_id.get(claim_id)
        if match is None:
            result["assessments"].append(
                {
                    "claim_id": claim_id,
                    "claim_text": claim_text,
                    "assessment": "no_retrieved_evidence",
                    "detail_assessments": [],
                    "evidence": [],
                    "reasons": [
                        "This is a deterministic text-level assessment, not a truth verdict.",
                        "No matcher result was supplied for this claim.",
                    ],
                }
            )
            continue
        result["assessments"].append(_assess_one(claim, match))

    if not result["assessments"] and result["errors"]:
        result["status"] = "error"
    elif result["errors"]:
        result["status"] = "completed_with_errors"
    else:
        result["status"] = "completed"
    return result
