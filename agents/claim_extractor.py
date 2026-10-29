"""Deterministic, injectable extraction of factual cybersecurity claims."""

import re
from typing import Any, Callable, Dict, List, Optional


ClaimRecord = Dict[str, Any]
Extractor = Callable[[str], Any]

_CITATION_PATTERN = re.compile(r"\[(\d+)\]")
_CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_VERSION_PATTERN = re.compile(
    r"\b(?:version\s+)?\d+(?:\.\d+)+(?:[-+._][A-Za-z0-9.-]+)?\b",
    re.IGNORECASE,
)

_CLAIM_TYPE_PATTERNS = (
    ("affected_versions", re.compile(r"\b(affect|affected|impact|impacted|vulnerable|version)\b", re.I)),
    ("exploitation", re.compile(r"\b(exploit|exploited|exploitation|attack|attacker|backdoor)\b", re.I)),
    ("mitigation", re.compile(r"\b(mitigat|remediat|patch|update|upgrade|downgrad|workaround)\w*\b", re.I)),
    ("vulnerability", re.compile(r"\b(vulnerab|flaw|injection|overflow|bypass|execution)\w*\b", re.I)),
    ("advisory", re.compile(r"\b(advisory|alert|bulletin|disclos|severity|security issue)\w*\b", re.I)),
)


def _claim_type(claim_text: str) -> str:
    for claim_type, pattern in _CLAIM_TYPE_PATTERNS:
        if pattern.search(claim_text):
            return claim_type
    return "other"


def _identifiers(claim_text: str) -> List[str]:
    identifiers = [match.upper() for match in _CVE_PATTERN.findall(claim_text)]
    for match in _VERSION_PATTERN.findall(claim_text):
        if match not in identifiers:
            identifiers.append(match)
    return identifiers


def _citations(claim_text: str) -> List[int]:
    seen = set()
    markers: List[int] = []
    for match in _CITATION_PATTERN.finditer(claim_text):
        marker = int(match.group(1))
        if marker not in seen:
            seen.add(marker)
            markers.append(marker)
    return markers


def _record(claim_text: str, claim_id: str) -> ClaimRecord:
    return {
        "claim_id": claim_id,
        "claim_text": claim_text,
        "claim_type": _claim_type(claim_text),
        "related_identifiers": _identifiers(claim_text),
        "source_citation_markers": _citations(claim_text),
    }


def _deterministic_extract(report: str) -> List[ClaimRecord]:
    claims: List[ClaimRecord] = []
    for sentence in re.split(r"(?<=[.!?])\s+|\n+", report.strip()):
        claim_text = sentence.strip()
        if not claim_text or not re.search(r"[A-Za-z]", claim_text):
            continue
        claims.append(_record(claim_text, f"claim-{len(claims) + 1}"))
    return claims


def _normalize_model_output(output: Any) -> List[ClaimRecord]:
    if not isinstance(output, list):
        raise ValueError("Extractor output must be a list of claim records.")

    normalized: List[ClaimRecord] = []
    for index, item in enumerate(output, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"Claim at index {index - 1} must be an object.")
        claim_text = item.get("claim_text")
        if not isinstance(claim_text, str) or not claim_text.strip():
            raise ValueError(f"Claim at index {index - 1} is missing claim_text.")

        record = _record(claim_text, str(item.get("claim_id") or f"claim-{index}"))
        if isinstance(item.get("claim_type"), str) and item["claim_type"].strip():
            record["claim_type"] = item["claim_type"]
        if isinstance(item.get("related_identifiers"), list):
            record["related_identifiers"] = item["related_identifiers"]
        if isinstance(item.get("source_citation_markers"), list):
            record["source_citation_markers"] = item["source_citation_markers"]
        normalized.append(record)
    return normalized


def extract_claims(
    report: str,
    extractor: Optional[Extractor] = None,
) -> Dict[str, Any]:
    """Extract structured claims without assigning truth or confidence.

    An injected extractor may return a list of claim dictionaries. Its output is
    normalized and validated; failures are returned explicitly.
    """
    if not isinstance(report, str) or not report.strip():
        return {
            "status": "empty",
            "claims": [],
            "error": "Report is empty.",
        }

    try:
        raw_claims = (
            _deterministic_extract(report)
            if extractor is None
            else extractor(report)
        )
        claims = (
            raw_claims
            if extractor is None
            else _normalize_model_output(raw_claims)
        )
        return {
            "status": "completed",
            "claims": claims,
            "error": None,
        }
    except Exception as exc:
        return {
            "status": "error",
            "claims": [],
            "error": f"Claim extraction failed: {type(exc).__name__}: {exc}",
        }
