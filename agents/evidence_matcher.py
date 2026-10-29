"""Deterministic candidate matching between claims and retrieved source text."""

import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


_TOKEN_RE = re.compile(r"[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)*")
_STOP_WORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from",
    "in", "is", "it", "of", "on", "or", "that", "the", "this", "to",
    "was", "were", "with", "which",
}


def _empty_result(status: str = "empty") -> Dict[str, Any]:
    return {
        "status": status,
        "matches": [],
        "unresolved_citations": [],
        "errors": [],
    }


def _citation_number(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value > 0:
        return value
    if isinstance(value, str) and value.strip().isdigit():
        number = int(value.strip())
        return number if number > 0 else None
    return None


def _valid_url(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _normalize_tokens(text: str) -> List[str]:
    return [
        token.lower()
        for token in _TOKEN_RE.findall(text)
        if token.lower() not in _STOP_WORDS
    ]


def _identifier_pattern(identifier: str) -> re.Pattern[str]:
    escaped = re.escape(identifier.strip())
    return re.compile(
        rf"(?<![A-Za-z0-9]){escaped}(?![A-Za-z0-9])",
        re.IGNORECASE,
    )


def _segments(text: str) -> Iterable[Tuple[int, int, str]]:
    """Yield readable sentence/line segments with offsets into the original text."""
    pattern = re.compile(r".+?(?:[.!?]+(?=\s|$)|\n+|$)", re.DOTALL)
    for match in pattern.finditer(text):
        start, end = match.span()
        segment = match.group(0).strip()
        if not segment:
            continue
        leading = len(match.group(0)) - len(match.group(0).lstrip())
        trailing = len(match.group(0)) - len(match.group(0).rstrip())
        start += leading
        end -= trailing
        if start < end:
            yield start, end, text[start:end]


def _evidence(
    retrieval: Dict[str, Any],
    start: int,
    end: int,
    method: str,
    citation_number: Optional[int],
) -> Dict[str, Any]:
    return {
        "url": retrieval["url"],
        "final_url": retrieval.get("final_url"),
        "passage": retrieval["text"][start:end],
        "start": start,
        "end": end,
        "match_method": method,
        "citation_number": citation_number,
    }


def _deduplicate_evidence(evidence: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    result = []
    for item in evidence:
        key = (
            item["url"],
            item["start"],
            item["end"],
            item["match_method"],
            item["citation_number"],
        )
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _match_identifiers(
    claim: Dict[str, Any],
    retrieval: Dict[str, Any],
    citation_number: Optional[int],
) -> List[Dict[str, Any]]:
    evidence: List[Dict[str, Any]] = []
    identifiers = claim.get("related_identifiers", [])
    if not isinstance(identifiers, list):
        return evidence

    text = retrieval["text"]
    for identifier in identifiers:
        if not isinstance(identifier, str) or not identifier.strip():
            continue
        pattern = _identifier_pattern(identifier)
        for match in pattern.finditer(text):
            segment = next(
                (
                    (start, end)
                    for start, end, _ in _segments(text)
                    if start <= match.start() < end
                ),
                (match.start(), match.end()),
            )
            evidence.append(
                _evidence(
                    retrieval,
                    segment[0],
                    segment[1],
                    "identifier",
                    citation_number,
                )
            )
    return evidence


def _match_phrase_overlap(
    claim: Dict[str, Any],
    retrieval: Dict[str, Any],
    citation_number: Optional[int],
    min_overlap: int,
) -> List[Dict[str, Any]]:
    claim_tokens = set(_normalize_tokens(claim["claim_text"]))
    if len(claim_tokens) < min_overlap:
        return []

    evidence: List[Dict[str, Any]] = []
    for start, end, passage in _segments(retrieval["text"]):
        source_tokens = set(_normalize_tokens(passage))
        if len(claim_tokens & source_tokens) >= min_overlap:
            evidence.append(
                _evidence(
                    retrieval,
                    start,
                    end,
                    "phrase_overlap",
                    citation_number,
                )
            )
    return evidence


def _prepare_inputs(
    source_records: Sequence[dict],
    retrieval_results: Sequence[dict],
) -> Tuple[Dict[int, List[Dict[str, Any]]], Dict[str, Dict[str, Any]], List[str]]:
    errors: List[str] = []
    citation_index: Dict[int, List[Dict[str, Any]]] = {}
    if not isinstance(source_records, (list, tuple)):
        errors.append("source_records must be a sequence.")
        source_records = []
    for index, record in enumerate(source_records):
        if not isinstance(record, dict):
            errors.append(f"Source record at index {index} must be an object.")
            continue
        url = record.get("url")
        if not _valid_url(url):
            errors.append(f"Source record at index {index} is missing a valid url.")
            continue
        number = _citation_number(record.get("citation_number"))
        if record.get("citation_number") is not None and number is None:
            errors.append(f"Source record at index {index} has an invalid citation_number.")
        if number is not None:
            citation_index.setdefault(number, []).append(record)

    retrieval_index: Dict[str, Dict[str, Any]] = {}
    if not isinstance(retrieval_results, (list, tuple)):
        errors.append("retrieval_results must be a sequence.")
        retrieval_results = []
    for index, retrieval in enumerate(retrieval_results):
        if not isinstance(retrieval, dict):
            errors.append(f"Retrieval result at index {index} must be an object.")
            continue
        url = retrieval.get("url")
        text = retrieval.get("text")
        if not _valid_url(url) or not isinstance(text, str):
            errors.append(f"Retrieval result at index {index} is missing url or text.")
            continue
        if retrieval.get("retrieval_status") != "retrieved":
            continue
        retrieval_index.setdefault(url.strip(), retrieval)

    return citation_index, retrieval_index, errors


def match_claims_to_evidence(
    claims: Sequence[dict],
    source_records: Sequence[dict],
    retrieval_results: Sequence[dict],
    *,
    min_overlap: int = 2,
) -> Dict[str, Any]:
    """Return deterministic candidate passages without assigning truth."""
    result = _empty_result()
    if not isinstance(claims, (list, tuple)):
        result["status"] = "error"
        result["errors"].append("claims must be a sequence.")
        return result
    if not claims:
        return result
    if not isinstance(min_overlap, int) or isinstance(min_overlap, bool) or min_overlap < 1:
        result["status"] = "error"
        result["errors"].append("min_overlap must be a positive integer.")
        return result

    citation_index, retrieval_index, errors = _prepare_inputs(
        source_records, retrieval_results
    )
    result["errors"].extend(errors)

    valid_claims = 0
    for index, claim in enumerate(claims):
        if not isinstance(claim, dict):
            result["errors"].append(f"Claim at index {index} must be an object.")
            continue
        claim_id = claim.get("claim_id")
        claim_text = claim.get("claim_text")
        if not isinstance(claim_id, str) or not claim_id.strip():
            result["errors"].append(f"Claim at index {index} is missing claim_id.")
            continue
        if not isinstance(claim_text, str) or not claim_text.strip():
            result["errors"].append(f"Claim at index {index} is missing claim_text.")
            continue
        valid_claims += 1

        markers = claim.get("source_citation_markers", [])
        if markers is None:
            markers = []
        if not isinstance(markers, list):
            result["errors"].append(f"Claim '{claim_id}' has invalid citation markers.")
            markers = []

        candidate_retrievals: List[Tuple[Dict[str, Any], Optional[int]]] = []
        unresolved = []
        ambiguous = []
        if markers:
            seen_markers = set()
            for marker in markers:
                number = _citation_number(marker)
                if number is None:
                    unresolved.append((marker, "invalid citation marker"))
                    continue
                if number in seen_markers:
                    continue
                seen_markers.add(number)
                records = citation_index.get(number, [])
                if not records:
                    unresolved.append((number, "no source record has this citation number"))
                    continue
                if len(records) > 1:
                    ambiguous.append((number, records))
                    continue
                source_url = records[0]["url"].strip()
                retrieval = retrieval_index.get(source_url)
                if retrieval is not None:
                    candidate_retrievals.append((retrieval, number))
                else:
                    unresolved.append((number, "cited source has no successful retrieval"))
        else:
            candidate_retrievals = [
                (retrieval, None) for retrieval in retrieval_index.values()
            ]

        for marker, reason in unresolved:
            item = {"claim_id": claim_id, "citation_number": marker, "reason": reason}
            result["unresolved_citations"].append(item)
        for marker, records in ambiguous:
            result["unresolved_citations"].append(
                {
                    "claim_id": claim_id,
                    "citation_number": marker,
                    "reason": "citation number is ambiguous.",
                    "urls": [record["url"] for record in records],
                }
            )

        evidence: List[Dict[str, Any]] = []
        for retrieval, citation_number in candidate_retrievals:
            evidence.extend(_match_identifiers(claim, retrieval, citation_number))
        if not evidence:
            for retrieval, citation_number in candidate_retrievals:
                evidence.extend(
                    _match_phrase_overlap(
                        claim, retrieval, citation_number, min_overlap
                    )
                )
        evidence = _deduplicate_evidence(evidence)

        if ambiguous:
            match_status = "citation_ambiguous"
        elif unresolved:
            match_status = "citation_unresolved"
        elif evidence:
            match_status = "matched"
        else:
            match_status = "unmatched"

        result["matches"].append(
            {
                "claim_id": claim_id,
                "claim_text": claim_text,
                "match_status": match_status,
                "evidence": evidence,
            }
        )

    if valid_claims == 0:
        result["status"] = "error"
    elif result["errors"]:
        result["status"] = "completed_with_errors"
    else:
        result["status"] = "completed"
    return result
