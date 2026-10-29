"""Offline-friendly orchestration for CERBERUS evidence processing.

This module consumes an existing completed Nightwatch/Phoenix-shaped result.
It never starts TinyFish research or calls Phoenix.  A result with an
ineligible research status is returned as ``skipped``.  Stage failures are
preserved explicitly; a usable partial pipeline returns
``completed_with_errors``.  Fatal input or orchestration failures return
``error``.  Unavailable stage outputs are represented by ``None`` for
claim extraction, matching, and assessment, and by an empty list for
retrieval results.
"""

from typing import Any, Callable, Dict, List, Optional

from agents.claim_extractor import extract_claims
from agents.evidence_assessor import assess_claim_evidence
from agents.evidence_matcher import match_claims_to_evidence
from agents.source_retriever import retrieve_source


StageFunction = Callable[..., Dict[str, Any]]
_RETRIEVAL_STATUSES = {
    "retrieved",
    "invalid_url",
    "unsupported_url",
    "malformed_url",
    "blocked_destination",
    "http_error",
    "redirect_limit_exceeded",
    "unsupported_content_type",
    "response_too_large",
    "empty_response",
    "timeout",
    "network_error",
    "parse_error",
    "pipeline_error",
}


def _result(
    status: str,
    research_result: Any,
    *,
    claim_extraction: Optional[Dict[str, Any]] = None,
    retrieval_results: Optional[List[Dict[str, Any]]] = None,
    evidence_matches: Optional[Dict[str, Any]] = None,
    evidence_assessment: Optional[Dict[str, Any]] = None,
    errors: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return {
        "status": status,
        "research_result": research_result,
        "claim_extraction": claim_extraction,
        "retrieval_results": retrieval_results if retrieval_results is not None else [],
        "evidence_matches": evidence_matches,
        "evidence_assessment": evidence_assessment,
        "errors": errors if errors is not None else [],
    }


def _stage_error(stage: str, exc: BaseException) -> str:
    return f"{stage} raised {type(exc).__name__}."


def _valid_claim_extraction(result: Any) -> bool:
    return (
        isinstance(result, dict)
        and result.get("status") in {"completed", "empty"}
        and isinstance(result.get("claims"), list)
        and (result.get("error") is None or result.get("status") == "empty")
    )


def _valid_matcher_result(result: Any) -> bool:
    return (
        isinstance(result, dict)
        and result.get("status") in {"empty", "completed", "completed_with_errors"}
        and isinstance(result.get("matches"), list)
        and isinstance(result.get("unresolved_citations"), list)
        and isinstance(result.get("errors"), list)
    )


def _valid_assessor_result(result: Any) -> bool:
    return (
        isinstance(result, dict)
        and result.get("status") in {"empty", "completed", "completed_with_errors"}
        and isinstance(result.get("assessments"), list)
        and isinstance(result.get("errors"), list)
    )


def _failed_retrieval(url: str, exc: BaseException) -> Dict[str, Any]:
    return {
        "url": url,
        "final_url": None,
        "status_code": None,
        "title": None,
        "text": "",
        "retrieval_status": "pipeline_error",
        "error": f"Source retriever raised {type(exc).__name__}.",
    }


def _invalid_retrieval(url: str, reason: str) -> Dict[str, Any]:
    return {
        "url": url,
        "final_url": None,
        "status_code": None,
        "title": None,
        "text": "",
        "retrieval_status": "pipeline_error",
        "error": f"Invalid source retrieval result: {reason}",
    }


def _validate_retrieval(url: str, retrieval: Any) -> Optional[str]:
    if not isinstance(retrieval, dict):
        return "result must be a dictionary."
    required_fields = {
        "url",
        "final_url",
        "status_code",
        "title",
        "text",
        "retrieval_status",
        "error",
    }
    missing = sorted(required_fields - retrieval.keys())
    if missing:
        return f"missing required fields: {', '.join(missing)}."
    if not isinstance(retrieval["url"], str) or not retrieval["url"].strip():
        return "url must be a non-empty string."
    if retrieval["url"].strip() != url:
        return "returned url does not match the requested URL."
    if not isinstance(retrieval["text"], str):
        return "text must be a string."
    status = retrieval["retrieval_status"]
    if not isinstance(status, str) or not status.strip():
        return "retrieval_status must be a non-empty string."
    if status not in _RETRIEVAL_STATUSES:
        return f"retrieval_status '{status}' is not recognized."
    if retrieval["final_url"] is not None and not isinstance(retrieval["final_url"], str):
        return "final_url must be a string or None."
    if retrieval["status_code"] is not None and not isinstance(retrieval["status_code"], int):
        return "status_code must be an integer or None."
    if retrieval["title"] is not None and not isinstance(retrieval["title"], str):
        return "title must be a string or None."
    if retrieval["error"] is not None and not isinstance(retrieval["error"], str):
        return "error must be a string or None."
    return None


def build_evidence_pipeline(
    research_result: Any,
    *,
    claim_extractor: StageFunction = extract_claims,
    source_retriever: StageFunction = retrieve_source,
    evidence_matcher: StageFunction = match_claims_to_evidence,
    evidence_assessor: StageFunction = assess_claim_evidence,
) -> Dict[str, Any]:
    """Build derived claim/evidence data from an existing research result."""
    if not isinstance(research_result, dict):
        return _result(
            "skipped",
            research_result,
            errors=["Research result must be a dictionary."],
        )

    if (
        research_result.get("success") is not True
        or research_result.get("status") != "completed"
        or not isinstance(research_result.get("report"), str)
        or not research_result.get("report").strip()
    ):
        return _result(
            "skipped",
            research_result,
            errors=["Research result is not eligible for evidence processing."],
        )

    errors: List[str] = []
    try:
        claim_extraction = claim_extractor(research_result["report"])
    except Exception as exc:
        return _result(
            "error",
            research_result,
            errors=[_stage_error("Claim extraction", exc)],
        )

    if not _valid_claim_extraction(claim_extraction):
        return _result(
            "error",
            research_result,
            claim_extraction=claim_extraction
            if isinstance(claim_extraction, dict)
            else None,
            errors=["Claim extraction returned an invalid or failed result."],
        )

    claims = claim_extraction["claims"]
    raw_source_records = research_result.get("source_records", [])
    if raw_source_records is None:
        source_records = []
    elif isinstance(raw_source_records, list):
        source_records = raw_source_records
    else:
        return _result(
            "error",
            research_result,
            claim_extraction=claim_extraction,
            errors=["source_records must be a list when supplied."],
        )

    retrieval_results: List[Dict[str, Any]] = []
    seen_urls = set()
    for index, source_record in enumerate(source_records):
        if not isinstance(source_record, dict):
            errors.append(f"Source record at index {index} is not an object.")
            continue
        url = source_record.get("url")
        if not isinstance(url, str) or not url.strip():
            errors.append(f"Source record at index {index} has no non-empty URL.")
            continue
        clean_url = url.strip()
        if clean_url in seen_urls:
            continue
        seen_urls.add(clean_url)
        try:
            retrieval = source_retriever(clean_url)
        except Exception as exc:
            retrieval_results.append(_failed_retrieval(clean_url, exc))
            errors.append(f"Source retrieval failed for {clean_url}.")
            continue
        validation_error = _validate_retrieval(clean_url, retrieval)
        if validation_error:
            errors.append(
                f"Source retriever returned an invalid result for {clean_url}: "
                f"{validation_error}"
            )
            retrieval_results.append(_invalid_retrieval(clean_url, validation_error))
            continue
        retrieval_results.append(retrieval)
        if retrieval["retrieval_status"] != "retrieved":
            errors.append(
                f"Source retrieval did not succeed for {clean_url}: "
                f"{retrieval['retrieval_status']}."
            )

    if not claims:
        try:
            evidence_matches = evidence_matcher(
                claims, source_records, retrieval_results
            )
        except Exception as exc:
            return _result(
                "error",
                research_result,
                claim_extraction=claim_extraction,
                retrieval_results=retrieval_results,
                errors=errors + [_stage_error("Evidence matching", exc)],
            )
        if not _valid_matcher_result(evidence_matches):
            return _result(
                "error",
                research_result,
                claim_extraction=claim_extraction,
                retrieval_results=retrieval_results,
                evidence_matches=evidence_matches
                if isinstance(evidence_matches, dict)
                else None,
                errors=errors + ["Evidence matcher returned an invalid result."],
            )
        if evidence_matches.get("errors"):
            errors.extend(
                f"Evidence matcher: {message}"
                for message in evidence_matches["errors"]
            )
        try:
            evidence_assessment = evidence_assessor(
                claims,
                evidence_matches,
                retrieval_results=retrieval_results,
            )
        except Exception as exc:
            return _result(
                "error",
                research_result,
                claim_extraction=claim_extraction,
                retrieval_results=retrieval_results,
                evidence_matches=evidence_matches,
                errors=errors + [_stage_error("Evidence assessment", exc)],
            )
        if not _valid_assessor_result(evidence_assessment):
            return _result(
                "error",
                research_result,
                claim_extraction=claim_extraction,
                retrieval_results=retrieval_results,
                evidence_matches=evidence_matches,
                evidence_assessment=evidence_assessment
                if isinstance(evidence_assessment, dict)
                else None,
                errors=errors + ["Evidence assessor returned an invalid result."],
            )
        if evidence_assessment.get("errors"):
            errors.extend(
                f"Evidence assessor: {message}"
                for message in evidence_assessment["errors"]
            )
        return _result(
            "completed_with_errors" if errors else "completed",
            research_result,
            claim_extraction=claim_extraction,
            retrieval_results=retrieval_results,
            evidence_matches=evidence_matches,
            evidence_assessment=evidence_assessment,
            errors=errors,
        )

    try:
        evidence_matches = evidence_matcher(
            claims, source_records, retrieval_results
        )
    except Exception as exc:
        return _result(
            "error",
            research_result,
            claim_extraction=claim_extraction,
            retrieval_results=retrieval_results,
            errors=errors + [_stage_error("Evidence matching", exc)],
        )
    if not _valid_matcher_result(evidence_matches):
        return _result(
            "error",
            research_result,
            claim_extraction=claim_extraction,
            retrieval_results=retrieval_results,
            evidence_matches=evidence_matches
            if isinstance(evidence_matches, dict)
            else None,
            errors=errors + ["Evidence matcher returned an invalid result."],
        )
    if evidence_matches.get("errors"):
        errors.extend(
            f"Evidence matcher: {message}"
            for message in evidence_matches["errors"]
        )

    try:
        evidence_assessment = evidence_assessor(
            claims,
            evidence_matches,
            retrieval_results=retrieval_results,
        )
    except Exception as exc:
        return _result(
            "error",
            research_result,
            claim_extraction=claim_extraction,
            retrieval_results=retrieval_results,
            evidence_matches=evidence_matches,
            errors=errors + [_stage_error("Evidence assessment", exc)],
        )
    if not _valid_assessor_result(evidence_assessment):
        return _result(
            "error",
            research_result,
            claim_extraction=claim_extraction,
            retrieval_results=retrieval_results,
            evidence_matches=evidence_matches,
            evidence_assessment=evidence_assessment
            if isinstance(evidence_assessment, dict)
            else None,
            errors=errors + ["Evidence assessor returned an invalid result."],
        )
    if evidence_assessment.get("errors"):
        errors.extend(
            f"Evidence assessor: {message}"
            for message in evidence_assessment["errors"]
        )

    return _result(
        "completed_with_errors" if errors else "completed",
        research_result,
        claim_extraction=claim_extraction,
        retrieval_results=retrieval_results,
        evidence_matches=evidence_matches,
        evidence_assessment=evidence_assessment,
        errors=errors,
    )
