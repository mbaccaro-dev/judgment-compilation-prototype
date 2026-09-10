"""Finds possible rule statements in document text."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any, Iterator

from .documentary_projection import (
    DEFAULT_ROOT,
    MANIFEST_SHA256,
    DocumentaryProjection,
)


SCHEMA = "jc/raw-judgment-candidates/1"
STATUS_PROPOSED = "PROPOSED_INTERPRETATION"
STATUS_UNRESOLVED = "UNRESOLVED"
CLAIM_CEILING = (
    "RAW_SOURCE_SIGNAL_ONLY;NO_ADMISSION_OR_ENTAILMENT_OR_APPLICABILITY_OR_"
    "COMPLIANCE_OR_RESPONSIBILITY_OR_EFFECT_OR_HIERARCHY_DERIVED_PRECEDENCE"
)


class RawJudgmentCandidateError(ValueError):
    """The candidate boundary received an invalid projection or record."""


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise RawJudgmentCandidateError(message)


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return sha256(_canonical(value)).hexdigest()


# Each pattern matches an exact text form.
_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("NORMATIVE_MODAL", "normative", re.compile(r"\b(?:shall|must|required|requirement|should|may not|must not)\b", re.I)),
    ("CONDITIONAL_TRIGGER", "conditional", re.compile(r"\b(?:if|when|where|upon|provided that|in the event|before|after)\b", re.I)),
    ("EXCEPTION_SIGNAL", "exception", re.compile(r"\b(?:except|unless|however|notwithstanding|waiver|exemption)\b", re.I)),
    ("EXPLICIT_PRECEDENCE_SIGNAL", "precedence", re.compile(r"\b(?:takes precedence|prevails?|supersedes|overrides|priority over)\b", re.I)),
    ("CONSTRAINT_SIGNAL", "constraint", re.compile(r"\b(?:limited to|only|at least|at most|no more than|cannot|may not|must not)\b", re.I)),
    ("DEPENDENCY_SIGNAL", "dependency", re.compile(r"\b(?:depends on|dependent on|prerequisite|requires|contingent on|subject to)\b", re.I)),
)
_CLAUSE_BREAK = re.compile(r"[.!?;](?=\s|$)")
_PROPOSED_KINDS = frozenset({"normative", "constraint", "dependency"})


def _clause_span(text: str, offset: int) -> tuple[int, int]:
    """Return an extracted-text span containing the requested offset."""

    start = 0
    for boundary in _CLAUSE_BREAK.finditer(text, 0, offset):
        start = boundary.end()
    end = len(text)
    next_boundary = _CLAUSE_BREAK.search(text, offset)
    if next_boundary is not None:
        end = next_boundary.end()
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    _need(start <= offset < end, "signal escaped extracted clause")
    return start, end


def _signals(clause: str) -> dict[str, list[str]]:
    result = {"modality": [], "condition": [], "exception": []}
    for pattern_id, kind, pattern in _PATTERNS:
        del pattern_id
        matches = sorted(
            {match.group(0) for match in pattern.finditer(clause)},
            key=lambda value: (value.casefold(), value),
        )
        if kind in {"normative", "constraint"}:
            result["modality"].extend(matches)
        elif kind == "conditional":
            result["condition"].extend(matches)
        elif kind == "exception":
            result["exception"].extend(matches)
    return {
        key: sorted(set(values), key=lambda value: (value.casefold(), value))
        for key, values in result.items()
    }


def _status(kind: str) -> str:
    # A lexical condition, exception, or precedence phrase is insufficient to
    # propose a completed relationship.  Explicit precedence is retained as
    # distinct evidence but is still not a resolved winner.
    return STATUS_PROPOSED if kind in _PROPOSED_KINDS else STATUS_UNRESOLVED


def _candidate(page: dict[str, Any], pattern_id: str, kind: str,
               match: re.Match[str]) -> dict[str, Any]:
    text = page["text"]
    start, end = _clause_span(text, match.start())
    quote = text[start:end]
    candidate_key = {
        "document_index": page["document_index"],
        "publication_id": page["publication_id"],
        "pdf_page_number": page["pdf_page_number"],
        "page_text_sha256": page["text_sha256"],
        "character_span": [start, end],
        "pattern_id": pattern_id,
        "pattern_span": [match.start(), match.end()],
        "matched_text": match.group(0),
    }
    return {
        "schema": SCHEMA,
        "candidate_id": "raw-judgment:" + _digest(candidate_key),
        "status": _status(kind),
        "pattern_id": pattern_id,
        "pattern_kind": kind,
        "matched_text": match.group(0),
        "source": {
            "document_index": page["document_index"],
            "publication_id": page["publication_id"],
            "pdf_page_index": page["pdf_page_index"],
            "pdf_page_number": page["pdf_page_number"],
            "source_file": dict(page["source_file"]),
            "source_sha256": page["source_sha256"],
            "extracted_file": dict(page["extracted_file"]),
            "page_text_sha256": page["text_sha256"],
            "manifest_sha256": page["manifest_sha256"],
            "character_span": {"start": start, "end": end, "interval": "HALF_OPEN", "unit": "UNICODE_CODE_POINT"},
            "lexical_match_character_span": {
                "start": match.start(),
                "end": match.end(),
                "interval": "HALF_OPEN",
                "unit": "UNICODE_CODE_POINT",
            },
            "exact_quote": quote,
            "exact_quote_sha256": sha256(quote.encode("utf-8")).hexdigest(),
        },
        "lexical_signals": _signals(quote),
        "precedence": {
            "explicit_precedence_signal": kind == "precedence",
            "resolved_winner": None,
            "hierarchy_is_precedence": False,
        },
        "evidence": {
            "present_source_evidence": "EXACT_EXTRACTED_TEXT",
            "absent_evidence": [],
            "conflicting_evidence": [],
            "conflict_status": "NO_CONFLICT_RESOLUTION_PERFORMED",
        },
        "semantic_disposition": {
            "admission": "NOT_ADMITTED",
            "applicability": None,
            "compliance": None,
            "responsibility": None,
            "external_effects": [],
        },
        "claim_ceiling": CLAIM_CEILING,
    }


def iter_raw_judgment_candidates(
    projection: DocumentaryProjection | None = None,
    *,
    root: Path | str = DEFAULT_ROOT,
    manifest_sha256: str = MANIFEST_SHA256,
    publication_id: str | None = None,
) -> Iterator[dict[str, Any]]:
    """Stream rule-statement matches from verified document pages."""

    _need(projection is None or (root == DEFAULT_ROOT and manifest_sha256 == MANIFEST_SHA256),
          "supply either a projection or root binding, not both")
    active = projection or DocumentaryProjection(root, manifest_sha256)
    _need(isinstance(active, DocumentaryProjection), "unsupported documentary projection")
    for page in active.iter_pages(view="plain", publication_id=publication_id):
        _need(page.get("record_type") == "PAGE" and page.get("view") == "plain", "invalid plain-page record")
        text = page.get("text")
        _need(type(text) is str, "page text unavailable")
        for pattern_id, kind, pattern in _PATTERNS:
            for match in pattern.finditer(text):
                yield _candidate(page, pattern_id, kind, match)


def summarize_raw_judgment_candidates(
    projection: DocumentaryProjection | None = None,
    *,
    root: Path | str = DEFAULT_ROOT,
    manifest_sha256: str = MANIFEST_SHA256,
) -> dict[str, Any]:
    """Scan the entire bound library and return compact deterministic accounting."""

    _need(projection is None or (root == DEFAULT_ROOT and manifest_sha256 == MANIFEST_SHA256),
          "supply either a projection or root binding, not both")
    active = projection or DocumentaryProjection(root, manifest_sha256)
    summary = active.summary()
    count = 0
    by_pattern: dict[str, int] = {}
    digest = sha256()
    for candidate in iter_raw_judgment_candidates(active):
        count += 1
        by_pattern[candidate["pattern_id"]] = by_pattern.get(candidate["pattern_id"], 0) + 1
        digest.update(_canonical(candidate))
        digest.update(b"\n")
    return {
        "schema": SCHEMA,
        "manifest_sha256": summary["manifest_sha256"],
        "corpus_id": summary["corpus_id"],
        "corpus_release": summary["corpus_release"],
        "document_count": summary["document_count"],
        "physical_page_count": summary["physical_page_count"],
        "processed_plain_page_count": summary["physical_page_count"],
        "candidate_count": count,
        "candidate_count_by_pattern": dict(sorted(by_pattern.items())),
        "candidate_stream_sha256": digest.hexdigest(),
        "admission": "NOT_ADMITTED",
        "claim_ceiling": CLAIM_CEILING,
    }
