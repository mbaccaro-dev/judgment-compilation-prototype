"""Finds possible operations and sequences in document text."""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import re
import unicodedata
from typing import Any, Iterator

from .documentary_projection import (
    DEFAULT_ROOT,
    MANIFEST_SHA256,
    DocumentaryProjection,
    DocumentaryProjectionError,
)


SCHEMA = "jc/raw-work-architecture-candidates/1"
NAMESPACE = "jc-raw-work-architecture-candidate"
PROPOSED = "PROPOSED_INTERPRETATION"
UNRESOLVED = "UNRESOLVED"
CEILING = (
    "SOURCE_BOUND_RAW_WORK_ARCHITECTURE_CANDIDATE_ONLY;NO_SEMANTIC_ADMISSION_OR_"
    "EXECUTABLE_OPERATION_OR_PROGRAM_OR_APPLICABILITY_OR_COMPLIANCE_OR_"
    "RESPONSIBILITY_OR_EXTERNAL_EFFECT"
)


class RawWorkArchitectureCandidateError(ValueError):
    """A candidate, source binding, or re-derivation is invalid."""


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise RawWorkArchitectureCandidateError(message)


def canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise RawWorkArchitectureCandidateError("invalid canonical candidate JSON") from exc


def digest(value: Any) -> str:
    return sha256(canonical(value)).hexdigest()


def normalize_quote(value: str) -> str:
    _need(type(value) is str, "quote must be text")
    return " ".join(unicodedata.normalize("NFC", value).split())


def _trim(text: str, start: int, end: int) -> tuple[int, int, str]:
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    return start, end, text[start:end]


def _sentence_spans(text: str) -> Iterator[tuple[int, int, str]]:
    start = 0
    for match in re.finditer(r"[.!?;](?=\s|$)", text):
        end = match.end()
        left, right, quote = _trim(text, start, end)
        if quote:
            yield left, right, quote
        start = end
    left, right, quote = _trim(text, start, len(text))
    if quote:
        yield left, right, quote


# Each pattern matches a small set of explicit action or sequence words.
_RULES: tuple[tuple[str, str, str, re.Pattern[str]], ...] = (
    ("ASSESS_OPERATION_SIGNAL", "WORK_OPERATION_INTERFACE", "ASSESS",
     re.compile(r"\b(?:assess|assesses|assessed|assessment|assessments)\b", re.I)),
    ("MONITOR_OPERATION_SIGNAL", "WORK_OPERATION_INTERFACE", "MONITOR",
     re.compile(r"\b(?:monitor|monitors|monitored|monitoring)\b", re.I)),
    ("REVIEW_OPERATION_SIGNAL", "WORK_OPERATION_INTERFACE", "REVIEW",
     re.compile(r"\b(?:review|reviews|reviewed|reviewing)\b", re.I)),
    ("REPORT_OPERATION_SIGNAL", "WORK_OPERATION_INTERFACE", "REPORT",
     re.compile(r"\b(?:report|reports|reported|reporting)\b", re.I)),
    ("AUTHORIZE_OPERATION_SIGNAL", "WORK_OPERATION_INTERFACE", "AUTHORIZE",
     re.compile(r"\b(?:authorize|authorizes|authorized|authorization)\b", re.I)),
    ("PERFORM_OPERATION_SIGNAL", "WORK_OPERATION_INTERFACE", "PERFORM",
     re.compile(r"\b(?:perform|performs|performed|performing)\b", re.I)),
    ("EXPLICIT_DEPENDENCY_SIGNAL", "ARCHITECTURE_COMPOSITION", "DEPENDENCY",
     re.compile(r"\b(?:depends on|dependent on|prerequisite|requires|contingent on|subject to)\b", re.I)),
    ("EXPLICIT_SEQUENCE_SIGNAL", "ARCHITECTURE_COMPOSITION", "SEQUENCE",
     re.compile(r"\b(?:before|after|following|prior to|subsequent to)\b", re.I)),
    ("COORDINATION_SIGNAL", "ARCHITECTURE_COMPOSITION", "COORDINATION",
     re.compile(r"\b(?:in coordination with|in conjunction with|as part of)\b", re.I)),
)


def _candidate_id(*, page: dict[str, Any], character_span: list[int],
                  pattern_id: str, exact_quote_sha256: str) -> str:
    return NAMESPACE + ":" + digest({
        "publication_id": page["publication_id"],
        "pdf_sha256": page["source_sha256"],
        "physical_page_index": page["pdf_page_index"],
        "character_span": character_span,
        "pattern_id": pattern_id,
        "exact_quote_sha256": exact_quote_sha256,
    })


def _unimplemented_shape(candidate_kind: str, operation_or_relation: str) -> dict[str, Any]:
    if candidate_kind == "WORK_OPERATION_INTERFACE":
        return {
            "proposed_operation_kind": operation_or_relation,
            "input_bindings": None,
            "output_binding": None,
            "implementation": None,
            "execution_status": UNRESOLVED,
        }
    return {
        "proposed_composition_kind": operation_or_relation,
        "upstream_operation": None,
        "downstream_operation": None,
        "branch_condition": None,
        "program": None,
        "execution_status": UNRESOLVED,
    }


class RawWorkArchitectureCandidates:
    """Stream exact-text proposals for Work and Architecture review."""

    def __init__(self, root=DEFAULT_ROOT, manifest_sha256: str = MANIFEST_SHA256):
        try:
            self.projection = DocumentaryProjection(root, manifest_sha256)
        except DocumentaryProjectionError as exc:
            raise RawWorkArchitectureCandidateError(str(exc)) from exc

    def _candidate(self, page: dict[str, Any], start: int, end: int,
                   pattern_id: str, candidate_kind: str,
                   operation_or_relation: str, matched_text: str) -> dict[str, Any]:
        text = page["text"]
        _need(0 <= start < end <= len(text), "candidate span escapes page text")
        quote = text[start:end]
        _need(quote == text[start:end] and bool(quote), "candidate quote/span mismatch")
        exact_quote_sha256 = sha256(quote.encode("utf-8")).hexdigest()
        normalized_quote_sha256 = sha256(normalize_quote(quote).encode("utf-8")).hexdigest()
        span = [start, end]
        return {
            "schema": SCHEMA,
            "candidate_id": _candidate_id(
                page=page, character_span=span, pattern_id=pattern_id,
                exact_quote_sha256=exact_quote_sha256,
            ),
            "interpretation_status": PROPOSED,
            "admission_status": UNRESOLVED,
            "candidate_kind": candidate_kind,
            "pattern_id": pattern_id,
            "matched_text": matched_text,
            "manifest_sha256": self.projection.manifest_sha256,
            "document": {
                "document_index": page["document_index"],
                "publication_id": page["publication_id"],
                "pdf_sha256": page["source_sha256"],
                "source_file": deepcopy(page["source_file"]),
            },
            "physical_page_index": page["pdf_page_index"],
            "physical_page_number": page["pdf_page_number"],
            "page_text_sha256": page["text_sha256"],
            "character_span": span,
            "exact_quote": quote,
            "exact_quote_sha256": exact_quote_sha256,
            "normalized_quote_sha256": normalized_quote_sha256,
            "proposal": _unimplemented_shape(candidate_kind, operation_or_relation),
            "semantic_coordinate": None,
            "source_support": "EXACT_EXTRACTED_TEXT_ONLY",
            "interpretation": "REQUIRES_SEPARATE_QUALIFICATION",
            "semantic_disposition": {
                "admission": "NOT_ADMITTED",
                "applicability": None,
                "compliance": None,
                "responsibility": None,
                "external_effects": [],
            },
            "ceiling": CEILING,
            "external_effects": [],
        }

    def _page_candidates(self, page: dict[str, Any]) -> Iterator[dict[str, Any]]:
        for sentence_start, sentence_end, sentence in _sentence_spans(page["text"]):
            if len(sentence) > 1_200:
                continue
            for pattern_id, candidate_kind, operation_or_relation, pattern in _RULES:
                # One witness per pattern per extracted sentence is enough to
                # expose a reviewable source signal without counting a repeated
                # word as a distinct proposed interface.
                match = pattern.search(sentence)
                if match is None:
                    continue
                yield self._candidate(
                    page, sentence_start, sentence_end, pattern_id,
                    candidate_kind, operation_or_relation, match.group(0),
                )

    def iter_candidates(self, publication_id: str | None = None) -> Iterator[dict[str, Any]]:
        seen: set[str] = set()
        try:
            for page in self.projection.iter_pages(view="plain", publication_id=publication_id):
                for candidate in self._page_candidates(page):
                    _need(candidate["candidate_id"] not in seen,
                          "duplicate source-derived candidate identity")
                    seen.add(candidate["candidate_id"])
                    yield candidate
        except DocumentaryProjectionError as exc:
            raise RawWorkArchitectureCandidateError(str(exc)) from exc

    def summary(self) -> dict[str, Any]:
        """Return full-library accounting without writing a candidate dump."""

        documents: set[str] = set()
        pages = 0
        total = 0
        by_kind: dict[str, int] = {}
        by_pattern: dict[str, int] = {}
        documents_with: dict[str, set[str]] = {
            "WORK_OPERATION_INTERFACE": set(), "ARCHITECTURE_COMPOSITION": set(),
        }
        stream_digest = sha256()
        try:
            for page in self.projection.iter_pages(view="plain"):
                documents.add(page["publication_id"])
                pages += 1
                for candidate in self._page_candidates(page):
                    total += 1
                    kind = candidate["candidate_kind"]
                    by_kind[kind] = by_kind.get(kind, 0) + 1
                    by_pattern[candidate["pattern_id"]] = by_pattern.get(candidate["pattern_id"], 0) + 1
                    documents_with[kind].add(page["publication_id"])
                    stream_digest.update(canonical(candidate))
                    stream_digest.update(b"\n")
        except DocumentaryProjectionError as exc:
            raise RawWorkArchitectureCandidateError(str(exc)) from exc
        expected = self.projection.summary()
        _need(len(documents) == expected["document_count"], "candidate document accounting drift")
        _need(pages == expected["physical_page_count"], "candidate page accounting drift")
        return {
            "schema": SCHEMA,
            "status": "FULL_LIBRARY_SOURCE_ACCOUNTED_CANDIDATES_ONLY",
            "manifest_sha256": self.projection.manifest_sha256,
            "document_count": len(documents),
            "physical_page_count": pages,
            "candidate_count": total,
            "candidate_count_by_kind": dict(sorted(by_kind.items())),
            "candidate_count_by_pattern": dict(sorted(by_pattern.items())),
            "documents_with_candidates_by_kind": {
                key: len(value) for key, value in sorted(documents_with.items())
            },
            "candidate_stream_sha256": stream_digest.hexdigest(),
            "admitted_interpretation_count": 0,
            "semantic_coordinate_assignments": 0,
            "ceiling": CEILING,
            "external_effects": [],
        }

    def validate_candidate(self, candidate: dict[str, Any]) -> dict[str, Any]:
        """Re-derive one candidate and reject any source or claim tampering."""

        _need(type(candidate) is dict, "candidate must be an object")
        _need(candidate.get("schema") == SCHEMA, "candidate schema mismatch")
        _need(candidate.get("interpretation_status") == PROPOSED and
              candidate.get("admission_status") == UNRESOLVED,
              "candidate admission status is invalid")
        _need(candidate.get("manifest_sha256") == self.projection.manifest_sha256,
              "candidate manifest identity mismatch")
        document = candidate.get("document")
        _need(type(document) is dict and type(document.get("publication_id")) is str,
              "candidate document identity is invalid")
        page_index = candidate.get("physical_page_index")
        _need(type(page_index) is int and page_index >= 0, "candidate page index is invalid")
        try:
            for page in self.projection.iter_pages(view="plain", publication_id=document["publication_id"]):
                if page["pdf_page_index"] != page_index:
                    continue
                expected = [row for row in self._page_candidates(page)
                            if row["candidate_id"] == candidate.get("candidate_id")]
                _need(len(expected) == 1 and canonical(expected[0]) == canonical(candidate),
                      "candidate source derivation mismatch")
                return deepcopy(expected[0])
        except DocumentaryProjectionError as exc:
            raise RawWorkArchitectureCandidateError(str(exc)) from exc
        raise RawWorkArchitectureCandidateError("candidate page is absent from source")


__all__ = [
    "CEILING", "MANIFEST_SHA256", "NAMESPACE", "PROPOSED", "SCHEMA", "UNRESOLVED",
    "RawWorkArchitectureCandidateError", "RawWorkArchitectureCandidates", "canonical",
    "digest", "normalize_quote",
]
