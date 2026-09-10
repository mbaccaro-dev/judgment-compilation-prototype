"""Finds possible domain terms in document text."""

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


SCHEMA = "jc/raw-domain-candidates/1"
NAMESPACE = "jc-raw-domain-candidate"
PROPOSED = "PROPOSED_INTERPRETATION"
UNRESOLVED = "UNRESOLVED"
CEILING = (
    "SOURCE_BOUND_RAW_DOMAIN_CANDIDATE_ONLY;NO_SEMANTIC_ADMISSION_OR_GS_L_I_"
    "ASSIGNMENT_OR_APPLICABILITY_OR_COMPLIANCE_OR_RESPONSIBILITY_OR_EXTERNAL_EFFECT"
)


class RawDomainCandidateError(ValueError):
    """A candidate, manifest, or exact-page derivation is invalid."""


def canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise RawDomainCandidateError("invalid canonical candidate JSON") from exc


def digest(value: Any) -> str:
    return sha256(canonical(value)).hexdigest()


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise RawDomainCandidateError(message)


def normalize_quote(value: str) -> str:
    """Use an explicit NFC-plus-whitespace form only for a secondary hash."""

    _need(type(value) is str, "quote must be text")
    return " ".join(unicodedata.normalize("NFC", value).split())


def _span_text(text: str, start: int, end: int) -> tuple[int, int, str]:
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    return start, end, text[start:end]


def _sentence_spans(text: str) -> Iterator[tuple[int, int, str]]:
    start = 0
    for match in re.finditer(r"[.!?;](?=\s|$)", text):
        end = match.end()
        left, right, quote = _span_text(text, start, end)
        if quote:
            yield left, right, quote
        start = end
    left, right, quote = _span_text(text, start, len(text))
    if quote:
        yield left, right, quote


# Each expression identifies an exact text form.
# The prefilter is an optimization: every string is a literal required by
# its matching expression, so it cannot turn a match into a non-match.
_RULES: tuple[tuple[str, re.Pattern[str], str, tuple[str, ...]], ...] = (
    (
        "EXPLICIT_TERM_DEFINITION",
        re.compile(
            r"\b(?:the\s+)?(?:term\s+)?(?P<label>[A-Za-z][A-Za-z0-9'’/() -]{1,100}?)"
            r"\s+(?:is|are)\s+defined\s+as\b",
            re.IGNORECASE,
        ),
        "EXPLICIT_DEFINITION",
        ("defined as",),
    ),
    (
        "EXPLICIT_TERM_MEANING",
        re.compile(
            r"\b(?:the\s+)?(?:term\s+)?(?P<label>[A-Za-z][A-Za-z0-9'’/() -]{1,100}?)"
            r"\s+(?:means|refers\s+to)\b",
            re.IGNORECASE,
        ),
        "EXPLICIT_DEFINITION",
        ("means", "refers to"),
    ),
    (
        "NAMED_VALUE_KIND",
        re.compile(
            r"\b(?P<label>[A-Za-z][A-Za-z0-9'’/() -]{1,100}?)\s+"
            r"(?:value\s+type|data\s+type|value\s+kind|unit\s+of\s+measure)\b",
            re.IGNORECASE,
        ),
        "NAMED_VALUE_KIND",
        ("value type", "data type", "value kind", "unit of measure"),
    ),
    (
        "TYPED_MEASUREMENT_LITERAL",
        re.compile(
            r"\b(?P<label>\d+(?:\.\d+)?\s*(?:milliseconds?|seconds?|minutes?|hours?|days?|"
            r"weeks?|months?|years?|bits?|bytes?|kilobytes?|megabytes?|gigabytes?|percent|%))\b",
            re.IGNORECASE,
        ),
        "TYPED_UNIT_LITERAL",
        ("0", "1", "2", "3", "4", "5", "6", "7", "8", "9"),
    ),
    (
        "EXACT_UNTYPED_RELATION",
        re.compile(
            r"\b(?P<label>[A-Za-z][A-Za-z0-9'’/() -]{1,100}?)\s+"
            r"(?:consists\s+of|is\s+composed\s+of|is\s+part\s+of|depends\s+on|"
            r"is\s+associated\s+with|is\s+related\s+to)\s+"
            r"[A-Za-z][A-Za-z0-9'’/() -]{1,160}\b",
            re.IGNORECASE,
        ),
        "EXACT_TEXT_RELATION_UNTYPED",
        ("consists of", "is composed of", "is part of", "depends on",
         "is associated with", "is related to"),
    ),
    (
        "RESPONSIBILITY_AUTHORITY_REL",
        re.compile(
            r"\b(?P<subject>[A-Za-z][A-Za-z0-9'’/() ,&\s-]{1,160}?)\s+"
            r"(?P<predicate>is\s+responsible\s+for|has\s+responsibility\s+for|"
            r"is\s+authorized\s+to|is\s+permitted\s+to|is\s+required\s+to)\s+"
            r"(?P<object>[A-Za-z][A-Za-z0-9'’/() ,&\s-]{1,300}?)(?=\s*[.;!?]|$)",
            re.IGNORECASE,
        ),
        "EXACT_TEXT_RELATION_UNTYPED",
        ("is responsible for", "has responsibility for", "is authorized to",
         "is permitted to", "is required to"),
    ),
    (
        "INCLUSION_REL",
        re.compile(
            r"\b(?P<subject>[A-Za-z][A-Za-z0-9'’/() ,&\s-]{1,160}?)\s+"
            r"(?P<predicate>includes|contains|comprises|consists\s+of|"
            r"is\s+composed\s+of|is\s+made\s+up\s+of|composed\s+of)\s+"
            r"(?P<object>[A-Za-z][A-Za-z0-9'’/() ,&\s-]{1,300}?)(?=\s*[.;!?]|$)",
            re.IGNORECASE,
        ),
        "EXACT_TEXT_RELATION_UNTYPED",
        ("includes", "contains", "comprises", "consists of", "is composed of",
         "is made up of", "composed of"),
    ),
    (
        "DEFINITION_COPULA",
        re.compile(
            r"\b(?P<subject>[A-Za-z][A-Za-z0-9'’/() ,&\s-]{1,160}?)\s+"
            r"(?P<predicate>is|are)\s+(?P<definition_cue>defined\s+as|known\s+as|"
            r"called|referred\s+to\s+as|understood\s+as)\s+"
            r"(?P<object>[A-Za-z][A-Za-z0-9'’/() ,&\s-]{1,300}?)(?=\s*[.;!?]|$)",
            re.IGNORECASE,
        ),
        "EXPLICIT_DEFINITION_SIGNAL_UNRESOLVED",
        ("defined as", "known as", "called", "referred to as", "understood as"),
    ),
)


def _source_candidate_id(*, publication_id: str, pdf_sha256: str,
                         page_index: int, character_span: list[int],
                         pattern_id: str, exact_quote_sha256: str) -> str:
    return NAMESPACE + ":" + digest({
        "publication_id": publication_id,
        "pdf_sha256": pdf_sha256,
        "physical_page_index": page_index,
        "character_span": character_span,
        "pattern_id": pattern_id,
        "exact_quote_sha256": exact_quote_sha256,
    })


class RawDomainCandidates:
    """Stream raw, non-admitted Domain candidates from verified plain pages."""

    def __init__(self, root=DEFAULT_ROOT, manifest_sha256: str = MANIFEST_SHA256):
        try:
            self.projection = DocumentaryProjection(root, manifest_sha256)
        except DocumentaryProjectionError as exc:
            raise RawDomainCandidateError(str(exc)) from exc

    def _candidate(self, page: dict[str, Any], start: int, end: int,
                   pattern_id: str, candidate_kind: str, source_label: str,
                   lexical_relation: dict[str, str] | None = None) -> dict[str, Any]:
        text = page["text"]
        _need(0 <= start < end <= len(text), "candidate span escapes page text")
        quote = text[start:end]
        _need(quote and quote == text[start:end], "candidate quote/span mismatch")
        exact_quote_sha256 = sha256(quote.encode("utf-8")).hexdigest()
        normalized_quote_sha256 = sha256(normalize_quote(quote).encode("utf-8")).hexdigest()
        span = [start, end]
        source_candidate_id = _source_candidate_id(
            publication_id=page["publication_id"], pdf_sha256=page["source_sha256"],
            page_index=page["pdf_page_index"], character_span=span,
            pattern_id=pattern_id, exact_quote_sha256=exact_quote_sha256,
        )
        return {
            "schema": SCHEMA,
            "source_candidate_id": source_candidate_id,
            "interpretation_status": PROPOSED,
            "admission_status": UNRESOLVED,
            "candidate_kind": candidate_kind,
            "pattern_id": pattern_id,
            "source_label": source_label,
            "manifest_sha256": self.projection.manifest_sha256,
            "document": {
                "document_index": page["document_index"],
                "publication_id": page["publication_id"],
                "pdf_sha256": page["source_sha256"],
            },
            "physical_page_index": page["pdf_page_index"],
            "physical_page_number": page["pdf_page_number"],
            "page_text_sha256": page["text_sha256"],
            "character_span": span,
            "exact_quote": quote,
            "exact_quote_sha256": exact_quote_sha256,
            "normalized_quote_sha256": normalized_quote_sha256,
            "semantic_coordinate": None,
            "lexical_relation": lexical_relation,
        "relation_interpretation": (
            UNRESOLVED
            if candidate_kind == "EXACT_TEXT_RELATION_UNTYPED" or lexical_relation is not None
            else None
        ),
            "ceiling": CEILING,
            "external_effects": [],
        }

    @staticmethod
    def _relation_capture(match: re.Match[str]) -> dict[str, str] | None:
        """Return literal captures without assigning a semantic relation."""

        groups = match.groupdict()
        if not {"subject", "predicate", "object"}.issubset(groups):
            return None
        values = {
            key: " ".join(groups[key].split())
            for key in ("subject", "predicate", "object")
        }
        if groups.get("definition_cue"):
            values["predicate"] = values["predicate"] + " " + " ".join(
                groups["definition_cue"].split()
            )
        return values if all(values.values()) else None

    def _page_candidates(self, page: dict[str, Any]) -> Iterator[dict[str, Any]]:
        for sentence_start, sentence_end, sentence in _sentence_spans(page["text"]):
            if len(sentence) > 1_200:
                continue
            folded_sentence = sentence.casefold()
            for pattern_id, pattern, candidate_kind, prefilter in _RULES:
                # One exact grammar witness per pattern and sentence keeps a
                # repeated word from producing indistinguishable candidates.
                if not any(needle in folded_sentence for needle in prefilter):
                    continue
                match = pattern.search(sentence)
                if match is None:
                    continue
                if pattern_id == "TYPED_MEASUREMENT_LITERAL":
                    start, end = sentence_start + match.start(), sentence_start + match.end()
                else:
                    start, end = sentence_start, sentence_end
                label = " ".join(
                    (match.groupdict().get("label") or match.groupdict().get("subject") or "").split()
                )
                if label:
                    yield self._candidate(
                        page, start, end, pattern_id, candidate_kind, label,
                        self._relation_capture(match),
                    )

    def iter_candidates(self, publication_id: str | None = None) -> Iterator[dict[str, Any]]:
        """Yield deterministic candidates while validating every visited source page."""

        seen: set[str] = set()
        try:
            for page in self.projection.iter_pages(view="plain", publication_id=publication_id):
                for candidate in self._page_candidates(page):
                    _need(candidate["source_candidate_id"] not in seen,
                          "duplicate source-derived candidate identity")
                    seen.add(candidate["source_candidate_id"])
                    yield candidate
        except DocumentaryProjectionError as exc:
            raise RawDomainCandidateError(str(exc)) from exc

    def summary(self) -> dict[str, Any]:
        """Perform full-library accounting without writing a candidate dump."""

        documents: set[str] = set()
        pages = 0
        candidates = 0
        candidate_documents: set[str] = set()
        per_pattern: dict[str, dict[str, Any]] = {
            pattern_id: {"candidate_count": 0, "document_ids": set(), "page_count": 0,
                         "page_keys": set()}
            for pattern_id, _, _, _ in _RULES
        }
        try:
            for page in self.projection.iter_pages(view="plain"):
                documents.add(page["publication_id"])
                pages += 1
                for candidate in self._page_candidates(page):
                    candidates += 1
                    candidate_documents.add(page["publication_id"])
                    pattern = per_pattern[candidate["pattern_id"]]
                    pattern["candidate_count"] += 1
                    pattern["document_ids"].add(page["publication_id"])
                    pattern["page_keys"].add((page["publication_id"], page["pdf_page_index"]))
        except DocumentaryProjectionError as exc:
            raise RawDomainCandidateError(str(exc)) from exc
        expected = self.projection.summary()
        _need(len(documents) == expected["document_count"], "candidate document accounting drift")
        _need(pages == expected["physical_page_count"], "candidate page accounting drift")
        uncovered = sorted(documents - candidate_documents)
        pattern_summary = [
            {
                "pattern_id": pattern_id,
                "candidate_count": details["candidate_count"],
                "document_count": len(details["document_ids"]),
                "physical_page_count": len(details["page_keys"]),
            }
            for pattern_id, details in sorted(per_pattern.items())
        ]
        return {
            "schema": SCHEMA,
            "status": "FULL_LIBRARY_SOURCE_ACCOUNTED_CANDIDATES_ONLY",
            "manifest_sha256": self.projection.manifest_sha256,
            "document_count": len(documents),
            "physical_page_count": pages,
            "candidate_count": candidates,
            "documents_with_candidates": sorted(candidate_documents),
            "uncovered_publication_ids": uncovered,
            "per_pattern": pattern_summary,
            "admitted_interpretation_count": 0,
            "semantic_coordinate_assignments": 0,
            "ceiling": CEILING,
            "external_effects": [],
        }

    def validate_candidate(self, candidate: dict[str, Any]) -> dict[str, Any]:
        """Re-derive one row from its exact source, rejecting rehashed tampering."""

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
                            if row["source_candidate_id"] == candidate.get("source_candidate_id")]
                _need(len(expected) == 1 and canonical(expected[0]) == canonical(candidate),
                      "candidate source derivation mismatch")
                return deepcopy(expected[0])
        except DocumentaryProjectionError as exc:
            raise RawDomainCandidateError(str(exc)) from exc
        raise RawDomainCandidateError("candidate page is absent from source")


__all__ = [
    "CEILING", "MANIFEST_SHA256", "NAMESPACE", "PROPOSED", "SCHEMA", "UNRESOLVED",
    "RawDomainCandidateError", "RawDomainCandidates", "canonical", "digest", "normalize_quote",
]
