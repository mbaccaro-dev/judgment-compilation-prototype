"""Verifies the source location for a proposed match."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from typing import Any

from .documentary_projection import (
    DEFAULT_ROOT,
    MANIFEST_SHA256,
    DocumentaryProjection,
)


SCHEMA = "jc/raw-candidate-provenance/1"
NORMALIZATION = "UNICODE_CASEFOLD_AND_WHITESPACE_COLLAPSE_V1"
OCCURRENCE_SCOPE = "FULL_FROZEN_PLAIN_PAGE_CORPUS_NO_CROSS_PAGE_MATCHES"
CANDIDATE_STATUS = "PROPOSED_RAW_SEMANTIC_CANDIDATE"
NOT_ADMITTED = "NOT_ADMITTED"
RAW_CLAIM_KIND = "EXACT_EXTRACTED_QUOTE"


class RawCandidateProvenanceError(ValueError):
    """A raw candidate does not exactly bind the retained source corpus."""


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _text(value: Any) -> bool:
    return type(value) is str and bool(value)


def _sha(value: Any) -> bool:
    return (type(value) is str and len(value) == 64 and
            all(char in "0123456789abcdef" for char in value))


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise RawCandidateProvenanceError(message)


def _keys(value: Any, expected: set[str], message: str) -> None:
    _need(type(value) is dict and set(value) == expected, message)


def normalized_spans(text: str) -> tuple[str, list[tuple[int, int]]]:
    """Return the declared normalized text and its exact source spans."""

    characters: list[str] = []
    spans: list[tuple[int, int]] = []
    for index, character in enumerate(text):
        if character.isspace():
            if characters and characters[-1] == " ":
                spans[-1] = (spans[-1][0], index + 1)
            elif characters:
                characters.append(" ")
                spans.append((index, index + 1))
        else:
            for folded in character.casefold():
                characters.append(folded)
                spans.append((index, index + 1))
    if characters and characters[-1] == " ":
        characters.pop()
        spans.pop()
    return "".join(characters), spans


def _occurrence_record(page: dict[str, Any], normalized: str,
                       spans: list[tuple[int, int]], position: int,
                       needle_length: int) -> dict[str, Any] | None:
    """Return one exact record unless a case-fold expansion cuts it in half."""

    finish = position + needle_length
    # A case-fold expansion may have several normalized code points for one
    # source character.  Never emit a partial source match.
    if ((position and spans[position] == spans[position - 1]) or
            (finish < len(spans) and spans[finish - 1] == spans[finish])):
        return None
    start, end = spans[position][0], spans[finish - 1][1]
    matched = page["text"][start:end]
    return {
        "publication_id": page["publication_id"],
        "source_pdf_sha256": page["source_sha256"],
        "physical_pdf_page_index": page["pdf_page_index"],
        "character_span": [start, end],
        "exact_quote": matched,
        "exact_quote_sha256": hashlib.sha256(matched.encode("utf-8")).hexdigest(),
        "normalized_quote_sha256": hashlib.sha256(
            normalized_spans(matched)[0].encode("utf-8")).hexdigest(),
        "page_text_sha256": page["text_sha256"],
    }


def _occurrence_records_from_pages(pages: Any, quote: str) -> list[dict[str, Any]]:
    """Compute exact records from one already verified plain-page snapshot."""

    needle, _ = normalized_spans(quote)
    _need(bool(needle), "candidate quote has no normalized text")
    records: list[dict[str, Any]] = []
    for page in pages:
        normalized, spans = normalized_spans(page["text"])
        cursor = 0
        while (position := normalized.find(needle, cursor)) >= 0:
            cursor = position + 1
            record = _occurrence_record(page, normalized, spans, position, len(needle))
            if record is not None:
                records.append(record)
    return records


def _aho_automaton(needles: dict[str, str]) -> tuple[
        list[dict[str, int]], list[int], list[list[str]]]:
    """Build the smallest local multi-quote matcher for one cache preparation."""

    from collections import deque

    transitions: list[dict[str, int]] = [{}]
    outputs: list[list[str]] = [[]]
    for quote, needle in needles.items():
        node = 0
        for character in needle:
            child = transitions[node].get(character)
            if child is None:
                child = len(transitions)
                transitions[node][character] = child
                transitions.append({})
                outputs.append([])
            node = child
        outputs[node].append(quote)

    failures = [0] * len(transitions)
    queue = deque(transitions[0].values())
    while queue:
        node = queue.popleft()
        for character, child in transitions[node].items():
            queue.append(child)
            failure = failures[node]
            while failure and character not in transitions[failure]:
                failure = failures[failure]
            failures[child] = transitions[failure].get(character, 0)
            outputs[child].extend(outputs[failures[child]])
    return transitions, failures, outputs


class OccurrenceInventoryCache:
    """Keep verified page records for exact quote searches."""

    def __init__(self, root: Path | str = DEFAULT_ROOT,
                 manifest_sha256: str = MANIFEST_SHA256):
        self.root = Path(root).resolve()
        self.manifest_sha256 = manifest_sha256
        self._pages: tuple[dict[str, Any], ...] | None = None
        self._source_snapshot: tuple[tuple[str, int, int], ...] | None = None
        self._binding: dict[str, Any] | None = None
        self._inventories: dict[str, dict[str, Any]] = {}

    def _snapshot(self, projection: DocumentaryProjection) -> tuple[tuple[str, int, int], ...]:
        descriptors: list[dict[str, Any]] = []
        for document in projection._documents_in_order:
            descriptors.extend((document["pdf"], document["extraction"]["plain"],
                                document["extraction"]["coverage"]))
        observed: list[tuple[str, int, int]] = []
        for descriptor in descriptors:
            path = projection._path(descriptor)
            try:
                stat = path.stat()
            except OSError as exc:
                raise RawCandidateProvenanceError(
                    f"occurrence-cache input unavailable: {descriptor['path']}") from exc
            observed.append((descriptor["path"], stat.st_size, stat.st_mtime_ns))
        return tuple(observed)

    def _clear(self) -> None:
        self._pages = None
        self._source_snapshot = None
        self._binding = None
        self._inventories.clear()

    def _ensure_snapshot(self) -> None:
        projection = DocumentaryProjection(self.root, self.manifest_sha256)
        observed = self._snapshot(projection)
        if self._source_snapshot is not None and observed != self._source_snapshot:
            self._clear()
        if self._pages is not None:
            return
        pages = tuple(deepcopy(page) for page in projection.iter_pages(view="plain"))
        self._pages = pages
        self._source_snapshot = self._snapshot(projection)
        summary = projection.summary()
        self._binding = {
            "root": str(self.root),
            "manifest_sha256": self.manifest_sha256,
            "corpus_id": summary["corpus_id"],
            "corpus_release": summary["corpus_release"],
            "physical_page_count": summary["physical_page_count"],
        }

    @property
    def corpus_binding(self) -> dict[str, Any]:
        self._ensure_snapshot()
        return deepcopy(self._binding)

    def matches(self, root: Path | str, manifest_sha256: str) -> bool:
        return self.root == Path(root).resolve() and self.manifest_sha256 == manifest_sha256

    def has_all(self, quotes: Any) -> bool:
        """Check prepared coverage while retaining the bound-corpus drift gate."""

        _need(type(quotes) in {list, tuple}, "candidate quote sequence required")
        self._ensure_snapshot()
        return all(_text(quote) and quote in self._inventories for quote in quotes)

    def prepare(self, quotes: Any) -> dict[str, dict[str, Any]]:
        """Find exact quote locations in one pass and keep the results in memory."""

        _need(type(quotes) in {list, tuple}, "candidate quote sequence required")
        unique: list[str] = []
        for quote in quotes:
            _need(_text(quote), "candidate quote required")
            if quote not in unique:
                unique.append(quote)
        self._ensure_snapshot()
        missing = [quote for quote in unique if quote not in self._inventories]
        if missing:
            needles: dict[str, str] = {}
            for quote in missing:
                needle, _ = normalized_spans(quote)
                _need(bool(needle), "candidate quote has no normalized text")
                needles[quote] = needle
            transitions, failures, outputs = _aho_automaton(needles)
            records = {quote: [] for quote in missing}
            # Page normalization and corpus traversal sit outside the quote
            # loop.  A document package therefore does one full pass rather
            # than one pass per candidate with a distinct claim text.
            for page in self._pages:
                normalized, spans = normalized_spans(page["text"])
                node = 0
                for end, character in enumerate(normalized):
                    while node and character not in transitions[node]:
                        node = failures[node]
                    node = transitions[node].get(character, 0)
                    for quote in outputs[node]:
                        record = _occurrence_record(
                            page, normalized, spans,
                            end - len(needles[quote]) + 1, len(needles[quote]))
                        if record is not None:
                            records[quote].append(record)
            for quote, occurrences in records.items():
                self._inventories[quote] = {
                    "normalization": NORMALIZATION,
                    "scope": OCCURRENCE_SCOPE,
                    "count": len(occurrences),
                    "inventory_sha256": digest(occurrences),
                }
        return {quote: deepcopy(self._inventories[quote]) for quote in unique}

    def inventory(self, quote: str) -> dict[str, Any]:
        """Single-quote compatibility path for callers outside batch replay."""

        return self.prepare((quote,))[quote]


def _occurrence_records(projection: DocumentaryProjection, quote: str) -> list[dict[str, Any]]:
    return _occurrence_records_from_pages(projection.iter_pages(view="plain"), quote)


def recompute_occurrence_inventory(
        quote: str, root: Path | str = DEFAULT_ROOT,
        manifest_sha256: str = MANIFEST_SHA256,
        occurrence_cache: OccurrenceInventoryCache | None = None) -> dict[str, Any]:
    """Recompute every normalized occurrence from verified raw page JSONL."""

    _need(_text(quote), "candidate quote required")
    if occurrence_cache is not None:
        _need(occurrence_cache.matches(root, manifest_sha256),
              "occurrence cache corpus identity mismatch")
        return occurrence_cache.inventory(quote)
    projection = DocumentaryProjection(root, manifest_sha256)
    occurrences = _occurrence_records(projection, quote)
    return {
        "normalization": NORMALIZATION,
        "scope": OCCURRENCE_SCOPE,
        "count": len(occurrences),
        "inventory_sha256": digest(occurrences),
    }


def corpus_accounting(root: Path | str = DEFAULT_ROOT,
                      manifest_sha256: str = MANIFEST_SHA256) -> dict[str, Any]:
    """Recompute document and physical-page accounting over the retained corpus."""

    projection = DocumentaryProjection(root, manifest_sha256)
    # Verify every manifest-bound input first.  The plain stream then checks
    # page identity and text hashes directly from each retained JSONL record.
    projection.verify()
    document_count = sum(1 for _ in projection.iter_documents())
    physical_page_count = sum(1 for _ in projection.iter_pages(view="plain"))
    summary = projection.summary()
    _need(document_count == summary["document_count"], "document accounting drift")
    _need(physical_page_count == summary["physical_page_count"], "page accounting drift")
    return {
        "status": "VERIFIED_RAW_CORPUS_ACCOUNTING",
        "manifest_sha256": manifest_sha256,
        "corpus_id": summary["corpus_id"],
        "corpus_release": summary["corpus_release"],
        "document_count": document_count,
        "physical_page_count": physical_page_count,
        "claim_ceiling": "RAW_DOCUMENT_AND_EXTRACTION_IDENTITY_ONLY;NO_SEMANTIC_ADMISSION_OR_TRUTH",
    }


def _candidate_page(projection: DocumentaryProjection, provenance: dict[str, Any]) -> dict[str, Any]:
    publication_id = provenance["publication_id"]
    page_index = provenance["physical_pdf_page_index"]
    _need(type(page_index) is int and page_index >= 0, "physical page index required")
    for page in projection.iter_pages(view="plain", publication_id=publication_id):
        if page["pdf_page_index"] == page_index:
            return page
    raise RawCandidateProvenanceError("candidate physical page unavailable")


def _validate_support_edges(candidate: dict[str, Any], *,
                            expected_support_edges: list[dict[str, Any]] | None) -> None:
    edges = candidate["support_edges"]
    _need(type(edges) is list, "support edges must be a list")
    _need(_sha(candidate["support_graph_sha256"]) and
          candidate["support_graph_sha256"] == digest(edges),
          "support graph digest mismatch")
    seen: set[str] = set()
    for edge in edges:
        _keys(edge, {"id", "candidate_id", "claim_text_sha256", "provenance_sha256"},
              "unsupported support edge shape")
        _need(_text(edge["id"]) and edge["id"] not in seen, "duplicate support edge")
        seen.add(edge["id"])
        _need(edge["candidate_id"] == candidate["candidate_id"],
              "support edge candidate binding mismatch")
        _need(edge["claim_text_sha256"] == candidate["claim"]["text_sha256"],
              "support edge claim binding mismatch")
        _need(edge["provenance_sha256"] == digest(candidate["provenance"]),
              "support edge provenance binding mismatch")
    if expected_support_edges is not None:
        _need(canonical(edges) == canonical(expected_support_edges),
              "support graph differs from its bound input")


def validate_raw_candidate(
        candidate: dict[str, Any], root: Path | str = DEFAULT_ROOT,
        manifest_sha256: str = MANIFEST_SHA256, *,
        expected_support_edges: list[dict[str, Any]] | None = None,
        occurrence_cache: OccurrenceInventoryCache | None = None) -> dict[str, Any]:
    """Verify a source match against the included document bytes."""

    _keys(candidate, {
        "schema", "candidate_id", "candidate_status", "semantic_admission_status",
        "interpretation_status", "context", "claim", "provenance", "occurrence_inventory",
        "support_edges", "support_graph_sha256", "claim_ceiling",
    }, "unsupported raw candidate shape")
    _need(candidate["schema"] == SCHEMA, "unsupported raw candidate schema")
    _need(_text(candidate["candidate_id"]), "candidate identity required")
    _need(candidate["candidate_status"] == CANDIDATE_STATUS, "candidate is not a proposal")
    _need(candidate["semantic_admission_status"] == NOT_ADMITTED,
          "raw provenance cannot admit a semantic candidate")
    _need(_text(candidate["interpretation_status"]), "interpretation status required")
    _need(candidate["claim_ceiling"] ==
          "RAW_DOCUMENT_AND_EXTRACTION_IDENTITY_ONLY;NO_SEMANTIC_ADMISSION_OR_TRUTH",
          "unsupported raw candidate ceiling")

    _keys(candidate["context"], {"corpus_id", "corpus_release", "manifest_sha256"},
          "unsupported corpus context")
    _keys(candidate["claim"], {"kind", "text", "text_sha256"}, "unsupported raw claim shape")
    _keys(candidate["provenance"], {
        "publication_id", "source_pdf_sha256", "physical_pdf_page_index", "view",
        "page_text_sha256", "character_span", "exact_quote", "exact_quote_sha256",
        "normalized_quote_sha256",
    }, "unsupported raw provenance shape")
    _keys(candidate["occurrence_inventory"], {"normalization", "scope", "count", "inventory_sha256"},
          "unsupported occurrence inventory shape")

    provenance = candidate["provenance"]
    _need(_text(provenance["publication_id"]) and provenance["view"] == "plain",
          "raw provenance requires a plain-page logical identity")
    span = provenance["character_span"]
    _need(type(span) is list and len(span) == 2 and all(type(item) is int for item in span),
          "character span requires two integer offsets")
    _need(all(_sha(provenance[name]) for name in (
        "source_pdf_sha256", "page_text_sha256", "exact_quote_sha256", "normalized_quote_sha256")),
        "raw provenance hash shape invalid")
    _need(candidate["claim"]["kind"] == RAW_CLAIM_KIND and _text(candidate["claim"]["text"]),
          "raw candidate claim must be an extracted quote")
    _need(_sha(candidate["claim"]["text_sha256"]), "raw candidate claim hash invalid")

    projection = DocumentaryProjection(root, manifest_sha256)
    summary = projection.summary()
    context = candidate["context"]
    _need(context == {
        "corpus_id": summary["corpus_id"],
        "corpus_release": summary["corpus_release"],
        "manifest_sha256": manifest_sha256,
    }, "candidate corpus context mismatch")
    document = projection.documents.get(provenance["publication_id"])
    _need(document is not None, "unknown candidate publication")
    _need(candidate["interpretation_status"] == document["interpretation_status"],
          "candidate interpretation status mismatch")
    page = _candidate_page(projection, provenance)
    start, end = span
    quote = provenance["exact_quote"]
    _need(0 <= start < end <= len(page["text"]) and page["text"][start:end] == quote,
          "candidate quote/span mismatch")
    _need(provenance["source_pdf_sha256"] == page["source_sha256"] and
          provenance["page_text_sha256"] == page["text_sha256"],
          "candidate source or page hash mismatch")
    _need(provenance["exact_quote_sha256"] == hashlib.sha256(quote.encode("utf-8")).hexdigest(),
          "candidate exact quote hash mismatch")
    normalized, _ = normalized_spans(quote)
    _need(provenance["normalized_quote_sha256"] == hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
          "candidate normalized quote hash mismatch")
    _need(candidate["claim"]["text"] == quote and
          candidate["claim"]["text_sha256"] == provenance["exact_quote_sha256"],
          "candidate claim text is not the bound quote")

    inventory = recompute_occurrence_inventory(
        quote, root, manifest_sha256, occurrence_cache=occurrence_cache)
    _need(candidate["occurrence_inventory"] == inventory,
          "candidate occurrence inventory is incomplete or altered")
    _validate_support_edges(candidate, expected_support_edges=expected_support_edges)
    return deepcopy(json.loads(canonical(candidate)))


__all__ = [
    "CANDIDATE_STATUS", "MANIFEST_SHA256", "NORMALIZATION", "NOT_ADMITTED",
    "OCCURRENCE_SCOPE", "RAW_CLAIM_KIND", "SCHEMA", "RawCandidateProvenanceError",
    "OccurrenceInventoryCache", "canonical", "corpus_accounting", "digest", "normalized_spans",
    "recompute_occurrence_inventory", "validate_raw_candidate",
]
