"""Reads document records from the included library."""

from __future__ import annotations

from copy import deepcopy
import hashlib
from itertools import zip_longest
import json
from pathlib import Path
import re
from typing import Any, Iterable, Iterator


SCHEMA = "jc/documentary-projection/1"
DEFAULT_ROOT = Path(__file__).resolve().parent / "data" / "library"
MANIFEST_SHA256 = "a11f0668efbde0ccfe7dcc6f12e6e7e4bf549193d68a409ebc06dc087599ce11"
VIEWS = ("plain", "layout")
SEGMENT_METHOD = "PAGE_TEXT_TERMINATOR_AND_BLANK_LINE_SEGMENTS_V1"
DOCUMENTARY_DISPOSITION = "DOCUMENTARY_SOURCE_ONLY"
UNRESOLVED_DISPOSITION = "UNRESOLVED_POLICY_SEMANTICS"


class DocumentaryProjectionError(ValueError):
    """The manifest, source bytes, or a projected record is invalid."""


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise DocumentaryProjectionError(message)


def _reject_constant(value: str) -> None:
    raise DocumentaryProjectionError(f"nonfinite manifest constant: {value}")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _need(key not in result, "duplicate manifest key")
        result[key] = value
    return result


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _segments(text: str, pattern: str) -> list[list[int]]:
    result: list[list[int]] = []
    start = 0
    for match in re.finditer(pattern, text):
        end = match.end()
        left, right = start, end
        while left < right and text[left].isspace():
            left += 1
        while right > left and text[right - 1].isspace():
            right -= 1
        if left < right:
            result.append([left, right])
        start = end
    left, right = start, len(text)
    while left < right and text[left].isspace():
        left += 1
    while right > left and text[right - 1].isspace():
        right -= 1
    if left < right:
        result.append([left, right])
    return result


def extracted_segment_spans(text: str) -> dict[str, list[list[int]]]:
    """Return reproducible extraction spans, without linguistic labels."""

    return {
        "terminator": _segments(text, r"[.!?;](?=\s|$)"),
        "blank_line": _segments(text, r"\r?\n[^\S\r\n]*\r?\n"),
    }


class DocumentaryProjection:
    """Stream verified document, page, coverage, and text-span records."""

    def __init__(self, root: Path | str = DEFAULT_ROOT,
                 manifest_sha256: str = MANIFEST_SHA256):
        self.root = Path(root).resolve()
        manifest_path = self.root / "manifest.json"
        try:
            raw = manifest_path.read_bytes()
        except OSError as exc:
            raise DocumentaryProjectionError("documentary manifest unavailable") from exc
        observed = hashlib.sha256(raw).hexdigest()
        _need(observed == manifest_sha256, "documentary manifest drift")
        _need(len(raw) <= 4_000_000, "documentary manifest too large")
        try:
            manifest = json.loads(raw.decode("utf-8"),
                                  object_pairs_hook=_unique_pairs,
                                  parse_constant=_reject_constant)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DocumentaryProjectionError("invalid documentary manifest") from exc
        _need(type(manifest) is dict, "documentary manifest must be an object")
        self.manifest = manifest
        self.manifest_sha256 = manifest_sha256
        documents = manifest.get("documents")
        files = manifest.get("files")
        _need(type(documents) is list and type(files) is list,
              "manifest documents and files must be lists")
        self.documents = {d["publication_id"]: d for d in documents}
        self.files = {f["path"]: f for f in files}
        _need(len(self.documents) == len(documents) == manifest.get("document_count"),
              "document identity cardinality mismatch")
        _need(len(self.files) == len(files), "file identity cardinality mismatch")
        _need(sum(d["page_count"] for d in documents) == manifest.get("physical_page_count"),
              "physical page cardinality mismatch")
        for document in documents:
            _need(type(document.get("document_index")) is int,
                  "document index is not an integer")
            for descriptor in [document["pdf"], *document["extraction"].values()]:
                _need(self.files.get(descriptor["path"]) == descriptor,
                      "document input is not bound to the manifest")
        self._documents_in_order = tuple(sorted(
            documents, key=lambda item: (item["document_index"], item["publication_id"])))

    def _path(self, descriptor: dict[str, Any]) -> Path:
        relative = Path(descriptor["path"])
        path = (self.root / relative).resolve()
        _need(not relative.is_absolute() and path.is_relative_to(self.root),
              "documentary path escapes root")
        return path

    def _verified_path(self, descriptor: dict[str, Any]) -> Path:
        path = self._path(descriptor)
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise DocumentaryProjectionError(f"documentary input unavailable: {descriptor['path']}") from exc
        _need(size == descriptor["bytes"] and _sha256_path(path) == descriptor["sha256"],
              f"documentary input drift: {descriptor['path']}")
        return path

    @staticmethod
    def _disposition() -> dict[str, Any]:
        return {
            "documentary": DOCUMENTARY_DISPOSITION,
            "policy_semantics": UNRESOLVED_DISPOSITION,
            "applicability": None,
            "satisfaction": None,
            "compliance": None,
            "responsibility": None,
            "external_effects": [],
        }

    def _document_record(self, document: dict[str, Any]) -> dict[str, Any]:
        self._verified_path(document["pdf"])
        return {
            "schema": SCHEMA,
            "record_type": "DOCUMENT",
            "corpus_id": self.manifest["corpus_id"],
            "corpus_release": self.manifest["corpus_release"],
            "manifest_sha256": self.manifest_sha256,
            "document_index": document["document_index"],
            "publication_id": document["publication_id"],
            "title": document["title"],
            "page_count": document["page_count"],
            "encrypted": document["encrypted"],
            "publication_metadata": deepcopy(document["publication_metadata"]),
            "coverage_status_counts": deepcopy(document["coverage_status_counts"]),
            "source_file": deepcopy(document["pdf"]),
            "extraction_files": deepcopy(document["extraction"]),
            "interpretation_status": document["interpretation_status"],
            "disposition": self._disposition(),
        }

    def iter_documents(self, publication_id: str | None = None) -> Iterator[dict[str, Any]]:
        """Yield exact source-bound document records, optionally for one identity."""

        for document in self._select_documents(publication_id):
            yield self._document_record(document)

    def _jsonl(self, descriptor: dict[str, Any]) -> Iterator[dict[str, Any]]:
        path = self._verified_path(descriptor)
        try:
            with path.open("r", encoding="utf-8") as stream:
                for line_number, line in enumerate(stream, 1):
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise DocumentaryProjectionError(
                            f"invalid JSONL at {descriptor['path']}:{line_number}") from exc
                    _need(type(record) is dict, "page JSONL record must be an object")
                    yield record
        except OSError as exc:
            raise DocumentaryProjectionError(f"documentary JSONL unavailable: {descriptor['path']}") from exc

    def _coverage_pages(self, document: dict[str, Any]) -> Iterator[dict[str, Any]]:
        expected = document["page_count"]
        count = 0
        for record in self._jsonl(document["extraction"]["coverage"]):
            count += 1
            self._validate_identity(document, record, count - 1, "coverage")
            yield record
        _need(count == expected, "coverage page cardinality drift")

    @staticmethod
    def _validate_identity(document: dict[str, Any], record: dict[str, Any],
                           page_index: int, view: str) -> None:
        _need(record.get("pub_id") == document["publication_id"],
              "page publication identity drift")
        _need(record.get("source_sha256") == document["pdf"]["sha256"],
              "page source identity drift")
        _need(record.get("pdf_page_index") == page_index and
              record.get("pdf_page_number") == page_index + 1,
              "page ordering drift")
        if view != "coverage":
            _need(record.get("view") == view and
                  len(record.get("text", "")) == record.get("char_count"),
                  "page text shape drift")
            _need(hashlib.sha256(record["text"].encode("utf-8")).hexdigest() ==
                  record.get("text_sha256"), "page text hash drift")

    def iter_coverage(self, publication_id: str | None = None) -> Iterator[dict[str, Any]]:
        """Yield verified per-page extraction coverage records."""

        documents = self._select_documents(publication_id)
        for document in documents:
            for coverage in self._coverage_pages(document):
                yield {
                    "schema": SCHEMA,
                    "record_type": "PAGE_COVERAGE",
                    "manifest_sha256": self.manifest_sha256,
                    "document_index": document["document_index"],
                    "publication_id": document["publication_id"],
                    "pdf_page_index": coverage["pdf_page_index"],
                    "pdf_page_number": coverage["pdf_page_number"],
                    "view": "coverage",
                    "source_file": deepcopy(document["pdf"]),
                    "coverage": deepcopy(coverage),
                    "source_sha256": coverage["source_sha256"],
                    "coverage_status": coverage["coverage_status"],
                    "disposition": self._disposition(),
                }

    def _select_documents(self, publication_id: str | None) -> tuple[dict[str, Any], ...]:
        if publication_id is None:
            return self._documents_in_order
        _need(type(publication_id) is str and publication_id in self.documents,
              "unknown publication identity")
        return (self.documents[publication_id],)

    def iter_pages(self, view: str = "plain", publication_id: str | None = None
                   ) -> Iterator[dict[str, Any]]:
        """Yield verified plain/layout page records in document/page order."""

        _need(view in VIEWS, "unsupported extraction view")
        for document in self._select_documents(publication_id):
            self._verified_path(document["pdf"])
            page_stream = self._jsonl(document["extraction"][view])
            coverage_stream = self._coverage_pages(document)
            count = 0
            sentinel = object()
            for page, coverage in zip_longest(page_stream, coverage_stream,
                                               fillvalue=sentinel):
                _need(page is not sentinel and coverage is not sentinel,
                      "page/coverage cardinality drift")
                self._validate_identity(document, page, count, view)
                _need(coverage["pdf_page_index"] == page["pdf_page_index"],
                      "page/coverage identity drift")
                coverage_hash = coverage[f"{view}_text_sha256"]
                _need(coverage_hash == page["text_sha256"],
                      "page/coverage text hash drift")
                count += 1
                yield {
                    "schema": SCHEMA,
                    "record_type": "PAGE",
                    "manifest_sha256": self.manifest_sha256,
                    "document_index": document["document_index"],
                    "publication_id": document["publication_id"],
                    "pdf_page_index": page["pdf_page_index"],
                    "pdf_page_number": page["pdf_page_number"],
                    "view": view,
                    "source_file": deepcopy(document["pdf"]),
                    "extracted_file": deepcopy(document["extraction"][view]),
                    "source_sha256": page["source_sha256"],
                    "text": page["text"],
                    "char_count": page["char_count"],
                    "text_sha256": page["text_sha256"],
                    "coverage": deepcopy(coverage),
                    "coverage_status": coverage["coverage_status"],
                    "disposition": self._disposition(),
                }
            _need(count == document["page_count"], "page cardinality drift")

    def iter_segments(self, view: str = "plain", publication_id: str | None = None
                      ) -> Iterator[dict[str, Any]]:
        """Yield exact extracted-text spans with an explicit nonsemantic ceiling."""

        for page in self.iter_pages(view=view, publication_id=publication_id):
            spans = extracted_segment_spans(page["text"])
            for kind in ("terminator", "blank_line"):
                for ordinal, character_span in enumerate(spans[kind], 1):
                    start, end = character_span
                    quote = page["text"][start:end]
                    yield {
                        "schema": SCHEMA,
                        "record_type": "EXTRACTED_SEGMENT",
                        "manifest_sha256": self.manifest_sha256,
                        "document_index": page["document_index"],
                        "publication_id": page["publication_id"],
                        "pdf_page_index": page["pdf_page_index"],
                        "pdf_page_number": page["pdf_page_number"],
                        "view": view,
                        "segment_kind": kind,
                        "segment_ordinal": ordinal,
                        "segment_method": SEGMENT_METHOD,
                        "character_span": character_span,
                        "exact_quote": quote,
                        "exact_quote_sha256": hashlib.sha256(quote.encode("utf-8")).hexdigest(),
                        "page_text_sha256": page["text_sha256"],
                        "source_sha256": page["source_sha256"],
                        "coverage": deepcopy(page["coverage"]),
                        "disposition": self._disposition(),
                    }

    def iter_records(self, include_coverage: bool = True,
                     include_segments: bool = False) -> Iterator[dict[str, Any]]:
        """Yield a deterministic full-corpus stream without retaining records."""

        for document in self.iter_documents():
            yield document
        if include_coverage:
            yield from self.iter_coverage()
        for view in VIEWS:
            yield from self.iter_pages(view=view)
        if include_segments:
            yield from self.iter_segments()

    def summary(self) -> dict[str, Any]:
        """Return manifest-level counts without scanning page text."""

        statuses: dict[str, int] = {}
        for document in self._documents_in_order:
            for status, count in document["coverage_status_counts"].items():
                statuses[status] = statuses.get(status, 0) + count
        return {
            "schema": SCHEMA,
            "manifest_sha256": self.manifest_sha256,
            "corpus_id": self.manifest["corpus_id"],
            "corpus_release": self.manifest["corpus_release"],
            "document_count": len(self._documents_in_order),
            "physical_page_count": self.manifest["physical_page_count"],
            "file_count": len(self.files),
            "view_page_counts": {
                "plain": self.manifest["physical_page_count"],
                "layout": self.manifest["physical_page_count"],
                "coverage": self.manifest["physical_page_count"],
            },
            "coverage_status_counts": dict(sorted(statuses.items())),
            "disposition": self._disposition(),
            "coverage_ceiling": self.manifest["coverage_ceiling"],
        }

    def verify(self) -> dict[str, Any]:
        """Verify all manifest-bound bytes; page streams validate identities lazily."""

        for descriptor in self.files.values():
            self._verified_path(descriptor)
        return {
            "status": "VERIFIED_MANIFEST_BOUND_BYTES",
            "manifest_sha256": self.manifest_sha256,
            "file_count": len(self.files),
            "document_count": len(self._documents_in_order),
            "physical_page_count": self.manifest["physical_page_count"],
        }


__all__ = [
    "DEFAULT_ROOT", "DOCUMENTARY_DISPOSITION", "MANIFEST_SHA256", "SCHEMA",
    "SEGMENT_METHOD", "UNRESOLVED_DISPOSITION", "DocumentaryProjection",
    "DocumentaryProjectionError", "extracted_segment_spans",
]
