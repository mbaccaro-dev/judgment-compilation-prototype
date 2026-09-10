"""Tests package behavior."""

import hashlib
import json
from pathlib import Path

import pytest

from judgment_compilation.documentary_projection import (
    DEFAULT_ROOT,
    MANIFEST_SHA256,
    UNRESOLVED_DISPOSITION,
    VIEWS,
    DocumentaryProjection,
    DocumentaryProjectionError,
    extracted_segment_spans,
)


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def test_summary_and_full_corpus_page_stream_are_typed_and_deterministic():
    projection = DocumentaryProjection()
    summary = projection.summary()
    assert summary["manifest_sha256"] == MANIFEST_SHA256
    assert summary["document_count"] == 195
    assert summary["physical_page_count"] == 15478
    assert summary["file_count"] == 780
    assert summary["disposition"]["policy_semantics"] == UNRESOLVED_DISPOSITION

    documents = list(projection.iter_documents())
    assert len(documents) == 195
    assert [record["document_index"] for record in documents] == list(range(1, 196))
    assert all(record["record_type"] == "DOCUMENT" for record in documents)
    assert all(record["source_file"]["sha256"] for record in documents)

    counts = {}
    for view in VIEWS:
        count = 0
        for record in projection.iter_pages(view=view):
            count += 1
            assert record["record_type"] == "PAGE"
            assert record["view"] == view
            assert record["source_sha256"] == record["source_file"]["sha256"]
            assert record["text_sha256"] == _digest(record["text"].encode("utf-8"))
            assert record["coverage"][f"{view}_text_sha256"] == record["text_sha256"]
            assert record["disposition"]["policy_semantics"] == UNRESOLVED_DISPOSITION
        counts[view] = count
    assert counts == {"plain": 15478, "layout": 15478}


def test_exact_spans_preserve_text_identity_and_leave_policy_unresolved():
    text = "Alpha. Beta?\n\nGamma"
    spans = extracted_segment_spans(text)
    assert [text[start:end] for start, end in spans["terminator"]] == ["Alpha.", "Beta?", "Gamma"]
    assert [text[start:end] for start, end in spans["blank_line"]] == ["Alpha. Beta?", "Gamma"]

    projection = DocumentaryProjection()
    page = next(projection.iter_pages(publication_id="NIST SP 800-100-upd1"))
    segment = next(projection.iter_segments(publication_id="NIST SP 800-100-upd1"))
    start, end = segment["character_span"]
    assert segment["record_type"] == "EXTRACTED_SEGMENT"
    assert segment["view"] == "plain"
    assert segment["exact_quote"] == page["text"][start:end]
    assert segment["exact_quote_sha256"] == _digest(segment["exact_quote"].encode("utf-8"))
    assert segment["page_text_sha256"] == page["text_sha256"]
    assert segment["source_sha256"] == page["source_sha256"]
    assert segment["disposition"]["policy_semantics"] == UNRESOLVED_DISPOSITION


def test_post_initialization_page_bytes_drift_is_rejected(tmp_path):
    def write_bound(relative: str, payload: bytes) -> dict[str, object]:
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
        return {"path": relative, "bytes": len(payload), "sha256": _digest(payload)}

    pdf = write_bound("doc.pdf", b"pdf")
    text = "One sentence."
    page = {
        "char_count": len(text),
        "document_file": "doc.pdf",
        "document_index": 1,
        "pdf_page_index": 0,
        "pdf_page_number": 1,
        "pub_id": "DOC-1",
        "source_sha256": pdf["sha256"],
        "text": text,
        "text_sha256": _digest(text.encode("utf-8")),
        "view": "plain",
    }
    layout = dict(page, view="layout")
    coverage = {
        "coverage_status": "NONIDENTICAL_DUAL_VIEW_AVAILABLE",
        "document_file": "doc.pdf",
        "document_index": 1,
        "layout_char_count": len(text),
        "layout_error": None,
        "layout_text_sha256": layout["text_sha256"],
        "layout_warnings": [],
        "pdf_page_index": 0,
        "pdf_page_number": 1,
        "plain_char_count": len(text),
        "plain_error": None,
        "plain_text_sha256": page["text_sha256"],
        "plain_warnings": [],
        "pub_id": "DOC-1",
        "source_sha256": pdf["sha256"],
    }

    def write_jsonl(relative: str, record: dict[str, object]) -> dict[str, object]:
        payload = (json.dumps(record, sort_keys=True) + "\n").encode("utf-8")
        return write_bound(relative, payload)

    plain_file = write_jsonl("pages/plain.jsonl", page)
    layout_file = write_jsonl("pages/layout.jsonl", layout)
    coverage_file = write_jsonl("pages/coverage.jsonl", coverage)
    document = {
        "coverage_status_counts": {"NONIDENTICAL_DUAL_VIEW_AVAILABLE": 1},
        "document_index": 1,
        "encrypted": False,
        "extraction": {"coverage": coverage_file, "layout": layout_file, "plain": plain_file},
        "interpretation_status": "DOCUMENTARY_SOURCE_ONLY_NOT_COMPILED_JUDGMENT",
        "page_count": 1,
        "pdf": pdf,
        "publication_id": "DOC-1",
        "publication_metadata": {},
        "title": "Fixture",
    }
    manifest = {
        "corpus_id": "fixture",
        "corpus_release": "fixture-1",
        "coverage_ceiling": "DOCUMENTARY_ONLY",
        "document_count": 1,
        "documents": [document],
        "files": [pdf, plain_file, layout_file, coverage_file],
        "physical_page_count": 1,
        "schema_version": 1,
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True).encode("utf-8")
    (tmp_path / "manifest.json").write_bytes(manifest_bytes)
    projection = DocumentaryProjection(tmp_path, _digest(manifest_bytes))
    assert next(projection.iter_pages())["text"] == text

    changed = json.dumps(dict(page, text="changed", char_count=7,
                              text_sha256=_digest(b"changed")), sort_keys=True) + "\n"
    (tmp_path / "pages/plain.jsonl").write_text(changed, encoding="utf-8")
    with pytest.raises(DocumentaryProjectionError, match="documentary input drift"):
        next(projection.iter_pages())
