"""Tests package behavior."""

from __future__ import annotations

from hashlib import sha256
import json

import pytest

from judgment_compilation.documentary_projection import DocumentaryProjection, DocumentaryProjectionError
from judgment_compilation.raw_judgment_candidates import (
    CLAIM_CEILING,
    STATUS_PROPOSED,
    STATUS_UNRESOLVED,
    _signals,
    iter_raw_judgment_candidates,
    summarize_raw_judgment_candidates,
)


def _sha(payload: bytes) -> str:
    return sha256(payload).hexdigest()


def _bound_fixture(tmp_path, text: str = "A system shall log events when active. Except during an outage, it must not delete records. A heading is not precedence."):
    def write_bound(relative: str, payload: bytes) -> dict[str, object]:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return {"path": relative, "bytes": len(payload), "sha256": _sha(payload)}

    pdf = write_bound("doc.pdf", b"fixture-pdf")
    base = {
        "char_count": len(text), "document_file": "doc.pdf", "document_index": 1,
        "pdf_page_index": 0, "pdf_page_number": 1, "pub_id": "DOC-1",
        "source_sha256": pdf["sha256"], "text": text,
        "text_sha256": _sha(text.encode("utf-8")),
    }
    def write_jsonl(relative: str, record: dict[str, object]) -> dict[str, object]:
        return write_bound(relative, (json.dumps(record, sort_keys=True) + "\n").encode("utf-8"))

    plain = write_jsonl("pages/plain.jsonl", dict(base, view="plain"))
    layout = write_jsonl("pages/layout.jsonl", dict(base, view="layout"))
    coverage = write_jsonl("pages/coverage.jsonl", {
        "coverage_status": "NONIDENTICAL_DUAL_VIEW_AVAILABLE", "document_file": "doc.pdf",
        "document_index": 1, "layout_char_count": len(text), "layout_error": None,
        "layout_text_sha256": base["text_sha256"], "layout_warnings": [],
        "pdf_page_index": 0, "pdf_page_number": 1, "plain_char_count": len(text),
        "plain_error": None, "plain_text_sha256": base["text_sha256"],
        "plain_warnings": [], "pub_id": "DOC-1", "source_sha256": pdf["sha256"],
    })
    document = {
        "coverage_status_counts": {"NONIDENTICAL_DUAL_VIEW_AVAILABLE": 1}, "document_index": 1,
        "encrypted": False, "extraction": {"coverage": coverage, "layout": layout, "plain": plain},
        "interpretation_status": "DOCUMENTARY_SOURCE_ONLY_NOT_COMPILED_JUDGMENT", "page_count": 1,
        "pdf": pdf, "publication_id": "DOC-1", "publication_metadata": {}, "title": "Fixture",
    }
    manifest = {
        "corpus_id": "fixture", "corpus_release": "fixture-1", "coverage_ceiling": "DOCUMENTARY_ONLY",
        "document_count": 1, "documents": [document], "files": [pdf, plain, layout, coverage],
        "physical_page_count": 1, "schema_version": 1,
    }
    raw = json.dumps(manifest, sort_keys=True).encode("utf-8")
    (tmp_path / "manifest.json").write_bytes(raw)
    return DocumentaryProjection(tmp_path, _sha(raw))


def test_full_library_accounting():
    first = summarize_raw_judgment_candidates()
    assert first["document_count"] == 195
    assert first["physical_page_count"] == first["processed_plain_page_count"] == 15478
    assert first["candidate_count"] > 0
    assert first["admission"] == "NOT_ADMITTED"


def test_fixture_stream_is_deterministic(tmp_path):
    # The fixture isolates determinism without duplicating the full retained
    # library's integrity scan, which is already covered by the accounting test.
    assert summarize_raw_judgment_candidates(_bound_fixture(tmp_path)) == summarize_raw_judgment_candidates(_bound_fixture(tmp_path))


def test_casefold_ties_have_a_total_deterministic_order():
    assert _signals("must Must MUST")["modality"] == ["MUST", "Must", "must"]


def test_source_bound_records_are_proposed_or_unresolved_without_admission(tmp_path):
    candidates = list(iter_raw_judgment_candidates(_bound_fixture(tmp_path)))
    assert {record["status"] for record in candidates} == {STATUS_PROPOSED, STATUS_UNRESOLVED}
    for record in candidates:
        source = record["source"]
        start, end = source["character_span"]["start"], source["character_span"]["end"]
        assert start < end
        assert _sha(source["exact_quote"].encode("utf-8")) == source["exact_quote_sha256"]
        assert record["semantic_disposition"] == {
            "admission": "NOT_ADMITTED", "applicability": None, "compliance": None,
            "responsibility": None, "external_effects": [],
        }
        assert record["claim_ceiling"] == CLAIM_CEILING


def test_manifest_or_page_tamper_rejects_before_accounting(tmp_path):
    projection = _bound_fixture(tmp_path)
    page_path = tmp_path / "pages/plain.jsonl"
    page_path.write_text(page_path.read_text(encoding="utf-8").replace("shall", "might"), encoding="utf-8")
    with pytest.raises(DocumentaryProjectionError, match="documentary input drift"):
        summarize_raw_judgment_candidates(projection)


def test_hierarchy_does_not_create_precedence_or_a_winner(tmp_path):
    records = list(iter_raw_judgment_candidates(_bound_fixture(tmp_path, "Heading: Controls. A process depends on logging.")))
    dependency = next(record for record in records if record["pattern_id"] == "DEPENDENCY_SIGNAL")
    assert dependency["precedence"] == {
        "explicit_precedence_signal": False, "resolved_winner": None, "hierarchy_is_precedence": False,
    }
    assert dependency["semantic_disposition"]["external_effects"] == []
