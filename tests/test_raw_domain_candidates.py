"""Tests package behavior."""

from copy import deepcopy
from hashlib import sha256
import json

import pytest

from judgment_compilation.raw_domain_candidates import (
    CEILING,
    MANIFEST_SHA256,
    PROPOSED,
    UNRESOLVED,
    RawDomainCandidateError,
    RawDomainCandidates,
    canonical,
)


def test_full_retained_library_is_accounted_without_semantic_admission():
    summary = RawDomainCandidates().summary()
    assert summary["manifest_sha256"] == MANIFEST_SHA256
    assert summary["document_count"] == 195
    assert summary["physical_page_count"] == 15478
    assert summary["candidate_count"] > 0
    assert summary["uncovered_publication_ids"] == []
    assert len(summary["documents_with_candidates"]) == 195
    by_pattern = {row["pattern_id"]: row for row in summary["per_pattern"]}
    assert {"RESPONSIBILITY_AUTHORITY_REL", "INCLUSION_REL", "DEFINITION_COPULA"} <= set(by_pattern)
    assert all(by_pattern[key]["candidate_count"] > 0 for key in by_pattern)
    assert summary["admitted_interpretation_count"] == 0
    assert summary["semantic_coordinate_assignments"] == 0
    assert "NO_SEMANTIC_ADMISSION" in summary["ceiling"]


def test_stream_is_deterministic_and_every_row_is_exactly_provenanced():
    extractor = RawDomainCandidates()
    first = list(extractor.iter_candidates())
    second = list(RawDomainCandidates().iter_candidates())
    assert canonical(first) == canonical(second)
    assert first
    assert len({row["source_candidate_id"] for row in first}) == len(first)
    for row in first:
        assert row["interpretation_status"] == PROPOSED
        assert row["admission_status"] == UNRESOLVED
        assert row["semantic_coordinate"] is None
        assert row["document"]["pdf_sha256"]
        assert row["physical_page_number"] == row["physical_page_index"] + 1
        assert row["exact_quote_sha256"] == sha256(row["exact_quote"].encode("utf-8")).hexdigest()
        assert row["exact_quote"]
        assert row["ceiling"] == CEILING
        assert row["external_effects"] == []


def test_candidate_validation_rejects_rehashed_provenance_or_admission_tampering():
    extractor = RawDomainCandidates()
    candidate = next(extractor.iter_candidates())
    assert extractor.validate_candidate(candidate) == candidate

    for mutate in (
        lambda row: row["document"].update(pdf_sha256="0" * 64),
        lambda row: row.update(page_text_sha256="0" * 64),
        lambda row: row.update(exact_quote="forged"),
        lambda row: row.update(admission_status="ADMITTED"),
        lambda row: row.update(semantic_coordinate={"Gs": "forged"}),
        lambda row: row.update(interpretation_status=UNRESOLVED),
    ):
        changed = deepcopy(candidate)
        mutate(changed)
        with pytest.raises(RawDomainCandidateError):
            extractor.validate_candidate(changed)


def test_manifest_or_page_tampering_fails_closed(tmp_path):
    def bound(relative, payload):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return {"path": relative, "bytes": len(payload), "sha256": sha256(payload).hexdigest()}

    pdf = bound("doc.pdf", b"pdf")
    text = "The term Widget is defined as a fixture."
    page = {"char_count": len(text), "document_file": "doc.pdf", "document_index": 1,
            "pdf_page_index": 0, "pdf_page_number": 1, "pub_id": "DOC-1",
            "source_sha256": pdf["sha256"], "text": text,
            "text_sha256": sha256(text.encode()).hexdigest(), "view": "plain"}
    coverage = {"coverage_status": "NONIDENTICAL_DUAL_VIEW_AVAILABLE", "document_file": "doc.pdf",
                "document_index": 1, "layout_char_count": len(text), "layout_error": None,
                "layout_text_sha256": page["text_sha256"], "layout_warnings": [],
                "pdf_page_index": 0, "pdf_page_number": 1, "plain_char_count": len(text),
                "plain_error": None, "plain_text_sha256": page["text_sha256"], "plain_warnings": [],
                "pub_id": "DOC-1", "source_sha256": pdf["sha256"]}
    page_file = bound("pages/plain.jsonl", (json.dumps(page, sort_keys=True) + "\n").encode())
    coverage_file = bound("pages/coverage.jsonl", (json.dumps(coverage, sort_keys=True) + "\n").encode())
    layout_file = bound("pages/layout.jsonl", (json.dumps(dict(page, view="layout"), sort_keys=True) + "\n").encode())
    document = {"coverage_status_counts": {"NONIDENTICAL_DUAL_VIEW_AVAILABLE": 1}, "document_index": 1,
                "encrypted": False, "extraction": {"coverage": coverage_file, "layout": layout_file, "plain": page_file},
                "interpretation_status": "DOCUMENTARY_SOURCE_ONLY_NOT_COMPILED_JUDGMENT", "page_count": 1,
                "pdf": pdf, "publication_id": "DOC-1", "publication_metadata": {}, "title": "Fixture"}
    manifest = {"corpus_id": "fixture", "corpus_release": "fixture-1", "coverage_ceiling": "DOCUMENTARY_ONLY",
                "document_count": 1, "documents": [document], "files": [pdf, page_file, layout_file, coverage_file],
                "physical_page_count": 1, "schema_version": 1}
    manifest_bytes = json.dumps(manifest, sort_keys=True).encode()
    (tmp_path / "manifest.json").write_bytes(manifest_bytes)
    extractor = RawDomainCandidates(tmp_path, sha256(manifest_bytes).hexdigest())
    candidate = next(extractor.iter_candidates())
    assert candidate["document"]["publication_id"] == "DOC-1"
    (tmp_path / "pages/plain.jsonl").write_text("{}\n", encoding="utf-8")
    with pytest.raises(RawDomainCandidateError, match="documentary input drift"):
        list(extractor.iter_candidates())


def test_new_relation_and_definition_signals_capture_only_literal_text():
    extractor = RawDomainCandidates()
    text = (
        "The office is responsible for publishing guidance. "
        "The catalog includes assessment items. "
        "A complete block is known as a full block."
    )
    page = {
        "document_index": 1,
        "publication_id": "FIXTURE-1",
        "source_sha256": "a" * 64,
        "pdf_page_index": 0,
        "pdf_page_number": 1,
        "text_sha256": sha256(text.encode("utf-8")).hexdigest(),
        "text": text,
    }
    rows = {row["pattern_id"]: row for row in extractor._page_candidates(page)}
    assert {"RESPONSIBILITY_AUTHORITY_REL", "INCLUSION_REL", "DEFINITION_COPULA"} <= set(rows)
    assert rows["RESPONSIBILITY_AUTHORITY_REL"]["lexical_relation"] == {
        "subject": "The office",
        "predicate": "is responsible for",
        "object": "publishing guidance",
    }
    assert rows["INCLUSION_REL"]["lexical_relation"] == {
        "subject": "The catalog",
        "predicate": "includes",
        "object": "assessment items",
    }
    assert rows["DEFINITION_COPULA"]["lexical_relation"] == {
        "subject": "A complete block",
        "predicate": "is known as",
        "object": "a full block",
    }
    for pattern_id in ("RESPONSIBILITY_AUTHORITY_REL", "INCLUSION_REL", "DEFINITION_COPULA"):
        row = rows[pattern_id]
        assert row["relation_interpretation"] == UNRESOLVED
        assert row["admission_status"] == UNRESOLVED
        assert row["semantic_coordinate"] is None
        assert row["lexical_relation"]["subject"] in row["exact_quote"]
        assert row["lexical_relation"]["predicate"] in row["exact_quote"]
        assert row["lexical_relation"]["object"] in row["exact_quote"]
