"""Tests package behavior."""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json

import pytest

from judgment_compilation.documentary_projection import DocumentaryProjection
from judgment_compilation.raw_work_architecture_candidates import (
    CEILING,
    PROPOSED,
    UNRESOLVED,
    RawWorkArchitectureCandidateError,
    RawWorkArchitectureCandidates,
)


def _sha(payload: bytes) -> str:
    return sha256(payload).hexdigest()


def _fixture(tmp_path, text: str = (
    "The organization shall assess controls before authorization. "
    "It must monitor results and report findings in coordination with partners."
)):
    def write(relative: str, payload: bytes) -> dict[str, object]:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return {"path": relative, "bytes": len(payload), "sha256": _sha(payload)}

    pdf = write("pdf/doc.pdf", b"fixture-pdf")
    base = {
        "char_count": len(text), "document_file": "pdf/doc.pdf", "document_index": 1,
        "pdf_page_index": 0, "pdf_page_number": 1, "pub_id": "DOC-1",
        "source_sha256": pdf["sha256"], "text": text,
        "text_sha256": _sha(text.encode("utf-8")),
    }
    def jsonl(relative: str, record: dict[str, object]) -> dict[str, object]:
        return write(relative, (json.dumps(record, sort_keys=True) + "\n").encode("utf-8"))

    plain = jsonl("pages/plain.jsonl", dict(base, view="plain"))
    layout = jsonl("pages/layout.jsonl", dict(base, view="layout"))
    coverage = jsonl("pages/coverage.jsonl", {
        "coverage_status": "DUAL_VIEW", "document_file": "pdf/doc.pdf", "document_index": 1,
        "layout_char_count": len(text), "layout_error": None,
        "layout_text_sha256": base["text_sha256"], "layout_warnings": [],
        "pdf_page_index": 0, "pdf_page_number": 1, "plain_char_count": len(text),
        "plain_error": None, "plain_text_sha256": base["text_sha256"],
        "plain_warnings": [], "pub_id": "DOC-1", "source_sha256": pdf["sha256"],
    })
    document = {
        "coverage_status_counts": {"DUAL_VIEW": 1}, "document_index": 1, "encrypted": False,
        "extraction": {"coverage": coverage, "layout": layout, "plain": plain},
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
    return RawWorkArchitectureCandidates(tmp_path, _sha(raw))


def test_full_library_accounting_is_explicit_and_unadmitted():
    summary = RawWorkArchitectureCandidates().summary()
    assert summary["document_count"] == 195
    assert summary["physical_page_count"] == 15478
    assert summary["candidate_count"] > 0
    assert summary["admitted_interpretation_count"] == 0
    assert summary["semantic_coordinate_assignments"] == 0


def test_candidate_keeps_work_and_architecture_as_unimplemented_proposals(tmp_path):
    compiler = _fixture(tmp_path)
    candidates = list(compiler.iter_candidates())
    kinds = {candidate["candidate_kind"] for candidate in candidates}
    assert kinds == {"WORK_OPERATION_INTERFACE", "ARCHITECTURE_COMPOSITION"}
    for candidate in candidates:
        start, end = candidate["character_span"]
        assert candidate["exact_quote"]
        assert _sha(candidate["exact_quote"].encode("utf-8")) == candidate["exact_quote_sha256"]
        assert candidate["interpretation_status"] == PROPOSED
        assert candidate["admission_status"] == UNRESOLVED
        assert candidate["semantic_coordinate"] is None
        assert candidate["semantic_disposition"] == {
            "admission": "NOT_ADMITTED", "applicability": None, "compliance": None,
            "responsibility": None, "external_effects": [],
        }
        assert candidate["ceiling"] == CEILING
        assert start < end
        assert candidate["proposal"]["execution_status"] == UNRESOLVED
        if candidate["candidate_kind"] == "WORK_OPERATION_INTERFACE":
            assert candidate["proposal"]["implementation"] is None
        else:
            assert candidate["proposal"]["program"] is None


def test_summary_is_deterministic_and_accounts_for_every_fixture_page(tmp_path):
    first = _fixture(tmp_path).summary()
    second = _fixture(tmp_path).summary()
    assert first == second
    assert first["document_count"] == first["physical_page_count"] == 1
    assert first["candidate_count_by_kind"]["WORK_OPERATION_INTERFACE"] > 0
    assert first["candidate_count_by_kind"]["ARCHITECTURE_COMPOSITION"] > 0


@pytest.mark.parametrize("mutate", [
    lambda record: record["document"].update(publication_id="OTHER"),
    lambda record: record.update(physical_page_index=9),
    lambda record: record.update(exact_quote="forged"),
    lambda record: record.update(semantic_coordinate={"Gs": [0], "L": 1, "I": 0}),
    lambda record: record["proposal"].update(implementation="invented"),
    lambda record: record["semantic_disposition"].update(compliance=True),
    lambda record: record.update(admission_status="ADMITTED"),
])
def test_tampering_or_admission_is_rejected(tmp_path, mutate):
    compiler = _fixture(tmp_path)
    candidate = deepcopy(next(compiler.iter_candidates()))
    mutate(candidate)
    with pytest.raises(RawWorkArchitectureCandidateError):
        compiler.validate_candidate(candidate)


def test_source_rederivation_accepts_exact_candidate(tmp_path):
    compiler = _fixture(tmp_path)
    candidate = next(compiler.iter_candidates())
    assert compiler.validate_candidate(candidate) == candidate
