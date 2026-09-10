"""Tests package behavior."""

from copy import deepcopy

import pytest

from judgment_compilation.raw_semantic_compiler import (
    CEILING,
    NOT_ADMITTED_SEMANTICS,
    RawSemanticCompiler,
    RawSemanticCompilerError,
    canonical,
)


def test_full_library_accounting_keeps_coverage_candidates_and_admission_separate():
    summary = RawSemanticCompiler().summary()
    coverage = summary["documentary_coverage"]
    assert coverage["document_count"] == 195
    assert coverage["physical_page_count"] == 15478
    assert summary["proposed_candidates"]["total_count"] > 0
    assert summary["proposed_candidates"]["domain_count"] > 0
    assert summary["proposed_candidates"]["judgment_count"] > 0
    assert summary["proposed_candidates"]["work_count"] > 0
    assert summary["proposed_candidates"]["architecture_count"] > 0
    assert summary["proposed_candidates"]["total_count"] == sum(
        summary["proposed_candidates"][key]
        for key in ("domain_count", "judgment_count", "work_count", "architecture_count")
    )
    assert summary["admitted_semantics"] == {
        "domain_count": 0,
        "judgment_count": 0,
        "work_count": 0,
        "architecture_count": 0,
        "total_count": 0,
        "reason": "SEPARATE_INTERPRETATION_QUALIFICATION_HAS_NOT_ADMITTED_RAW_CANDIDATES",
    }
    assert summary["capability_status"] == {
        "judgment_decomposition": "NOT_IMPLEMENTED_BY_RAW_CANDIDATE_COMPILER",
        "work_decomposition": "NOT_IMPLEMENTED_BY_RAW_CANDIDATE_COMPILER",
        "architecture_decomposition": "NOT_IMPLEMENTED_BY_RAW_CANDIDATE_COMPILER",
        "architecture_composition": "NOT_IMPLEMENTED_BY_RAW_CANDIDATE_COMPILER",
        "executable_inquiry_program": "NOT_IMPLEMENTED_BY_RAW_CANDIDATE_COMPILER",
    }
    assert len(summary["per_document"]) == 195
    assert sum(row["physical_page_count"] for row in summary["per_document"]) == 15478
    assert summary["claim_ceiling"] == CEILING
    assert summary["external_effects"] == []


def test_candidate_pages_are_deterministic_bounded_and_never_admitted():
    compiler = RawSemanticCompiler()
    first = list(compiler.iter_candidates(limit=12))
    second = list(RawSemanticCompiler().iter_candidates(limit=12))
    assert canonical(first) == canonical(second)
    assert len(first) == 12
    assert all(row["semantic_admission_status"] == NOT_ADMITTED_SEMANTICS for row in first)
    assert {row["stack"] for row in first} == {"DOMAIN"}
    next_page = list(compiler.iter_candidates(offset=12, limit=4))
    assert next_page
    assert {row["candidate_id"] for row in first}.isdisjoint(
        row["candidate_id"] for row in next_page
    )


def test_summary_and_document_filter_are_consistent():
    compiler = RawSemanticCompiler()
    record = next(compiler.iter_candidates(limit=1))
    if record["stack"] == "DOMAIN":
        publication_id = record["raw_candidate"]["document"]["publication_id"]
    else:
        publication_id = record["raw_candidate"]["source"]["publication_id"]
    filtered = list(compiler.iter_candidates(publication_id=publication_id, limit=10))
    assert filtered
    for item in filtered:
        source_id = (item["raw_candidate"]["document"]["publication_id"]
                     if item["stack"] == "DOMAIN"
                     else item["raw_candidate"]["source"]["publication_id"])
        assert source_id == publication_id


def test_work_and_architecture_are_publicly_iterable_raw_proposals():
    compiler = RawSemanticCompiler()
    rows = list(compiler.iter_candidates(stacks=("WORK", "ARCHITECTURE"), limit=8))
    assert rows
    assert {row["stack"] for row in rows} <= {"WORK", "ARCHITECTURE"}
    assert all(row["semantic_admission_status"] == NOT_ADMITTED_SEMANTICS for row in rows)
    assert canonical(rows) == canonical(list(
        RawSemanticCompiler().iter_candidates(stacks=("WORK", "ARCHITECTURE"), limit=8)
    ))


def test_on_demand_validation_rejects_source_or_admission_tampering():
    compiler = RawSemanticCompiler()
    record = next(compiler.iter_candidates(limit=1))
    work_record = next(compiler.iter_candidates(stacks=("WORK",), limit=1))
    assert compiler.validate_candidate_provenance_many([record, work_record]) == [record, work_record]
    # The established single-record surface remains a compatibility wrapper.
    assert compiler.validate_candidate_provenance(record) == record

    changed_quote = deepcopy(record)
    changed_quote["raw_candidate"]["exact_quote"] = "forged" 
    with pytest.raises(RawSemanticCompilerError):
        compiler.validate_candidate_provenance(changed_quote)

    changed_admission = deepcopy(record)
    changed_admission["semantic_admission_status"] = "ADMITTED"
    with pytest.raises(RawSemanticCompilerError):
        compiler.validate_candidate_provenance(changed_admission)
