"""Tests package behavior."""
from copy import deepcopy

import pytest

from judgment_compilation.document_programs import ReviewedDocumentPrograms
from judgment_compilation.raw_semantic_compiler import RawSemanticCompiler, RawSemanticCompilerError
from test_semantic_values import fixture


def _raw_summary():
    return {
        "documentary_coverage": {"manifest_sha256": "1" * 64, "document_count": 2},
        "per_document": [
            {
                "publication_id": "doc-a", "document_index": 1,
                "manifest_sha256": "1" * 64,
                "source_file": {"sha256": "a" * 64},
                "extraction_files": {"plain": {"sha256": "b" * 64}},
                "coverage_status_counts": {"VERIFIED": 1},
                "interpretation_status": "DOCUMENTARY_SOURCE_ONLY_NOT_COMPILED_JUDGMENT",
                "domain_proposed_candidate_count": 1,
                "judgment_proposed_candidate_count": 0,
                "work_proposed_candidate_count": 0,
                "architecture_proposed_candidate_count": 0,
                "proposed_candidate_count": 1,
                "raw_candidate_evidence_sha256": "c" * 64,
            },
            {
                "publication_id": "doc-b", "document_index": 2,
                "manifest_sha256": "1" * 64,
                "source_file": {"sha256": "d" * 64},
                "extraction_files": {"plain": {"sha256": "e" * 64}},
                "coverage_status_counts": {"VERIFIED": 2},
                "interpretation_status": "DOCUMENTARY_SOURCE_ONLY_NOT_COMPILED_JUDGMENT",
                "domain_proposed_candidate_count": 0,
                "judgment_proposed_candidate_count": 0,
                "work_proposed_candidate_count": 0,
                "architecture_proposed_candidate_count": 0,
                "proposed_candidate_count": 0,
                "raw_candidate_evidence_sha256": "f" * 64,
            },
        ],
    }


def _index():
    return {
        "schema": "jc/reviewed-document-package-index/1",
        "status": "SOURCE_BOUND_NOT_EXECUTED",
        "packages": [{"id": "held-doc-a", "publication_id": "doc-a", "sha256": "2" * 64}],
        "external_effects": [],
    }


def test_publication_coverage_keeps_raw_and_reviewed_passage_dispositions_distinct():
    report = RawSemanticCompiler._coverage_report(_raw_summary(), _index())

    assert report["publication_count"] == 2
    assert report["registered_reviewed_package_ids"] == ["held-doc-a"]
    assert report["publications"][0]["registered_reviewed_document_packages"] == [
        {"package_id": "held-doc-a", "package_sha256": "2" * 64}
    ]
    assert report["publications"][0]["semantic_disposition"]["raw_candidates"] == "NOT_ADMITTED"
    assert report["publications"][0]["semantic_disposition"]["whole_document_semantic_completion"] == "NOT_ESTABLISHED"
    assert report["publications"][1]["registered_reviewed_document_packages"] == []
    assert report["publications"][1]["executable_applicability"]["status"] == "NOT_ESTABLISHED_FOR_WHOLE_DOCUMENT"
    assert report["external_effects"] == []


@pytest.mark.parametrize("mutation", [
    lambda raw, index: raw["per_document"].append(deepcopy(raw["per_document"][0])),
    lambda raw, index: index["packages"].append(deepcopy(index["packages"][0])),
    lambda raw, index: index["packages"][0].update(publication_id="outside-retained-library"),
])
def test_publication_coverage_rejects_duplicate_or_mismatched_identities(mutation):
    raw, index = _raw_summary(), _index()
    mutation(raw, index)
    with pytest.raises(RawSemanticCompilerError):
        RawSemanticCompiler._coverage_report(raw, index)


def test_real_library_report_has_one_row_per_retained_publication_and_dynamic_package_ids():
    programs = ReviewedDocumentPrograms(fixture())
    summary = RawSemanticCompiler(reviewed_program_index=programs.index).summary()
    report = summary["publication_coverage"]

    assert summary["documentary_coverage"]["document_count"] == 195
    assert report["publication_count"] == 195
    assert len(report["publications"]) == 195
    assert report["registered_reviewed_package_ids"] == [
        package["id"] for package in programs.index()["packages"]
    ]
    assert all(row["raw_candidates"]["raw_candidate_evidence_sha256"] for row in report["publications"])
    assert all(row["executable_applicability"]["status"] ==
               "NOT_ESTABLISHED_FOR_WHOLE_DOCUMENT" for row in report["publications"])
