"""Tests package behavior."""
from copy import deepcopy
from pathlib import Path

import pytest

from judgment_compilation.application import Application
from judgment_compilation.source_accounting import CEILING, SCHEMA, SourceAccountingError


@pytest.fixture(scope="module")
def app():
    return Application()


@pytest.fixture(scope="module")
def manifest(app):
    return app.source_accounting.build()


def test_manifest_reconciles_all_current_inventory_owners(manifest):
    assert manifest["schema"] == SCHEMA
    accounting = manifest["source_accounting"]
    assert accounting["status"] == "COMPLETE_FOR_RETAINED_PACKAGE_INPUTS"
    assert accounting["library"]["document_count"] == 195
    assert accounting["library"]["physical_page_count"] == 15478
    assert accounting["library"]["file_count"] == 780
    assert accounting["catalog"]["structural_records"] == 15546
    assert accounting["catalog"]["controls_and_enhancements"] == 1196
    assert accounting["profiles"]["profile_count"] == 4
    assert accounting["profiles"]["literal_selection_rows"] == 902
    assert accounting["assessments"]["assessment_controls"] == 1014
    assert accounting["assessments"]["objectives"] == 3715
    assert accounting["assessments"]["methods"] == 2931
    assert accounting["assessments"]["objects"] == 14101
    assert accounting["requirements"]["total_templates"] == 2138


def test_manifest_is_deterministic_and_exactly_validated(app, manifest):
    assert app.source_accounting.build() == manifest
    assert app.source_accounting.validate(manifest) == manifest


@pytest.mark.parametrize("mutation", [
    lambda value: value["source_accounting"]["library"].update(document_count=1),
    lambda value: value["source_accounting"]["profiles"]["source_identities"][0].update(source_sha256="0" * 64),
    lambda value: value["source_accounting"]["requirements"].update(total_templates=2137),
    lambda value: value["interpretation_admission"].update(pack_sha256="0" * 64),
    lambda value: value["executable_coverage"].update(executable_policy_templates=2138),
])
def test_validation_rejects_inventory_substitution(app, manifest, mutation):
    changed = deepcopy(manifest)
    mutation(changed)
    with pytest.raises(SourceAccountingError, match="manifest mismatch"):
        app.source_accounting.validate(changed)


def test_three_claim_dimensions_remain_distinct(manifest):
    assert manifest["source_accounting"]["status"] == "COMPLETE_FOR_RETAINED_PACKAGE_INPUTS"
    assert manifest["interpretation_admission"]["scope"] == "EXACT_REVIEWED_SEMANTIC_PACK_ONLY"
    assert manifest["interpretation_admission"]["does_not_admit_requirement_templates"] is True
    coverage = manifest["executable_coverage"]
    assert coverage["full_library_semantic_compilation"] == "INCOMPLETE"
    assert coverage["admitted_policy_semantic_template_mappings"] == 0
    assert coverage["executable_policy_templates"] == 0
    assert coverage["exact_reviewed_source_mappings"] == 5
    assert coverage["bounded_reviewed_pack_executable_mappings"] == 5
    assert len(coverage["source_mapping_index_sha256"]) == 64
    assert coverage["residual"] == "FULL_LIBRARY_EXECUTABLE_SEMANTIC_COMPILATION_INCOMPLETE"
    assert manifest["coverage_ceiling"] == CEILING
    assert manifest["explicit_selection_confirmed"] is False
    assert manifest["compliance_verdict"] is None
    assert manifest["external_effects"] == []


def test_manifest_is_compact_and_does_not_copy_corpus_rows(manifest):
    assert manifest["source_accounting"]["requirements"]["rows_embedded"] is False
    assert manifest["source_accounting"]["profiles"]["selector_rows_embedded"] is False
    assert "rows" not in manifest["source_accounting"]["requirements"]
    assert "documents" not in manifest["source_accounting"]["library"]


def test_consumer_route_exposes_accounting_without_model_or_effect(app, manifest):
    result = app.query({"mode": "accounting", "request": {"operation": "manifest"}})
    assert result["route"] == "DETERMINISTIC_NIST_SOURCE_ACCOUNTING"
    assert result["kernel"]["manifest_sha256"] == manifest["manifest_sha256"]
    assert result["escalation"]["status"] == "CLARIFICATION_REQUIRED"
    assert result["inference"]["model_calls"] == 0
    assert result["egress"]["external_effects"] == []


def test_cli_and_gui_expose_source_accounting():
    root = Path(__file__).parents[1]
    html = (root / "judgment_compilation/static/index.html").read_text(encoding="utf-8")
    cli = (root / "judgment_compilation/cli.py").read_text(encoding="utf-8")
    assert 'id="sourceAccounting"' in html
    assert 'mode:"accounting"' in html
    assert "source-accounting" in cli
