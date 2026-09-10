"""Tests package behavior."""
from copy import deepcopy
from pathlib import Path

import pytest

from judgment_compilation.application import Application
from judgment_compilation.source_mappings import CEILING, SCHEMA, SourceMappingError


@pytest.fixture(scope="module")
def app():
    return Application()


@pytest.fixture(scope="module")
def index(app):
    return app.source_mappings.build()


def test_exact_reviewed_source_mappings_are_separate_from_generic_templates(index):
    assert index["schema"] == SCHEMA
    assert index["counts"] == {
        "generic_requirement_templates": 2138,
        "generic_requirement_policy_semantic_mappings": 0,
        "exact_reviewed_source_mappings": 5,
        "bounded_reviewed_pack_executable_mappings": 5,
    }
    assert [row["source_id"] for row in index["rows"]] == [
        "AC-2(l)", "AC-6 Control", "PS-4(a)", "PS-4(b)", "SI-2(c)"
    ]
    assert all(row["execution_binding"]["generic_requirement_runtime_executable"] is False
               for row in index["rows"])
    assert all(row["execution_binding"]["bounded_reviewed_pack_executable"] is True
               for row in index["rows"])
    assert index["full_library_semantic_compilation"] == "INCOMPLETE"
    assert index["coverage_ceiling"] == CEILING


def test_mappings_bind_exact_sources_interpretations_and_executable_operations(index):
    ps4a = next(row for row in index["rows"] if row["source_id"] == "PS-4(a)")
    assert ps4a["statement_id"] == "ps-4_smt.a"
    assert ps4a["source_binding"]["template_sha256"] == \
        "aabea98d1dd7487ff69a65b9683663ede0ff542500eef6cbdc247b520923bf9c"
    assert ps4a["source_binding"]["physical_pdf_page_one_based"] == 251
    assert ps4a["source_binding"]["character_span"] == {
        "start": 2296, "end": 2372, "interval": "HALF_OPEN", "unit": "UNICODE_CODE_POINT"
    }
    assert "ps4a_timing_scope" in ps4a["interpretation_binding"]["interpretation_ids"]
    assert ps4a["interpretation_binding"]["work_interpretation_ids"] == [
        "compare_ps4a_access_disable_period"
    ]
    assert "compare_ps4a_access_disable_period" in ps4a["execution_binding"]["work_ids"]
    assert "ps4a-access-disable-timing" in ps4a["execution_binding"]["architecture_ids"]
    ac6 = next(row for row in index["rows"] if row["source_id"] == "AC-6 Control")
    assert ac6["execution_binding"]["scope"] == "REVIEW_SELECTION_ONLY"
    assert ac6["interpretation_binding"]["work_interpretation_ids"] == []


def test_rebuild_and_exact_validator_are_deterministic(app, index):
    assert app.source_mappings.build() == index
    assert app.source_mappings.validate(index) == index


@pytest.mark.parametrize("mutation", [
    lambda value: value["rows"].pop(),
    lambda value: value["rows"][0]["source_binding"].update(source_sha256="0" * 64),
    lambda value: value["rows"][0]["interpretation_binding"].update(interpretation_ids=[]),
    lambda value: value["rows"][0]["execution_binding"].update(bounded_reviewed_pack_executable=False),
    lambda value: value.update(pack_sha256="0" * 64),
    lambda value: value["counts"].update(generic_requirement_policy_semantic_mappings=2138),
])
def test_validator_rejects_source_interpretation_execution_or_admission_drift(app, index, mutation):
    changed = deepcopy(index)
    mutation(changed)
    with pytest.raises(SourceMappingError, match="source mapping index mismatch"):
        app.source_mappings.validate(changed)


def test_consumer_surfaces_mapping_index_without_model_authority_or_effect(app, index):
    result = app.query({"mode": "mappings", "request": {"operation": "index"}})
    assert result["route"] == "DETERMINISTIC_REVIEWED_SOURCE_MAPPINGS"
    assert result["kernel"]["index_sha256"] == index["index_sha256"]
    assert result["escalation"]["status"] == "CLARIFICATION_REQUIRED"
    assert result["inference"]["model_calls"] == 0
    assert result["egress"]["external_effects"] == []
    assert result["kernel"]["explicit_selection_confirmed"] is False


def test_cli_and_gui_expose_reviewed_source_mappings():
    root = Path(__file__).parents[1]
    cli = (root / "judgment_compilation/cli.py").read_text(encoding="utf-8")
    html = (root / "judgment_compilation/static/index.html").read_text(encoding="utf-8")
    assert "source-mappings" in cli
    assert 'id="sourceMappings"' in html
    assert 'mode:"mappings"' in html
