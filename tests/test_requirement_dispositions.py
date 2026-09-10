"""Tests package behavior."""
from copy import deepcopy
from pathlib import Path

import pytest

from judgment_compilation.application import Application
from judgment_compilation.nist_requirements import (
    DISPOSITION_CEILING, DISPOSITION_SCHEMA, RequirementError, Requirements,
)


@pytest.fixture(scope="module")
def requirements():
    return Requirements()


@pytest.fixture(scope="module")
def index(requirements):
    return requirements.disposition_index()


def test_index_is_exhaustive_sorted_and_non_executable(index):
    assert index["schema"] == DISPOSITION_SCHEMA
    assert index["counts"] == {
        "total_templates": 2138,
        "supported_documentary_templates": 2138,
        "unsupported_documentary_templates": 0,
        "admitted_policy_semantic_mappings": 0,
        "executable_policy_templates": 0,
    }
    rows = index["rows"]
    ids = [row["statement_id"] for row in rows]
    hashes = [row["template_sha256"] for row in rows]
    assert ids == sorted(ids) and len(ids) == len(set(ids)) == 2138
    assert len(hashes) == len(set(hashes)) == 2138
    assert all(row["disposition"] == {
        "documentary_status": "SOURCE_TEMPLATE_ONLY",
        "policy_semantic_mapping": {
            "status": "NOT_ADMITTED",
            "residual": "REQUIREMENT_TO_POLICY_SEMANTICS_NOT_ADMITTED",
        },
        "executable_policy": False,
        "ceiling": DISPOSITION_CEILING,
    } for row in rows)


def test_index_rebuild_is_deterministic_and_validated(requirements, index):
    assert requirements.disposition_index() == index
    assert requirements.validate_disposition_index(index) == index


@pytest.mark.parametrize("mutation", [
    lambda value: value["rows"].pop(),
    lambda value: value["rows"].append(deepcopy(value["rows"][0])),
    lambda value: value["counts"].update(total_templates=1),
    lambda value: value["rows"][0]["disposition"].update(executable_policy=True),
    lambda value: value["rows"][0].update(template_sha256="0" * 64),
])
def test_validator_rejects_omission_duplication_or_false_admission(requirements, index, mutation):
    changed = deepcopy(index)
    mutation(changed)
    with pytest.raises(RequirementError, match="disposition index mismatch"):
        requirements.validate_disposition_index(changed)


def test_rows_keep_exact_source_and_parameter_references(index):
    row = next(row for row in index["rows"] if row["statement_id"] == "ps-4_smt.a")
    assert row["source"]["xml_id"] == "ps-4_smt.a"
    assert row["source"]["source_sha256"] == index["source_sha256"]
    assert row["root_parameter_ids"] == ["ps-04_odp.01"]
    parameter = row["parameters"][0]
    assert parameter["parameter_id"] == "ps-04_odp.01"
    assert parameter["source"]["source_sha256"] == index["source_sha256"]
    assert parameter["dependency_parameter_ids"] == []


@pytest.fixture(scope="module")
def app():
    return Application()


def test_consumer_route_exposes_full_index(app):
    result = app.query({"mode": "requirements", "request": {
        "schema": "jc/requirement-request/1", "operation": "dispositions"}})
    assert result["route"] == "DETERMINISTIC_REQUIREMENT_DISPOSITION_INDEX"
    assert result["kernel"]["index_sha256"] == app.requirements.disposition_index()["index_sha256"]
    assert result["kernel"]["counts"]["total_templates"] == 2138
    assert result["escalation"]["status"] == "CLARIFICATION_REQUIRED"
    assert result["inference"]["model_calls"] == 0
    assert result["egress"]["external_effects"] == []


def test_gui_and_cli_expose_disposition_audit():
    html = (Path(__file__).parents[1] / "judgment_compilation/static/index.html").read_text(encoding="utf-8")
    cli = (Path(__file__).parents[1] / "judgment_compilation/cli.py").read_text(encoding="utf-8")
    assert 'id="auditRequirementDispositions"' in html
    assert 'operation:"dispositions"' in html
    assert "requirement-dispositions" in cli
