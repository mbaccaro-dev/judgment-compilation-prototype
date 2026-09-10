from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import shutil

import pytest

from judgment_compilation.application import Application
from judgment_compilation.kernel import canonical
from judgment_compilation.nist_assessments import (
    Assessments, AssessmentError, EXPECTED, SCHEMA, SOURCE_FILE,
)
from judgment_compilation.nist_catalog import Catalog


def inspect_request(control_id: str) -> dict:
    return {"schema": SCHEMA, "operation": "INSPECT", "control_id": control_id}


def prepare_request(assessments: Assessments, control_id: str = "ps-4") -> dict:
    inspected = assessments.inspect(inspect_request(control_id))
    objective = next(row for row in inspected["objectives"] if row["objective_id"] == "ps-4_obj.a")
    method = next(row for row in inspected["methods"] if row["method_id"] == "ps-4_asm-examine")
    source_object = method["objects"][0]
    return {
        "schema": SCHEMA,
        "operation": "PREPARE",
        "request_id": "assessment-request-001",
        "control_id": control_id,
        "objective_id": objective["objective_id"],
        "method_id": method["method_id"],
        "object_refs": [{"object_id": source_object["object_id"],
                         "object_sha256": source_object["serialized_xml_sha256"]}],
        "scenario_scope": {"entity_ids": ["business-a", "system-a"],
                           "purpose": "Prepare a bounded review of access termination records."},
    }


@pytest.fixture(scope="module")
def assessments() -> Assessments:
    return Assessments(Catalog.compile())


def test_complete_assessment_population_is_pinned_and_not_a_finding(assessments: Assessments) -> None:
    summary = assessments.summary()
    assert {key: summary[key] for key in EXPECTED} == EXPECTED
    assert summary["source_sha256"] == "a9e23b09116d5e651461d61777c2e7dc1f3454ab3f9e1e8fdf8af01c37dc01be"
    assert "NO_" in summary["ceiling"] and "COMPLIANCE" in summary["ceiling"]


def test_ps4_selection_executes_all_four_stages_but_preserves_ceiling(assessments: Assessments) -> None:
    request = prepare_request(assessments)
    first = assessments.prepare(request)
    assert canonical(first) == canonical(assessments.prepare(request))
    assert first["status"] == "PREPARED_SOURCE_BOUND_SELECTION"
    assert first["objective"]["objective_id"] == "ps-4_obj.a"
    assert first["objective"]["parameter_refs"][0]["id_ref"] == "ps-04_odp.01"
    assert first["method"]["method_code"] == "EXAMINE"
    assert first["selected_objects"][0]["exact_text"] == "Personnel security policy"
    assert [row["stage"] for row in first["semantic_execution"]] == ["Domain", "Judgment", "Work", "Architecture"]
    assert first["relation_basis"] == "CALLER_SELECTED_WITHIN_SAME_CONTROL"
    assert first["semantic_execution"][1]["objective_method_suitability"] == "UNRESOLVED"
    reasons = {row["reason"] for row in first["residuals"]}
    assert "ASSESSMENT_PERFORMANCE_NOT_ESTABLISHED" in reasons
    assert "EVIDENCE_AUTHENTICITY_RELEVANCE_AND_SUFFICIENCY_NOT_ESTABLISHED" in reasons
    assert first["assessment_finding"] is None
    assert first["compliance_verdict"] is None
    assert first["responsibility_determination"] is None
    assert first["external_effects"] == []


def test_nested_objectives_and_missing_method_are_preserved(assessments: Assessments) -> None:
    si2 = assessments.inspect(inspect_request("si-2"))
    by_id = {row["objective_id"]: row for row in si2["objectives"]}
    assert by_id["si-2_obj.c-1"]["parent_objective_id"] == "si-2_obj.c"
    assert by_id["si-2_obj.c-2"]["parent_objective_id"] == "si-2_obj.c"
    assert by_id["si-2_obj.c-1"]["paragraphs"][0]["exact_text"] != by_id["si-2_obj.c-2"]["paragraphs"][0]["exact_text"]
    ac1 = assessments.inspect(inspect_request("ac-1"))
    assert {method["method_code"] for method in ac1["methods"]} == {"EXAMINE", "INTERVIEW"}


def test_known_source_anomalies_are_preserved_without_invented_repairs(assessments: Assessments) -> None:
    sa24 = assessments.inspect(inspect_request("sa-24"))
    cross = [row for row in sa24["assessment_for"] if row["target_owner"] == "ac-2"]
    assert cross
    assert {row["resolution_status"] for row in cross} == {
        "RESOLVED_CROSS_CONTROL_IDENTITY_INTERPRETATION_UNRESOLVED"}
    broken = next(row for row in sa24["assessment_for"] if row["raw_href"] == "#ac-2_smt.a.5")
    assert broken["target_owner"] is None
    assert broken["resolution_status"] == "UNRESOLVED_TARGET"
    sa1513 = assessments.inspect(inspect_request("sa-15.13"))
    examine = next(row for row in sa1513["methods"] if row["method_code"] == "EXAMINE")
    assert examine["method_id"] == "sa-15.13_asm-examine"
    assert examine["raw_label"] == "SA-15(12)-Examine"


@pytest.mark.parametrize("mutation, error", [
    (lambda value: value.update(control_id="ac-1"), "objective does not belong"),
    (lambda value: value.update(method_id="ps-4_asm-test"), "object does not belong"),
    (lambda value: value["object_refs"][0].update(object_sha256="0" * 64), "hash mismatch"),
    (lambda value: value["object_refs"].append(deepcopy(value["object_refs"][0])), "duplicate"),
    (lambda value: value.update(assessment_finding="satisfied"), "unexpected or missing"),
])
def test_foreign_modified_duplicate_or_authority_shaped_selection_fails_closed(
        assessments: Assessments, mutation, error: str) -> None:
    request = prepare_request(assessments)
    mutation(request)
    with pytest.raises(AssessmentError, match=error):
        assessments.prepare(request)


def test_source_byte_drift_fails_before_inspection(tmp_path: Path) -> None:
    source = Path(__file__).resolve().parents[1] / "judgment_compilation" / "data" / "corpus" / "source" / SOURCE_FILE
    target = tmp_path / "data" / "corpus" / "source"
    target.mkdir(parents=True)
    shutil.copyfile(source, target / SOURCE_FILE)
    path = target / SOURCE_FILE
    path.write_bytes(path.read_bytes().replace(b"Personnel security policy", b"Personnel security POLICY", 1))
    with pytest.raises(AssessmentError, match="checksum drift"):
        Assessments(Catalog.compile(), tmp_path)


def test_source_byte_drift_at_a_previously_compiled_path_fails_closed(tmp_path: Path) -> None:
    source = Path(__file__).resolve().parents[1] / "judgment_compilation" / "data" / "corpus" / "source" / SOURCE_FILE
    target = tmp_path / "data" / "corpus" / "source"
    target.mkdir(parents=True)
    shutil.copyfile(source, target / SOURCE_FILE)
    Assessments(Catalog.compile(), tmp_path)
    path = target / SOURCE_FILE
    path.write_bytes(path.read_bytes().replace(b"Personnel security policy", b"Personnel security POLICY", 1))
    with pytest.raises(AssessmentError, match="checksum drift"):
        Assessments(Catalog.compile(), tmp_path)


def test_work_and_architecture_reject_altered_or_disconnected_stage_receipts(
        assessments: Assessments) -> None:
    prepared = assessments.prepare(prepare_request(assessments))
    domain, judgment, work, _ = prepared["semantic_execution"]
    altered = assessments._seal_stage("Judgment", {
        key: deepcopy(value) for key, value in judgment.items()
        if key not in {"stage", "result_sha256", "warrant"}
    } | {"warrant": "CALLER_ASSERTED"})
    with pytest.raises(AssessmentError, match="missing, altered, or foreign"):
        assessments.bind_selection(domain, altered)
    foreign_domain = deepcopy(domain)
    foreign_domain["scenario_scope"]["purpose"] = "Different request."
    foreign_domain = assessments._seal_stage("Domain", {
        key: deepcopy(value) for key, value in foreign_domain.items()
        if key not in {"stage", "result_sha256"}
    })
    with pytest.raises(AssessmentError, match="disconnected"):
        assessments.compose_selection(foreign_domain, judgment, work, prepared["residuals"])


def test_claim_identity_binds_the_complete_canonical_request(assessments: Assessments) -> None:
    first_request = prepare_request(assessments)
    second_request = deepcopy(first_request)
    second_request["scenario_scope"]["purpose"] = "Prepare a different bounded review."
    first = assessments.prepare(first_request)
    second = assessments.prepare(second_request)
    assert first["request_sha256"] != second["request_sha256"]
    assert first["claim"]["id"] != second["claim"]["id"]


def test_application_advisory_cannot_turn_selection_into_finding(assessments: Assessments) -> None:
    request = prepare_request(assessments)

    class Hostile:
        model = "test"

        def recommend(self, packet):
            packet["deterministic_result"]["assessment_finding"] = "SATISFIED"
            packet["deterministic_result"]["residuals"].clear()
            return "The control is compliant and the assessor should approve it."

    baseline = Application().query({"mode": "assessments", "request": request})
    actual = Application(Hostile()).query({"mode": "assessments", "request": request, "recommend": True})
    assert actual["kernel"] == baseline["kernel"]
    assert actual["kernel"]["assessment_finding"] is None
    assert actual["kernel"]["compliance_verdict"] is None
    assert actual["kernel"]["external_effects"] == []
    assert actual["route"] == "DETERMINISTIC_NIST_ASSESSMENT_SELECTION"
    assert actual["inference"]["authority"] == "ADVISORY_ONLY"
