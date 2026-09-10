from copy import deepcopy
import json
from pathlib import Path

import pytest

from judgment_compilation.document_programs import ReviewedDocumentProgramError, ReviewedDocumentPrograms
from judgment_compilation.application import Application
from judgment_compilation.nist import build_pack


PACKAGE_ID = "nist-sp-800-100-page-39"
RECOVERY_PACKAGE_ID = "nist-sp-800-101-recovery-activity"
CENTRALIZED_PACKAGE_ID = "nist-sp-800-111-centralized-management"


@pytest.fixture(scope="module")
def programs() -> ReviewedDocumentPrograms:
    return ReviewedDocumentPrograms(build_pack()["semantic_pack"])


def request(*, needs=True, strategy=True, same_organization=True, unknowns=None):
    strategy_org = "org-a" if same_organization else "org-b"
    entities = {"org-a": "organization"}
    if not same_organization:
        entities["org-b"] = "organization"
    facts = []
    if needs is not None:
        facts.append({"id": "needs-a", "predicate": "needs_assessment_conducted",
                      "arguments": {"organization": "org-a"}, "value": needs})
    if strategy is not None:
        facts.append({"id": "strategy", "predicate": "strategy_developed",
                      "arguments": {"organization": strategy_org}, "value": strategy})
    return {
        "request_id": "reviewed-request-001",
        "scenario_id": "reviewed-scenario-001",
        "entities": entities,
        "facts": facts,
        "bindings": {"evaluate_named_prerequisite_facts": {"organization": ["org-a"]}},
        "unknowns": unknowns or [],
    }


def recovery_request(*, include=("evidence", "conditions", "methods"),
                     fact_activity="recovery-a", fact_device="device-a", unknowns=None):
    predicates = {
        "evidence": "digital_evidence_recovered_from_mobile_device",
        "conditions": "forensically_sound_conditions_used_for_recovery_activity",
        "methods": "accepted_methods_used_for_recovery_activity",
    }
    entities = {"recovery-a": "system", "device-a": "system"}
    entities[fact_activity] = "system"
    entities[fact_device] = "system"
    payload = {
        "request_id": "recovery-request-001",
        "scenario_id": "recovery-scenario-001",
        "entities": entities,
        "bindings": {
            "evaluate_same_activity_recovery_facts": {
                "recovery_activity": ["recovery-a"],
                "mobile_device": ["device-a"],
            }
        },
        "facts": [
            {
                "id": key,
                "predicate": predicates[key],
                "arguments": {
                    "recovery_activity": fact_activity,
                    "mobile_device": fact_device,
                },
                "value": True,
            }
            for key in include
        ],
    }
    if unknowns is not None:
        payload["unknowns"] = unknowns
    return payload


def centralized_request(*, storage=True, standalone=False, small=False,
                        include=("storage", "standalone", "small"), unknowns=None):
    predicates = {
        "storage": "storage_encryption_deployment",
        "standalone": "standalone_deployment",
        "small": "very_small_scale_deployment",
    }
    values = {"storage": storage, "standalone": standalone, "small": small}
    payload = {
        "request_id": "centralized-request-001",
        "scenario_id": "centralized-scenario-001",
        "entities": {"deployment-a": "system"},
        "bindings": {"evaluate_recommendation_applicability": {"deployment": ["deployment-a"]}},
        "facts": [
            {
                "id": key,
                "predicate": predicates[key],
                "arguments": {"deployment": "deployment-a"},
                "value": values[key],
            }
            for key in include
        ],
    }
    if unknowns is not None:
        payload["unknowns"] = unknowns
    return payload


def test_index_names_common_package_without_claiming_oscal(programs):
    index = programs.index()
    assert [row["id"] for row in index["packages"]] == [
        PACKAGE_ID, RECOVERY_PACKAGE_ID, "nist-sp-800-108-counter-mode-capacity-guard",
        CENTRALIZED_PACKAGE_ID, "nist-sp-800-145-section-2-caller-reports", "nist-sp-800-150-tlp-table-3-3", "nist-sp-800-30r1-table-g5",
        "nist-sp-800-37r2-p1-assignment-entry",
    ]
    assert index["source_format_policy"]["common_package"] == "jc/reviewed-batch-input/4"
    assert index["source_format_policy"]["original_pdf_remains_source_authority"] is True
    assert index["external_effects"] == []


def test_sp800111_package_replays_source_and_executes_all_complete_assignments(programs):
    inspected = programs.inspect(CENTRALIZED_PACKAGE_ID)
    assert inspected["materialized"]["architecture_id"] == "sp800111_recommendation_applicability_evaluation"
    assert len(inspected["materialized"]["qualified_nodes"]) == 6
    citation = inspected["source_citations"][0]["citation"]
    assert citation["provenance"]["physical_pdf_page_number"] == 7
    assert citation["provenance"]["character_span"] == [63, 221]
    expected = {
        (True, False, False): True,
        (True, False, True): False,
        (True, True, False): False,
        (True, True, True): False,
        (False, False, False): False,
        (False, False, True): False,
        (False, True, False): False,
        (False, True, True): False,
    }
    for (storage, standalone, small), value in expected.items():
        result = programs.execute(
            CENTRALIZED_PACKAGE_ID,
            centralized_request(storage=storage, standalone=standalone, small=small),
        )
        execution = result["execution"]["execution"]["execution"]
        assert execution["status"] == "COMPLETE"
        assert execution["outputs"][0]["predicate"] == "centralized_management_recommendation_applies"
        assert execution["outputs"][0]["value"] is value
        assert execution["steps"][0]["work_id"] == "resolve_sp800111_recommendation_applicability"
        assert execution["compliance_verdict"] is None
        assert execution["responsibility_determination"] is None
        assert execution["external_effects"] == []


def test_sp800111_missing_conflicting_or_declared_unknown_facts_remain_unresolved(programs):
    missing = centralized_request(include=("storage", "standalone"))
    conflict = centralized_request()
    conflict["facts"].append({
        "id": "standalone-conflict",
        "predicate": "standalone_deployment",
        "arguments": {"deployment": "deployment-a"},
        "value": True,
    })
    unknown = centralized_request(include=("storage", "standalone"), unknowns=[{
        "id": "small-unknown",
        "text": "very-small-scale status unavailable",
        "predicate": "very_small_scale_deployment",
        "arguments": {"deployment": "deployment-a"},
    }])
    for payload in (missing, conflict, unknown):
        execution = programs.execute(CENTRALIZED_PACKAGE_ID, payload)["execution"]["execution"]["execution"]
        assert execution["status"] == "UNRESOLVED"
        assert execution["outputs"] == []


def test_sp800101_package_replays_exact_source_and_narrow_complete_result(programs):
    inspected = programs.inspect(RECOVERY_PACKAGE_ID)
    assert inspected["materialized"]["architecture_id"] == "sp800101_same_activity_recovery_fact_evaluation"
    assert len(inspected["source_citations"]) == 1
    citation = inspected["source_citations"][0]["citation"]
    assert citation["provenance"]["physical_pdf_page_number"] == 4
    assert citation["provenance"]["character_span"] == [966, 1117]

    first = programs.execute(RECOVERY_PACKAGE_ID, recovery_request())
    assert first == programs.execute(RECOVERY_PACKAGE_ID, recovery_request())
    execution = first["execution"]["execution"]["execution"]
    assert execution["status"] == "COMPLETE"
    assert len(execution["outputs"]) == 1
    assert execution["outputs"][0]["predicate"] == "source_named_recovery_conditions_methods_facts_cooccur"
    assert execution["outputs"][0]["support"] == ["conditions", "evidence", "methods"]
    assert execution["compliance_verdict"] is None
    assert execution["responsibility_determination"] is None
    assert execution["external_effects"] == []
    assert first["external_effects"] == []


@pytest.mark.parametrize("payload", [
    recovery_request(include=("evidence", "conditions")),
    recovery_request(fact_activity="recovery-b"),
    recovery_request(fact_device="device-b"),
    recovery_request(include=("evidence", "conditions"), unknowns=[{
        "id": "missing-methods",
        "text": "method evidence unavailable",
        "predicate": "accepted_methods_used_for_recovery_activity",
        "arguments": {"recovery_activity": "recovery-a", "mobile_device": "device-a"},
    }]),
])
def test_sp800101_missing_cross_bound_or_unknown_facts_remain_unresolved(programs, payload):
    execution = programs.execute(RECOVERY_PACKAGE_ID, payload)["execution"]["execution"]["execution"]
    assert execution["status"] == "UNRESOLVED"
    assert execution["outputs"] == []
    assert execution["compliance_verdict"] is None
    assert execution["responsibility_determination"] is None
    assert execution["external_effects"] == []


def test_reviewed_package_replays_and_executes_only_narrow_result(programs):
    inspected = programs.inspect(PACKAGE_ID)
    assert inspected["materialized"]["architecture_id"] == (
        "nist100_awareness_training_named_prerequisite_fact_evaluation")
    citation = inspected["source_citations"][0]["citation"]
    assert citation["provenance"]["physical_pdf_page_number"] == 40
    assert citation["provenance"]["character_span"] == [2881, 3098]
    assert citation["claim"]["text"].startswith("4.3.3 Implementing an Awareness")
    assert citation["claim"]["text"].endswith("31")
    assert citation["claim"]["provenance_sha256"]
    assert citation["occurrence_scope"] == (
        "ALL_RETAINED_FROZEN_PLAIN_PAGE_EXTRACTIONS_ONLY_NO_CROSS_PAGE_MATCHES")
    first = programs.execute(PACKAGE_ID, request())
    assert first == programs.execute(PACKAGE_ID, request())
    execution = first["execution"]["execution"]["execution"]
    assert execution["status"] == "COMPLETE"
    assert len(execution["outputs"]) == 1
    output = execution["outputs"][0]
    assert output["predicate"] == "source_named_needs_assessment_and_strategy_prerequisites_satisfied"
    assert output["support"] == ["needs-a", "strategy"]
    assert execution["compliance_verdict"] is None
    assert execution["responsibility_determination"] is None
    assert execution["external_effects"] == []


@pytest.mark.parametrize("payload", [
    request(needs=None), request(strategy=None), request(same_organization=False), request(needs=False),
])
def test_missing_false_or_cross_entity_inputs_do_not_produce_conclusion(programs, payload):
    result = programs.execute(PACKAGE_ID, payload)
    execution = result["execution"]["execution"]["execution"]
    assert execution["status"] == "UNRESOLVED"
    assert execution["outputs"] == []


def test_unknown_bound_fact_blocks_but_unrelated_unknown_survives(programs):
    bound = request(strategy=None, unknowns=[{
        "id": "unknown-a", "text": "strategy evidence unavailable",
        "predicate": "strategy_developed", "arguments": {"organization": "org-a"},
    }])
    assert programs.execute(PACKAGE_ID, bound)["execution"]["execution"]["execution"]["status"] == "UNRESOLVED"
    unrelated = request(unknowns=[{
        "id": "unknown-b", "text": "other organization evidence unavailable",
        "predicate": "needs_assessment_conducted", "arguments": {"organization": "org-b"},
    }])
    unrelated["entities"]["org-b"] = "organization"
    assert programs.execute(PACKAGE_ID, unrelated)["execution"]["execution"]["execution"]["status"] == "COMPLETE"


def test_unknown_package_and_malformed_request_reject(programs):
    with pytest.raises(ReviewedDocumentProgramError):
        programs.inspect("missing")
    with pytest.raises(ReviewedDocumentProgramError):
        programs.execute(PACKAGE_ID, {"entities": {}})


def test_reviewed_execution_identity_is_required_preserved_and_hash_bound(programs):
    payload = request()
    first = programs.execute(PACKAGE_ID, payload)
    assert first == programs.execute(PACKAGE_ID, deepcopy(payload))
    assert first["request_id"] == payload["request_id"]
    assert first["scenario_id"] == payload["scenario_id"]
    assert first["execution"]["request_id"] == payload["request_id"]
    assert first["execution"]["scenario_id"] == payload["scenario_id"]

    distinct_identity = deepcopy(payload)
    distinct_identity["request_id"] = "reviewed-request-002"
    distinct_identity["scenario_id"] = "reviewed-scenario-002"
    second = programs.execute(PACKAGE_ID, distinct_identity)
    assert first["execution"]["execution"] == second["execution"]["execution"]
    assert first["request_sha256"] != second["request_sha256"]
    assert first["result_sha256"] != second["result_sha256"]

    for field in ("request_id", "scenario_id"):
        missing = deepcopy(payload)
        missing.pop(field)
        with pytest.raises(ReviewedDocumentProgramError):
            programs.execute(PACKAGE_ID, missing)
        blank = deepcopy(payload)
        blank[field] = " "
        with pytest.raises(ReviewedDocumentProgramError):
            programs.execute(PACKAGE_ID, blank)


def test_application_exposes_plain_reviewed_package_index_and_execution():
    app = Application()
    index = app.query({"mode": "reviewed_programs"})
    assert index["route"] == "DETERMINISTIC_REVIEWED_DOCUMENT_PROGRAM_INDEX"
    assert index["kernel"]["packages"][0]["id"] == PACKAGE_ID
    assert index["inference"]["model_calls"] == 0
    result = app.query({
        "mode": "reviewed_program",
        "request": {"operation": "execute", "package_id": PACKAGE_ID,
                    "execution_request": request()},
    })
    assert result["route"] == "DETERMINISTIC_REVIEWED_DOCUMENT_PROGRAM"
    assert "establish only" in result["answer"]
    assert "source named needs assessment and strategy prerequisites satisfied" in result["answer"]
    assert "all prerequisites" in result["answer"]
    assert result["escalation"]["status"] == "NO_KNOWN_AMBIGUITY"
    assert result["egress"]["request_id"] == "reviewed-request-001"
    assert result["egress"]["scenario_id"] == "reviewed-scenario-001"
    assert result["egress"]["result_sha256"] == result["kernel"]["execution"]["result_sha256"]
    assert result["egress"]["external_effects"] == []


def test_large_pinned_artifact_does_not_widen_untrusted_request_json_limit():
    from judgment_compilation.kernel import strict_json, Rejected

    raw = json.dumps({"text": "x" * 100001})
    with pytest.raises(Rejected, match="request size"):
        strict_json(raw)
    assert strict_json(raw, max_chars=len(raw)) == {"text": "x" * 100001}
    for invalid in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}'):
        with pytest.raises(Rejected):
            strict_json(invalid, max_chars=510334)
    record, package = ReviewedDocumentPrograms._load(
        "nist-sp-800-145-section-2-caller-reports")
    assert record["bytes"] > 100000 and isinstance(package, dict)
