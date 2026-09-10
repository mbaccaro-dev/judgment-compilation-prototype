"""Tests package behavior."""
from copy import deepcopy

import pytest

from judgment_compilation.kernel import canonical
from judgment_compilation.nist_requirements import REQUEST_SCHEMA, Requirements
from judgment_compilation.sc7_direct_external_connection_family import (
    CEILING,
    DirectExternalConnectionFamilyError,
    build_definition,
    instantiate,
    validate_definition,
)


EXPECTED = {
    "sc-7.25_smt": ("sc-7.25", "a49d3576cdb23dc03bb87398eb6558f52d82e6bfdc4febba3993ddd9c2298986",
                    ["sc-07.25_odp.01", "sc-07.25_odp.02"]),
    "sc-7.27_smt": ("sc-7.27", "e3384bbbc7d08f730a3c0aefbc9fe4684e3441913ab668258459f9035f3ecc7b",
                    ["sc-07.27_odp.01", "sc-07.27_odp.02"]),
}


def request_for(statement_id):
    control_id, template_sha256, parameter_ids = EXPECTED[statement_id]
    requirements = Requirements()
    source_sha256 = requirements.ask({"schema": REQUEST_SCHEMA, "operation": "inspect",
                                      "statement_id": statement_id})["source_sha256"]
    scope = {"organization_id": "example-org", "system_id": "example-system"}
    return {
        "schema": REQUEST_SCHEMA,
        "operation": "instantiate",
        "statement_id": statement_id,
        "source_sha256": source_sha256,
        "template_sha256": template_sha256,
        "scope": scope,
        "parameters": [
            {"parameter_id": parameter_ids[0], "control_id": control_id,
             "source_sha256": source_sha256, "scope": scope,
             "values": ["fictional directly connected system"], "evidence_refs": ["example:subject"]},
            {"parameter_id": parameter_ids[1], "control_id": control_id,
             "source_sha256": source_sha256, "scope": scope,
             "values": ["fictional boundary device"], "evidence_refs": ["example:device"]},
        ],
    }


def test_definition_rebuilds_both_exact_source_records_with_typed_slot_roles():
    definition = build_definition()
    assert definition["authority_ceiling"] == CEILING
    assert definition["policy_semantic_mapping"]["status"] == "NOT_ADMITTED"
    assert definition["external_effects"] == []
    assert [row["statement_id"] for row in definition["controls"]] == list(EXPECTED)
    for control in definition["controls"]:
        expected_control, expected_hash, parameter_ids = EXPECTED[control["statement_id"]]
        assert control["control_id"] == expected_control
        assert control["template_sha256"] == expected_hash
        assert control["skeleton"] == (
            "Prohibit the direct connection of <PARAMETER_1> to an external network "
            "without the use of <PARAMETER_2>."
        )
        roles = control["domain_parameter_roles"]
        assert [(row["slot"], row["parameter_id"], row["role"])
                for row in roles] == [(1, parameter_ids[0], "direct_connection_subject"),
                                      (2, parameter_ids[1], "boundary_protection_device")]
        assert [control["judgment"]["stack"], control["work"]["stack"], control["architecture"]["stack"]] == [
            "JUDGMENT", "WORK", "ARCHITECTURE"]


@pytest.mark.parametrize("statement_id", list(EXPECTED))
def test_exact_bindings_execute_a_deterministic_four_stack_flow(statement_id):
    request = request_for(statement_id)
    first = instantiate(request)
    second = instantiate(deepcopy(request))
    assert canonical(first) == canonical(second)
    assert first["status"] == "INSTANTIATED"
    assert [stage["stack"] for stage in first["stages"]] == ["DOMAIN", "JUDGMENT", "WORK", "ARCHITECTURE"]
    assert first["stages"][2]["status"] == "APPLIED"
    assert first["stages"][3]["status"] == "COMPLETE"
    assert first["work_result"]["instance"] is not None
    assert first["applicability"] is first["violation"] is first["compliance_verdict"] is None
    assert first["responsibility"] is first["action"] is None
    assert first["external_effects"] == []


@pytest.mark.parametrize("mutation", ["slot_swap", "source", "template", "control"])
def test_definition_or_cross_control_drift_fails_closed(mutation):
    if mutation == "slot_swap":
        candidate = build_definition()
        roles = candidate["controls"][0]["domain_parameter_roles"]
        roles[0], roles[1] = roles[1], roles[0]
        with pytest.raises(DirectExternalConnectionFamilyError):
            validate_definition(candidate)
        return
    request = request_for("sc-7.25_smt")
    if mutation == "source":
        request["source_sha256"] = "0" * 64
    elif mutation == "template":
        request["template_sha256"] = EXPECTED["sc-7.27_smt"][1]
    else:
        request["parameters"][0]["control_id"] = "sc-7.27"
    with pytest.raises(DirectExternalConnectionFamilyError):
        instantiate(request)


def test_unresolved_bindings_stay_unresolved_and_never_become_policy_decisions():
    request = request_for("sc-7.27_smt")
    request["parameters"].pop()
    result = instantiate(request)
    assert result["status"] == "UNRESOLVED"
    assert result["stages"][2]["status"] == result["stages"][3]["status"] == "UNRESOLVED"
    assert result["applicability"] is result["violation"] is result["compliance_verdict"] is None
    assert result["responsibility"] is result["action"] is None
    assert result["external_effects"] == []
