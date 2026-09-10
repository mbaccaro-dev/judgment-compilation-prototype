"""Tests package behavior."""

from pathlib import Path

from judgment_compilation.application import Application


PACKAGE_ID = "nist-sp-800-100-page-39"


def test_reviewed_program_index_is_available_from_the_plain_page():
    html = (Path(__file__).parents[1] / "judgment_compilation" / "static" / "index.html").read_text(encoding="utf-8")
    assert 'id="reviewedPrograms"' in html
    assert 'mode:"reviewed_programs"' in html
    assert '/api/query' in html


def test_sp800_100_example_is_inspected_from_its_citation_then_reports_a_missing_fact():
    app = Application()
    index = app.query({"mode": "reviewed_programs"})
    package = next(item for item in index["kernel"]["packages"] if item["id"] == PACKAGE_ID)
    inspected = app.query({"mode": "reviewed_program", "request": {"operation": "inspect", "package_id": package["id"]}})
    step = inspected["kernel"]["materialized"]["program"]["composition"]["architecture"]["ordered_steps"][0]
    supplied_input = step["work"]["inputs"][0]
    citation = inspected["kernel"]["source_citations"][0]["citation"]
    provenance = citation["provenance"]
    roles = {}
    for item in step["work"]["inputs"]:
        for role, entity_type in item.get("roles", item.get("arguments", {})).items():
            roles[role] = entity_type
    for role, entity_type in step["work"].get("typed_bindings", {}).items():
        roles.setdefault(role, entity_type)
    binding_roles = step["work"].get("typed_bindings") or roles
    role_values = {role: f"example-{role}" for role in roles}
    arguments = {role: role_values[role] for role in supplied_input.get("roles", supplied_input.get("arguments", {}))}

    assert provenance["physical_pdf_page_number"] == provenance["physical_pdf_page_index"] + 1
    assert citation["claim"]["text"] == provenance["exact_quote"]
    assert provenance["exact_quote"]

    response = app.query(
        {
            "mode": "reviewed_program",
            "request": {
                "operation": "execute",
                "package_id": package["id"],
                "execution_request": {
                    "request_id": "reviewed-ui-request-001",
                    "scenario_id": "reviewed-ui-scenario-001",
                    "entities": {role_values[role]: entity_type for role, entity_type in roles.items()},
                    "facts": [
                        {
                            "id": "supplied-1",
                            "predicate": supplied_input["predicate"],
                            "arguments": arguments,
                            "value": True,
                        }
                    ],
                    "bindings": {step["step_id"]: {role: [role_values[role]] for role in binding_roles}},
                    "unknowns": [],
                },
            },
        }
    )

    assert response["route"] == "DETERMINISTIC_REVIEWED_DOCUMENT_PROGRAM"
    assert response["escalation"]["status"] == "CLARIFICATION_REQUIRED"
    assert response["escalation"]["required_inputs"]
    assert response["egress"]["request_id"] == "reviewed-ui-request-001"
    assert response["egress"]["scenario_id"] == "reviewed-ui-scenario-001"
    assert response["inference"]["model_calls"] == 0
