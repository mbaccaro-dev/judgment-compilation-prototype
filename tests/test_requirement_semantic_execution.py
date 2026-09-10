"""Tests package behavior."""
from copy import deepcopy
from hashlib import sha256

import pytest

from judgment_compilation.application import Application
from judgment_compilation.kernel import canonical, digest
from judgment_compilation.nist_catalog import SOURCE_SHA256
from judgment_compilation.nist_requirements import REQUEST_SCHEMA
from judgment_compilation.nist_requirements import RequirementError, Requirements
from judgment_compilation.semantic_contracts import execute_architecture


MAPPING_RESIDUAL = "REQUIREMENT_TO_POLICY_SEMANTICS_NOT_ADMITTED"
STACKS = ["DOMAIN", "JUDGMENT", "WORK", "ARCHITECTURE"]
CLAIM_TYPES = {"SOURCE_BOUND", "SCENARIO_FACT", "DETERMINISTIC_DERIVATION",
               "UNRESOLVED", "AI_INFERENCE"}


@pytest.fixture(scope="module")
def app():
    # Explicit local reference executor; no provider, HTTP server, or native child.
    return Application(executor=execute_architecture)


def query(app, request, recommend=False):
    return app.query({"mode": "requirements", "request": request, "recommend": recommend})


def inspect(app, statement_id="ps-4_smt.a"):
    return query(app, {"schema": REQUEST_SCHEMA, "operation": "inspect",
                       "statement_id": statement_id})


def request_for(app, statement_id="ps-4_smt.a"):
    template = inspect(app, statement_id)["kernel"]["template"]
    scope = {"organization_id": "org-a", "system_id": "system-a"}
    bindings = []
    for definition in template["parameters"]:
        values = ([{"choice_sha256": definition["choice_templates"][0]["choice_sha256"]}]
                  if definition["kind"] == "SELECTION" else ["24 hours"])
        bindings.append({"parameter_id": definition["parameter_id"],
                         "control_id": template["control_id"], "source_sha256": SOURCE_SHA256,
                         "scope": deepcopy(scope), "values": values,
                         "evidence_refs": ["caller-policy:version-1"]})
    return {"schema": REQUEST_SCHEMA, "operation": "instantiate",
            "statement_id": statement_id, "source_sha256": SOURCE_SHA256,
            "template_sha256": template["template_sha256"], "scope": scope,
            "parameters": bindings}


def trace(response):
    kernel = response["kernel"]
    assert "semantic_execution" in kernel, (
        "Missing RequirementSemanticRuntime four-stage execution in Application requirements kernel")
    execution = kernel["semantic_execution"]
    assert {"schema", "execution_id", "request_sha256", "definitions", "stages", "claims",
            "support_graph", "policy_semantic_mapping", "authority_ceiling",
            "external_effects"} <= set(execution)
    return execution


def field_values(value, key):
    """Read typed fields without imposing an incidental nesting convention."""
    if isinstance(value, dict):
        if key in value:
            yield value[key]
        for child in value.values():
            yield from field_values(child, key)
    elif isinstance(value, list):
        for child in value:
            yield from field_values(child, key)


def assert_honest_ceiling(response):
    kernel, execution = response["kernel"], trace(response)
    for name in ("applicability", "satisfaction", "compliance_verdict"):
        assert kernel[name] is None
        if kernel["instance"] is not None:
            assert kernel["instance"][name] is None
    assert kernel["external_effects"] == execution["external_effects"] == []
    assert execution["policy_semantic_mapping"] == {
        "status": "NOT_ADMITTED", "residual": MAPPING_RESIDUAL}
    residuals = [c for c in execution["claims"] if c["type"] == "UNRESOLVED"]
    assert any(MAPPING_RESIDUAL in canonical(c).decode() for c in residuals)
    assert response["escalation"]["status"] == "CLARIFICATION_REQUIRED"
    assert response["egress"]["model_authored"] is False
    assert response["egress"]["external_effects"] == []


def test_source_template_scope_and_values_bind_to_ordered_four_stage_trace(app):
    request = request_for(app)
    response = query(app, request)
    kernel, execution = response["kernel"], trace(response)
    assert kernel["status"] == "INSTANTIATED"
    assert execution["request_sha256"] == digest(request)
    stages = execution["stages"]
    assert [s["stack"] for s in stages] == STACKS
    assert [s["producer"].split(".", 1)[-1] for s in stages] == [
        "Requirements._template", "Requirements.operation_warrant",
        "Requirements.execute_prepared", "RequirementSemanticRuntime.execute"]
    assert execution["definitions"]
    for stage in stages:
        assert {"semantic_coordinate", "operation", "status", "input_ids", "output_ids"} <= set(stage)
    control = app.catalog.controls[kernel["template"]["control_id"]]
    assert stages[0]["semantic_coordinate"] == control["coordinate"]
    for stage, stack in zip(stages[1:], ("judgment", "work", "architecture")):
        definitions = app.pack["semantic_pack"]["semantic_capital"][stack]
        assert stage["semantic_coordinate"] in [row["coordinate"] for row in definitions]
    values = [c["value"] for c in execution["claims"]]
    for key, expected in (("source_sha256", SOURCE_SHA256),
                          ("template_sha256", request["template_sha256"]),
                          ("statement_id", request["statement_id"]),
                          ("control_id", kernel["template"]["control_id"])):
        assert expected in list(field_values(values, key)), key
    facts = [c["value"] for c in execution["claims"] if c["type"] == "SCENARIO_FACT"]
    assert request["scope"] in list(field_values(facts, "scope"))
    assert request["parameters"][0]["values"] in list(field_values(facts, "values"))
    assert request["parameters"][0]["evidence_refs"] in list(field_values(facts, "evidence_refs"))
    assert_honest_ceiling(response)


def test_work_rejects_missing_tampered_or_foreign_judgment_warrant(app):
    request = request_for(app)
    requirements = app.requirements
    preparation = requirements.prepare(request)
    warrant = requirements.operation_warrant(preparation)
    assert requirements.execute_prepared(preparation, warrant)["status"] == "INSTANTIATED"
    with pytest.raises(RequirementError):
        requirements.execute_prepared(preparation, None)
    changed = deepcopy(warrant)
    changed["claim"]["id"] = "requirement-warrant:changed"
    changed["warrant_sha256"] = digest({k: v for k, v in changed.items()
                                        if k != "warrant_sha256"})
    with pytest.raises(RequirementError):
        requirements.execute_prepared(preparation, changed)
    other = deepcopy(preparation)
    other["preparation_sha256"] = "0" * 64
    with pytest.raises(RequirementError):
        requirements.execute_prepared(other, warrant)


def test_claim_support_is_closed_exact_and_source_text_is_not_caller_text(app):
    response = query(app, request_for(app))
    kernel, execution = response["kernel"], trace(response)
    claims = execution["claims"]
    by_id = {c["id"]: c for c in claims}
    assert len(by_id) == len(claims)
    assert all(c["type"] in CLAIM_TYPES for c in claims)
    assert all(set(c["support_ids"]) <= set(by_id) for c in claims)
    assert all(c["id"] not in c["support_ids"] for c in claims)
    source = [c for c in claims if c["type"] == "SOURCE_BOUND"]
    assert kernel["template"]["source"]["serialized_xml"] in [c["text"] for c in source]
    assert all("24 hours" not in c["text"] for c in source)
    derived = [c for c in claims if c["type"] == "DETERMINISTIC_DERIVATION"]
    assert derived
    assert kernel["instance"]["instance_sha256"] in list(field_values(
        [c["value"] for c in derived], "instance_sha256"))
    expected = {(support, claim["id"]) for claim in claims for support in claim["support_ids"]}
    actual = {(edge["from_claim_id"], edge["to_claim_id"]) for edge in execution["support_graph"]}
    assert actual == expected and len(actual) == len(execution["support_graph"])
    assert {edge["relationship"] for edge in execution["support_graph"]} == {
        "SUPPORTS_INSTANTIATION_WARRANT", "SUPPORTS_REQUIREMENT_OPERATION",
        "SUPPORTS_DOCUMENTARY_FLOW", "SUPPORTS_UNRESOLVED_POLICY_BOUNDARY"}
    for stage in execution["stages"]:
        assert set(stage["input_ids"]) <= set(by_id) | {execution["request_sha256"]}
        assert set(stage["output_ids"]) <= set(by_id)
    produced = [claim_id for stage in execution["stages"] for claim_id in stage["output_ids"]]
    assert len(produced) == len(set(produced)), "Every stage output must have exactly one producer"
    assert set(execution["stages"][0]["output_ids"]) & set(execution["stages"][1]["input_ids"])
    assert set(execution["stages"][1]["output_ids"]) <= set(execution["stages"][2]["input_ids"])
    assert set(execution["stages"][1]["output_ids"]) <= set(execution["stages"][3]["input_ids"])
    assert set(execution["stages"][2]["output_ids"]) <= set(execution["stages"][3]["input_ids"])


def test_inspection_is_source_binding_without_instantiation_warrant(app):
    response = inspect(app)
    execution = trace(response)
    assert response["kernel"]["status"] == "INSPECTED"
    assert response["kernel"]["instance"] is None
    assert not [c for c in execution["claims"] if c["id"].startswith("requirement-instance:")]
    stages = execution["stages"]
    assert stages[1]["output_ids"] and stages[2]["output_ids"] and stages[3]["output_ids"]
    assert set(stages[1]["output_ids"]) <= set(stages[2]["input_ids"])
    assert set(stages[1]["output_ids"] + stages[2]["output_ids"]) <= set(stages[3]["input_ids"])
    assert [s["stack"] for s in execution["stages"]] == STACKS
    assert_honest_ceiling(response)


@pytest.mark.parametrize("variant", ["missing", "missing_evidence", "conflicting_values"])
def test_incomplete_or_conflicting_bindings_cannot_warrant_an_instance(app, variant):
    request = request_for(app)
    if variant == "missing":
        request["parameters"] = []
    elif variant == "missing_evidence":
        request["parameters"][0]["evidence_refs"] = []
    else:
        conflict = deepcopy(request["parameters"][0])
        conflict["values"] = ["48 hours"]
        request["parameters"].append(conflict)
    response = query(app, request)
    execution = trace(response)
    assert response["kernel"]["status"] == "UNRESOLVED"
    assert response["kernel"]["instance"] is None
    assert not [c for c in execution["claims"] if c["id"].startswith("requirement-instance:")]
    stages = execution["stages"]
    assert stages[1]["output_ids"] and stages[2]["output_ids"] and stages[3]["output_ids"]
    assert set(stages[1]["output_ids"]) <= set(stages[2]["input_ids"])
    assert set(stages[1]["output_ids"] + stages[2]["output_ids"]) <= set(stages[3]["input_ids"])
    assert_honest_ceiling(response)


@pytest.mark.parametrize("field,value", [
    ("parameter_id", "foreign-parameter"),
    ("control_id", "ac-2"),
    ("source_sha256", "0" * 64),
    ("scope", {"organization_id": "org-b", "system_id": "system-a"}),
    ("scope", {"organization_id": "org-a", "system_id": "system-b"}),
])
def test_foreign_parameter_qualifiers_fail_before_semantic_release(app, field, value):
    request = request_for(app)
    request["parameters"][0][field] = value
    with pytest.raises(ValueError):
        query(app, request)


@pytest.mark.parametrize("field,value", [
    ("statement_id", "ps-4_smt.b"), ("source_sha256", "0" * 64),
    ("template_sha256", "0" * 64),
])
def test_statement_source_and_template_cannot_be_substituted(app, field, value):
    request = request_for(app)
    request[field] = value
    with pytest.raises(ValueError):
        query(app, request)


def test_selected_nested_choice_requires_its_exact_dependency(app):
    request = request_for(app, "ac-7_smt.b")
    request["parameters"] = [b for b in request["parameters"]
                             if b["parameter_id"] == "ac-07_odp.03"]
    response = query(app, request)
    execution = trace(response)
    assert response["kernel"]["instance"] is None
    assert any(r.get("reason") == "MISSING_PARAMETER" and
               r.get("parameter_id") == "ac-07_odp.04"
               for r in response["kernel"]["residuals"])
    assert not [c for c in execution["claims"] if c["id"].startswith("requirement-instance:")]


def test_parameter_handle_reordering_preserves_binding_meaning(app):
    request = request_for(app, "ac-2.2_smt")
    first = query(app, request)
    reordered = deepcopy(request)
    reordered["parameters"].reverse()
    assert reordered != request
    second = query(app, reordered)
    trace(first)
    trace(second)
    one, two = first["kernel"]["instance"], second["kernel"]["instance"]
    for field in ("scope", "control_id", "statement_id", "source_sha256", "template_sha256",
                  "parameter_bindings", "selected_choices", "ancestor_context", "blocks"):
        assert one[field] == two[field], field
    assert first["egress"]["request_sha256"] == digest(request)
    assert second["egress"]["request_sha256"] == digest(reordered)


@pytest.mark.parametrize("field,value", [
    ("applicability", True), ("applicability", [True, False]),
    ("satisfaction", True), ("compliance_verdict", True),
    ("external_effects", ["disable-account"]),
    ("facts", [{"predicate": "applicable", "value": True},
               {"predicate": "applicable", "value": False}]),
])
def test_caller_cannot_invent_or_conflict_policy_semantics_in_template_request(app, field, value):
    request = request_for(app)
    request[field] = value
    with pytest.raises(ValueError):
        query(app, request)


@pytest.mark.parametrize("mutation", ["reorder_handles", "text", "support", "scope", "compliance", "effect"])
def test_advisory_mutation_cannot_rewrite_claims_support_or_effects(app, monkeypatch, mutation):
    request = request_for(app)
    expected = query(app, request, recommend=True)
    trace(expected)
    observed = []

    class HostileAdviser:
        model = "local-test-double"
        def recommend(self, packet):
            kernel = packet["deterministic_result"]
            execution = kernel["semantic_execution"]
            if mutation == "reorder_handles":
                execution["claims"].reverse()
            elif mutation == "text":
                execution["claims"][0]["text"] += " The system is compliant."
            elif mutation == "support":
                execution["support_graph"][0]["from_claim_id"] = "foreign:unsupported"
            elif mutation == "scope":
                kernel["instance"]["scope"]["organization_id"] = "org-b"
            elif mutation == "compliance":
                kernel["compliance_verdict"] = True
            else:
                execution["external_effects"].append("disable-account")
            observed.append(mutation)
            return "Unverified advisory claim."

    monkeypatch.setattr(app, "recommender", HostileAdviser())
    actual = query(app, request, recommend=True)
    assert observed == [mutation], "The intended adversarial mutation did not run"
    assert actual["inference"]["status"] == "RECOMMENDATION"
    assert actual["inference"]["authority"] == "ADVISORY_ONLY"
    for field in ("answer", "request", "kernel", "ingress", "egress",
                  "provenance", "integrity", "escalation"):
        assert actual[field] == expected[field], field
    assert_honest_ceiling(actual)


def test_consumer_digests_cover_the_whole_semantic_execution_and_text(app):
    request = request_for(app)
    response = query(app, request)
    trace(response)
    assert canonical(response) == canonical(query(app, request))
    assert response["egress"]["result_sha256"] == digest(response["kernel"])
    assert response["integrity"]["result_sha256"] == digest(response["kernel"])
    assert response["egress"]["text_sha256"] == sha256(response["answer"].encode()).hexdigest()
    assert response["egress"]["instance_sha256"] == response["kernel"]["instance"]["instance_sha256"]
    assert response["inference"]["model_calls"] == 0
    assert_honest_ceiling(response)
