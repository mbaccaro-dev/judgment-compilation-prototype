from copy import deepcopy

import pytest

from judgment_compilation.inquiry_planner import InquiryPlanner
from judgment_compilation.kernel import SemanticRuntime, Rejected, canonical, digest
from tests.test_operation_interfaces import consumer_fixture


def planner_and_result(mutate_request=None):
    pack, raw = consumer_fixture()
    request = __import__("json").loads(raw)
    if mutate_request:
        mutate_request(request)
    raw = canonical(request).decode()
    runtime = SemanticRuntime(pack, digest(pack))
    return InquiryPlanner(pack, requirement_disposition_index_sha256="a" * 64), runtime.execute(raw)


def test_success_preserves_narrow_conclusion_and_scope_limit_inquiry():
    planner, result = planner_and_result()
    plan = planner.plan(result)
    assert plan["status"] == "CLARIFICATION_REQUIRED"
    assert plan["model_calls"] == 0
    assert plan["external_effects_executed"] == []
    assert any(i["class"] == "MISSING_AUTHORITY" and i["reason"] == "SCOPE_LIMIT" for i in plan["inquiries"])
    assert any("within_window" in c.get("predicate", "") for c in result["claims"] if c["id"] in plan["conclusion_partition"]["unaffected_applied_claim_ids"])
    assert planner.plan(result) == plan


def test_unknown_category_blocks_only_dependent_flow_and_is_inquired():
    def mutate(request):
        request["statements"] = ["Purchase A has elapsed 45 fixed days."]
        request["unknowns"] = ["The exact item category is unknown."]
    planner, result = planner_and_result(mutate)
    plan = planner.plan(result)
    classes = {i["class"] for i in plan["inquiries"]}
    assert "UNKNOWN_VALUE" in classes
    assert "MISSING_FACT" in classes or "DEPENDENCY_BLOCKED" in classes
    assert plan["conclusion_partition"]["unresolved_or_blocked_steps"]


def test_missing_role_conflict_and_unsupported_request_are_distinct():
    pack, raw = consumer_fixture()
    pack["messages"] = {"unsupported": "That question has no admitted operation."}
    runtime = SemanticRuntime(pack, digest(pack))
    planner = InquiryPlanner(pack)

    request = __import__("json").loads(raw)
    request["entities"] = []
    with pytest.raises(Rejected):
        runtime.execute(canonical(request).decode())

    request = __import__("json").loads(raw)
    request["question"] = "Invent a refund authorization."
    plan = planner.plan(runtime.execute(canonical(request).decode()))
    assert any(i["class"] == "UNSUPPORTED_OPERATION" for i in plan["inquiries"])

    synthetic = runtime.execute(raw)
    claim = next(c for c in synthetic["claims"] if c["type"] == "UNRESOLVED")
    claim.update(reason="CONFLICTING_FACTS", predicate="elapsed", fact_ids=["f1", "f2"])
    body = deepcopy(synthetic); body.pop("canonical_kernel_result_hash")
    synthetic["canonical_kernel_result_hash"] = digest(body)
    plan = planner.plan(synthetic)
    assert any(i["class"] == "CONFLICTING_FACTS" for i in plan["inquiries"])


def test_tamper_foreign_pack_and_authority_escalation_fail_closed():
    planner, result = planner_and_result()
    for mutate in (
        lambda r: r["claims"][0].update(text="Refund approved."),
        lambda r: r["pack_binding"].update(id="foreign"),
        lambda r: r.update(external_effects=["refund"]),
    ):
        changed = deepcopy(result); mutate(changed)
        with pytest.raises(Rejected):
            planner.plan(changed)


def test_inquiry_order_is_canonical_after_equivalent_residual_reordering():
    planner, result = planner_and_result()
    claim = next(c for c in result["claims"] if c["type"] == "UNRESOLVED")
    claim["residuals"] = [
        {"reason": "MISSING_FACT", "predicate": "alpha", "arguments": {"x": "one"}},
        {"reason": "MISSING_PARAMETER", "predicate": "beta", "arguments": {"x": "one"}},
    ]
    body = deepcopy(result); body.pop("canonical_kernel_result_hash")
    result["canonical_kernel_result_hash"] = digest(body)
    first = planner.plan(result)
    result["claims"].reverse()
    claim = next(c for c in result["claims"] if c["type"] == "UNRESOLVED")
    claim["residuals"].reverse()
    body = deepcopy(result); body.pop("canonical_kernel_result_hash")
    result["canonical_kernel_result_hash"] = digest(body)
    second = planner.plan(result)
    def semantic(plan):
        return [{k:v for k,v in row.items() if k != "id"} for row in plan["inquiries"]]
    assert semantic(first) == semantic(second)


def test_documentary_requirement_without_admitted_semantics_is_classified_exactly():
    planner, result = planner_and_result()
    claim = next(c for c in result["claims"] if c["type"] == "UNRESOLVED")
    claim.update(
        reason="REQUIREMENT_TO_POLICY_SEMANTICS_NOT_ADMITTED",
        predicate="nist_requirement:ps-4_smt.a",
    )
    body = deepcopy(result); body.pop("canonical_kernel_result_hash")
    result["canonical_kernel_result_hash"] = digest(body)

    plan = planner.plan(result)

    matching = [
        row for row in plan["inquiries"]
        if row["reason"] == "REQUIREMENT_TO_POLICY_SEMANTICS_NOT_ADMITTED"
    ]
    assert len(matching) == 1
    assert matching[0]["class"] == "MISSING_SEMANTIC_MAPPING"
    assert matching[0]["automatic_resolution"] is False


def test_unknown_residual_reason_is_rejected_instead_of_reclassified_as_authority():
    planner, result = planner_and_result()
    claim = next(c for c in result["claims"] if c["type"] == "UNRESOLVED")
    claim.update(reason="FUTURE_UNREVIEWED_RESIDUAL")
    body = deepcopy(result); body.pop("canonical_kernel_result_hash")
    result["canonical_kernel_result_hash"] = digest(body)

    with pytest.raises(Rejected, match="unsupported residual reason"):
        planner.plan(result)
