from copy import deepcopy

import pytest

from judgment_compilation.interpretation_qualification import REVIEW_SCHEMA, digest, qualify_interpretation
from judgment_compilation.qualified_node_builder import (
    QualifiedNodeBuilderError,
    TARGET_SCHEMA,
    compose_qualified_node,
    decompose_qualified_node,
    qualification_target,
)
from test_semantic_values import fixture


def _parts(stack):
    pack = fixture()
    if stack == "judgment":
        node = deepcopy(pack["judgments"][0])
        node["id"] = "candidate-general"
    elif stack == "work":
        node = deepcopy(pack["work"][0])
        node["id"] = "candidate-select"
    else:
        node = deepcopy(pack["architectures"][0])
        node["id"] = "candidate-flow"
    return {"node": node, "source_ids": ["fictional-policy"]}


def _qualified(stack, parts, context=None):
    pack = fixture() if context is None else context
    source = pack["sources"][0]
    quote = "Fictional reviewed source support."
    source_index = {
        source["id"]: {
            "source_sha256": source["sha256"],
            "quote_sha256": digest(quote),
            "locator": "fictional-policy#reviewed-node",
        }
    }
    target = qualification_target(stack, parts, pack)
    subject_kind = "JUDGMENT" if stack == "judgment" else "SEMANTIC_DEFINITION"
    claim = {
        "id": f"reviewed-{stack}-candidate",
        "source_support": [{"source_id": source["id"], **source_index[source["id"]]}],
        "interpretation": {
            "rationale": "A fictional independent review binds these exact typed candidate parts.",
            "mapping": {"stack": stack, "candidate_id": parts["node"]["id"]},
            "scope": {"fixture": "generic semantic contract"},
            "limits": ["Fixture-only source-reviewed construction."],
            "negative_case": "Changed parts require a new review.",
        },
        "derivation_binding": {
            "subject_kind": subject_kind,
            "subject_id": parts["node"]["id"],
            "target_contract_sha256": digest(target),
        },
    }
    review = {
        "schema": REVIEW_SCHEMA,
        "id": f"review-{stack}",
        "decision": "REVIEW_CONFIRMED",
        "reviewed_claim_sha256": digest(claim),
        "reviewer_evidence": ["fictional-review#independent-check"],
    }
    pins = {review["id"]: digest(review)}
    return qualify_interpretation(claim, review, source_index, target, review_pins=pins), source_index, pins


@pytest.mark.parametrize("stack", ["judgment", "work", "architecture"])
def test_compose_then_decompose_preserves_each_typed_stack_without_effects(stack):
    parts = _parts(stack)
    qualification, source_index, pins = _qualified(stack, parts)
    context = fixture()
    before = deepcopy(context)

    candidate = compose_qualified_node(
        stack, parts, qualification, source_index=source_index, review_pins=pins, context=context,
    )

    assert decompose_qualified_node(candidate) == parts
    assert candidate["status"] == "SOURCE_BOUND_NOT_EXECUTED"
    assert candidate["external_effects"] == []
    assert context == before


def test_missing_review_or_changed_source_binding_is_rejected():
    parts = _parts("judgment")
    qualification, source_index, pins = _qualified("judgment", parts)
    with pytest.raises(QualifiedNodeBuilderError):
        compose_qualified_node("judgment", parts, {}, source_index=source_index, review_pins=pins, context=fixture())

    changed = deepcopy(parts)
    changed["source_ids"] = ["invented-source"]
    with pytest.raises(QualifiedNodeBuilderError):
        compose_qualified_node("judgment", changed, qualification, source_index=source_index, review_pins=pins, context=fixture())

    with pytest.raises(QualifiedNodeBuilderError, match="full validated semantic-pack context required"):
        compose_qualified_node("judgment", parts, qualification, source_index=source_index, review_pins=pins, context={})


def test_invented_precedence_unknown_operation_and_incompatible_ports_are_rejected():
    judgment = _parts("judgment")
    qualification, source_index, pins = _qualified("judgment", judgment)
    invented_precedence = deepcopy(judgment)
    invented_precedence["node"]["overrides"] = [{"judgment_id": "electronics", "source_ids": ["fictional-policy"]}]
    with pytest.raises(QualifiedNodeBuilderError):
        compose_qualified_node("judgment", invented_precedence, qualification, source_index=source_index, review_pins=pins, context=fixture())

    work = _parts("work")
    unknown_operation = deepcopy(work)
    unknown_operation["node"]["operation"] = "INVENTED_OPERATION"
    qualification, source_index, pins = _qualified("work", unknown_operation)
    with pytest.raises(QualifiedNodeBuilderError):
        compose_qualified_node("work", unknown_operation, qualification, source_index=source_index, review_pins=pins, context=fixture())

    comparison = _parts("work")
    comparison["node"] = deepcopy(fixture()["work"][1])
    comparison["node"]["id"] = "candidate-compare"
    incompatible_ports = deepcopy(comparison)
    incompatible_ports["node"]["right"]["arguments"] = {"item": "foreign"}
    qualification, source_index, pins = _qualified("work", incompatible_ports)
    with pytest.raises(QualifiedNodeBuilderError):
        compose_qualified_node("work", incompatible_ports, qualification, source_index=source_index, review_pins=pins, context=fixture())


@pytest.mark.parametrize("mutation", [
    lambda node: node["steps"][0].update(work="not-present"),
    lambda node: node["steps"][0].update(depends_on=["compare"]),
    lambda node: node.update(completion={"required_steps": ["select"], "exclusive_terminal_groups": [["compare"]]}),
])
def test_dangling_or_cyclic_architecture_is_rejected(mutation):
    parts = _parts("architecture")
    changed = deepcopy(parts)
    mutation(changed["node"])
    qualification, source_index, pins = _qualified("architecture", changed)
    with pytest.raises(QualifiedNodeBuilderError):
        compose_qualified_node("architecture", changed, qualification, source_index=source_index, review_pins=pins, context=fixture())


def test_candidate_hash_rejects_modified_parts_after_construction():
    parts = _parts("judgment")
    qualification, source_index, pins = _qualified("judgment", parts)
    candidate = compose_qualified_node(
        "judgment", parts, qualification, source_index=source_index, review_pins=pins, context=fixture(),
    )
    candidate["qualified_parts"]["node"]["residual"] = "Changed after construction."
    with pytest.raises(QualifiedNodeBuilderError):
        decompose_qualified_node(candidate)


def test_review_cannot_be_replayed_against_a_different_valid_predecessor_context():
    original = fixture()
    parts = _parts("judgment")
    qualification, source_index, pins = _qualified("judgment", parts, original)
    changed = fixture()
    changed["semantic_capital"]["judgment"][0]["label"] = "Changed existing meaning"

    with pytest.raises(QualifiedNodeBuilderError, match="exact independently reviewed"):
        compose_qualified_node(
            "judgment", parts, qualification,
            source_index=source_index, review_pins=pins, context=changed,
        )
