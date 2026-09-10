from copy import deepcopy

import pytest

from judgment_compilation.interpretation_qualification import REVIEW_SCHEMA, digest, qualify_interpretation
from judgment_compilation.qualified_definition_builder import (
    QualifiedDefinitionBuilderError,
    TARGET_SCHEMA,
    compose_qualified_definition,
    decompose_qualified_definition,
    qualification_target,
    recompose_qualified_definition,
)
from judgment_compilation.qualified_node_builder import (
    compose_qualified_node,
    qualification_target as node_qualification_target,
)
from judgment_compilation.semantic_contracts import semantic_coordinate
from test_semantic_values import fixture


_PATHS = {"judgment": [0, 2], "work": [1, 1], "architecture": [0, 1]}


def _parts(stack):
    return {
        "definition": {
            "coordinate": semantic_coordinate(stack, _PATHS[stack]),
            "label": f"Candidate {stack} definition",
            "aliases": [f"candidate-{stack}"],
        },
        "source_ids": ["fictional-policy"],
    }


def _source_index():
    source = fixture()["sources"][0]
    quote = "Fictional reviewed source support."
    return {
        source["id"]: {
            "source_sha256": source["sha256"],
            "quote_sha256": digest(quote),
            "locator": "fictional-policy#reviewed-definition",
        }
    }


def _qualified_definition(stack, parts, context=None):
    context = fixture() if context is None else context
    source_index = _source_index()
    source_id = "fictional-policy"
    target = qualification_target(stack, parts, context)
    claim = {
        "id": f"reviewed-{stack}-definition",
        "source_support": [{"source_id": source_id, **source_index[source_id]}],
        "interpretation": {
            "rationale": "A fictional independent review binds this exact definition candidate.",
            "mapping": {"stack": stack, "coordinate": parts["definition"]["coordinate"]},
            "scope": {"fixture": "generic semantic contract"},
            "limits": ["Fixture-only source-reviewed construction."],
            "negative_case": "Changed definition, support, or predecessor requires a new review.",
        },
        "derivation_binding": {
            "subject_kind": "SEMANTIC_DEFINITION",
            "subject_id": f"semantic-definition:{stack}:{digest(parts['definition']['coordinate'])}",
            "target_contract_sha256": digest(target),
        },
    }
    review = {
        "schema": REVIEW_SCHEMA,
        "id": f"review-{stack}-definition",
        "decision": "REVIEW_CONFIRMED",
        "reviewed_claim_sha256": digest(claim),
        "reviewer_evidence": ["fictional-review#independent-check"],
    }
    pins = {review["id"]: digest(review)}
    return qualify_interpretation(claim, review, source_index, target, review_pins=pins), source_index, pins


@pytest.mark.parametrize("stack", ["judgment", "work", "architecture"])
def test_each_stack_gets_a_reviewed_coordinate_identity_and_lossless_structural_recomposition(stack):
    parts = _parts(stack)
    qualification, source_index, pins = _qualified_definition(stack, parts)
    predecessor = fixture()
    before = deepcopy(predecessor)

    candidate = compose_qualified_definition(
        stack, parts, qualification, source_index=source_index, review_pins=pins, context=predecessor,
    )
    successor = recompose_qualified_definition(predecessor, candidate)

    assert decompose_qualified_definition(candidate) == parts
    assert candidate["definition_id"].endswith(digest(parts["definition"]["coordinate"]))
    assert candidate["status"] == "SOURCE_BOUND_NOT_EXECUTED"
    assert candidate["external_effects"] == []
    assert candidate["definition_parts"]["coordinate"] == parts["definition"]["coordinate"]
    assert candidate["definition_parts"]["parent_coordinate"] is not None
    assert candidate["definition_parts"]["child_coordinates"] == []
    assert candidate["definition_parts"]["relation"] == "STACK_DEFINITION_PARENT"
    assert candidate["definition_parts"]["implies_specialization"] is False
    assert candidate["definition_parts"]["implies_precedence"] is False
    assert candidate["definition_parts"]["implies_execution"] is False
    assert parts["definition"] in successor["semantic_capital"][stack]
    assert predecessor == before


def test_recomposed_definition_context_can_precede_concrete_node_qualification():
    parts = _parts("judgment")
    qualification, source_index, pins = _qualified_definition("judgment", parts)
    successor = recompose_qualified_definition(
        fixture(),
        compose_qualified_definition(
            "judgment", parts, qualification, source_index=source_index, review_pins=pins, context=fixture(),
        ),
    )
    node = deepcopy(successor["judgments"][0])
    node["id"] = "definition-backed-general"
    node["semantic_coordinate"] = deepcopy(parts["definition"]["coordinate"])
    node_parts = {"node": node, "source_ids": ["fictional-policy"]}
    target = node_qualification_target("judgment", node_parts, successor)
    claim = {
        "id": "reviewed-definition-backed-node",
        "source_support": [{"source_id": "fictional-policy", **source_index["fictional-policy"]}],
        "interpretation": {
            "rationale": "A separate fictional review binds the concrete node to the held definition context.",
            "mapping": {"node_id": node["id"]},
            "scope": {"fixture": "generic semantic contract"},
            "limits": ["Fixture-only source-reviewed construction."],
            "negative_case": "Changed node requires a new review.",
        },
        "derivation_binding": {
            "subject_kind": "JUDGMENT",
            "subject_id": node["id"],
            "target_contract_sha256": digest(target),
        },
    }
    review = {
        "schema": REVIEW_SCHEMA,
        "id": "review-definition-backed-node",
        "decision": "REVIEW_CONFIRMED",
        "reviewed_claim_sha256": digest(claim),
        "reviewer_evidence": ["fictional-review#independent-check"],
    }
    node_pins = {review["id"]: digest(review)}
    node_qualification = qualify_interpretation(claim, review, source_index, target, review_pins=node_pins)

    node_candidate = compose_qualified_node(
        "judgment", node_parts, node_qualification,
        source_index=source_index, review_pins=node_pins, context=successor,
    )
    assert node_candidate["status"] == "SOURCE_BOUND_NOT_EXECUTED"


def test_review_source_context_and_definition_schema_drift_fail_closed():
    parts = _parts("work")
    qualification, source_index, pins = _qualified_definition("work", parts)
    with pytest.raises(QualifiedDefinitionBuilderError):
        compose_qualified_definition("work", parts, {}, source_index=source_index, review_pins=pins, context=fixture())

    invented_relation = deepcopy(parts)
    invented_relation["definition"]["relation"] = "IMPLIES_PRECEDENCE"
    with pytest.raises(QualifiedDefinitionBuilderError):
        compose_qualified_definition(
            "work", invented_relation, qualification, source_index=source_index, review_pins=pins, context=fixture(),
        )

    dangling = deepcopy(parts)
    dangling["definition"]["coordinate"] = semantic_coordinate("work", [9, 0])
    dangling_qualification, source_index, pins = _qualified_definition("work", dangling)
    with pytest.raises(QualifiedDefinitionBuilderError):
        compose_qualified_definition(
            "work", dangling, dangling_qualification, source_index=source_index, review_pins=pins, context=fixture(),
        )

    drifted_context = fixture()
    drifted_context["sources"][0]["sha256"] = "0" * 64
    with pytest.raises(QualifiedDefinitionBuilderError):
        compose_qualified_definition(
            "work", parts, qualification, source_index=source_index, review_pins=pins, context=drifted_context,
        )


def test_tampered_candidate_or_predecessor_cannot_recompose():
    parts = _parts("architecture")
    qualification, source_index, pins = _qualified_definition("architecture", parts)
    candidate = compose_qualified_definition(
        "architecture", parts, qualification, source_index=source_index, review_pins=pins, context=fixture(),
    )
    candidate["definition_parts"]["parent_coordinate"] = None
    with pytest.raises(QualifiedDefinitionBuilderError):
        recompose_qualified_definition(fixture(), candidate)

    candidate = compose_qualified_definition(
        "architecture", parts, qualification, source_index=source_index, review_pins=pins, context=fixture(),
    )
    drifted_predecessor = fixture()
    drifted_predecessor["semantic_capital"]["architecture"][0]["label"] = "Changed predecessor"
    with pytest.raises(QualifiedDefinitionBuilderError):
        recompose_qualified_definition(drifted_predecessor, candidate)


def test_review_cannot_be_replayed_to_create_a_candidate_for_another_valid_predecessor():
    original = fixture()
    parts = _parts("judgment")
    qualification, source_index, pins = _qualified_definition("judgment", parts, original)
    changed = fixture()
    changed["semantic_capital"]["judgment"][0]["label"] = "Changed existing meaning"

    with pytest.raises(QualifiedDefinitionBuilderError, match="exact independently reviewed"):
        compose_qualified_definition(
            "judgment", parts, qualification,
            source_index=source_index, review_pins=pins, context=changed,
        )
