from copy import deepcopy

import pytest

from judgment_compilation.interpretation_qualification import REVIEW_SCHEMA, digest, qualify_interpretation
from judgment_compilation.qualified_node_builder import compose_qualified_node, qualification_target
from judgment_compilation.qualified_program_builder import (
    QualifiedProgramBuilderError,
    build_qualified_program,
    decompose_qualified_program,
    execute_qualified_program,
)
from judgment_compilation.semantic_contracts import validate_semantic_pack
from test_semantic_values import fixture, request


def _reviewed(stack, parts, context):
    source = context["sources"][0]
    quote = "Fictional reviewed source support."
    source_index = {
        source["id"]: {
            "source_sha256": source["sha256"],
            "quote_sha256": digest(quote),
            "locator": "fictional-policy#qualified-program",
        }
    }
    target = qualification_target(stack, parts, context)
    subject_kind = "JUDGMENT" if stack == "judgment" else "SEMANTIC_DEFINITION"
    claim = {
        "id": f"reviewed-program-{stack}",
        "source_support": [{"source_id": source["id"], **source_index[source["id"]]}],
        "interpretation": {
            "rationale": "Fixture review binds the exact next component and context.",
            "mapping": {"stack": stack, "candidate_id": parts["node"]["id"]},
            "scope": {"fixture": "qualified aggregate"},
            "limits": ["Fixture-only source-reviewed construction."],
            "negative_case": "Changed parts or context require a new review.",
        },
        "derivation_binding": {
            "subject_kind": subject_kind,
            "subject_id": parts["node"]["id"],
            "target_contract_sha256": digest(target),
        },
    }
    review = {
        "schema": REVIEW_SCHEMA,
        "id": f"review-program-{stack}",
        "decision": "REVIEW_CONFIRMED",
        "reviewed_claim_sha256": digest(claim),
        "reviewer_evidence": ["fictional-review#aggregate-independent-check"],
    }
    pins = {review["id"]: digest(review)}
    return qualify_interpretation(claim, review, source_index, target, review_pins=pins), source_index, pins


def _qualified_chain(*, use_candidate_judgment=True, use_candidate_work=True):
    original = fixture()
    context = fixture()

    judgment = {"node": deepcopy(context["judgments"][0]), "source_ids": ["fictional-policy"]}
    judgment["node"]["id"] = "candidate-general"
    qualification, source_index, pins = _reviewed("judgment", judgment, context)
    candidate_judgment = compose_qualified_node(
        "judgment", judgment, qualification, source_index=source_index, review_pins=pins, context=context,
    )
    context["judgments"].append(deepcopy(judgment["node"]))
    context = validate_semantic_pack(context)

    work = {"node": deepcopy(context["work"][0]), "source_ids": ["fictional-policy"]}
    work["node"]["id"] = "candidate-select"
    if use_candidate_judgment:
        work["node"].update({"operation": "APPLY_JUDGMENT", "judgment": "candidate-general"})
        work["node"].pop("judgments")
    qualification, source_index, pins = _reviewed("work", work, context)
    candidate_work = compose_qualified_node(
        "work", work, qualification, source_index=source_index, review_pins=pins, context=context,
    )
    context["work"].append(deepcopy(work["node"]))
    context = validate_semantic_pack(context)

    architecture = {"node": deepcopy(context["architectures"][0]), "source_ids": ["fictional-policy"]}
    architecture["node"]["id"] = "candidate-flow"
    if use_candidate_work:
        architecture["node"]["steps"][0]["work"] = "candidate-select"
    qualification, source_index, pins = _reviewed("architecture", architecture, context)
    candidate_architecture = compose_qualified_node(
        "architecture", architecture, qualification, source_index=source_index, review_pins=pins, context=context,
    )
    return original, [candidate_judgment, candidate_work, candidate_architecture]


def test_build_decompose_and_execute_aggregate_of_qualified_nodes():
    context, candidates = _qualified_chain()
    before = deepcopy(context)

    program = build_qualified_program(context, candidates, "candidate-flow")
    parts = decompose_qualified_program(context, program)
    result = execute_qualified_program(context, program, request([1, 1], 45))

    assert parts == {"architecture_id": "candidate-flow", "qualified_nodes": candidates}
    assert result["status"] == "COMPLETE"
    assert result["execution"]["execution"]["outputs"][0]["value"] == {"amount": 30, "unit_path": [2, 1]}
    assert result["external_effects"] == result["execution"]["external_effects"] == []
    assert context == before


@pytest.mark.parametrize("variant", ["missing", "raw", "source-drift", "dependency-drift"])
def test_builder_fails_closed_for_missing_unqualified_or_drifted_components(variant):
    context, candidates = _qualified_chain()
    if variant == "missing":
        candidates = candidates[:-1]
    elif variant == "raw":
        candidates[1] = {"stack": "work"}
    elif variant == "source-drift":
        context["sources"][0]["sha256"] = "0" * 64
    else:
        context["architectures"][0]["steps"][0]["depends_on"] = ["compare"]

    with pytest.raises(QualifiedProgramBuilderError):
        build_qualified_program(context, candidates, "candidate-flow")


@pytest.mark.parametrize("chain", [
    {"use_candidate_judgment": False},
    {"use_candidate_work": False},
])
def test_builder_rejects_qualified_components_not_reached_by_selected_program(chain):
    context, candidates = _qualified_chain(**chain)
    with pytest.raises(QualifiedProgramBuilderError, match="not reach"):
        build_qualified_program(context, candidates, "candidate-flow")


@pytest.mark.parametrize("mutation", [
    lambda program: program["qualified_nodes"][0]["qualified_parts"]["node"].update(residual="changed"),
    lambda program: program["composition"]["architecture"]["ordered_steps"][0].update(depends_on=["compare"]),
    lambda program: program["qualified_nodes"][2]["qualified_parts"]["node"]["steps"][0].update(work="dangling"),
])
def test_decomposition_rejects_changed_program_or_dangling_component(mutation):
    context, candidates = _qualified_chain()
    program = build_qualified_program(context, candidates, "candidate-flow")
    changed = deepcopy(program)
    mutation(changed)

    with pytest.raises(QualifiedProgramBuilderError):
        decompose_qualified_program(context, changed)
