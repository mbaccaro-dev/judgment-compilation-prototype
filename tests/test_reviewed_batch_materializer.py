from copy import deepcopy
import importlib.util
from pathlib import Path
import sys

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
for candidate in (PROJECT_ROOT, PROJECT_ROOT / "tests"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

MODULE_PATH = Path(__file__).with_name("reviewed_batch_materializer.py")
if not MODULE_PATH.is_file():
    MODULE_PATH = PROJECT_ROOT / "judgment_compilation" / "reviewed_batch_materializer.py"
SPEC = importlib.util.spec_from_file_location(
    "judgment_compilation.reviewed_batch_materializer", MODULE_PATH,
)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)

from judgment_compilation.interpretation_qualification import REVIEW_SCHEMA, digest, qualify_interpretation
from judgment_compilation.documentary_projection import DocumentaryProjection
from judgment_compilation.qualified_definition_builder import qualification_target as definition_target
from judgment_compilation.qualified_domain_builder import qualification_target as domain_target
from judgment_compilation.qualified_node_builder import qualification_target as node_target
from judgment_compilation.qualified_predicate_builder import qualification_target as predicate_target
from judgment_compilation.semantic_contracts import semantic_coordinate, validate_semantic_pack
from test_semantic_values import fixture


def _review(stack, parts, context, target):
    source = context["sources"][0]
    quote = "Fictional independently reviewed source support."
    source_index = {
        source["id"]: {
            "source_sha256": source["sha256"],
            "quote_sha256": digest(quote),
            "locator": "fictional-policy#reviewed-batch",
        }
    }
    is_definition = "definition" in parts
    subject_id = (
        f"semantic-definition:{stack}:{digest(parts['definition']['coordinate'])}"
        if is_definition else parts["node"]["id"]
    )
    claim = {
        "id": f"reviewed-batch-{stack}-{'definition' if is_definition else 'node'}",
        "source_support": [{"source_id": source["id"], **source_index[source["id"]]}],
        "interpretation": {
            "rationale": "Fixture review binds exact typed parts and predecessor context.",
            "mapping": {"stack": stack, "subject_id": subject_id},
            "scope": {"fixture": "reviewed batch"},
            "limits": ["Fixture-only source-reviewed materialization."],
            "negative_case": "Changed component or predecessor requires new review.",
        },
        "derivation_binding": {
            "subject_kind": "JUDGMENT" if stack == "judgment" and not is_definition else "SEMANTIC_DEFINITION",
            "subject_id": subject_id,
            "target_contract_sha256": digest(target),
        },
    }
    review = {
        "schema": REVIEW_SCHEMA,
        "id": f"fixture-review-{stack}-{'definition' if is_definition else 'node'}",
        "decision": "REVIEW_CONFIRMED",
        "reviewed_claim_sha256": digest(claim),
        "reviewer_evidence": ["fixture-review#independent-check"],
    }
    qualification = qualify_interpretation(
        claim, review, source_index, target, review_pins={review["id"]: digest(review)},
    )
    return {
        "stack": stack,
        "parts": parts,
        "qualification": qualification,
        "source_index": source_index,
        "review_pins": {review["id"]: digest(review)},
    }


def _definition(stack, coordinate):
    return {
        "definition": {
            "coordinate": semantic_coordinate(stack, coordinate),
            "label": f"Reviewed {stack} batch definition",
            "aliases": [f"reviewed-{stack}-batch"],
        },
        "source_ids": ["fictional-policy"],
    }


def _domain_definition(context):
    parts = {
        "definition": {
            "path": [3, 1],
            "label": "Reviewed refund determination",
            "aliases": ["reviewed-refund-determination"],
        },
        "occurrence": 0,
        "source_ids": ["fictional-policy"],
    }


    source = context["sources"][0]
    quote = "Fictional independently reviewed source support."
    source_index = {
        source["id"]: {
            "source_sha256": source["sha256"],
            "quote_sha256": digest(quote),
            "locator": "fictional-policy#reviewed-domain",
        }
    }
    target = domain_target("DEFINITION", parts, context)
    subject_id = "domain:definition:" + digest({"root_id": context["root_id"], "parts": parts})
    claim = {
        "id": "reviewed-batch-domain-definition",
        "source_support": [{"source_id": source["id"], **source_index[source["id"]]}],
        "interpretation": {
            "rationale": "Fixture review binds the exact Domain definition and predecessor context.",
            "mapping": {"stack": "domain", "subject_id": subject_id},
            "scope": {"fixture": "reviewed batch"},
            "limits": ["Fixture-only source-reviewed materialization."],
            "negative_case": "Changed definition or predecessor requires new review.",
        },
        "derivation_binding": {
            "subject_kind": "DOMAIN_DEFINITION",
            "subject_id": subject_id,
            "target_contract_sha256": digest(target),
        },
    }
    review = {
        "schema": REVIEW_SCHEMA,
        "id": "fixture-review-domain-definition",
        "decision": "REVIEW_CONFIRMED",
        "reviewed_claim_sha256": digest(claim),
        "reviewer_evidence": ["fixture-review#independent-check"],
    }
    return {
        "record_kind": "DEFINITION",
        "parts": parts,
        "qualification": qualify_interpretation(
            claim, review, source_index, target, review_pins={review["id"]: digest(review)},
        ),
        "source_index": source_index,
        "review_pins": {review["id"]: digest(review)},
    }


def _predicate(context):
    parts = {
        "predicate": {
            "id": "reviewed-fact-kind",
            "roles": {"item": "purchase"},
            "origin": "INPUT",
            "input_kind": "SCENARIO_FACT",
            "value_type": "BOOLEAN",
        },
        "fact_kind": {"scope": "SCENARIO_FACT"},
        "source_ids": ["fictional-policy"],
    }
    source = context["sources"][0]
    quote = "Fictional independently reviewed source support."
    source_index = {
        source["id"]: {
            "source_sha256": source["sha256"],
            "quote_sha256": digest(quote),
            "locator": "fictional-policy#reviewed-predicate",
        }
    }
    target = predicate_target(parts, context)
    claim = {
        "id": "reviewed-batch-predicate",
        "source_support": [{"source_id": source["id"], **source_index[source["id"]]}],
        "interpretation": {
            "rationale": "Fixture review binds the exact fact kind and predecessor context.",
            "mapping": {"stack": "predicate", "subject_id": "predicate:reviewed-fact-kind"},
            "scope": {"fixture": "reviewed batch"},
            "limits": ["Fixture-only source-reviewed materialization."],
            "negative_case": "Changed fact kind or predecessor requires new review.",
        },
        "derivation_binding": {
            "subject_kind": "SEMANTIC_DEFINITION",
            "subject_id": "predicate:reviewed-fact-kind",
            "target_contract_sha256": digest(target),
        },
    }
    review = {
        "schema": REVIEW_SCHEMA,
        "id": "fixture-review-predicate",
        "decision": "REVIEW_CONFIRMED",
        "reviewed_claim_sha256": digest(claim),
        "reviewer_evidence": ["fixture-review#independent-check"],
    }
    return {
        "parts": parts,
        "qualification": qualify_interpretation(
            claim, review, source_index, target, review_pins={review["id"]: digest(review)},
        ),
        "source_index": source_index,
        "review_pins": {review["id"]: digest(review)},
    }


def reviewed_batch(source_document=None):
    initial = fixture()
    context = deepcopy(initial)
    sources = []
    if source_document is not None:
        context["sources"].append({
            "id": source_document["publication_id"],
            "sha256": source_document["source_file"]["sha256"],
        })
        context = validate_semantic_pack(context)
        sources.append(source_document)
    predicates = [_predicate(context)]
    context["predicates"].append(deepcopy(predicates[0]["parts"]["predicate"]))
    context = validate_semantic_pack(context)
    domain = _domain_definition(context)
    context["domain"].append(deepcopy(domain["parts"]["definition"]))
    context = validate_semantic_pack(context)
    definitions = []
    for stack, path in (("judgment", [0, 2]), ("work", [1, 1]), ("architecture", [0, 1])):
        parts = _definition(stack, path)
        entry = _review(stack, parts, context, definition_target(stack, parts, context))
        definitions.append(entry)
        context["semantic_capital"][stack].append(deepcopy(parts["definition"]))
        context = validate_semantic_pack(context)

    judgment = {"node": deepcopy(context["judgments"][0]), "source_ids": ["fictional-policy"]}
    judgment["node"].update(id="reviewed-general", semantic_coordinate=semantic_coordinate("judgment", [0, 2]))
    judgment_entry = _review("judgment", judgment, context, node_target("judgment", judgment, context))
    context["judgments"].append(deepcopy(judgment["node"]))
    context = validate_semantic_pack(context)

    work = {"node": deepcopy(context["work"][0]), "source_ids": ["fictional-policy"]}
    work["node"].update(
        id="reviewed-select",
        semantic_coordinate=semantic_coordinate("work", [1, 1]),
        operation="APPLY_JUDGMENT",
        judgment="reviewed-general",
        domain_path=[3, 1],
    )
    work["node"].pop("judgments")
    work_entry = _review("work", work, context, node_target("work", work, context))
    context["work"].append(deepcopy(work["node"]))
    context = validate_semantic_pack(context)

    architecture = {"node": deepcopy(context["architectures"][0]), "source_ids": ["fictional-policy"]}
    architecture["node"].update(id="reviewed-flow", semantic_coordinate=semantic_coordinate("architecture", [0, 1]))
    architecture["node"]["steps"][0]["work"] = "reviewed-select"
    architecture_entry = _review(
        "architecture", architecture, context, node_target("architecture", architecture, context),
    )
    return initial, {
        "schema": MODULE.INPUT_SCHEMA,
        "sources": sources,
        "predicates": predicates,
        "domain": [domain],
        "definitions": definitions,
        "nodes": [judgment_entry, work_entry, architecture_entry],
        "architecture_id": "reviewed-flow",
    }


def test_registers_retained_source_before_connected_four_stack_materialization():
    document = next(DocumentaryProjection().iter_documents(
        publication_id="NIST SP 800-100-upd1",
    ))
    context, batch = reviewed_batch(source_document=document)

    materialized = MODULE.materialize_reviewed_batch(context, batch)
    parts = MODULE.decompose_reviewed_batch(context, materialized)

    assert len(materialized["qualified_source_candidates"]) == 1
    assert materialized["qualified_source_candidates"][0]["source_registration"] == {
        "id": document["publication_id"],
        "sha256": document["source_file"]["sha256"],
    }
    assert materialized["source_context_sha256"] != materialized["initial_context_sha256"]
    assert MODULE.recompose_reviewed_batch(context, parts) == materialized


def test_materializes_connected_four_stack_record_and_losslessly_recomposes():
    context, batch = reviewed_batch()
    before = deepcopy(context)

    materialized = MODULE.materialize_reviewed_batch(context, batch)
    parts = MODULE.decompose_reviewed_batch(context, materialized)

    assert MODULE.recompose_reviewed_batch(context, parts) == materialized
    assert set(materialized["stack_records"]) == {"domain", "judgment", "work", "architecture"}
    assert materialized["source_context_sha256"] != materialized["predicate_context_sha256"]
    assert materialized["predicate_context_sha256"] != materialized["domain_context_sha256"]
    assert materialized["qualified_predicate_candidates"][0]["predicate_id"] == "reviewed-fact-kind"
    assert materialized["stack_records"]["domain"]["domain_path"] == [3, 1]
    assert materialized["stack_records"]["domain"]["producer"].startswith("qualified-domain:")
    assert materialized["domain_context_sha256"] != materialized["initial_context_sha256"]
    assert materialized["stack_records"]["work"]["producer"] == "semantic_contracts._evaluate"
    assert materialized["program"]["architecture_id"] == "reviewed-flow"
    assert materialized["external_effects"] == []
    assert context == before


@pytest.mark.parametrize("mutation", [
    lambda batch: batch["domain"][0]["parts"]["definition"].update(label="changed"),
    lambda batch: batch["domain"][0].pop("qualification"),
    lambda batch: batch["definitions"].reverse(),
    lambda batch: batch["nodes"].reverse(),
    lambda batch: batch["nodes"][1].pop("qualification"),
    lambda batch: batch["nodes"][1]["source_index"]["fictional-policy"].update(source_sha256="0" * 64),
])
def test_rejects_reordered_missing_or_substituted_review_inputs(mutation):
    context, batch = reviewed_batch()
    mutation(batch)
    with pytest.raises(MODULE.ReviewedBatchMaterializerError):
        MODULE.materialize_reviewed_batch(context, batch)


def test_rejects_unknown_operation_and_dependency_mismatch_even_with_fresh_review_shape():
    context, batch = reviewed_batch()
    unknown = deepcopy(batch)
    unknown["nodes"][1]["parts"]["node"]["operation"] = "INVENTED_OPERATION"
    with pytest.raises(MODULE.ReviewedBatchMaterializerError):
        MODULE.materialize_reviewed_batch(context, unknown)

    mismatched = deepcopy(batch)
    mismatched["nodes"][2]["parts"]["node"]["steps"][0]["work"] = "select"
    with pytest.raises(MODULE.ReviewedBatchMaterializerError):
        MODULE.materialize_reviewed_batch(context, mismatched)


def test_rejects_preexisting_domain_without_the_qualified_batch_producer():
    context, batch = reviewed_batch()
    batch["domain"] = []
    with pytest.raises(MODULE.ReviewedBatchMaterializerError):
        MODULE.materialize_reviewed_batch(context, batch)


@pytest.mark.parametrize("mutation", [
    lambda record: record["qualified_domain_candidates"][0]["semantic_record"].update(identity="tampered"),
    lambda record: record["qualified_nodes"][0]["qualified_parts"]["node"].update(residual="tampered"),
    lambda record: record["stack_records"]["architecture"]["definition"]["ordered_steps"][0].update(depends_on=["compare"]),
])
def test_rejects_tampered_materialized_components(mutation):
    context, batch = reviewed_batch()
    materialized = MODULE.materialize_reviewed_batch(context, batch)
    mutation(materialized)
    with pytest.raises(MODULE.ReviewedBatchMaterializerError):
        MODULE.decompose_reviewed_batch(context, materialized)


def independent_work_batch(operations, *, orphan=False):
    initial, batch = reviewed_batch()
    context = deepcopy(initial)
    context["predicates"].append(deepcopy(batch["predicates"][0]["parts"]["predicate"]))
    context["domain"].append(deepcopy(batch["domain"][0]["parts"]["definition"]))
    for entry in batch["definitions"]:
        context["semantic_capital"][entry["stack"]].append(deepcopy(entry["parts"]["definition"]))
    context = validate_semantic_pack(context)
    definition_context = deepcopy(context)
    judgment, template, architecture = [deepcopy(entry["parts"]) for entry in batch["nodes"]]
    entries = [_review("judgment", judgment, context, node_target("judgment", judgment, context))]
    context["judgments"].append(deepcopy(judgment["node"]))
    context = validate_semantic_pack(context)
    steps = []
    for index, operation in enumerate(operations):
        parts = deepcopy(template)
        parts["node"].update(id=f"reviewed-select-{index}", operation=operation)
        if operation == "RESOLVE_JUDGMENTS":
            parts["node"]["judgments"] = [parts["node"].pop("judgment")]
        entries.append(_review("work", parts, context, node_target("work", parts, context)))
        context["work"].append(deepcopy(parts["node"]))
        context = validate_semantic_pack(context)
        steps.append({"id": f"select-{index}", "work": parts["node"]["id"], "depends_on": []})
    architecture["node"]["steps"] = steps[:1] if orphan else steps
    entries.append(_review("architecture", architecture, context, node_target("architecture", architecture, context)))
    batch["nodes"] = entries
    return initial, batch, definition_context


@pytest.mark.parametrize("operations", [
    ["APPLY_JUDGMENT", "APPLY_JUDGMENT"],
    ["RESOLVE_JUDGMENTS", "RESOLVE_JUDGMENTS"],
    ["APPLY_JUDGMENT", "RESOLVE_JUDGMENTS"],
])
def test_independent_reviewed_work_steps_recompose_and_preserve_partial_results(operations):
    from judgment_compilation.qualified_program_builder import execute_qualified_program

    initial, batch, definition_context = independent_work_batch(operations)
    materialized = MODULE.materialize_reviewed_batch(initial, batch)
    assert MODULE.recompose_reviewed_batch(
        initial, MODULE.decompose_reviewed_batch(initial, materialized),
    ) == materialized
    request = {
        "entities": {"item-a": "purchase", "item-b": "purchase"},
        "facts": [{"id": "category-a", "predicate": "category", "arguments": {"item": "item-a"}, "value": [1, 2]}],
        "bindings": {"select-0": {"target": ["item-a"]}, "select-1": {"target": ["item-b"]}},
        "unknowns": [],
    }
    result = execute_qualified_program(definition_context, materialized["program"], request)
    execution = result["execution"]["execution"]
    assert [step["status"] for step in execution["steps"]] == ["APPLIED", "UNRESOLVED"]
    assert len(execution["outputs"]) == 1
    assert execution["outputs"][0]["arguments"] == {"item": "item-a"}
    assert "category-a" in execution["outputs"][0]["support"]
    assert execution["compliance_verdict"] is None
    assert result["external_effects"] == []


def test_independently_reviewed_orphan_work_is_rejected_by_dependency_closure():
    initial, batch, _ = independent_work_batch(["RESOLVE_JUDGMENTS"] * 2, orphan=True)
    with pytest.raises(MODULE.ReviewedBatchMaterializerError, match="no connected executable program") as caught:
        MODULE.materialize_reviewed_batch(initial, batch)
    assert "does not reach every qualified Work" in str(caught.value.__cause__)
