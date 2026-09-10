from copy import deepcopy

import pytest

from judgment_compilation.semantic_contracts import canonical
from judgment_compilation.semantic_node_composition import (
    SemanticNodeCompositionError,
    compose_architecture_program,
    decompose_stack_definition,
    decompose_architecture,
    decompose_judgment,
    decompose_work,
    execute_composed_program,
    rebind_architecture,
    rebind_judgment,
    rebind_stack_definition,
    rebind_work,
    stack_definition_relations,
)
from test_semantic_values import fixture, request


def test_composition_connects_admitted_nodes_and_executes_through_runtime():
    pack = fixture()
    program = compose_architecture_program(pack, "flow")
    judgment = decompose_judgment(pack, "electronics")
    work = decompose_work(pack, "select")
    architecture = decompose_architecture(pack, "flow")

    assert judgment["overrides"][0]["judgment_id"] == "general"
    assert work["producer_interface"] == "semantic_contracts._execute_work:RESOLVE_JUDGMENTS"
    assert [step["step_id"] for step in architecture["ordered_steps"]] == ["select", "compare"]
    assert architecture["dependency_edges"] == [{"from_step": "select", "to_step": "compare"}]
    assert rebind_judgment(pack, judgment) == judgment
    assert rebind_work(pack, work) == work
    assert rebind_architecture(pack, architecture) == architecture

    result = execute_composed_program(pack, program, request([1, 1], 45))
    assert result["status"] == "COMPLETE"
    assert result["execution"]["outputs"][0]["value"] == {"amount": 60, "unit_path": [2, 1]}
    assert result["external_effects"] == []
    assert result["execution"]["external_effects"] == []


def test_storage_reordering_preserves_composition_meaning_and_hash():
    original = fixture()
    reordered = deepcopy(original)
    for key in ("domain", "entity_kinds", "predicates", "sources", "judgments", "work", "architectures"):
        reordered[key].reverse()
    for stack in ("judgment", "work", "architecture"):
        reordered["semantic_capital"][stack].reverse()
    reordered["architectures"][0]["steps"].reverse()

    first = compose_architecture_program(original, "flow")
    second = compose_architecture_program(reordered, "flow")
    assert first["semantic_sha256"] == second["semantic_sha256"]
    assert first["program_sha256"] == second["program_sha256"]
    first_execution = execute_composed_program(original, first, request([1, 1]))
    second_execution = execute_composed_program(reordered, second, request([1, 1]))
    assert first_execution["status"] == second_execution["status"] == "COMPLETE"
    assert first_execution["execution"]["outputs"] == second_execution["execution"]["outputs"]
    assert [step["step_id"] for step in first_execution["execution"]["steps"]] == [
        step["step_id"] for step in second_execution["execution"]["steps"]
    ]


def test_unknown_is_preserved_as_unresolved_and_program_cannot_be_edited():
    pack = fixture()
    program = compose_architecture_program(pack, "flow")
    unknown_request = request(None)
    result = execute_composed_program(pack, program, unknown_request)
    assert result["status"] == "UNRESOLVED"
    assert result["execution"]["outputs"] == []

    altered = deepcopy(program)
    altered["architecture"]["ordered_steps"][0]["depends_on"] = ["compare"]
    with pytest.raises(SemanticNodeCompositionError):
        execute_composed_program(pack, altered, request([1, 1]))

    altered_judgment = decompose_judgment(pack, "electronics")
    altered_judgment["overrides"] = []
    with pytest.raises(SemanticNodeCompositionError):
        rebind_judgment(pack, altered_judgment)

    altered_work = decompose_work(pack, "select")
    altered_work["producer_interface"] = "invented.producer"
    with pytest.raises(SemanticNodeCompositionError):
        rebind_work(pack, altered_work)

    altered_architecture = decompose_architecture(pack, "flow")
    altered_architecture["ordered_steps"][1]["depends_on"] = []
    with pytest.raises(SemanticNodeCompositionError):
        rebind_architecture(pack, altered_architecture)


def test_program_binds_work_domain_path_and_domain_provenance():
    pack = fixture()
    program = compose_architecture_program(pack, "flow")

    changed_work_domain = deepcopy(pack)
    changed_work_domain["work"][0]["domain_path"] = []
    assert compose_architecture_program(changed_work_domain, "flow")["program_sha256"] != program["program_sha256"]
    with pytest.raises(SemanticNodeCompositionError):
        execute_composed_program(changed_work_domain, program, request([1, 1], 45))

    changed_unit_source = deepcopy(pack)
    unit = next(node for node in changed_unit_source["domain"] if node.get("unit"))
    replacement = "replacement-unit-source"
    changed_unit_source["sources"].append({"id": replacement, "sha256": "2" * 64})
    unit["unit"]["source_ids"] = [replacement]
    assert compose_architecture_program(changed_unit_source, "flow")["program_sha256"] != program["program_sha256"]
    with pytest.raises(SemanticNodeCompositionError):
        execute_composed_program(changed_unit_source, program, request([1, 1], 45))


def test_cycles_and_dangling_work_are_rejected_before_program_release():
    cyclic = fixture()
    cyclic["architectures"][0]["steps"][0]["depends_on"] = ["compare"]
    with pytest.raises(SemanticNodeCompositionError):
        compose_architecture_program(cyclic, "flow")

    dangling = fixture()
    dangling["architectures"][0]["steps"][0]["work"] = "not-admitted"
    with pytest.raises(SemanticNodeCompositionError):
        compose_architecture_program(dangling, "flow")


def test_coordinate_parent_is_only_definition_adjacency_not_precedence():
    relations = stack_definition_relations(fixture(), "judgment")
    electronics = next(row for row in relations if row["label"] == "Electronics exception warrant")
    assert electronics["parent_coordinate"] == {"Gs": [1], "L": 0}
    assert electronics["implies_specialization"] is False
    assert electronics["implies_precedence"] is False
    assert electronics["implies_execution"] is False

    pack = fixture()
    pack["judgments"][1].pop("overrides")
    # A descendant coordinate cannot replace the explicit, source-bound edge.
    program = compose_architecture_program(pack, "flow")
    result = execute_composed_program(pack, program, request([1, 1]))
    assert result["status"] == "UNRESOLVED"
    assert result["execution"]["steps"][0]["residuals"][0]["reason"] == "CONFLICTING_JUDGMENTS"


@pytest.mark.parametrize("stack", ["judgment", "work", "architecture"])
def test_reusable_stack_definitions_decompose_and_recompose_without_added_meaning(stack):
    pack = fixture()
    relation = stack_definition_relations(pack, stack)[-1]
    parts = decompose_stack_definition(pack, stack, relation["coordinate"])

    assert rebind_stack_definition(pack, parts) == parts
    assert parts["implies_specialization"] is False
    assert parts["implies_precedence"] is False
    assert parts["implies_execution"] is False

    changed = deepcopy(parts)
    changed["label"] += " changed"
    with pytest.raises(SemanticNodeCompositionError):
        rebind_stack_definition(pack, changed)
