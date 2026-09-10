"""Connects reviewed nodes into an executable program."""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from .operation_interfaces import operation_interfaces
from .semantic_contracts import (
    CEILING,
    SemanticContractError,
    canonical,
    digest,
    execute_architecture,
    validate_semantic_pack,
)


SCHEMA = "jc-semantic-node-composition/1"


class SemanticNodeCompositionError(ValueError):
    """A requested composition is not an admitted, executable program."""


def _validated(pack: Any) -> dict:
    try:
        return validate_semantic_pack(pack)
    except SemanticContractError as exc:
        raise SemanticNodeCompositionError(str(exc)) from exc


def _index(rows: list[dict], identifier: str, kind: str) -> dict:
    if type(identifier) is not str:
        raise SemanticNodeCompositionError(f"invalid {kind} id")
    found = next((row for row in rows if row["id"] == identifier), None)
    if found is None:
        raise SemanticNodeCompositionError(f"unknown admitted {kind}: {identifier}")
    return found


def _coordinate_key(coordinate: dict) -> tuple[tuple[int, ...], int]:
    return tuple(coordinate["Gs"]), coordinate["L"]


def _coordinate_parent(coordinate: dict) -> dict | None:
    """Return the structural parent only; it carries no policy semantics."""
    gs = coordinate["Gs"]
    if len(gs) == 1:
        return None
    return {"Gs": deepcopy(gs[:-1]), "L": gs[-1]}


def stack_definition_relations(pack: Any, stack: str) -> list[dict]:
    """Return parent and child coordinates for definitions."""
    admitted = _validated(pack)
    if stack not in ("judgment", "work", "architecture"):
        raise SemanticNodeCompositionError("unknown semantic stack")
    rows = admitted["semantic_capital"][stack]
    by_key = {_coordinate_key(row["coordinate"]): row for row in rows}
    relations = []
    for row in sorted(rows, key=lambda value: _coordinate_key(value["coordinate"])):
        coordinate = deepcopy(row["coordinate"])
        parent = _coordinate_parent(coordinate)
        children = [
            deepcopy(other["coordinate"])
            for other in rows
            if _coordinate_parent(other["coordinate"]) == coordinate
        ]
        relations.append({
            "stack": stack,
            "coordinate": coordinate,
            "label": row["label"],
            "aliases": sorted(deepcopy(row["aliases"])),
            "parent_coordinate": parent,
            "child_coordinates": sorted(children, key=_coordinate_key),
            "relation": "STACK_DEFINITION_PARENT",
            "implies_specialization": False,
            "implies_precedence": False,
            "implies_execution": False,
        })
        if parent is not None and _coordinate_key(parent) not in by_key:
            # Reject a missing parent before building the relation.
            raise SemanticNodeCompositionError("definition parent is not admitted")
    return relations


def decompose_stack_definition(pack: Any, stack: str, coordinate: Any) -> dict:
    """Return one Judgment, Work, or Architecture definition."""
    if type(coordinate) is not dict:
        raise SemanticNodeCompositionError("invalid semantic definition coordinate")
    found = next(
        (row for row in stack_definition_relations(pack, stack)
         if row["coordinate"] == coordinate),
        None,
    )
    if found is None:
        raise SemanticNodeCompositionError("unknown admitted semantic definition")
    return found


def rebind_stack_definition(pack: Any, parts: Any) -> dict:
    """Losslessly recompose one unchanged reusable stack definition."""
    if type(parts) is not dict or parts.get("stack") not in ("judgment", "work", "architecture"):
        raise SemanticNodeCompositionError("invalid semantic definition parts")
    expected = decompose_stack_definition(pack, parts["stack"], parts.get("coordinate"))
    if canonical(parts) != canonical(expected):
        raise SemanticNodeCompositionError("semantic definition parts drift from the admitted definition")
    return expected


def _definition_relation(pack: dict, stack: str, coordinate: dict) -> dict:
    found = next(
        (row for row in stack_definition_relations(pack, stack)
         if row["coordinate"] == coordinate),
        None,
    )
    if found is None:
        raise SemanticNodeCompositionError("node has no admitted stack definition")
    return found


def _sort_canonical(values: list[Any]) -> list[Any]:
    return [deepcopy(value) for value in sorted(values, key=canonical)]


def decompose_judgment(pack: Any, judgment_id: str) -> dict:
    """Return all declared parts of an admitted Judgment warrant."""
    admitted = _validated(pack)
    judgment = _index(admitted["judgments"], judgment_id, "Judgment")
    return {
        "id": judgment["id"],
        "stack_definition": _definition_relation(admitted, "judgment", judgment["semantic_coordinate"]),
        "typed_bindings": deepcopy(judgment["bindings"]),
        "premises": _sort_canonical(judgment["premises"]),
        "output": deepcopy(judgment["output"]),
        "overrides": _sort_canonical(judgment.get("overrides", [])),
        "source_ids": sorted(judgment["source_ids"]),
        "residual": judgment.get("residual"),
    }


def rebind_judgment(pack: Any, parts: Any) -> dict:
    """Verify and return the recorded parts of one reviewed Judgment."""
    if type(parts) is not dict or type(parts.get("id")) is not str:
        raise SemanticNodeCompositionError("invalid Judgment parts")
    expected = decompose_judgment(pack, parts["id"])
    if canonical(parts) != canonical(expected):
        raise SemanticNodeCompositionError("Judgment parts drift from the admitted warrant")
    return expected


def decompose_work(pack: Any, work_id: str) -> dict:
    """Connect a Work definition to its real runtime producer and ports."""
    admitted = _validated(pack)
    work = _index(admitted["work"], work_id, "Work")
    interface = operation_interfaces(admitted)[work_id]
    result = {
        "id": work["id"],
        "stack_definition": _definition_relation(admitted, "work", work["semantic_coordinate"]),
        "domain_path": deepcopy(work["domain_path"]),
        "declared_operation": interface["operation"],
        "producer_interface": interface["producer"],
        "typed_bindings": deepcopy(interface["bindings"]),
        "inputs": _sort_canonical(interface["inputs"]),
        "output": deepcopy(interface["output"]),
        "judgment_dependencies": sorted(interface["judgment_ids"]),
        "conclusion_scope": interface["conclusion_scope"],
        "missing_or_conflicting_input": interface["missing_or_conflicting_input"],
        "external_effects": [],
    }
    if "finite_enum_program" in interface:
        result["finite_enum_program"] = deepcopy(interface["finite_enum_program"])
        result["source_ids"] = deepcopy(interface["source_ids"])
    return result


def rebind_work(pack: Any, parts: Any) -> dict:
    """Accept only a Work node bound to its declared runtime interface."""
    if type(parts) is not dict or type(parts.get("id")) is not str:
        raise SemanticNodeCompositionError("invalid Work parts")
    expected = decompose_work(pack, parts["id"])
    if canonical(parts) != canonical(expected):
        raise SemanticNodeCompositionError("Work parts drift from the admitted interface")
    return expected


def _ordered_steps(architecture: dict) -> list[dict]:
    """Return the steps in topological order."""
    steps = {step["id"]: step for step in architecture["steps"]}
    ready = sorted(step_id for step_id, step in steps.items() if not step["depends_on"])
    result = []
    complete: set[str] = set()
    while ready:
        step_id = ready.pop(0)
        result.append(steps[step_id])
        complete.add(step_id)
        for candidate_id in sorted(steps):
            candidate = steps[candidate_id]
            if candidate_id not in complete and candidate_id not in ready and set(candidate["depends_on"]) <= complete:
                ready.append(candidate_id)
        ready.sort()
    if len(result) != len(steps):
        raise SemanticNodeCompositionError("architecture dependency cycle")
    return result


def decompose_architecture(pack: Any, architecture_id: str) -> dict:
    """Expose ordered executable wiring and its terminal/unresolved contract."""
    admitted = _validated(pack)
    architecture = _index(admitted["architectures"], architecture_id, "Architecture")
    steps = _ordered_steps(architecture)
    work_ids = {row["id"] for row in admitted["work"]}
    if any(step["work"] not in work_ids for step in steps):
        raise SemanticNodeCompositionError("architecture names work that is not admitted")
    ordered_steps = [
        {
            "step_id": step["id"],
            "work_id": step["work"],
            "depends_on": sorted(step["depends_on"]),
            "work": decompose_work(admitted, step["work"]),
        }
        for step in steps
    ]
    edges = sorted(
        [{"from_step": dependency, "to_step": step["id"]}
         for step in steps for dependency in step["depends_on"]],
        key=canonical,
    )
    completion = deepcopy(architecture.get("completion"))
    if completion is not None:
        completion["required_steps"] = sorted(completion["required_steps"])
        completion["exclusive_terminal_groups"] = sorted(
            [sorted(group) for group in completion["exclusive_terminal_groups"]], key=canonical)
    return {
        "id": architecture["id"],
        "stack_definition": _definition_relation(admitted, "architecture", architecture["semantic_coordinate"]),
        "ordered_steps": ordered_steps,
        "dependency_edges": edges,
        "completion": completion,
        "terminal_contract": {
            "complete_only_after": completion["required_steps"] if completion else [step["id"] for step in steps],
            "unresolved_on_missing_or_conflicting_input": True,
            "external_effects": [],
        },
    }


def rebind_architecture(pack: Any, parts: Any) -> dict:
    """Accept only an unchanged acyclic Architecture wiring declaration."""
    if type(parts) is not dict or type(parts.get("id")) is not str:
        raise SemanticNodeCompositionError("invalid Architecture parts")
    expected = decompose_architecture(pack, parts["id"])
    if canonical(parts) != canonical(expected):
        raise SemanticNodeCompositionError("Architecture parts drift from the admitted wiring")
    return expected


def _source_rows(pack: dict, ids: set[str]) -> list[dict]:
    return [deepcopy(row) for row in sorted(pack["sources"], key=lambda value: value["id"])
            if row["id"] in ids]


def _semantic_basis(pack: dict, architecture: dict) -> dict:
    works = [step["work_id"] for step in architecture["ordered_steps"]]
    work_parts = [decompose_work(pack, work_id) for work_id in sorted(set(works))]
    judgment_ids = {identifier for work in work_parts for identifier in work["judgment_dependencies"]}
    judgments = [decompose_judgment(pack, identifier) for identifier in sorted(judgment_ids)]
    source_ids = {source for judgment in judgments for source in judgment["source_ids"]}
    source_ids.update(source for work in work_parts for source in work.get("source_ids", []))
    return {
        "schema": SCHEMA,
        "pack_identity": {key: pack[key] for key in ("schema", "id", "root_id")},
        # Bind the typed vocabulary and every documentary source available to
        # this admitted pack. Lists are normalized because storage order is not
        # meaning; any actual definition, unit, provenance, or source change is.
        "domain": sorted(deepcopy(pack["domain"]), key=canonical),
        "entity_kinds": sorted(pack["entity_kinds"]),
        "predicates": sorted(deepcopy(pack["predicates"]), key=canonical),
        "sources": sorted(deepcopy(pack["sources"]), key=canonical),
        "architecture": architecture,
        "work": work_parts,
        "judgments": judgments,
        "judgment_sources": _source_rows(pack, source_ids),
    }


def compose_architecture_program(pack: Any, architecture_id: str) -> dict:
    """Build a program from one Architecture and its dependencies."""
    admitted = _validated(pack)
    architecture = rebind_architecture(admitted, decompose_architecture(admitted, architecture_id))
    semantic_sha256 = digest(_semantic_basis(admitted, architecture))
    body = {
        "schema": SCHEMA,
        "pack_id": admitted["id"],
        "architecture_id": architecture["id"],
        "architecture": architecture,
        "semantic_sha256": semantic_sha256,
        "claim_ceiling": CEILING,
        "external_effects": [],
    }
    program_sha256 = digest(body)
    return {**body, "composition_id": f"composition:{program_sha256}", "program_sha256": program_sha256}


def execute_composed_program(pack: Any, program: Any, request: Any) -> dict:
    """Verify an unchanged composition and execute it through the one runtime."""
    if type(program) is not dict or type(program.get("architecture_id")) is not str:
        raise SemanticNodeCompositionError("invalid composed program")
    admitted = _validated(pack)
    expected = compose_architecture_program(admitted, program["architecture_id"])
    if canonical(program) != canonical(expected):
        raise SemanticNodeCompositionError("program is not the exact admitted composition for this pack")
    try:
        execution = execute_architecture(admitted, expected["architecture_id"], request)
    except SemanticContractError as exc:
        raise SemanticNodeCompositionError(str(exc)) from exc
    return {
        "schema": SCHEMA,
        "composition_id": expected["composition_id"],
        "program_sha256": expected["program_sha256"],
        "semantic_sha256": expected["semantic_sha256"],
        "status": execution["status"],
        "execution": execution,
        "claim_ceiling": CEILING,
        "external_effects": [],
    }
