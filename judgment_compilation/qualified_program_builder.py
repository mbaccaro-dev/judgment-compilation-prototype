"""Builds a program from reviewed check nodes."""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from .qualified_node_builder import QualifiedNodeBuilderError, decompose_qualified_node
from .semantic_contracts import SemanticContractError, canonical, digest, validate_semantic_pack
from .semantic_node_composition import (
    SemanticNodeCompositionError,
    compose_architecture_program,
    execute_composed_program,
)


SCHEMA = "jc/qualified-program-builder/1"
STATUS = "SOURCE_BOUND_NOT_EXECUTED"
CEILING = (
    "SOURCE_REVIEWED_PROGRAM_CANDIDATE_ONLY;NO_PACK_ADMISSION_OR_SELECTION_OR_"
    "COMPLIANCE_OR_RESPONSIBILITY_OR_EXTERNAL_EFFECT"
)
_COLLECTIONS = {
    "judgment": "judgments",
    "work": "work",
    "architecture": "architectures",
}


class QualifiedProgramBuilderError(ValueError):
    """Qualified nodes cannot be replayed as one exact source-reviewed program."""


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise QualifiedProgramBuilderError(message)


def _keys(value: Any, required: set[str]) -> None:
    _need(type(value) is dict and set(value) == required, "unsupported qualified-program shape")


def _validated_context(context: Any) -> dict:
    try:
        return validate_semantic_pack(context)
    except SemanticContractError as exc:
        raise QualifiedProgramBuilderError("full validated semantic-pack context required for qualified-program construction") from exc


def _qualified_parts(candidate: Any) -> tuple[str, dict]:
    try:
        parts = decompose_qualified_node(candidate)
    except QualifiedNodeBuilderError as exc:
        raise QualifiedProgramBuilderError("each program component must be an intact qualified node") from exc
    stack = candidate["stack"]
    _need(stack in _COLLECTIONS, "unknown qualified-node stack")
    return stack, parts


def _build_combined_pack(context: Any, qualified_nodes: Any) -> dict:
    """Replay every reviewed node against its exact before/after pack hashes."""
    pack = _validated_context(context)
    _need(type(qualified_nodes) is list and qualified_nodes, "nonempty qualified-node sequence required")
    present: set[str] = set()

    for candidate in qualified_nodes:
        stack, parts = _qualified_parts(candidate)
        _need(candidate["context_sha256"] == digest(pack),
              "qualified node context differs from the combined program context")
        collection = _COLLECTIONS[stack]
        node = parts["node"]
        _need(node["id"] not in {row["id"] for row in pack[collection]},
              "qualified node duplicates an admitted or prior program node")
        next_pack = deepcopy(pack)
        next_pack[collection].append(deepcopy(node))
        pack = _validated_context(next_pack)
        _need(candidate["candidate_context_sha256"] == digest(pack),
              "qualified node does not produce its reviewed combined context")
        present.add(stack)

    _need(present == set(_COLLECTIONS),
          "qualified program requires reviewed Judgment, Work, and Architecture components")
    return pack


def _architecture_ids(qualified_nodes: list[dict]) -> set[str]:
    return {
        candidate["qualified_parts"]["node"]["id"]
        for candidate in qualified_nodes
        if candidate["stack"] == "architecture"
    }


def _require_candidate_dependency_closure(
    combined: dict, qualified_nodes: list[dict], architecture_id: str,
) -> None:
    """Verify that every new component belongs to the selected program."""
    architecture_ids = _architecture_ids(qualified_nodes)
    _need(architecture_ids == {architecture_id},
          "qualified program requires exactly its selected Architecture component")
    architecture = next(row for row in combined["architectures"] if row["id"] == architecture_id)
    reachable_work = {step["work"] for step in architecture["steps"]}
    qualified_work = {
        candidate["qualified_parts"]["node"]["id"]
        for candidate in qualified_nodes if candidate["stack"] == "work"
    }
    _need(qualified_work <= reachable_work,
          "selected Architecture does not reach every qualified Work component")

    work_index = {row["id"]: row for row in combined["work"]}
    reachable_judgments: set[str] = set()
    for work_id in reachable_work:
        work = work_index[work_id]
        if work["operation"] == "APPLY_JUDGMENT":
            reachable_judgments.add(work["judgment"])
        elif work["operation"] == "RESOLVE_JUDGMENTS":
            reachable_judgments.update(work["judgments"])
        elif work["operation"] == "COMPARE_INTEGER_POWER_OF_TWO_MINUS_ONE":
            reachable_judgments.add(work["judgment"])
        elif work["operation"] == "FINITE_ENUM_TABLE_LOOKUP":
            reachable_judgments.add(work["judgment"])
    qualified_judgments = {
        candidate["qualified_parts"]["node"]["id"]
        for candidate in qualified_nodes if candidate["stack"] == "judgment"
    }
    _need(qualified_judgments <= reachable_judgments,
          "selected Architecture and Work do not reach every qualified Judgment component")


def build_qualified_program(context: Any, qualified_nodes: Any, architecture_id: Any) -> dict:
    """Build a program from verified Judgment, Work, and Architecture nodes."""
    _need(type(architecture_id) is str and architecture_id, "qualified architecture id required")
    combined = _build_combined_pack(context, qualified_nodes)
    _need(architecture_id in _architecture_ids(qualified_nodes),
          "program architecture must itself be a qualified Architecture component")
    _require_candidate_dependency_closure(combined, qualified_nodes, architecture_id)
    try:
        composition = compose_architecture_program(combined, architecture_id)
    except SemanticNodeCompositionError as exc:
        raise QualifiedProgramBuilderError("qualified components cannot compose as the selected architecture") from exc

    initial = _validated_context(context)
    body = {
        "schema": SCHEMA,
        "status": STATUS,
        "initial_context_sha256": digest(initial),
        "qualified_nodes": deepcopy(qualified_nodes),
        "architecture_id": architecture_id,
        "combined_context_sha256": digest(combined),
        "composition": composition,
        "claim_ceiling": CEILING,
        "external_effects": [],
    }
    program_sha256 = digest(body)
    return {
        **body,
        "program_id": f"qualified-program:{program_sha256}",
        "program_sha256": program_sha256,
    }


def decompose_qualified_program(context: Any, program: Any) -> dict:
    """Return the exact qualified inputs after rebuilding and hash-checking it."""
    _keys(program, {
        "schema", "status", "initial_context_sha256", "qualified_nodes", "architecture_id",
        "combined_context_sha256", "composition", "claim_ceiling", "external_effects",
        "program_id", "program_sha256",
    })
    _need(program["schema"] == SCHEMA and program["status"] == STATUS,
          "unsupported qualified program")
    _need(program["claim_ceiling"] == CEILING and program["external_effects"] == [],
          "qualified program standing or effect ceiling is invalid")
    initial = _validated_context(context)
    _need(program["initial_context_sha256"] == digest(initial),
          "program initial context differs from its reviewed context")
    body = {key: deepcopy(value) for key, value in program.items()
            if key not in {"program_id", "program_sha256"}}
    expected_hash = digest(body)
    _need(program["program_sha256"] == expected_hash and program["program_id"] == f"qualified-program:{expected_hash}",
          "qualified program hash mismatch")
    expected = build_qualified_program(initial, program["qualified_nodes"], program["architecture_id"])
    _need(canonical(program) == canonical(expected),
          "qualified program differs from its exact combined composition")
    return {
        "architecture_id": program["architecture_id"],
        "qualified_nodes": deepcopy(program["qualified_nodes"]),
    }


def execute_qualified_program(context: Any, program: Any, request: Any) -> dict:
    """Execute a verified program through the node composer."""
    parts = decompose_qualified_program(context, program)
    combined = _build_combined_pack(context, parts["qualified_nodes"])
    try:
        execution = execute_composed_program(combined, program["composition"], request)
    except SemanticNodeCompositionError as exc:
        raise QualifiedProgramBuilderError("qualified program execution was rejected by the semantic runtime") from exc
    return {
        "schema": SCHEMA,
        "program_id": program["program_id"],
        "program_sha256": program["program_sha256"],
        "status": execution["status"],
        "execution": execution,
        "claim_ceiling": CEILING,
        "external_effects": [],
    }


__all__ = [
    "CEILING", "SCHEMA", "STATUS", "QualifiedProgramBuilderError",
    "build_qualified_program", "decompose_qualified_program", "execute_qualified_program",
]
