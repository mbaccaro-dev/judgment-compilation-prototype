"""Validates reviewed definitions against the compiled records."""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from .interpretation_qualification import (
    InterpretationQualificationError,
    validate_reviewed_interpretation,
)
from .semantic_contracts import SemanticContractError, canonical, digest, validate_semantic_pack
from .semantic_node_composition import (
    SemanticNodeCompositionError,
    decompose_stack_definition,
    rebind_stack_definition,
)


SCHEMA = "jc/qualified-definition-builder/2"
TARGET_SCHEMA = "jc/qualified-definition-target/2"
STATUS = "SOURCE_BOUND_NOT_EXECUTED"
CEILING = (
    "SOURCE_REVIEWED_TYPED_DEFINITION_CANDIDATE_ONLY;NO_PACK_ADMISSION_OR_SELECTION_OR_"
    "EXECUTION_OR_COMPLIANCE_OR_RESPONSIBILITY_OR_EXTERNAL_EFFECT"
)
_STACKS = {"judgment", "work", "architecture"}


class QualifiedDefinitionBuilderError(ValueError):
    """A definition candidate lacks exact reviewed support or a valid predecessor."""


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise QualifiedDefinitionBuilderError(message)


def _keys(value: Any, required: set[str]) -> None:
    _need(type(value) is dict and set(value) == required, "unsupported qualified-definition shape")


def _text(value: Any) -> bool:
    return type(value) is str and bool(value.strip())


def _target_contract(stack: str, parts: Any, context_sha256: str) -> dict:
    return {
        "schema": TARGET_SCHEMA,
        "stack": stack,
        "parts": deepcopy(parts),
        "predecessor_context_sha256": context_sha256,
    }


def _definition_id(stack: str, definition: dict) -> str:
    """Identify a definition only by its stack and explicit ``(Gs, L)`` coordinate."""
    return f"semantic-definition:{stack}:{digest(definition['coordinate'])}"


def _validated_context(context: Any) -> dict:
    try:
        return validate_semantic_pack(context)
    except SemanticContractError as exc:
        raise QualifiedDefinitionBuilderError(
            "full validated semantic-pack predecessor context required for qualified-definition construction"
        ) from exc


def qualification_target(stack: str, parts: Any, context: Any) -> dict:
    """Return the exact contract an independent definition review must sign."""
    _need(stack in _STACKS, "unknown qualified-definition stack")
    predecessor = _validated_context(context)
    return _target_contract(stack, parts, digest(predecessor))


def _validated_qualification(
    stack: str,
    parts: Any,
    qualification: Any,
    source_index: Any,
    review_pins: Any,
    context_sha256: str,
) -> dict:
    try:
        record = validate_reviewed_interpretation(
            qualification,
            source_index,
            _target_contract(stack, parts, context_sha256),
            review_pins=review_pins,
        )
    except InterpretationQualificationError as exc:
        raise QualifiedDefinitionBuilderError("exact independently reviewed source-reviewed binding required") from exc
    return record


def _validated_parts(parts: Any, qualification: dict, context: dict, stack: str) -> tuple[dict, list[str]]:
    _keys(parts, {"definition", "source_ids"})
    definition, source_ids = parts["definition"], parts["source_ids"]
    _keys(definition, {"coordinate", "label", "aliases"})
    _need(type(source_ids) is list and source_ids and all(_text(value) for value in source_ids),
          "explicit qualified source ids required")
    _need(len(source_ids) == len(set(source_ids)), "duplicate qualified source ids")

    supported = {row["source_id"] for row in qualification["claim"]["source_support"]}
    _need(set(source_ids) == supported, "candidate source ids drift from reviewed source support")
    available = {row["id"]: row for row in context["sources"]}
    _need(set(source_ids) <= set(available), "qualified source is absent from semantic-pack predecessor context")
    for source_id in source_ids:
        qualified = next(row for row in qualification["claim"]["source_support"] if row["source_id"] == source_id)
        _need(available[source_id]["sha256"] == qualified["source_sha256"],
              "semantic-pack source hash drifts from reviewed source support")
    _need(qualification["claim"]["derivation_binding"]["subject_kind"] == "SEMANTIC_DEFINITION",
          "review subject kind does not match semantic definition")
    _need(qualification["claim"]["derivation_binding"]["subject_id"] == _definition_id(stack, definition),
          "review subject id does not match definition coordinate")
    return deepcopy(definition), sorted(source_ids)


def _candidate_context(context: dict, stack: str, definition: dict) -> dict:
    candidate = deepcopy(context)
    rows = candidate["semantic_capital"][stack]
    _need(all(row["coordinate"] != definition["coordinate"] for row in rows),
          "definition coordinate already exists in semantic-pack predecessor context")
    rows.append(deepcopy(definition))
    try:
        return validate_semantic_pack(candidate)
    except SemanticContractError as exc:
        raise QualifiedDefinitionBuilderError(
            "candidate definition is not valid in the supplied semantic-pack predecessor context"
        ) from exc


def compose_qualified_definition(
    stack: str,
    parts: Any,
    qualification: Any,
    *,
    source_index: Any,
    review_pins: Any,
    context: Any,
) -> dict:
    """Build a reviewed definition candidate from typed parts."""
    _need(stack in _STACKS, "unknown qualified-definition stack")
    predecessor = _validated_context(context)
    qualified = _validated_qualification(
        stack, parts, qualification, source_index, review_pins, digest(predecessor)
    )
    definition, source_ids = _validated_parts(parts, qualified, predecessor, stack)
    successor = _candidate_context(predecessor, stack, definition)
    try:
        definition_parts = decompose_stack_definition(successor, stack, definition["coordinate"])
    except SemanticNodeCompositionError as exc:
        raise QualifiedDefinitionBuilderError("candidate definition has no valid structural decomposition") from exc

    body = {
        "schema": SCHEMA,
        "stack": stack,
        "status": STATUS,
        "definition_id": _definition_id(stack, definition),
        "qualified_parts": {"definition": definition, "source_ids": source_ids},
        "definition_parts": definition_parts,
        "qualification_sha256": digest(qualified),
        "predecessor_context_sha256": digest(predecessor),
        "candidate_context_sha256": digest(successor),
        "claim_ceiling": CEILING,
        "external_effects": [],
    }
    candidate_sha256 = digest(body)
    return {
        **body,
        "candidate_id": f"qualified-definition:{candidate_sha256}",
        "candidate_sha256": candidate_sha256,
    }


def decompose_qualified_definition(candidate: Any) -> dict:
    """Return exact reviewed authoring parts after canonical candidate verification."""
    _keys(candidate, {
        "schema", "stack", "status", "definition_id", "qualified_parts", "definition_parts",
        "qualification_sha256", "predecessor_context_sha256", "candidate_context_sha256",
        "claim_ceiling", "external_effects", "candidate_id", "candidate_sha256",
    })
    _need(candidate["schema"] == SCHEMA and candidate["stack"] in _STACKS,
          "unsupported qualified-definition candidate")
    _need(candidate["status"] == STATUS and candidate["claim_ceiling"] == CEILING,
          "candidate standing or ceiling is invalid")
    _need(candidate["external_effects"] == [], "qualified-definition candidates cannot carry effects")
    body = {key: deepcopy(value) for key, value in candidate.items()
            if key not in {"candidate_id", "candidate_sha256"}}
    expected = digest(body)
    _need(candidate["candidate_sha256"] == expected and candidate["candidate_id"] == f"qualified-definition:{expected}",
          "qualified-definition candidate hash mismatch")
    _keys(candidate["qualified_parts"], {"definition", "source_ids"})
    definition = candidate["qualified_parts"]["definition"]
    _keys(definition, {"coordinate", "label", "aliases"})
    _need(candidate["definition_id"] == _definition_id(candidate["stack"], definition),
          "candidate definition identity drifts from coordinate")
    return deepcopy(candidate["qualified_parts"])


def recompose_qualified_definition(context: Any, candidate: Any) -> dict:
    """Rebuild a definition and verify its recorded structure."""
    parts = decompose_qualified_definition(candidate)
    predecessor = _validated_context(context)
    _need(digest(predecessor) == candidate["predecessor_context_sha256"],
          "predecessor semantic-pack context drifts from qualified candidate")
    successor = _candidate_context(predecessor, candidate["stack"], parts["definition"])
    _need(digest(successor) == candidate["candidate_context_sha256"],
          "recomposed semantic-pack context drifts from qualified candidate")
    try:
        expected_parts = rebind_stack_definition(successor, candidate["definition_parts"])
    except SemanticNodeCompositionError as exc:
        raise QualifiedDefinitionBuilderError("candidate structural decomposition is not losslessly rebindable") from exc
    _need(canonical(expected_parts) == canonical(candidate["definition_parts"]),
          "candidate structural decomposition drifts from recomposed definition")
    return successor


__all__ = [
    "CEILING", "SCHEMA", "STATUS", "TARGET_SCHEMA", "QualifiedDefinitionBuilderError",
    "compose_qualified_definition", "decompose_qualified_definition", "qualification_target",
    "recompose_qualified_definition",
]
