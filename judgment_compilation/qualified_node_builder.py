"""Validates reviewed check nodes."""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from .interpretation_qualification import (
    InterpretationQualificationError,
    validate_reviewed_interpretation,
)
from .operation_interfaces import operation_interfaces
from .semantic_contracts import (
    SemanticContractError,
    canonical,
    digest,
    validate_semantic_pack,
)


SCHEMA = "jc/qualified-node-builder/2"
TARGET_SCHEMA = "jc/qualified-node-target/2"
STATUS = "SOURCE_BOUND_NOT_EXECUTED"
CEILING = (
    "SOURCE_REVIEWED_TYPED_NODE_CANDIDATE_ONLY;NO_PACK_ADMISSION_OR_SELECTION_OR_"
    "EXECUTION_OR_COMPLIANCE_OR_RESPONSIBILITY_OR_EXTERNAL_EFFECT"
)
_STACKS = {"judgment": "JUDGMENT", "work": "SEMANTIC_DEFINITION", "architecture": "SEMANTIC_DEFINITION"}


class QualifiedNodeBuilderError(ValueError):
    """A detached candidate lacks reviewed support or a typed contract context."""


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise QualifiedNodeBuilderError(message)


def _keys(value: Any, required: set[str]) -> None:
    _need(type(value) is dict and set(value) == required, "unsupported qualified-node shape")


def _text(value: Any) -> bool:
    return type(value) is str and bool(value.strip())


def _target_contract(stack: str, parts: Any, context_sha256: str) -> dict:
    """The reviewed object includes the exact predecessor semantic context."""
    return {
        "schema": TARGET_SCHEMA,
        "stack": stack,
        "parts": deepcopy(parts),
        "predecessor_context_sha256": context_sha256,
    }


def _validated_context(context: Any) -> dict:
    try:
        return validate_semantic_pack(context)
    except SemanticContractError as exc:
        raise QualifiedNodeBuilderError(
            "full validated semantic-pack context required for qualified-node construction"
        ) from exc


def qualification_target(stack: str, parts: Any, context: Any) -> dict:
    """Return the exact contract an independent node review must sign."""
    _need(stack in _STACKS, "unknown qualified-node stack")
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
        raise QualifiedNodeBuilderError("exact independently reviewed source-reviewed binding required") from exc
    claim = record["claim"]
    binding = claim["derivation_binding"]
    _need(binding["subject_kind"] == _STACKS[stack], "review subject kind does not match node stack")
    return record


def _validated_parts(parts: Any, qualification: dict, context: dict) -> tuple[dict, list[str]]:
    _keys(parts, {"node", "source_ids"})
    node, source_ids = parts["node"], parts["source_ids"]
    _need(type(node) is dict and _text(node.get("id")), "typed node identity required")
    _need(type(source_ids) is list and source_ids and all(_text(value) for value in source_ids),
          "explicit qualified source ids required")
    _need(len(source_ids) == len(set(source_ids)), "duplicate qualified source ids")

    supported = {row["source_id"] for row in qualification["claim"]["source_support"]}
    _need(set(source_ids) == supported, "candidate source ids drift from reviewed source support")
    available = {row["id"]: row for row in context["sources"]}
    _need(set(source_ids) <= set(available), "qualified source is absent from semantic-pack context")
    for source_id in source_ids:
        source = qualification["claim"]["source_support"]
        qualified = next(row for row in source if row["source_id"] == source_id)
        _need(available[source_id]["sha256"] == qualified["source_sha256"],
              "semantic-pack source hash drifts from reviewed source support")
    if "source_ids" in node:
        _need(sorted(node["source_ids"]) == sorted(source_ids),
              "Judgment source ids must equal independently reviewed support")
    _need(qualification["claim"]["derivation_binding"]["subject_id"] == node["id"],
          "review subject id does not match candidate node")
    return deepcopy(node), sorted(source_ids)


def _candidate_pack(context: dict, stack: str, node: dict) -> dict:
    candidate = deepcopy(context)
    collection = {"judgment": "judgments", "work": "work", "architecture": "architectures"}[stack]
    _need(node["id"] not in {row["id"] for row in candidate[collection]},
          "candidate id already exists in semantic-pack context")
    candidate[collection].append(deepcopy(node))
    try:
        validated = validate_semantic_pack(candidate)
        # This is the existing runtime's derived interface check.  It rejects
        # unknown Work operations and proves the actual producer/ports match.
        if stack == "work":
            operation_interfaces(validated)[node["id"]]
        return validated
    except (SemanticContractError, KeyError) as exc:
        raise QualifiedNodeBuilderError("candidate typed parts are not valid in the supplied semantic-pack context") from exc


def compose_qualified_node(
    stack: str,
    parts: Any,
    qualification: Any,
    *,
    source_index: Any,
    review_pins: Any,
    context: Any,
) -> dict:
    """Build a reviewed node candidate from typed parts."""
    _need(stack in _STACKS, "unknown qualified-node stack")
    validated_context = _validated_context(context)
    qualified = _validated_qualification(
        stack, parts, qualification, source_index, review_pins, digest(validated_context)
    )
    node, source_ids = _validated_parts(parts, qualified, validated_context)
    candidate_pack = _candidate_pack(validated_context, stack, node)

    body = {
        "schema": SCHEMA,
        "stack": stack,
        "status": STATUS,
        "qualified_parts": {"node": node, "source_ids": source_ids},
        "qualification_sha256": digest(qualified),
        "context_sha256": digest(validated_context),
        "candidate_context_sha256": digest(candidate_pack),
        "claim_ceiling": CEILING,
        "external_effects": [],
    }
    candidate_sha256 = digest(body)
    return {
        **body,
        "candidate_id": f"qualified-node:{candidate_sha256}",
        "candidate_sha256": candidate_sha256,
    }


def decompose_qualified_node(candidate: Any) -> dict:
    """Return the exact reviewed typed parts after verifying the canonical hash."""
    _keys(candidate, {
        "schema", "stack", "status", "qualified_parts", "qualification_sha256",
        "context_sha256", "candidate_context_sha256", "claim_ceiling", "external_effects",
        "candidate_id", "candidate_sha256",
    })
    _need(candidate["schema"] == SCHEMA and candidate["stack"] in _STACKS,
          "unsupported qualified-node candidate")
    _need(candidate["status"] == STATUS and candidate["claim_ceiling"] == CEILING,
          "candidate standing or ceiling is invalid")
    _need(candidate["external_effects"] == [], "qualified-node candidates cannot carry effects")
    body = {key: deepcopy(value) for key, value in candidate.items()
            if key not in {"candidate_id", "candidate_sha256"}}
    expected = digest(body)
    _need(candidate["candidate_sha256"] == expected and candidate["candidate_id"] == f"qualified-node:{expected}",
          "qualified-node candidate hash mismatch")
    _keys(candidate["qualified_parts"], {"node", "source_ids"})
    return deepcopy(candidate["qualified_parts"])


__all__ = [
    "CEILING", "SCHEMA", "STATUS", "TARGET_SCHEMA", "QualifiedNodeBuilderError",
    "compose_qualified_node", "decompose_qualified_node", "qualification_target",
]
