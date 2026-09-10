"""Validates reviewed domain records."""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from judgment_compilation.interpretation_qualification import (
    InterpretationQualificationError,
    validate_reviewed_interpretation,
)
from judgment_compilation.semantic_contracts import (
    SemanticContractError,
    canonical,
    coordinate,
    digest,
    identity,
    validate_semantic_pack,
)


SCHEMA = "jc/qualified-domain-builder/1"
TARGET_SCHEMA = "jc/qualified-domain-target/1"
STATUS = "SOURCE_BOUND_NOT_EXECUTED"
CEILING = (
    "SOURCE_REVIEWED_TYPED_DOMAIN_CANDIDATE_ONLY;NO_PACK_ADMISSION_OR_SELECTION_OR_"
    "EXECUTION_OR_COMPLIANCE_OR_RESPONSIBILITY_OR_EXTERNAL_EFFECT"
)
_KINDS = {"DEFINITION", "INSTANCE", "TYPED_VALUE"}
_SUBJECT_KINDS = {
    "DEFINITION": "DOMAIN_DEFINITION",
    "INSTANCE": "DOMAIN_INSTANCE",
    "TYPED_VALUE": "DOMAIN_TYPED_VALUE",
}


class QualifiedDomainBuilderError(ValueError):
    """A Domain candidate lacks an exact review or an express contract form."""


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise QualifiedDomainBuilderError(message)


def _keys(value: Any, required: set[str]) -> None:
    _need(type(value) is dict and set(value) == required, "unsupported qualified-domain shape")


def _text(value: Any) -> bool:
    return type(value) is str and bool(value.strip())


def _validated_context(context: Any) -> dict:
    try:
        return validate_semantic_pack(context)
    except SemanticContractError as exc:
        raise QualifiedDomainBuilderError(
            "full validated semantic-pack predecessor context required for qualified-Domain construction"
        ) from exc


def _path(value: Any) -> list[int]:
    _need(type(value) is list and len(value) <= 64 and
          all(type(part) is int and 1 <= part <= 2147483647 for part in value),
          "invalid canonical Domain path")
    return deepcopy(value)


def _occurrence(value: Any) -> int:
    _need(type(value) is int and 0 <= value <= 2147483647, "invalid Domain occurrence")
    return value


def _source_ids(parts: dict, qualification: dict, context: dict) -> list[str]:
    source_ids = parts["source_ids"]
    _need(type(source_ids) is list and source_ids and all(_text(value) for value in source_ids),
          "explicit qualified source ids required")
    _need(len(source_ids) == len(set(source_ids)), "duplicate qualified source ids")
    supported = {row["source_id"] for row in qualification["claim"]["source_support"]}
    _need(set(source_ids) == supported, "candidate source ids drift from reviewed source support")
    available = {row["id"]: row for row in context["sources"]}
    _need(set(source_ids) <= set(available), "qualified source is absent from semantic-pack predecessor context")
    for source_id in source_ids:
        reviewed = next(row for row in qualification["claim"]["source_support"] if row["source_id"] == source_id)
        _need(available[source_id]["sha256"] == reviewed["source_sha256"],
              "semantic-pack source hash drifts from reviewed source support")
    return sorted(source_ids)


def _subject_id(kind: str, parts: dict, context: dict) -> str:
    return "domain:" + kind.lower() + ":" + digest({
        "root_id": context["root_id"], "parts": parts,
    })


def _target_contract(kind: str, parts: Any, context_sha256: str) -> dict:
    return {
        "schema": TARGET_SCHEMA,
        "record_kind": kind,
        "parts": deepcopy(parts),
        "predecessor_context_sha256": context_sha256,
    }


def qualification_target(kind: str, parts: Any, context: Any) -> dict:
    _need(kind in _KINDS, "unknown qualified-Domain record kind")
    predecessor = _validated_context(context)
    return _target_contract(kind, parts, digest(predecessor))


def _validated_qualification(kind: str, parts: Any, qualification: Any, source_index: Any,
                             review_pins: Any, context: dict) -> dict:
    try:
        qualified = validate_reviewed_interpretation(
            qualification, source_index, _target_contract(kind, parts, digest(context)), review_pins=review_pins,
        )
    except InterpretationQualificationError as exc:
        raise QualifiedDomainBuilderError("exact independently reviewed source-reviewed binding required") from exc
    binding = qualified["claim"]["derivation_binding"]
    _need(binding["subject_kind"] == _SUBJECT_KINDS[kind],
          "review subject kind does not match the Domain record kind")
    _need(binding["subject_id"] == _subject_id(kind, parts, context),
          "review subject id does not bind the exact Domain record")
    return qualified


def _node_by_path(context: dict, path: list[int]) -> dict | None:
    return next((node for node in context["domain"] if node["path"] == path), None)


def _neighborhood(context: dict, path: list[int], occurrence: int) -> dict:
    parent_path = path[:-1] if path else None
    return {
        "coordinate": coordinate(path, occurrence),
        "parent_path": parent_path,
        "parent_coordinate": coordinate(parent_path, occurrence) if parent_path is not None else None,
        "relation": "DOMAIN_POSITION_PARENT",
        "implies_specialization": False,
        "implies_precedence": False,
        "implies_execution": False,
        "implies_storage_meaning": False,
    }


def _definition_parts(parts: Any, qualification: dict, context: dict) -> tuple[dict, list[str], int]:
    _keys(parts, {"definition", "occurrence", "source_ids"})
    definition = parts["definition"]
    _need(type(definition) is dict and set(definition) in (
        {"path", "label", "aliases"},
        {"path", "label", "aliases", "entity_kind"},
        {"path", "label", "aliases", "specializes"},
        {"path", "label", "aliases", "unit"},
        {"path", "label", "aliases", "entity_kind", "specializes"},
        {"path", "label", "aliases", "entity_kind", "unit"},
        {"path", "label", "aliases", "specializes", "unit"},
        {"path", "label", "aliases", "entity_kind", "specializes", "unit"},
    ), "unsupported Domain definition record")
    path = _path(definition.get("path"))
    _need(path and _node_by_path(context, path) is None and _node_by_path(context, path[:-1]) is not None,
          "Domain definition must add one non-root position below its existing structural parent")
    _need(type(definition["label"]) is str and definition["label"].strip() == definition["label"] and definition["label"],
          "invalid Domain definition label")
    _need(type(definition["aliases"]) is list and all(type(value) is str and value.strip() == value and value for value in definition["aliases"]),
          "invalid Domain definition aliases")
    _need(len(definition["aliases"]) == len(set(definition["aliases"])), "duplicate Domain definition aliases")
    source_ids = _source_ids(parts, qualification, context)
    occurrence = _occurrence(parts["occurrence"])
    _need(occurrence == 0, "reusable Domain definitions require the canonical zero occurrence")
    candidate = deepcopy(context)
    candidate["domain"].append(deepcopy(definition))
    try:
        validate_semantic_pack(candidate)
    except SemanticContractError as exc:
        raise QualifiedDomainBuilderError("candidate Domain definition is not valid in the supplied predecessor context") from exc
    return deepcopy(definition), source_ids, occurrence


def _instance_parts(parts: Any, qualification: dict, context: dict) -> tuple[dict, list[str]]:
    _keys(parts, {"instance", "source_ids"})
    instance = parts["instance"]
    _keys(instance, {"path", "occurrence"})
    path, occurrence = _path(instance["path"]), _occurrence(instance["occurrence"])
    _need(_node_by_path(context, path) is not None, "Domain instance references no existing Domain definition")
    return {"path": path, "occurrence": occurrence}, _source_ids(parts, qualification, context)


def _is_specialization(context: dict, actual: list[int], expected: list[int]) -> bool:
    nodes = {tuple(node["path"]): node for node in context["domain"]}
    todo, visited = [tuple(actual)], set()
    while todo:
        path = todo.pop()
        if path == tuple(expected):
            return True
        if path not in visited:
            visited.add(path)
            todo.extend(tuple(edge["path"]) for edge in nodes[path].get("specializes", []))
    return False


def _typed_value_parts(parts: Any, qualification: dict, context: dict) -> tuple[dict, list[str]]:
    _keys(parts, {"typed_value", "source_ids"})
    typed = parts["typed_value"]
    _keys(typed, {"predicate_id", "value"})
    predicate = next((row for row in context["predicates"] if row["id"] == typed["predicate_id"]), None)
    _need(predicate is not None, "typed value references no declared predicate")
    value_type = predicate.get("value_type", "BOOLEAN")
    value = typed["value"]
    if value_type == "BOOLEAN":
        _need(type(value) is bool, "invalid Boolean typed value")
    elif value_type == "INTEGER":
        _need(type(value) is int and not isinstance(value, bool) and 0 <= value <= 2147483647,
              "invalid INTEGER typed value")
    elif value_type == "UNSIGNED_64_INTEGER":
        _need(type(value) is int and 0 <= value <= 18446744073709551615,
              "invalid UNSIGNED_64_INTEGER typed value")
    elif value_type == "DOMAIN":
        path = _path(value)
        _need(_node_by_path(context, path) is not None and _is_specialization(context, path, predicate["domain_root"]),
              "Domain typed value is outside the predicate's explicit classification root")
    elif value_type == "QUANTITY":
        _keys(value, {"amount", "unit_path"})
        _need(type(value["amount"]) is int and not isinstance(value["amount"], bool) and 0 <= value["amount"] <= 2147483647,
              "invalid QUANTITY amount")
        unit_path = _path(value["unit_path"])
        _need((_node_by_path(context, unit_path) or {}).get("unit") is not None,
              "QUANTITY typed value references no declared unit")
    else:
        _need(False, "unsupported typed-value record")
    return deepcopy(typed), _source_ids(parts, qualification, context)


def _validated_parts(kind: str, parts: Any, qualification: dict, context: dict) -> tuple[dict, list[str], dict, dict]:
    if kind == "DEFINITION":
        definition, source_ids, occurrence = _definition_parts(parts, qualification, context)
        candidate = deepcopy(context)
        candidate["domain"].append(deepcopy(definition))
        successor = _validated_context(candidate)
        semantic = {
            "identity": identity(context["root_id"], definition["path"], occurrence),
            "structural_neighborhood": _neighborhood(successor, definition["path"], occurrence),
        }
        return {"definition": definition, "occurrence": occurrence, "source_ids": source_ids}, source_ids, successor, semantic
    if kind == "INSTANCE":
        instance, source_ids = _instance_parts(parts, qualification, context)
        semantic = {
            "identity": identity(context["root_id"], instance["path"], instance["occurrence"]),
            "instance_coordinate": coordinate(instance["path"], instance["occurrence"]),
            "definition_coordinate": coordinate(instance["path"], 0),
            "relation": "TYPED_INSTANCE_OF_DOMAIN_DEFINITION",
            "implies_specialization": False,
            "implies_precedence": False,
            "implies_execution": False,
            "implies_storage_meaning": False,
        }
        return {"instance": instance, "source_ids": source_ids}, source_ids, context, semantic
    typed, source_ids = _typed_value_parts(parts, qualification, context)
    return {"typed_value": typed, "source_ids": source_ids}, source_ids, context, {
        "predicate_id": typed["predicate_id"], "value_type": next(row for row in context["predicates"] if row["id"] == typed["predicate_id"]).get("value_type", "BOOLEAN"),
    }


def compose_qualified_domain(kind: str, parts: Any, qualification: Any, *, source_index: Any,
                             review_pins: Any, context: Any) -> dict:
    """Return one source-reviewed Domain candidate without selecting a pack."""
    _need(kind in _KINDS, "unknown qualified-Domain record kind")
    predecessor = _validated_context(context)
    qualified = _validated_qualification(kind, parts, qualification, source_index, review_pins, predecessor)
    qualified_parts, _sources, successor, semantic = _validated_parts(kind, parts, qualified, predecessor)
    body = {
        "schema": SCHEMA,
        "record_kind": kind,
        "status": STATUS,
        "qualified_parts": qualified_parts,
        "semantic_record": semantic,
        "qualification_sha256": digest(qualified),
        "predecessor_context_sha256": digest(predecessor),
        "candidate_context_sha256": digest(successor),
        "claim_ceiling": CEILING,
        "external_effects": [],
    }
    candidate_sha256 = digest(body)
    return {**body, "candidate_id": f"qualified-domain:{candidate_sha256}", "candidate_sha256": candidate_sha256}


def decompose_qualified_domain(candidate: Any) -> dict:
    _keys(candidate, {
        "schema", "record_kind", "status", "qualified_parts", "semantic_record", "qualification_sha256",
        "predecessor_context_sha256", "candidate_context_sha256", "claim_ceiling", "external_effects",
        "candidate_id", "candidate_sha256",
    })
    _need(candidate["schema"] == SCHEMA and candidate["record_kind"] in _KINDS,
          "unsupported qualified-Domain candidate")
    _need(candidate["status"] == STATUS and candidate["claim_ceiling"] == CEILING and candidate["external_effects"] == [],
          "qualified-Domain candidate standing, ceiling, or effects are invalid")
    body = {key: deepcopy(value) for key, value in candidate.items() if key not in {"candidate_id", "candidate_sha256"}}
    expected = digest(body)
    _need(candidate["candidate_sha256"] == expected and candidate["candidate_id"] == f"qualified-domain:{expected}",
          "qualified-Domain candidate hash mismatch")
    return deepcopy(candidate["qualified_parts"])


def recompose_qualified_domain(context: Any, candidate: Any) -> dict:
    """Rebuild a domain definition against its recorded predecessor."""
    parts = decompose_qualified_domain(candidate)
    predecessor = _validated_context(context)
    _need(digest(predecessor) == candidate["predecessor_context_sha256"],
          "predecessor semantic-pack context drifts from qualified Domain candidate")
    if candidate["record_kind"] != "DEFINITION":
        _need(candidate["candidate_context_sha256"] == digest(predecessor),
              "non-definition Domain candidate cannot change its predecessor context")
        return predecessor
    rebuilt = deepcopy(predecessor)
    rebuilt["domain"].append(deepcopy(parts["definition"]))
    successor = _validated_context(rebuilt)
    _need(digest(successor) == candidate["candidate_context_sha256"],
          "recomposed Domain context drifts from qualified candidate")
    return successor


__all__ = [
    "CEILING", "SCHEMA", "STATUS", "TARGET_SCHEMA", "QualifiedDomainBuilderError",
    "compose_qualified_domain", "decompose_qualified_domain", "qualification_target", "recompose_qualified_domain",
]
