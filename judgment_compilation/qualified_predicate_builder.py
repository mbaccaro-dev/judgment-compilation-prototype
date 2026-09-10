"""Validates reviewed predicate records."""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from .interpretation_qualification import InterpretationQualificationError, validate_reviewed_interpretation
from .semantic_contracts import (
    SemanticContractError,
    VALUE_TYPES,
    canonical,
    digest,
    validate_semantic_pack,
)


SCHEMA = "jc/qualified-predicate-builder/1"
TARGET_SCHEMA = "jc/qualified-predicate-target/1"
STATUS = "SOURCE_BOUND_NOT_EXECUTED"
CEILING = (
    "SOURCE_REVIEWED_PREDICATE_EXTENSION_ONLY;NO_PACK_ADMISSION_OR_SELECTION_OR_"
    "COMPLIANCE_OR_RESPONSIBILITY_OR_EXTERNAL_EFFECT"
)
_INPUT_KINDS = {"SCENARIO_FACT", "PARAMETER_BINDING", "EVIDENCE"}
_DERIVED_SCOPE = "DERIVED_OUTPUT"


class QualifiedPredicateBuilderError(ValueError):
    """A predicate extension is not an exact reviewed semantic-pack successor."""


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise QualifiedPredicateBuilderError(message)


def _keys(value: Any, required: set[str], optional: set[str] = set()) -> None:
    _need(type(value) is dict and required <= set(value) <= required | optional,
          "unsupported predicate extension fields")


def _context(context: Any) -> dict:
    try:
        return validate_semantic_pack(context)
    except SemanticContractError as exc:
        raise QualifiedPredicateBuilderError("full validated semantic-pack context required") from exc


def _parts(parts: Any, context: dict) -> dict:
    _keys(parts, {"predicate", "fact_kind", "source_ids"})
    predicate = parts["predicate"]
    _need(type(predicate) is dict, "predicate definition required")
    origin = predicate.get("origin")
    _need(origin in {"INPUT", "DERIVED"}, "predicate origin must be INPUT or DERIVED")
    required = {"id", "roles", "origin", "value_type"}
    optional = {"classification", "domain_root", "enum_values"}
    if origin == "INPUT":
        required.add("input_kind")
    _keys(predicate, required, optional)
    _need(type(predicate["id"]) is str and bool(predicate["id"]), "predicate id required")
    _need(type(predicate["roles"]) is dict and bool(predicate["roles"]), "predicate roles required")
    _need(all(type(role) is str and type(kind) is str and kind in context["entity_kinds"]
              for role, kind in predicate["roles"].items()), "predicate roles must bind exact entity kinds")
    _need(predicate["value_type"] in VALUE_TYPES, "unsupported predicate value type")
    is_domain = predicate["value_type"] == "DOMAIN"
    _need(is_domain == ("domain_root" in predicate), "domain root must match predicate value type")
    _need((not is_domain and "classification" not in predicate) or
          (is_domain and predicate.get("classification") == "EXACT"),
          "domain predicates require exact classification semantics")
    if is_domain:
        _need(type(predicate["domain_root"]) is list and
              tuple(predicate["domain_root"]) in {tuple(row["path"]) for row in context["domain"]},
              "predicate domain root is unsupported")
    fact_kind = parts["fact_kind"]
    _keys(fact_kind, {"scope"})
    _need(type(fact_kind["scope"]) is str and bool(fact_kind["scope"]), "fact-kind scope required")
    if origin == "INPUT":
        _need(predicate["input_kind"] in _INPUT_KINDS and
              fact_kind["scope"] == predicate["input_kind"],
              "input fact-kind scope must match its supported input kind")
    else:
        _need(fact_kind["scope"] == _DERIVED_SCOPE,
              "derived fact kinds must declare the derived-output scope")
    source_ids = parts["source_ids"]
    _need(type(source_ids) is list and source_ids and all(type(row) is str for row in source_ids),
          "predicate source ids required")
    _need(len(source_ids) == len(set(source_ids)), "predicate source ids must be unique")
    _need(set(source_ids) <= {row["id"] for row in context["sources"]},
          "predicate source ids absent from context")
    _need(predicate["id"] not in {row["id"] for row in context["predicates"]},
          "predicate identity collision or redefinition")
    return deepcopy(parts)


def qualification_target(parts: Any, context: Any) -> dict:
    """Return the exact target that independent interpretation review must bind."""
    predecessor = _context(context)
    checked = _parts(parts, predecessor)
    return {
        "schema": TARGET_SCHEMA,
        "parts": checked,
        "predecessor_context_sha256": digest(predecessor),
    }


def _source_index(source_index: Any, parts: dict, context: dict) -> dict:
    _need(type(source_index) is dict and set(source_index) == set(parts["source_ids"]),
          "source index must bind exactly the predicate sources")
    sources = {row["id"]: row for row in context["sources"]}
    for source_id, support in source_index.items():
        _need(type(support) is dict and set(support) == {"source_sha256", "quote_sha256", "locator"},
              "unsupported predicate source binding")
        _need(type(support["source_sha256"]) is str and support["source_sha256"] == sources[source_id]["sha256"],
              "predicate source binding does not match context source")
        _need(type(support["quote_sha256"]) is str and type(support["locator"]) is str and bool(support["locator"]),
              "predicate source binding incomplete")
    return deepcopy(source_index)


def _successor(context: dict, parts: dict) -> dict:
    successor = deepcopy(context)
    successor["predicates"].append(deepcopy(parts["predicate"]))
    return _context(successor)


def compose_qualified_predicate(
    parts: Any,
    qualification: Any,
    *,
    source_index: Any,
    review_pins: Any,
    context: Any,
) -> dict:
    """Create one reviewed source-reviewed predicate extension receipt."""
    predecessor = _context(context)
    checked = _parts(parts, predecessor)
    sources = _source_index(source_index, checked, predecessor)
    target = qualification_target(checked, predecessor)
    subject_id = f"predicate:{checked['predicate']['id']}"
    try:
        qualified = validate_reviewed_interpretation(qualification, sources, target, review_pins=review_pins)
    except InterpretationQualificationError as exc:
        raise QualifiedPredicateBuilderError("predicate interpretation qualification did not replay") from exc
    binding = qualified["claim"]["derivation_binding"]
    _need(binding["subject_kind"] == "SEMANTIC_DEFINITION" and binding["subject_id"] == subject_id,
          "predicate qualification binds the wrong subject")
    _need({row["source_id"] for row in qualified["claim"]["source_support"]} == set(checked["source_ids"]),
          "predicate qualification sources differ from declared fact-kind sources")
    successor = _successor(predecessor, checked)
    body = {
        "schema": SCHEMA,
        "status": STATUS,
        "predicate_id": checked["predicate"]["id"],
        "qualified_parts": checked,
        "qualification_sha256": digest(qualified),
        "predecessor_context_sha256": digest(predecessor),
        "candidate_context_sha256": digest(successor),
        "claim_ceiling": CEILING,
        "external_effects": [],
    }
    candidate_sha256 = digest(body)
    return {**body, "candidate_id": f"qualified-predicate:{candidate_sha256}", "candidate_sha256": candidate_sha256}


def decompose_qualified_predicate(candidate: Any) -> dict:
    """Verify a receipt and return its exact fact-kind parts."""
    _keys(candidate, {
        "schema", "status", "predicate_id", "qualified_parts", "qualification_sha256",
        "predecessor_context_sha256", "candidate_context_sha256", "claim_ceiling",
        "external_effects", "candidate_id", "candidate_sha256",
    })
    _need(candidate["schema"] == SCHEMA and candidate["status"] == STATUS,
          "unsupported predicate receipt standing")
    _need(candidate["claim_ceiling"] == CEILING and candidate["external_effects"] == [],
          "predicate receipt ceiling or effects drift")
    _need(type(candidate["qualification_sha256"]) is str and bool(candidate["qualification_sha256"]),
          "predicate qualification digest required")
    _need(type(candidate["predecessor_context_sha256"]) is str and
          type(candidate["candidate_context_sha256"]) is str,
          "predicate context digests required")
    _need(candidate["predicate_id"] == candidate["qualified_parts"].get("predicate", {}).get("id"),
          "predicate receipt identity differs from its parts")
    body = {key: deepcopy(value) for key, value in candidate.items()
            if key not in {"candidate_id", "candidate_sha256"}}
    expected = digest(body)
    _need(candidate["candidate_sha256"] == expected and candidate["candidate_id"] == f"qualified-predicate:{expected}",
          "predicate receipt hash mismatch")
    return deepcopy(candidate["qualified_parts"])


def recompose_qualified_predicate(context: Any, candidate: Any) -> dict:
    """Apply an intact predicate receipt to its exact predecessor pack."""
    predecessor = _context(context)
    parts = decompose_qualified_predicate(candidate)
    _need(candidate["predecessor_context_sha256"] == digest(predecessor),
          "predicate receipt predecessor context differs")
    checked = _parts(parts, predecessor)
    successor = _successor(predecessor, checked)
    _need(candidate["candidate_context_sha256"] == digest(successor),
          "predicate receipt successor context differs")
    return successor


__all__ = [
    "CEILING", "SCHEMA", "STATUS", "TARGET_SCHEMA", "QualifiedPredicateBuilderError",
    "compose_qualified_predicate", "decompose_qualified_predicate", "qualification_target",
    "recompose_qualified_predicate",
]
