"""Registers a verified document in the source index."""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from .documentary_projection import (
    MANIFEST_SHA256,
    DocumentaryProjection,
    DocumentaryProjectionError,
)
from .semantic_contracts import SemanticContractError, canonical, digest, validate_semantic_pack


SCHEMA = "jc/qualified-source-builder/1"
STATUS = "SOURCE_BOUND_NOT_EXECUTED"
CEILING = (
    "SOURCE_BOUND_DOCUMENTARY_SOURCE_REGISTRATION_ONLY;NO_SEMANTIC_INTERPRETATION_OR_"
    "PACK_ADMISSION_OR_SELECTION_OR_COMPLIANCE_OR_RESPONSIBILITY_OR_EXTERNAL_EFFECT"
)


class QualifiedSourceBuilderError(ValueError):
    """A retained-document source registration is invalid or cannot replay."""


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise QualifiedSourceBuilderError(message)


def _keys(value: Any, required: set[str]) -> None:
    _need(type(value) is dict and set(value) == required,
          "unsupported qualified-source candidate shape")


def _context(context: Any) -> dict:
    try:
        return validate_semantic_pack(context)
    except SemanticContractError as exc:
        raise QualifiedSourceBuilderError(
            "full validated semantic-pack predecessor context required"
        ) from exc


def _projection(projection: DocumentaryProjection | None) -> DocumentaryProjection:
    try:
        resolved = DocumentaryProjection() if projection is None else projection
    except DocumentaryProjectionError as exc:
        raise QualifiedSourceBuilderError("retained documentary library is unavailable") from exc
    _need(type(resolved) is DocumentaryProjection,
          "exact DocumentaryProjection implementation required")
    _need(resolved.manifest_sha256 == MANIFEST_SHA256,
          "documentary manifest is not the package-pinned retained library")
    return resolved


def _exact_document(documentary_record: Any,
                    projection: DocumentaryProjection | None) -> tuple[dict, dict]:
    _need(type(documentary_record) is dict,
          "retained documentary source record required")
    publication_id = documentary_record.get("publication_id")
    _need(type(publication_id) is str and bool(publication_id.strip()),
          "documentary publication identity required")
    library = _projection(projection)
    try:
        current = next(library.iter_documents(publication_id=publication_id))
    except (DocumentaryProjectionError, StopIteration) as exc:
        raise QualifiedSourceBuilderError(
            "documentary source is absent from the exact retained library"
        ) from exc
    _need(canonical(current) == canonical(documentary_record),
          "documentary source record drifts from current retained bytes")
    source_file = current["source_file"]
    source = {"id": publication_id, "sha256": source_file["sha256"]}
    return deepcopy(current), source


def _candidate_context(context: dict, source: dict) -> dict:
    successor = deepcopy(context)
    _need(source["id"] not in {row["id"] for row in successor["sources"]},
          "documentary source identity already exists in predecessor context")
    successor["sources"].append(deepcopy(source))
    try:
        return validate_semantic_pack(successor)
    except SemanticContractError as exc:
        raise QualifiedSourceBuilderError(
            "documentary source registration is invalid in predecessor context"
        ) from exc


def compose_qualified_source(documentary_record: Any, *, context: Any,
                             projection: DocumentaryProjection | None = None) -> dict:
    """Return one exact, effect-free, unselected documentary registration."""
    predecessor = _context(context)
    document, source = _exact_document(documentary_record, projection)
    successor = _candidate_context(predecessor, source)
    body = {
        "schema": SCHEMA,
        "status": STATUS,
        "source_registration": source,
        "documentary_record": document,
        "documentary_record_sha256": digest(document),
        "predecessor_context_sha256": digest(predecessor),
        "candidate_context_sha256": digest(successor),
        "claim_ceiling": CEILING,
        "external_effects": [],
    }
    candidate_sha256 = digest(body)
    return {
        **body,
        "candidate_id": f"qualified-source:{candidate_sha256}",
        "candidate_sha256": candidate_sha256,
    }


def decompose_qualified_source(candidate: Any) -> dict:
    """Return the exact retained document after candidate integrity checks."""
    _keys(candidate, {
        "schema", "status", "source_registration", "documentary_record",
        "documentary_record_sha256", "predecessor_context_sha256",
        "candidate_context_sha256", "claim_ceiling", "external_effects",
        "candidate_id", "candidate_sha256",
    })
    _need(candidate["schema"] == SCHEMA and candidate["status"] == STATUS,
          "unsupported qualified-source candidate")
    _need(candidate["claim_ceiling"] == CEILING and candidate["external_effects"] == [],
          "qualified-source standing, ceiling, or effects drift")
    body = {key: deepcopy(value) for key, value in candidate.items()
            if key not in {"candidate_id", "candidate_sha256"}}
    expected = digest(body)
    _need(candidate["candidate_sha256"] == expected and
          candidate["candidate_id"] == f"qualified-source:{expected}",
          "qualified-source candidate hash mismatch")
    _need(candidate["documentary_record_sha256"] == digest(candidate["documentary_record"]),
          "documentary record hash mismatch")
    _need(candidate["source_registration"] == {
        "id": candidate["documentary_record"]["publication_id"],
        "sha256": candidate["documentary_record"]["source_file"]["sha256"],
    }, "source registration drifts from documentary record")
    return deepcopy(candidate["documentary_record"])


def recompose_qualified_source(context: Any, candidate: Any, *,
                               projection: DocumentaryProjection | None = None) -> dict:
    """Rebuild a source registration and verify the current source bytes."""
    document = decompose_qualified_source(candidate)
    predecessor = _context(context)
    _need(digest(predecessor) == candidate["predecessor_context_sha256"],
          "predecessor semantic-pack context drifts from source candidate")
    current, source = _exact_document(document, projection)
    _need(canonical(current) == canonical(document) and
          source == candidate["source_registration"],
          "retained documentary registration no longer replays")
    successor = _candidate_context(predecessor, source)
    _need(digest(successor) == candidate["candidate_context_sha256"],
          "recomposed source context drifts from candidate")
    return successor


__all__ = [
    "CEILING", "SCHEMA", "STATUS", "QualifiedSourceBuilderError",
    "compose_qualified_source", "decompose_qualified_source",
    "recompose_qualified_source",
]
