"""Builds one batch from reviewed records."""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from .qualified_definition_builder import (
    QualifiedDefinitionBuilderError,
    compose_qualified_definition,
    recompose_qualified_definition,
)
from .qualified_domain_builder import (
    QualifiedDomainBuilderError,
    compose_qualified_domain,
    decompose_qualified_domain,
    recompose_qualified_domain,
)
from .qualified_node_builder import (
    QualifiedNodeBuilderError,
    compose_qualified_node,
    decompose_qualified_node,
)
from .qualified_predicate_builder import (
    QualifiedPredicateBuilderError,
    compose_qualified_predicate,
    recompose_qualified_predicate,
)
from .qualified_program_builder import (
    QualifiedProgramBuilderError,
    build_qualified_program,
)
from .qualified_source_builder import (
    QualifiedSourceBuilderError,
    compose_qualified_source,
    decompose_qualified_source,
    recompose_qualified_source,
)
from .semantic_contracts import SemanticContractError, canonical, digest, validate_semantic_pack
from .semantic_node_composition import (
    SemanticNodeCompositionError,
    decompose_architecture,
    decompose_judgment,
    decompose_work,
)


INPUT_SCHEMA = "jc/reviewed-batch-input/4"
SCHEMA = "jc/reviewed-batch-materializer/4"
STATUS = "SOURCE_BOUND_NOT_EXECUTED"
CEILING = (
    "SOURCE_REVIEWED_BATCH_MATERIALIZATION_ONLY;NO_PACK_ADMISSION_OR_SELECTION_OR_"
    "COMPLIANCE_OR_RESPONSIBILITY_OR_EXTERNAL_EFFECT"
)
_STACKS = ("judgment", "work", "architecture")
_COLLECTIONS = {
    "judgment": "judgments",
    "work": "work",
    "architecture": "architectures",
}


class ReviewedBatchMaterializerError(ValueError):
    """A batch does not replay as one reviewed, connected semantic program."""


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise ReviewedBatchMaterializerError(message)


def _keys(value: Any, required: set[str], message: str) -> None:
    _need(type(value) is dict and set(value) == required, message)


def _context(context: Any) -> dict:
    try:
        return validate_semantic_pack(context)
    except SemanticContractError as exc:
        raise ReviewedBatchMaterializerError("full validated semantic-pack context required") from exc


def _input_entry(entry: Any, stack: str, kind: str) -> dict:
    _keys(
        entry,
        {"stack", "parts", "qualification", "source_index", "review_pins"},
        f"unsupported reviewed {kind} entry",
    )
    _need(entry["stack"] == stack, f"reviewed {kind} order must be Judgment, Work, Architecture")
    return deepcopy(entry)


def _domain_input_entry(entry: Any) -> dict:
    _keys(
        entry,
        {"record_kind", "parts", "qualification", "source_index", "review_pins"},
        "unsupported reviewed Domain entry",
    )
    _need(entry["record_kind"] in {"DEFINITION", "INSTANCE", "TYPED_VALUE"},
          "unknown reviewed Domain record kind")
    return deepcopy(entry)


def _predicate_input_entry(entry: Any) -> dict:
    _keys(entry, {"parts", "qualification", "source_index", "review_pins"},
          "unsupported reviewed predicate entry")
    return deepcopy(entry)


def _input(batch: Any) -> dict:
    required = {"schema", "sources", "predicates", "domain", "definitions", "nodes", "architecture_id"}
    _need(type(batch) is dict and (set(batch) == required or set(batch) == required | {"entity_kind_extensions"}),
          "unsupported reviewed-batch input")
    _need(batch["schema"] == INPUT_SCHEMA, "unsupported reviewed-batch input schema")
    _need(type(batch["sources"]) is list,
           "reviewed documentary source registrations must be a list")
    _need(type(batch.get("entity_kind_extensions", [])) is list,
          "reviewed entity-kind extensions must be a list")
    _need(type(batch["predicates"]) is list,
          "reviewed predicate extensions must be a list")
    _need(type(batch["domain"]) is list and batch["domain"],
          "at least one reviewed Domain candidate required")
    _need(type(batch["definitions"]) is list and len(batch["definitions"]) == len(_STACKS),
          "one reviewed Judgment, Work, and Architecture definition required")
    _need(type(batch["nodes"]) is list and len(batch["nodes"]) >= len(_STACKS),
          "at least one reviewed Judgment, Work, and Architecture node required")
    _need(type(batch["architecture_id"]) is str and bool(batch["architecture_id"]),
          "reviewed Architecture id required")
    return deepcopy(batch)


def recompose_entity_kind_extensions(context: Any, extensions: Any) -> dict:
    """Replay fresh source-neutral caller entity kinds before predicates."""
    predecessor = _context(context)
    _need(type(extensions) is list and all(
        type(kind) is str and bool(kind) and kind.strip() == kind
        for kind in extensions
    ), "invalid reviewed entity-kind extension")
    _need(len(extensions) == len(set(extensions)), "duplicate reviewed entity-kind extension")
    _need(not (set(extensions) & set(predecessor["entity_kinds"])),
          "reviewed entity kind already exists in predecessor context")
    successor = deepcopy(predecessor)
    successor["entity_kinds"].extend(extensions)
    return _context(successor)


def _materialize_entity_kind_extensions(context: dict, extensions: Any) -> tuple[list[str], dict]:
    checked = deepcopy(extensions)
    return checked, recompose_entity_kind_extensions(context, checked)


def _materialize_sources(context: dict, documents: list[dict]) -> tuple[list[dict], dict]:
    current = context
    candidates: list[dict] = []
    for document in documents:
        try:
            candidate = compose_qualified_source(document, context=current)
            current = recompose_qualified_source(current, candidate)
        except QualifiedSourceBuilderError as exc:
            raise ReviewedBatchMaterializerError(
                "retained documentary source registration did not replay"
            ) from exc
        candidates.append(candidate)
    return candidates, current


def _replay_sources(context: dict, candidates: Any) -> tuple[list[dict], dict]:
    _need(type(candidates) is list, "held documentary source registrations must be a list")
    current = context
    replayed: list[dict] = []
    for candidate in candidates:
        try:
            decompose_qualified_source(candidate)
            current = recompose_qualified_source(current, candidate)
        except QualifiedSourceBuilderError as exc:
            raise ReviewedBatchMaterializerError(
                "held documentary source registration cannot recompose"
            ) from exc
        replayed.append(deepcopy(candidate))
    return replayed, current


def _materialize_predicates(context: dict, entries: list[dict]) -> tuple[list[dict], dict]:
    current = context
    candidates: list[dict] = []
    for raw in entries:
        entry = _predicate_input_entry(raw)
        try:
            candidate = compose_qualified_predicate(
                entry["parts"], entry["qualification"], source_index=entry["source_index"],
                review_pins=entry["review_pins"], context=current,
            )
            current = recompose_qualified_predicate(current, candidate)
        except QualifiedPredicateBuilderError as exc:
            raise ReviewedBatchMaterializerError("reviewed predicate extension did not replay") from exc
        candidates.append(candidate)
    return candidates, current


def _replay_predicates(context: dict, candidates: Any) -> tuple[list[dict], dict]:
    _need(type(candidates) is list, "held predicate extensions must be a list")
    current = context
    replayed: list[dict] = []
    for candidate in candidates:
        try:
            current = recompose_qualified_predicate(current, candidate)
        except QualifiedPredicateBuilderError as exc:
            raise ReviewedBatchMaterializerError("held predicate extension cannot recompose") from exc
        replayed.append(deepcopy(candidate))
    return replayed, current


def _materialize_domain(context: dict, entries: list[dict]) -> tuple[list[dict], dict]:
    current = context
    candidates: list[dict] = []
    for raw in entries:
        entry = _domain_input_entry(raw)
        try:
            candidate = compose_qualified_domain(
                entry["record_kind"],
                entry["parts"],
                entry["qualification"],
                source_index=entry["source_index"],
                review_pins=entry["review_pins"],
                context=current,
            )
            current = recompose_qualified_domain(current, candidate)
        except QualifiedDomainBuilderError as exc:
            raise ReviewedBatchMaterializerError("reviewed Domain candidate did not replay") from exc
        candidates.append(candidate)
    return candidates, current


def _replay_domain(context: dict, candidates: Any) -> tuple[list[dict], dict]:
    _need(type(candidates) is list and candidates, "at least one held Domain candidate required")
    current = context
    replayed: list[dict] = []
    for candidate in candidates:
        try:
            current = recompose_qualified_domain(current, candidate)
        except QualifiedDomainBuilderError as exc:
            raise ReviewedBatchMaterializerError("held Domain candidate cannot recompose") from exc
        replayed.append(deepcopy(candidate))
    return replayed, current


def _materialize_definitions(context: dict, entries: list[dict]) -> tuple[list[dict], dict]:
    current = context
    candidates: list[dict] = []
    for stack, entry in zip(_STACKS, entries, strict=True):
        entry = _input_entry(entry, stack, "definition")
        try:
            candidate = compose_qualified_definition(
                stack,
                entry["parts"],
                entry["qualification"],
                source_index=entry["source_index"],
                review_pins=entry["review_pins"],
                context=current,
            )
            current = recompose_qualified_definition(current, candidate)
        except QualifiedDefinitionBuilderError as exc:
            raise ReviewedBatchMaterializerError("reviewed definition did not replay") from exc
        candidates.append(candidate)
    return candidates, current


def _replay_definitions(context: dict, candidates: Any) -> tuple[list[dict], dict]:
    _need(type(candidates) is list and len(candidates) == len(_STACKS),
          "one held definition candidate for each executable stack required")
    current = context
    replayed: list[dict] = []
    for stack, candidate in zip(_STACKS, candidates, strict=True):
        _need(type(candidate) is dict and candidate.get("stack") == stack,
              "definition candidates must retain canonical stack order")
        try:
            current = recompose_qualified_definition(current, candidate)
        except QualifiedDefinitionBuilderError as exc:
            raise ReviewedBatchMaterializerError("held definition candidate cannot recompose") from exc
        replayed.append(deepcopy(candidate))
    return replayed, current


def _append_node(context: dict, candidate: Any) -> dict:
    """Replay the public qualified-node record while preserving its exact hashes."""
    try:
        parts = decompose_qualified_node(candidate)
    except QualifiedNodeBuilderError as exc:
        raise ReviewedBatchMaterializerError("reviewed node candidate is not intact") from exc
    stack = candidate["stack"]
    _need(stack in _COLLECTIONS, "unknown reviewed node stack")
    _need(candidate["context_sha256"] == digest(context), "reviewed node context differs from batch context")
    successor = deepcopy(context)
    collection = _COLLECTIONS[stack]
    node = parts["node"]
    _need(node["id"] not in {row["id"] for row in successor[collection]},
          "reviewed node duplicates a predecessor component")
    successor[collection].append(deepcopy(node))
    successor = _context(successor)
    _need(candidate["candidate_context_sha256"] == digest(successor),
          "reviewed node does not produce its claimed successor context")
    return successor


def _node_groups(entries: Any, *, candidate: bool = False) -> dict[str, list[Any]]:
    """Require canonical Judgment+, Work+, Architecture order."""
    _need(type(entries) is list and len(entries) >= len(_STACKS),
          "reviewed nodes must include Judgment, Work, and Architecture")
    groups: dict[str, list[Any]] = {stack: [] for stack in _STACKS}
    position = 0
    for entry in entries:
        stack = entry.get("stack") if type(entry) is dict else None
        _need(stack in _STACKS, "reviewed node has an unknown stack")
        expected = _STACKS[position]
        if stack != expected:
            _need(position < len(_STACKS) - 1 and stack == _STACKS[position + 1],
                  "qualified nodes must retain Judgment, Work, Architecture group order")
            position += 1
        groups[stack].append(entry)
    _need(groups["judgment"] and groups["work"] and len(groups["architecture"]) == 1,
          "reviewed nodes require Judgment+, Work+, and exactly one Architecture")
    for entry in groups["work"]:
        node = (
            decompose_qualified_node(entry)["node"]
            if candidate else entry.get("parts", {}).get("node")
        )
        _need(type(node) is dict, "reviewed Work node parts required")
    # Native node validation checks each operation; program dependency closure
    # requires every newly reviewed Work and Judgment to be reachable. Independent
    # steps do not require a particular number of Judgment resolvers.
    return groups


def _materialize_nodes(context: dict, entries: list[dict]) -> tuple[list[dict], dict]:
    current = context
    candidates: list[dict] = []
    groups = _node_groups(entries)
    for stack in _STACKS:
        for entry in groups[stack]:
            entry = _input_entry(entry, stack, "node")
            try:
                candidate = compose_qualified_node(
                    stack,
                    entry["parts"],
                    entry["qualification"],
                    source_index=entry["source_index"],
                    review_pins=entry["review_pins"],
                    context=current,
                )
            except QualifiedNodeBuilderError as exc:
                raise ReviewedBatchMaterializerError("reviewed node did not replay") from exc
            current = _append_node(current, candidate)
            candidates.append(candidate)
    return candidates, current


def _replay_nodes(context: dict, candidates: Any) -> tuple[list[dict], dict]:
    current = context
    replayed: list[dict] = []
    groups = _node_groups(candidates, candidate=True)
    for stack in _STACKS:
        for candidate in groups[stack]:
            _need(type(candidate) is dict and candidate.get("stack") == stack,
                  "qualified nodes must retain canonical stack order")
            current = _append_node(current, candidate)
            replayed.append(deepcopy(candidate))
    return replayed, current


def _stack_records(combined: dict, domain_candidates: list[dict], qualified_nodes: list[dict],
                   architecture_id: str) -> dict:
    """Expose exact four-stack connectivity and each result's actual producer."""
    groups = _node_groups(qualified_nodes, candidate=True)
    node_parts = {
        stack: [decompose_qualified_node(candidate)["node"] for candidate in candidates]
        for stack, candidates in groups.items()
    }
    work_nodes = [decompose_work(combined, node["id"]) for node in node_parts["work"]]
    work = next(
        (node for node in work_nodes if node["declared_operation"] == "RESOLVE_JUDGMENTS"),
        work_nodes[0],
    )
    domain = next(
        (row for row in combined["domain"] if row["path"] == work["domain_path"]),
        None,
    )
    _need(domain is not None, "reviewed Work has no exact Domain producer")
    producer = next(
        (
            candidate["candidate_id"]
            for candidate in domain_candidates
            if candidate["record_kind"] == "DEFINITION"
            and decompose_qualified_domain(candidate)["definition"]["path"] == work["domain_path"]
        ),
        None,
    )
    _need(producer is not None, "reviewed Work Domain binding has no qualified Domain producer")
    return {
        "domain": {
            "definition": deepcopy(domain),
            "domain_path": deepcopy(work["domain_path"]),
            "producer": producer,
        },
        "judgment": (
            {"definition": decompose_judgment(combined, node_parts["judgment"][0]["id"]),
             "producer": "semantic_contracts._evaluate"}
            if len(node_parts["judgment"]) == 1 else
            {"definitions": [decompose_judgment(combined, node["id"]) for node in node_parts["judgment"]],
             "producers": ["semantic_contracts._evaluate"] * len(node_parts["judgment"])}
        ),
        "work": (
            {"definition": work, "producer": work["producer_interface"]}
            if len(work_nodes) == 1 else
            {"definitions": work_nodes, "producers": [node["producer_interface"] for node in work_nodes]}
        ),
        "architecture": {
            "definition": decompose_architecture(combined, architecture_id),
            "producer": "semantic_node_composition.compose_architecture_program",
        },
    }


def _assemble(context: dict, sources: Any, entity_kind_extensions: Any, predicates: Any, domain: Any, definitions: Any,
               nodes: Any, architecture_id: Any) -> dict:
    _need(type(architecture_id) is str and bool(architecture_id), "reviewed Architecture id required")
    source_candidates, source_context = _replay_sources(context, sources)
    extensions, entity_kind_context = _materialize_entity_kind_extensions(source_context, entity_kind_extensions)
    predicate_candidates, predicate_context = _replay_predicates(entity_kind_context, predicates)
    domain_candidates, domain_context = _replay_domain(predicate_context, domain)
    definition_candidates, definition_context = _replay_definitions(domain_context, definitions)
    qualified_nodes, combined = _replay_nodes(definition_context, nodes)
    try:
        program = build_qualified_program(definition_context, qualified_nodes, architecture_id)
    except QualifiedProgramBuilderError as exc:
        raise ReviewedBatchMaterializerError("reviewed batch has no connected executable program") from exc
    _need(program["combined_context_sha256"] == digest(combined),
          "program combined context differs from reviewed batch replay")
    body = {
        "schema": SCHEMA,
        "status": STATUS,
        "initial_context_sha256": digest(context),
        "qualified_source_candidates": source_candidates,
        "source_context_sha256": digest(source_context),
        "entity_kind_extensions": extensions,
        "entity_kind_context_sha256": digest(entity_kind_context),
        "qualified_predicate_candidates": predicate_candidates,
        "predicate_context_sha256": digest(predicate_context),
        "qualified_domain_candidates": domain_candidates,
        "domain_context_sha256": digest(domain_context),
        "reviewed_definition_candidates": definition_candidates,
        "definition_context_sha256": digest(definition_context),
        "qualified_nodes": qualified_nodes,
        "architecture_id": architecture_id,
        "combined_context_sha256": digest(combined),
        "stack_records": _stack_records(combined, domain_candidates, qualified_nodes, architecture_id),
        "program": program,
        "claim_ceiling": CEILING,
        "external_effects": [],
    }
    batch_sha256 = digest(body)
    return {
        **body,
        "batch_id": f"reviewed-batch:{batch_sha256}",
        "batch_sha256": batch_sha256,
    }


def materialize_reviewed_batch(context: Any, batch: Any) -> dict:
    """Build one connected program record from verified inputs."""
    predecessor = _context(context)
    reviewed = _input(batch)
    sources, source_context = _materialize_sources(predecessor, reviewed["sources"])
    extensions, entity_kind_context = _materialize_entity_kind_extensions(
        source_context, reviewed.get("entity_kind_extensions", [])
    )
    predicates, predicate_context = _materialize_predicates(entity_kind_context, reviewed["predicates"])
    domain, domain_context = _materialize_domain(predicate_context, reviewed["domain"])
    definitions, definition_context = _materialize_definitions(domain_context, reviewed["definitions"])
    nodes, _ = _materialize_nodes(definition_context, reviewed["nodes"])
    return _assemble(predecessor, sources, extensions, predicates, domain, definitions, nodes, reviewed["architecture_id"])


def decompose_reviewed_batch(context: Any, materialized: Any) -> dict:
    """Verify a batch and return its component records."""
    _keys(
        materialized,
        {
             "schema", "status", "initial_context_sha256", "qualified_source_candidates",
            "source_context_sha256", "entity_kind_extensions", "entity_kind_context_sha256",
            "qualified_predicate_candidates", "predicate_context_sha256",
             "qualified_domain_candidates",
            "domain_context_sha256", "reviewed_definition_candidates",
            "definition_context_sha256", "qualified_nodes", "architecture_id", "combined_context_sha256",
            "stack_records", "program", "claim_ceiling", "external_effects", "batch_id", "batch_sha256",
        },
        "unsupported reviewed-batch materialization",
    )
    _need(materialized["schema"] == SCHEMA and materialized["status"] == STATUS,
          "unsupported reviewed-batch standing")
    _need(materialized["claim_ceiling"] == CEILING and materialized["external_effects"] == [],
          "reviewed-batch ceiling or effects drift")
    predecessor = _context(context)
    _need(materialized["initial_context_sha256"] == digest(predecessor),
          "reviewed-batch predecessor context drifts")
    body = {key: deepcopy(value) for key, value in materialized.items()
            if key not in {"batch_id", "batch_sha256"}}
    expected_hash = digest(body)
    _need(materialized["batch_sha256"] == expected_hash and
          materialized["batch_id"] == f"reviewed-batch:{expected_hash}",
          "reviewed-batch hash mismatch")
    parts = {
        "qualified_source_candidates": deepcopy(materialized["qualified_source_candidates"]),
        "entity_kind_extensions": deepcopy(materialized["entity_kind_extensions"]),
        "qualified_predicate_candidates": deepcopy(materialized["qualified_predicate_candidates"]),
        "qualified_domain_candidates": deepcopy(materialized["qualified_domain_candidates"]),
        "reviewed_definition_candidates": deepcopy(materialized["reviewed_definition_candidates"]),
        "qualified_nodes": deepcopy(materialized["qualified_nodes"]),
        "architecture_id": materialized["architecture_id"],
    }
    expected = recompose_reviewed_batch(predecessor, parts)
    _need(canonical(materialized) == canonical(expected),
          "reviewed-batch components do not losslessly recompose")
    return parts


def recompose_reviewed_batch(context: Any, parts: Any) -> dict:
    """Rebuild a batch from its verified components."""
    _keys(parts, {"qualified_source_candidates", "entity_kind_extensions", "qualified_predicate_candidates", "qualified_domain_candidates", "reviewed_definition_candidates", "qualified_nodes", "architecture_id"},
          "unsupported reviewed-batch parts")
    predecessor = _context(context)
    return _assemble(
        predecessor,
        parts["qualified_source_candidates"],
        parts["entity_kind_extensions"],
        parts["qualified_predicate_candidates"],
        parts["qualified_domain_candidates"],
        parts["reviewed_definition_candidates"],
        parts["qualified_nodes"],
        parts["architecture_id"],
    )


__all__ = [
    "CEILING", "INPUT_SCHEMA", "SCHEMA", "STATUS", "ReviewedBatchMaterializerError",
    "decompose_reviewed_batch", "materialize_reviewed_batch", "recompose_entity_kind_extensions", "recompose_reviewed_batch",
]
