"""Groups source matches from the same document location."""

from __future__ import annotations

from hashlib import sha256
import json
from typing import Any, Iterable


SCHEMA = "jc/raw-program-graphs/1"
GRAPH_SCHEMA = "jc/raw-program-graph/1"
DECOMPOSITION_SCHEMA = "jc/raw-program-graph-decomposition/1"
COMPILER_SCHEMA = "jc/raw-semantic-compiler/1"
RECORD_TYPE = "RAW_SEMANTIC_CANDIDATE"
STACKS = ("DOMAIN", "JUDGMENT", "WORK", "ARCHITECTURE")
HELD_STATUS = "HELD_RAW_PROPOSAL_ONLY"
CEILING = (
    "RAW_SOURCE_CORRELATION_ONLY;NO_SEMANTIC_ADMISSION_OR_QUALIFICATION_OR_"
    "EXECUTABLE_OPERATION_OR_PROGRAM_OR_APPLICABILITY_OR_COMPLIANCE_OR_"
    "RESPONSIBILITY_OR_EXTERNAL_EFFECT"
)


class RawProgramGraphError(ValueError):
    """A raw proposal graph is malformed, unsupported, or tampered."""


def canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise RawProgramGraphError("invalid canonical graph JSON") from exc


def digest(value: Any) -> str:
    return sha256(canonical(value)).hexdigest()


def _copy(value: Any) -> Any:
    return json.loads(canonical(value))


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise RawProgramGraphError(message)


def _text(value: Any) -> bool:
    return type(value) is str and bool(value)


def _sha256(value: Any) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _source_from_raw(stack: str, raw: dict[str, Any]) -> dict[str, Any]:
    if stack in {"DOMAIN", "WORK", "ARCHITECTURE"}:
        document = raw.get("document")
        _need(type(document) is dict, "raw candidate document identity missing")
        source = {
            "publication_id": document.get("publication_id"),
            "source_pdf_sha256": document.get("pdf_sha256"),
            "physical_pdf_page_index": raw.get("physical_page_index"),
            "page_text_sha256": raw.get("page_text_sha256"),
            "character_span": raw.get("character_span"),
            "exact_quote": raw.get("exact_quote"),
            "exact_quote_sha256": raw.get("exact_quote_sha256"),
            "manifest_sha256": raw.get("manifest_sha256"),
        }
    else:
        raw_source = raw.get("source")
        _need(type(raw_source) is dict, "raw Judgment source identity missing")
        span = raw_source.get("character_span")
        _need(type(span) is dict, "raw Judgment character span missing")
        source = {
            "publication_id": raw_source.get("publication_id"),
            "source_pdf_sha256": raw_source.get("source_sha256"),
            "physical_pdf_page_index": raw_source.get("pdf_page_index"),
            "page_text_sha256": raw_source.get("page_text_sha256"),
            "character_span": [span.get("start"), span.get("end")],
            "exact_quote": raw_source.get("exact_quote"),
            "exact_quote_sha256": raw_source.get("exact_quote_sha256"),
            "manifest_sha256": raw_source.get("manifest_sha256"),
        }
    _validate_source(source)
    return source


def _validate_source(source: dict[str, Any]) -> None:
    _need(
        type(source) is dict
        and set(source)
        == {
            "publication_id",
            "source_pdf_sha256",
            "physical_pdf_page_index",
            "page_text_sha256",
            "character_span",
            "exact_quote",
            "exact_quote_sha256",
            "manifest_sha256",
        },
        "unsupported documentary source shape",
    )
    _need(_text(source["publication_id"]), "source publication identity missing")
    _need(
        all(
            _sha256(source[key])
            for key in (
                "source_pdf_sha256",
                "page_text_sha256",
                "exact_quote_sha256",
                "manifest_sha256",
            )
        ),
        "source hash is malformed",
    )
    span = source["character_span"]
    _need(
        type(span) is list
        and len(span) == 2
        and all(type(item) is int for item in span)
        and 0 <= span[0] < span[1],
        "source span is invalid",
    )
    _need(
        type(source["physical_pdf_page_index"]) is int
        and source["physical_pdf_page_index"] >= 0,
        "source page index is invalid",
    )
    quote = source["exact_quote"]
    _need(
        _text(quote) and span[1] - span[0] == len(quote),
        "source quote does not match its span",
    )
    _need(
        source["exact_quote_sha256"] == sha256(quote.encode("utf-8")).hexdigest(),
        "source quote hash mismatch",
    )


def source_id(source: dict[str, Any]) -> str:
    _validate_source(source)
    return "raw-source:" + digest(source)


def _validate_record(record: Any) -> tuple[str, str, dict[str, Any], dict[str, Any]]:
    _need(
        type(record) is dict
        and set(record)
        == {
            "schema",
            "record_type",
            "stack",
            "candidate_id",
            "raw_candidate",
            "semantic_admission_status",
            "provenance_validation",
            "claim_ceiling",
        },
        "unsupported raw compiler record shape",
    )
    _need(
        record["schema"] == COMPILER_SCHEMA and record["record_type"] == RECORD_TYPE,
        "raw compiler record identity mismatch",
    )
    stack = record["stack"]
    _need(stack in STACKS, "unknown raw candidate stack")
    _need(
        record["semantic_admission_status"] == "NOT_ADMITTED",
        "only non-admitted raw candidates may form proposal graphs",
    )
    candidate_id = record["candidate_id"]
    raw = record["raw_candidate"]
    _need(_text(candidate_id) and type(raw) is dict, "raw candidate identity missing")
    raw_id = raw.get("source_candidate_id") if stack == "DOMAIN" else raw.get("candidate_id")
    _need(raw_id == candidate_id, "raw candidate identifier mismatch")
    source = _source_from_raw(stack, raw)
    return stack, candidate_id, _copy(raw), source


def _normalized_records(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    _need(not isinstance(records, (str, bytes, dict)), "records must be an iterable of records")
    normalized: list[dict[str, Any]] = []
    candidate_ids: set[str] = set()
    for record in records:
        stack, candidate_id, raw, source = _validate_record(record)
        _need(candidate_id not in candidate_ids, "duplicate raw candidate identifier")
        candidate_ids.add(candidate_id)
        normalized.append(
            {
                "stack": stack,
                "candidate_id": candidate_id,
                "source": source,
                "raw_record": _copy(record),
                "raw_candidate": raw,
            }
        )
    _need(normalized, "at least one raw candidate is required")
    return sorted(
        normalized,
        key=lambda row: (source_id(row["source"]), row["stack"], row["candidate_id"]),
    )


def _signal_entries(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for row in rows:
        raw = row["raw_candidate"]
        precedence = raw.get("precedence")
        if type(precedence) is dict and precedence.get("explicit_precedence_signal") is True:
            entries.append(
                {
                    "candidate_id": row["candidate_id"],
                    "source_id": source_id(row["source"]),
                    "kind": "EXPLICIT_PRECEDENCE_SIGNAL_ONLY",
                    "resolved_winner": None,
                }
            )
        signals = raw.get("lexical_signals")
        if (
            type(signals) is dict
            and type(signals.get("exception")) is list
            and signals["exception"]
        ):
            entries.append(
                {
                    "candidate_id": row["candidate_id"],
                    "source_id": source_id(row["source"]),
                    "kind": "EXCEPTION_SIGNAL_ONLY",
                    "matched_terms": sorted(
                        set(signals["exception"]),
                        key=lambda value: (value.casefold(), value),
                    ),
                }
            )
    return sorted(
        entries, key=lambda entry: (entry["source_id"], entry["candidate_id"], entry["kind"])
    )


def _operation(row: dict[str, Any]) -> dict[str, Any]:
    proposal = row["raw_candidate"].get("proposal")
    kind = proposal.get("proposed_operation_kind") if type(proposal) is dict else None
    return {
        "candidate_id": row["candidate_id"],
        "source_id": source_id(row["source"]),
        "source_proposed_operation_kind": kind,
        "inputs": [],
        "outputs": [],
        "judgment_dependencies": [],
        "unknown_conflict_behavior": "UNRESOLVED_NO_SOURCE_SUPPORTED_OPERATION_INTERFACE",
        "execution_status": "UNRESOLVED_NOT_EXECUTABLE",
    }


def _architecture_step(row: dict[str, Any]) -> dict[str, Any]:
    proposal = row["raw_candidate"].get("proposal")
    kind = proposal.get("proposed_composition_kind") if type(proposal) is dict else None
    return {
        "candidate_id": row["candidate_id"],
        "source_id": source_id(row["source"]),
        "source_proposed_composition_kind": kind,
        "execution_status": "UNRESOLVED_NOT_A_PROGRAM_STEP",
    }


def _build_graph(rows: list[dict[str, Any]]) -> dict[str, Any]:
    _need(rows, "graph requires at least one raw candidate")
    source = rows[0]["source"]
    identity = source_id(source)
    _need(
        all(source_id(row["source"]) == identity for row in rows),
        "a proposal graph may not join distinct documentary sources",
    )
    records = [_copy(row["raw_record"]) for row in rows]
    by_stack = {stack: [row for row in rows if row["stack"] == stack] for stack in STACKS}
    candidate_ids = [row["candidate_id"] for row in rows]
    graph_key = {"source_id": identity, "candidate_ids": candidate_ids}
    body = {
        "schema": GRAPH_SCHEMA,
        "status": HELD_STATUS,
        "source": {"source_id": identity, **_copy(source)},
        "candidate_ids": candidate_ids,
        "raw_records": records,
        "domain_context": {
            "candidate_ids": [row["candidate_id"] for row in by_stack["DOMAIN"]],
            "semantic_coordinates": [],
            "status": "UNRESOLVED_NO_ADMITTED_DOMAIN_BINDING",
        },
        "judgment": {
            "candidate_ids": [row["candidate_id"] for row in by_stack["JUDGMENT"]],
            "bindings": [],
            "premises": [],
            "conclusion": None,
            "exception_or_precedence": _signal_entries(by_stack["JUDGMENT"]),
            "unresolved": "NO_SOURCE_SUPPORTED_JUDGMENT_DECOMPOSITION",
        },
        "work": {
            "operations": [_operation(row) for row in by_stack["WORK"]],
            "unresolved": "NO_SOURCE_SUPPORTED_WORK_INPUT_OUTPUT_OR_JUDGMENT_DEPENDENCY",
        },
        "architecture": {
            "ordered_steps": [_architecture_step(row) for row in by_stack["ARCHITECTURE"]],
            "edges": [],
            "unresolved": [row["candidate_id"] for row in by_stack["ARCHITECTURE"]],
            "terminal_routes": [],
            "status": "UNRESOLVED_NOT_AN_EXECUTABLE_PROGRAM",
        },
        "claim_ceiling": CEILING,
        "external_effects": [],
    }
    graph = {"graph_id": "raw-program-graph:" + digest(graph_key), **body}
    graph["graph_sha256"] = digest(graph)
    return graph


def build_raw_program_graphs(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Group source matches into document-local proposal graphs."""

    rows = _normalized_records(records)
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        groups.setdefault(source_id(row["source"]), []).append(row)
    graphs = [_build_graph(groups[key]) for key in sorted(groups)]
    result = {
        "schema": SCHEMA,
        "status": HELD_STATUS,
        "graphs": graphs,
        "claim_ceiling": CEILING,
        "external_effects": [],
    }
    result["graph_set_sha256"] = digest(result)
    return result


def decompose_graph(graph: dict[str, Any]) -> dict[str, Any]:
    validate_graph(graph)
    return {
        "schema": DECOMPOSITION_SCHEMA,
        "source_id": graph["source"]["source_id"],
        "raw_records": _copy(graph["raw_records"]),
    }


def recompose_graph(decomposition: dict[str, Any]) -> dict[str, Any]:
    _need(
        type(decomposition) is dict
        and set(decomposition) == {"schema", "source_id", "raw_records"},
        "unsupported graph decomposition shape",
    )
    _need(
        decomposition["schema"] == DECOMPOSITION_SCHEMA and _text(decomposition["source_id"]),
        "graph decomposition identity mismatch",
    )
    _need(
        type(decomposition["raw_records"]) is list and decomposition["raw_records"],
        "graph decomposition lacks raw records",
    )
    result = build_raw_program_graphs(decomposition["raw_records"])
    _need(len(result["graphs"]) == 1, "decomposition crosses documentary source identities")
    graph = result["graphs"][0]
    _need(
        graph["source"]["source_id"] == decomposition["source_id"],
        "decomposition source identity mismatch",
    )
    return graph


def validate_graph(graph: dict[str, Any]) -> dict[str, Any]:
    _need(
        type(graph) is dict and graph.get("schema") == GRAPH_SCHEMA,
        "unsupported raw program graph",
    )
    source = graph.get("source")
    _need(type(source) is dict and "source_id" in source, "graph source identity missing")
    raw_source = {key: value for key, value in source.items() if key != "source_id"}
    _validate_source(raw_source)
    _need(source["source_id"] == source_id(raw_source), "graph source identity tampered")
    _need(
        graph.get("architecture", {}).get("edges") == [],
        "raw proposal graph may not contain inferred architecture edges",
    )
    _need(
        graph.get("architecture", {}).get("terminal_routes") == [],
        "raw proposal graph may not contain terminal routes",
    )
    _need(
        graph.get("claim_ceiling") == CEILING and graph.get("status") == HELD_STATUS,
        "graph claim ceiling or status changed",
    )
    expected = recompose_graph(
        {
            "schema": DECOMPOSITION_SCHEMA,
            "source_id": source["source_id"],
            "raw_records": graph.get("raw_records"),
        }
    )
    _need(canonical(graph) == canonical(expected), "raw proposal graph does not recompose exactly")
    return _copy(graph)


__all__ = [
    "CEILING",
    "DECOMPOSITION_SCHEMA",
    "GRAPH_SCHEMA",
    "HELD_STATUS",
    "RawProgramGraphError",
    "SCHEMA",
    "build_raw_program_graphs",
    "canonical",
    "decompose_graph",
    "digest",
    "recompose_graph",
    "source_id",
    "validate_graph",
]
