from __future__ import annotations

from copy import deepcopy
from hashlib import sha256

import pytest

from judgment_compilation import raw_program_graphs


def _record(stack: str, candidate_id: str, *, explicit_precedence: bool = False) -> dict:
    quote = "Assess the system before review."
    quote_digest = sha256(quote.encode("utf-8")).hexdigest()
    manifest = "a" * 64
    source = {
        "publication_id": "NIST-SP-800-EXAMPLE",
        "source_sha256": "b" * 64,
        "pdf_page_index": 4,
        "page_text_sha256": "c" * 64,
        "manifest_sha256": manifest,
        "character_span": {"start": 20, "end": 20 + len(quote)},
        "exact_quote": quote,
        "exact_quote_sha256": quote_digest,
    }
    raw = {
        "candidate_id": candidate_id,
        "source": source,
        "precedence": {
            "explicit_precedence_signal": explicit_precedence,
            "resolved_winner": None,
            "hierarchy_is_precedence": False,
        },
        "lexical_signals": {"modality": [], "condition": [], "exception": []},
    }
    if stack in {"WORK", "ARCHITECTURE"}:
        raw = {
            "candidate_id": candidate_id,
            "document": {
                "publication_id": source["publication_id"],
                "pdf_sha256": source["source_sha256"],
            },
            "physical_page_index": source["pdf_page_index"],
            "page_text_sha256": source["page_text_sha256"],
            "manifest_sha256": manifest,
            "character_span": [20, 20 + len(quote)],
            "exact_quote": quote,
            "exact_quote_sha256": quote_digest,
            "proposal": (
                {"proposed_operation_kind": "ASSESS"}
                if stack == "WORK"
                else {"proposed_composition_kind": "SEQUENCE"}
            ),
        }
    return {
        "schema": "jc/raw-semantic-compiler/1",
        "record_type": "RAW_SEMANTIC_CANDIDATE",
        "stack": stack,
        "candidate_id": candidate_id,
        "raw_candidate": raw,
        "semantic_admission_status": "NOT_ADMITTED",
        "provenance_validation": {"status": "AVAILABLE_ON_DEMAND_NOT_BULK_ATTESTED"},
        "claim_ceiling": "RAW_ONLY",
    }


def _records(*, explicit_precedence: bool = False) -> list[dict]:
    return [
        _record("JUDGMENT", "raw-judgment:1", explicit_precedence=explicit_precedence),
        _record("WORK", "raw-work:1"),
        _record("ARCHITECTURE", "raw-architecture:1"),
    ]


def _one_graph(records: list[dict] | None = None) -> dict:
    result = raw_program_graphs.build_raw_program_graphs(records or _records())
    assert result["status"] == raw_program_graphs.HELD_STATUS
    assert len(result["graphs"]) == 1
    return result["graphs"][0]


def test_build_is_deterministic_and_ignores_irrelevant_input_order() -> None:
    forward = raw_program_graphs.build_raw_program_graphs(_records())
    reverse = raw_program_graphs.build_raw_program_graphs(list(reversed(_records())))

    assert raw_program_graphs.canonical(forward) == raw_program_graphs.canonical(reverse)
    graph = forward["graphs"][0]
    assert graph["source"]["publication_id"] == "NIST-SP-800-EXAMPLE"
    assert graph["work"]["operations"][0]["inputs"] == []
    assert graph["work"]["operations"][0]["outputs"] == []
    assert graph["work"]["operations"][0]["judgment_dependencies"] == []
    assert graph["architecture"]["edges"] == []
    assert graph["architecture"]["terminal_routes"] == []
    assert "QUALIFICATION" in graph["claim_ceiling"]


def test_rejects_tampered_source_identity_and_invented_edge() -> None:
    graph = _one_graph()
    source_tamper = deepcopy(graph)
    source_tamper["source"]["source_id"] = "raw-source:tampered"
    with pytest.raises(raw_program_graphs.RawProgramGraphError):
        raw_program_graphs.validate_graph(source_tamper)

    edge_tamper = deepcopy(graph)
    edge_tamper["architecture"]["edges"] = [
        {"from": "raw-work:1", "to": "raw-architecture:1"}
    ]
    with pytest.raises(raw_program_graphs.RawProgramGraphError):
        raw_program_graphs.validate_graph(edge_tamper)


def test_lossless_decompose_and_recompose() -> None:
    graph = _one_graph()
    decomposition = raw_program_graphs.decompose_graph(graph)
    recomposed = raw_program_graphs.recompose_graph(decomposition)

    assert raw_program_graphs.canonical(recomposed) == raw_program_graphs.canonical(graph)
    assert raw_program_graphs.validate_graph(graph) == graph


def test_no_precedence_is_inferred_from_a_raw_signal() -> None:
    graph = _one_graph(_records(explicit_precedence=True))
    signals = graph["judgment"]["exception_or_precedence"]

    assert signals == [
        {
            "candidate_id": "raw-judgment:1",
            "source_id": graph["source"]["source_id"],
            "kind": "EXPLICIT_PRECEDENCE_SIGNAL_ONLY",
            "resolved_winner": None,
        }
    ]
    assert graph["judgment"]["bindings"] == []
    assert graph["judgment"]["conclusion"] is None
