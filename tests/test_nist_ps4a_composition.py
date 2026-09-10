"""Tests package behavior."""
from copy import deepcopy

import pytest

from judgment_compilation import nist_ps4a_composition as subject
from judgment_compilation.nist import build_pack
from judgment_compilation.semantic_contracts import canonical
from judgment_compilation.semantic_node_composition import (
    SemanticNodeCompositionError,
    compose_architecture_program,
    execute_composed_program,
    rebind_architecture,
    rebind_judgment,
    rebind_work,
)


@pytest.fixture(scope="module")
def evidence():
    return subject.build_composition_evidence()


@pytest.fixture(scope="module")
def pack():
    return build_pack()["semantic_pack"]


def test_exact_reviewed_source_and_all_expected_rows(evidence):
    assert evidence["source"]["source_id"] == "PS-4(a)"
    assert evidence["source"]["statement_id"] == "ps-4_smt.a"
    assert evidence["source"]["physical_pdf_page_one_based"] == 251
    assert evidence["source"]["character_span"]["start"] == 2296
    assert evidence["source"]["character_span"]["end"] == 2372
    assert evidence["source"]["character_span"]["interval"] == "HALF_OPEN"
    assert evidence["judgment_ids"] == list(subject.JUDGMENT_IDS)
    assert evidence["work_ids"] == list(subject.WORK_IDS)
    assert evidence["architecture_id"] == subject.ARCHITECTURE_ID
    assert len(evidence["decomposed"]["judgments"]) == 3
    assert len(evidence["decomposed"]["work"]) == 4
    assert evidence["decomposed"]["architecture"]["id"] == subject.ARCHITECTURE_ID


def test_judgment_work_architecture_round_trip_is_lossless(evidence):
    assert canonical(evidence["decomposed"]["judgments"]) == canonical(evidence["recomposed"]["judgments"])
    assert canonical(evidence["decomposed"]["work"]) == canonical(evidence["recomposed"]["work"])
    assert canonical(evidence["decomposed"]["architecture"]) == canonical(evidence["recomposed"]["architecture"])
    assert evidence["recomposed"]["composition"]["architecture_id"] == subject.ARCHITECTURE_ID
    assert evidence["execution"]["status"] == "COMPLETE"
    assert evidence["execution"]["execution"]["outputs"][-1]["predicate"] == "ps4a_within_supplied_period"


def test_rebuild_is_deterministic_and_does_not_mutate_pack(evidence):
    again = subject.build_composition_evidence()
    assert again["evidence_sha256"] == evidence["evidence_sha256"]
    assert again["execution"] == evidence["execution"]


def test_source_provenance_and_typed_edges_are_falsifiable(evidence, pack):
    judgment = deepcopy(evidence["decomposed"]["judgments"][0])
    judgment["source_ids"] = []
    with pytest.raises(SemanticNodeCompositionError):
        rebind_judgment(pack, judgment)

    work = deepcopy(evidence["decomposed"]["work"][1])
    work["producer_interface"] = "invented-producer"
    with pytest.raises(SemanticNodeCompositionError):
        rebind_work(pack, work)

    architecture = deepcopy(evidence["decomposed"]["architecture"])
    architecture["dependency_edges"].append({"from_step": "invented", "to_step": "compare"})
    with pytest.raises(SemanticNodeCompositionError):
        rebind_architecture(pack, architecture)

    program = deepcopy(evidence["recomposed"]["composition"])
    program["architecture"]["ordered_steps"][0]["depends_on"] = ["invented"]
    with pytest.raises(SemanticNodeCompositionError):
        execute_composed_program(pack, program, subject.semantic_request_from_example())


def test_hidden_relevant_unknown_blocks_the_composed_program(evidence, pack):
    request = subject.semantic_request_from_example()
    request["unknowns"] = [{
        "id": "unknown-duration",
        "text": "The access-disable elapsed duration still needs confirmation.",
        "predicate": "elapsed_termination_to_access_disable_seconds",
        "arguments": {
            "organization": "org-a", "system": "system-a",
            "employee": "employee-a", "account": "account-a",
        },
    }]
    result = execute_composed_program(pack, evidence["recomposed"]["composition"], request)
    assert result["status"] == "UNRESOLVED"
    assert all(output["predicate"] == "ps4a_timing_scope" for output in result["execution"]["outputs"])
    assert not any(output["predicate"] in {"ps4a_within_supplied_period", "ps4a_exceeds_supplied_period"}
                   for output in result["execution"]["outputs"])
    assert result["external_effects"] == []


def test_held_ceiling_and_no_admission_or_effects(evidence):
    assert evidence["status"] == "SOURCE_BOUND_NOT_EXECUTED"
    assert evidence["explicit_selection_confirmed"] is False
    assert evidence["external_effects"] == []
    assert "NO_EVENT_EVIDENCE" in evidence["claim_ceiling"]
    assert evidence["execution"]["claim_ceiling"]
    assert evidence["execution"]["external_effects"] == []


