"""Tests package behavior."""
from copy import deepcopy
import pytest

from judgment_compilation import nist_ac6_composition as subject
from judgment_compilation.nist import build_pack
from judgment_compilation.semantic_contracts import canonical
from judgment_compilation.semantic_node_composition import SemanticNodeCompositionError, execute_composed_program, rebind_architecture, rebind_judgment, rebind_work


@pytest.fixture(scope="module")
def evidence():
    return subject.build_composition_evidence()


@pytest.fixture(scope="module")
def pack():
    return build_pack()["semantic_pack"]


def _step(result):
    return next(row for row in result["execution"]["steps"] if row["step_id"] == "least_privilege_relevance")


def test_ac6_source_and_complete_typed_example_are_exact(evidence):
    assert evidence["source"]["source_id"] == "AC-6 Control"
    assert evidence["source"]["statement_id"] == "ac-6_smt"
    assert evidence["judgment_ids"] == list(subject.JUDGMENT_IDS)
    assert evidence["work_ids"] == list(subject.WORK_IDS)
    assert evidence["selected_ac6_step"]["status"] == "APPLIED"
    assert evidence["selected_ac6_step"]["output"]["predicate"] == "least_privilege_relevance"


def test_judgment_work_architecture_round_trip_is_lossless(evidence):
    assert canonical(evidence["decomposed"]["judgments"]) == canonical(evidence["recomposed"]["judgments"])
    assert canonical(evidence["decomposed"]["work"]) == canonical(evidence["recomposed"]["work"])
    assert canonical(evidence["decomposed"]["architecture"]) == canonical(evidence["recomposed"]["architecture"])
    assert evidence["recomposed"]["composition"]["architecture_id"] == subject.ARCHITECTURE_ID


def test_missing_or_conflicting_typed_relation_stays_unresolved(evidence, pack):
    missing = subject.semantic_request_from_example()
    missing["facts"] = [row for row in missing["facts"] if row["predicate"] != "administrator_account"]
    result = execute_composed_program(pack, evidence["recomposed"]["composition"], missing)
    assert result["status"] == "UNRESOLVED" and _step(result)["status"] == "UNRESOLVED"
    assert _step(result)["output"] is None
    assert {row["reason"] for row in _step(result)["residuals"]} == {"MISSING_FACT"}
    conflicting = subject.semantic_request_from_example()
    conflicting["facts"].append({"id": "administrator-account-false", "predicate": "administrator_account", "arguments": {"account": "account-a"}, "value": False})
    result = execute_composed_program(pack, evidence["recomposed"]["composition"], conflicting)
    assert result["status"] == "UNRESOLVED"
    assert {row["reason"] for row in _step(result)["residuals"]} == {"CONFLICTING_FACTS"}


def test_provenance_edges_and_program_hash_are_falsifiable(evidence, pack):
    judgment = deepcopy(evidence["decomposed"]["judgments"][0]); judgment["source_ids"] = []
    with pytest.raises(SemanticNodeCompositionError): rebind_judgment(pack, judgment)
    work = deepcopy(evidence["decomposed"]["work"][0]); work["producer_interface"] = "invented-producer"
    with pytest.raises(SemanticNodeCompositionError): rebind_work(pack, work)
    architecture = deepcopy(evidence["decomposed"]["architecture"]); architecture["dependency_edges"].append({"from_step": "invented", "to_step": "least_privilege_relevance"})
    with pytest.raises(SemanticNodeCompositionError): rebind_architecture(pack, architecture)
    program = deepcopy(evidence["recomposed"]["composition"]); program["program_sha256"] = "0" * 64
    with pytest.raises(SemanticNodeCompositionError): execute_composed_program(pack, program, subject.semantic_request_from_example())


def test_rebuild_is_deterministic_and_claim_ceiling_stays_narrow(evidence):
    again = subject.build_composition_evidence()
    assert again["evidence_sha256"] == evidence["evidence_sha256"] and again["execution"] == evidence["execution"]
    assert evidence["status"] == "SOURCE_BOUND_NOT_EXECUTED" and evidence["explicit_selection_confirmed"] is False
    assert evidence["external_effects"] == [] and "NO_AUTHORIZATION" in evidence["claim_ceiling"]
    assert "NO_ASSIGNED_TASK_NECESSITY_DETERMINATION" in evidence["claim_ceiling"]
    assert evidence["execution"]["external_effects"] == []

