"""Tests package behavior."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re

import pymupdf
import pytest

from judgment_compilation import nist
from judgment_compilation.integrity import verify_inputs
from judgment_compilation.kernel import Rejected, SemanticRuntime, canonical, digest
from judgment_compilation.semantic_contracts import execute_architecture


@pytest.fixture(scope="module")
def pack() -> dict:
    return nist.build_pack()


@pytest.fixture(scope="module")
def runtime(pack: dict) -> SemanticRuntime:
    return nist.trusted_runtime(pack)


def raw(request: dict | None = None) -> str:
    return canonical(nist.example_request() if request is None else request).decode("utf-8")


def test_fresh_identity_and_exact_responsibility_scopes(runtime: SemanticRuntime, pack: dict) -> None:
    request = nist.example_request()
    result = runtime.execute(raw(request))

    assert [entity["id"] for entity in result["scenario"]["entities"]] == ["org-a", "org-b", "person-a", "account-a"]
    assert result["compliance_verdict"] is None
    assert result["responsibility_determination"] is None
    assert result["external_effects"] == []
    assert result["model_authority"] == "NONE"
    assert len(result["interpretation_trace"]) == 4
    assert {source["id"] for source in result["provenance"].values()} == {"AC-2(l)", "AC-6 Control", "PS-4(a)", "PS-4(b)"}

    allowed = {item["text"] for item in pack["unknown_scopes"]}
    assert set(request["unknowns"]) == allowed
    assert all(item["scope"] in {"RESPONSIBILITY", "RESPONSIBILITY_AND_TIMELINESS"} for item in pack["unknown_scopes"])
    assert result["unknown_bindings"]

    blocked = deepcopy(request)
    blocked["unknowns"].append("A different unqualified uncertainty is present.")
    blocked_result = runtime.execute(raw(blocked))
    assert blocked_result["interpretation_trace"] == []
    assert any(claim["type"] == "UNRESOLVED" and claim["text"] == blocked["unknowns"][-1] for claim in blocked_result["claims"])


def test_provenance_is_source_bound_and_independently_matches_pdf_text(runtime: SemanticRuntime) -> None:
    result = runtime.execute(raw())
    item = result["provenance"]["AC-2(l)"]

    assert item["oscal_source_file"]["sha256"] == "a9e23b09116d5e651461d61777c2e7dc1f3454ab3f9e1e8fdf8af01c37dc01be"
    assert item["structural_oscal_locator"].endswith("/group/ac/control/ac-2/part/ac-2_smt/part/ac-2_smt.l")
    assert item["quote_sha256"] == hashlib.sha256(item["quote"].encode("utf-8")).hexdigest()
    source = nist.ROOT / item["source_file"]["path"]
    with pymupdf.open(source) as document:
        page_text = document[item["physical_pdf_page_index_zero_based"]].get_text("text", sort=False)
    span = item["character_span"]
    assert page_text[span["start"] : span["end"]] == item["quote"]
    occurrences = item["all_exact_normalized_occurrences"]
    assert len(occurrences) == item["occurrence_count"] == 1
    occurrence = occurrences[0]
    for field in (
        "source_file",
        "physical_pdf_page_index_zero_based",
        "physical_pdf_page_one_based",
        "character_span",
        "quote",
        "quote_sha256",
        "normalized_quote_sha256",
        "sentence_index_one_based",
        "printed_page_label",
    ):
        assert occurrence[field] == item[field]


@pytest.mark.corpus_integrity
def test_all_frozen_pdf_exact_normalized_occurrences_are_independently_exhaustive(pack: dict) -> None:
    """Re-scan each pinned PDF once; the pack cannot assert its occurrence list."""
    items = list(pack["sources"].items())
    coverage = items[0][1]["occurrence_scope"]["sources"]
    assert all(item["occurrence_scope"]["sources"] == coverage for _, item in items)

    patterns = {}
    independent = {}
    for label, item in items:
        quote = " ".join(item["quote"].split())
        patterns[label] = re.compile(r"\s+".join(re.escape(word) for word in quote.split()))
        independent[label] = []

    for source in coverage:
        with pymupdf.open(nist.ROOT / source["path"]) as document:
            assert source["pages_scanned"] == len(document)
            for index, pdf_page in enumerate(document):
                page_text = pdf_page.get_text("text", sort=False)
                for label, pattern in patterns.items():
                    independent[label].extend(
                        (source["sha256"], index, match.start(), match.end())
                        for match in pattern.finditer(page_text)
                    )

    for label, item in items:
        actual = [
            (occurrence["source_file"]["sha256"], occurrence["physical_pdf_page_index_zero_based"],
             occurrence["character_span"]["start"], occurrence["character_span"]["end"])
            for occurrence in item["all_exact_normalized_occurrences"]
        ]
        assert actual == independent[label]
        assert len(actual) == item["occurrence_count"]


@pytest.mark.parametrize("mutation", ["drop_unknown", "invent_fact", "identity_merge", "ingress_authority"])
def test_ingress_identity_and_unknown_mutations_fail_closed(runtime: SemanticRuntime, mutation: str) -> None:
    value = raw()
    if mutation == "identity_merge":
        request = nist.example_request()
        request["entities"][1]["id"] = "org-a"
        with pytest.raises(Rejected):
            runtime.execute(raw(request))
        return
    proposal = runtime.parse(value)
    if mutation == "drop_unknown":
        proposal["request"]["unknowns"] = []
    elif mutation == "invent_fact":
        proposal["facts"].append({"text": "Business B is responsible."})
    else:
        proposal["authority_ceiling"] = {"external_effects": True}
    with pytest.raises(Rejected):
        runtime.admit_ingress(value, proposal)


@pytest.mark.parametrize("mutation", ["replay", "provenance", "support", "unknown", "effect"])
def test_egress_replay_and_authority_mutations_fail_closed(runtime: SemanticRuntime, mutation: str) -> None:
    value = raw()
    proposal = runtime.egress_proposal(value)
    if mutation == "replay":
        changed = nist.example_request()
        changed["request_id"] += "-other"
        with pytest.raises(Rejected):
            runtime.admit_egress(raw(changed), proposal)
        return
    if mutation == "provenance":
        proposal["provenance"]["AC-2(l)"]["quote"] += " forged"
    elif mutation == "support":
        proposal["support_graph"][0]["from"] = "entity:org-b"
    elif mutation == "unknown":
        proposal["segments"] = [segment for segment in proposal["segments"] if segment["id"] != "unknown:0"]
    else:
        proposal["external_effects"] = ["revoke"]
    with pytest.raises(Rejected):
        runtime.admit_egress(value, proposal)


def test_independent_pack_and_input_pins_reject_tampering(pack: dict) -> None:
    altered = deepcopy(pack)
    altered["sources"]["PS-4(a)"]["quote"] += " altered"
    with pytest.raises(Rejected):
        nist.trusted_runtime(altered)
    with pytest.raises(Rejected):
        SemanticRuntime(altered, digest(altered))

    verified = verify_inputs(nist.ROOT)
    assert verified["status"] == "VERIFIED"
    assert type(verified["file_count"]) is int and verified["file_count"] > 0
    assert re.fullmatch(r"[0-9a-f]{64}", verified["input_index_sha256"])


def test_changed_frozen_source_bytes_reject_before_pack_construction(monkeypatch: pytest.MonkeyPatch) -> None:
    original = Path.read_bytes

    def altered(path: Path) -> bytes:
        value = original(path)
        return value + b"forged" if path.name == "NIST.SP.800-53r5.pdf" else value

    monkeypatch.setattr(Path, "read_bytes", altered)
    with pytest.raises(Rejected):
        nist.build_pack()


def test_cross_employee_account_facts_do_not_create_source_warrants(runtime: SemanticRuntime) -> None:
    request = nist.example_request()
    request["entities"].append({"id": "person-b", "alias": "Employee B", "kind": "person"})
    request["statements"][-1] = "Employee B retains access through Employee A's administrator account."
    result = runtime.execute(raw(request))
    assert result["interpretation_trace"] == []
    assert not any(claim["type"] == "SOURCE_BOUND" for claim in result["claims"])


def test_arbitrary_alias_renaming_preserves_identity_bound_derivation(runtime: SemanticRuntime) -> None:
    changed = nist.example_request()
    replacements = {
        "Business A": "Acme West", "Business B": "Acme East",
        "Employee A": "Robin", "Employee A's administrator account": "Console identity",
    }
    for entity in changed["entities"]:
        entity["alias"] = replacements[entity["alias"]]
    for old, new in sorted(replacements.items(), key=lambda pair: len(pair[0]), reverse=True):
        changed["statements"] = [statement.replace(old, new) for statement in changed["statements"]]
    result = runtime.execute(raw(changed))
    assert result["scenario"] == changed
    assert any("Robin" in claim["text"] and claim["type"] == "DETERMINISTIC_DERIVATION" for claim in result["claims"])
    scenario_bound_claims = [claim["text"] for claim in result["claims"] if claim["type"] != "UNRESOLVED"]
    assert all("Business A" not in text and "Employee A" not in text for text in scenario_bound_claims)


def test_generic_ambiguous_parser_preserves_statement_without_source_warrant(pack: dict) -> None:
    altered = deepcopy(pack)
    altered["fact_templates"].append(deepcopy(altered["fact_templates"][0]))
    generic = SemanticRuntime(altered, digest(altered))
    result = generic.execute(raw())
    unresolved = next(claim for claim in result["claims"] if claim["id"] == "statement:0")
    assert {key: unresolved[key] for key in ("id", "text", "reason")} == {
        "id": "statement:0",
        "text": nist.example_request()["statements"][0],
        "reason": "AMBIGUOUS_STATEMENT",
    }
    assert not any(claim["type"] == "SOURCE_BOUND" for claim in result["claims"])


def test_unrelated_domain_applies_typed_judgment_with_only_declared_support() -> None:
    from judgment_compilation.semantic_contracts import COORDINATE_MODEL, SCHEMA, semantic_coordinate
    def definition(stack, path, label):
        return {"coordinate": semantic_coordinate(stack, path), "label": label, "aliases": []}
    pack = {
        "schema": SCHEMA, "id": "LIBRARY_LOAN_RULE", "root_id": "library",
        "domain": [{"path": [], "label": "Library", "aliases": []}, {"path": [1], "label": "Loans", "aliases": []}],
        "semantic_capital": {
            "coordinate_model": COORDINATE_MODEL,
            "judgment": [definition("judgment", [0], "Loan-status warrant")],
            "work": [definition("work", [0], "Apply judgment")],
            "architecture": [definition("architecture", [0], "Loan assessment")],
        },
        "entity_kinds": ["book"],
        "predicates": [
            {"id": "loan_open", "roles": {"book": "book"}, "origin": "INPUT"},
            {"id": "pending_return", "roles": {"book": "book"}, "origin": "DERIVED"},
        ],
        "sources": [{"id": "library-policy", "sha256": "0" * 64}],
        "judgments": [{
            "id": "pending_return", "semantic_coordinate": semantic_coordinate("judgment", [0]),
            "bindings": {"book": "book"},
            "premises": [{"predicate": "loan_open", "arguments": {"book": "book"}, "value": True}],
            "output": {"predicate": "pending_return", "arguments": {"book": "book"}, "value": True, "semantic_kind": "SCENARIO_DERIVATION"},
            "source_ids": ["library-policy"], "residual": "A loan fact is required.",
        }],
        "work": [{"id": "apply:pending_return", "semantic_coordinate": semantic_coordinate("work", [0]),
                  "operation": "APPLY_JUDGMENT", "judgment": "pending_return", "domain_path": [1]}],
        "architectures": [{"id": "loan-assessment", "semantic_coordinate": semantic_coordinate("architecture", [0]),
                           "steps": [{"id": "apply", "work": "apply:pending_return", "depends_on": []}]}],
    }
    result = execute_architecture(pack, "loan-assessment", {
        "entities": {"book-1": "book"},
        "facts": [{"id": "statement:0", "predicate": "loan_open", "arguments": {"book": "book-1"}, "value": True}],
        "bindings": {"apply": {"book": ["book-1"]}}, "unknowns": [],
    })
    output = result["outputs"][0]
    assert result["status"] == "COMPLETE" and output["support"] == ["statement:0"]
    assert result["support_graph"] == [{"from": "statement:0", "to": output["id"], "relation": "SUPPORTS"}]


def test_malformed_json_and_cancelled_execution_release_no_partial_result(runtime: SemanticRuntime) -> None:
    for malformed in ('{"request_id":"x","request_id":"y"}', '{"x":NaN}', '[]', '{'):
        with pytest.raises(Rejected):
            runtime.execute(malformed)
    value = raw()
    proposal = runtime.egress_proposal(value)
    with pytest.raises(Rejected):
        runtime.execute(value, cancelled=True)
    with pytest.raises(Rejected):
        runtime.admit_egress(value, proposal, cancelled=True)


def test_fresh_adapter_and_kernel_do_not_import_legacy_semantic_population() -> None:
    for path in (nist.ROOT / "nist.py", nist.ROOT / "kernel.py"):
        source = path.read_text(encoding="utf-8")
        assert "data/semantic" not in source
        assert "population_records" not in source
