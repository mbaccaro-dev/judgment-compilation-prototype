from copy import deepcopy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))
from judgment_compilation.document_programs import ReviewedDocumentPrograms, _PACKAGES
from judgment_compilation.kernel import canonical
from judgment_compilation.application import Application

PACKAGE_ID = "nist-sp-800-108-counter-mode-capacity-guard"
PACKAGE_TITLE = "SP 800-108 Counter Mode strict n/r capacity-boundary guard"


class Programs:
    def __init__(self, packages=None):
        self.packages = packages or [{"id": key, **deepcopy(value)} for key, value in sorted(_PACKAGES.items())]
    def index(self):
        return {"packages": deepcopy(self.packages)}


def app(packages=None):
    candidate = Application.__new__(Application)
    candidate.catalog = type("Catalog", (), {"controls": {"ac-2": {"title": "Account Management", "aliases": []}}})()
    candidate.pack = {"semantic_pack": {"domain": []}, "fact_templates": []}
    candidate.document_programs = Programs(packages)
    candidate.integrity = {}
    candidate.interpretation_admission = {}
    candidate.recommender = None
    candidate._catalog_query = lambda control_id: {
        "answer": "AC-2 source result", "kernel": {"residual": [], "candidates": [
            {"rendered_text": "AC-2 exact source text"}]},
        "egress": {"text": "AC-2 source result", "type": "DETERMINISTIC_DERIVATION",
                   "authority": "TEST_SOURCE_LOOKUP_ONLY", "external_effects": []}, "provenance": []}
    return candidate


@pytest.mark.parametrize("question", [PACKAGE_ID, PACKAGE_TITLE])
def test_exact_id_or_full_title_returns_a_source_bound_selection_only(question):
    candidate = app()
    first = candidate.query({"mode": "inquiry", "question": question})
    assert canonical(first) == canonical(candidate.query({"mode": "inquiry", "question": question}))
    assert first["route"] == "DETERMINISTIC_PLAIN_ENGLISH_INQUIRY"
    assert first["kernel"]["status"] == "SOURCE_REVIEWED_PROGRAM_DISCOVERY"
    selection = first["kernel"]["reviewed_program_selection"]
    assert selection["package_id"] == PACKAGE_ID and selection["title"] == PACKAGE_TITLE and selection["scope"]
    assert selection["status"] == "SOURCE_BOUND_NOT_EXECUTED"
    assert selection["next_typed_input_step"]["operation"] == "inspect"
    assert selection["next_typed_input_step"]["package_id"] == PACKAGE_ID
    assert first["kernel"]["executable_warrant"] is None and first["kernel"]["semantic_bindings"] == []
    assert first["kernel"]["claims"][0]["type"] == "DETERMINISTIC_DERIVATION"
    assert first["kernel"]["claims"][0]["scope"] == "PROGRAM_DISCOVERY_ONLY"
    assert first["egress"]["type"] == "DETERMINISTIC_DERIVATION"
    assert first["egress"]["scope"] == "PROGRAM_DISCOVERY_ONLY"
    assert first["egress"]["external_effects"] == [] and first["inference"]["model_calls"] == 0 and first["provenance"] == []
    assert first["egress"]["authority"] == "REVIEWED_PROGRAM_SELECTION_ONLY;NO_INSPECTION_OR_EXECUTION_OR_APPLICABILITY_DETERMINATION"


def test_selection_never_inspects_executes_or_parses_facts():
    candidate = app()
    candidate.document_programs.inspect = lambda *_: pytest.fail("selection inspected a package")
    candidate.document_programs.execute = lambda *_: pytest.fail("selection executed a package")
    result = candidate.query({"mode": "inquiry", "question": PACKAGE_ID})
    assert result["kernel"]["status"] == "SOURCE_REVIEWED_PROGRAM_DISCOVERY"
    assert result["request"] == {"question": PACKAGE_ID} and "facts" not in result["ingress"]


@pytest.mark.parametrize("question", [PACKAGE_ID + " now", "counter mode capacity guard", "Why did the chicken cross the road?"])
def test_near_match_or_unrelated_input_is_not_selected(question):
    result = app()._plain_inquiry(question)
    assert result["kernel"]["status"] != "SOURCE_REVIEWED_PROGRAM_DISCOVERY"
    assert "reviewed_program_selection" not in result["kernel"]


def test_duplicate_literal_selection_fails_closed():
    packages = Programs().index()["packages"]
    duplicate = deepcopy(packages[0]); duplicate["id"] = "duplicate-id"; duplicate["title"] = packages[0]["title"]
    result = app([*packages, duplicate])._plain_inquiry(packages[0]["title"])
    assert result["kernel"]["status"] == "UNRESOLVED_AMBIGUOUS_REVIEWED_PROGRAM_SELECTION"
    assert result["provenance"] == [] and result["egress"]["external_effects"] == []


def test_exact_control_lookup_is_unchanged():
    result = app().query({"mode": "inquiry", "question": "What does AC-2 say about account management?"})
    assert result["kernel"]["status"] == "RESOLVED_TO_SOURCE_CONTROL"
    assert result["kernel"]["semantic_bindings"] == [{"kind": "NIST_CONTROL", "control_id": "ac-2", "basis": "EXPLICIT_CONTROL_ID"}]
    assert result["inference"]["model_calls"] == 0 and result["egress"]["external_effects"] == []


def test_exact_control_with_unbound_scope_is_partial_and_repeatable():
    question = "Does AC-2 require our moon-base payroll system to publish employee salaries?"
    candidate = app()
    first = candidate.query({"mode": "inquiry", "question": question})
    assert canonical(first) == canonical(candidate.query({"mode": "inquiry", "question": question}))
    assert first["kernel"]["status"] == "PARTIALLY_RESOLVED_SOURCE_CONTROL_WITH_UNBOUND_SCOPE"
    assert first["kernel"]["semantic_bindings"] == [{"kind": "NIST_CONTROL", "control_id": "ac-2", "basis": "EXPLICIT_CONTROL_ID"}]
    assert first["kernel"]["unbound_scope_terms"] == [
        "base", "employee", "moon", "payroll", "publish", "require", "salaries", "system",
    ]
    assert first["egress"]["type"] == "UNRESOLVED"
    assert first["egress"]["result_scope"] == "PARTIAL_SOURCE_CONTEXT_ONLY"
    assert first["egress"]["external_effects"] == [] and first["inference"]["model_calls"] == 0
    assert [claim["type"] for claim in first["kernel"]["claims"]] == ["SOURCE_BOUND", "UNRESOLVED", "DETERMINISTIC_DERIVATION"]
