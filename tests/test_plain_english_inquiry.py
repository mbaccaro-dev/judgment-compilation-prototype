from __future__ import annotations

import json
import subprocess
import sys

import pytest

from judgment_compilation.application import Application
from judgment_compilation.kernel import canonical
from judgment_compilation.nist import ROOT


@pytest.fixture(scope="module")
def app() -> Application:
    return Application()


def test_unrelated_plain_english_is_accepted_and_remains_unresolved(app: Application) -> None:
    payload = {"mode": "inquiry", "question": "Why did the chicken cross the road?"}
    result = app.query(payload)
    assert result["route"] == "DETERMINISTIC_PLAIN_ENGLISH_INQUIRY"
    assert result["kernel"]["accepted_inquiry"] is True
    assert result["kernel"]["status"] == "UNRESOLVED_OUTSIDE_COMPILED_SEMANTICS"
    assert result["kernel"]["semantic_bindings"] == []
    assert set(result["kernel"]["unbound_terms"]) == {"chicken", "cross", "road"}
    assert result["egress"]["type"] == "UNRESOLVED"
    assert result["egress"]["model_authored"] is False
    assert result["egress"]["external_effects"] == []
    assert result["escalation"]["status"] == "CLARIFICATION_REQUIRED"
    assert result["inference"]["model_calls"] == 0
    assert "No compiled NIST check matches this question." in result["answer"]
    assert canonical(result) == canonical(app.query(payload))


def test_exact_control_inside_plain_english_routes_to_source_without_policy_verdict(app: Application) -> None:
    result = app.query({"mode": "inquiry", "question": "What does AC-2 say about account management?"})
    assert result["kernel"]["status"] == "RESOLVED_TO_SOURCE_CONTROL"
    assert result["kernel"]["semantic_bindings"] == [
        {"kind": "NIST_CONTROL", "control_id": "ac-2", "basis": "EXPLICIT_CONTROL_ID"}
    ]
    assert result["kernel"]["source_result"]["status"] == "resolved"
    assert result["kernel"]["compliance_verdict"] is None
    assert result["kernel"]["responsibility_assignment"] is None
    assert result["kernel"]["executable_warrant"] is None
    assert result["egress"]["type"] == "SOURCE_BOUND"
    assert "AC-2 - Account Management" in result["answer"]


def test_nist_related_but_unbound_question_is_not_forced_into_a_rule(app: Application) -> None:
    result = app.query({"mode": "inquiry", "question": "Should Business B revoke access now?"})
    assert result["kernel"]["status"] == "UNRESOLVED_WITHIN_NIST_SCOPE"
    assert "access" in result["kernel"]["matched_terms"]
    assert result["kernel"]["responsibility_assignment"] is None
    assert result["kernel"]["executable_warrant"] is None
    assert result["egress"]["type"] == "UNRESOLVED"


def test_multiple_controls_do_not_create_an_invented_relationship(app: Application) -> None:
    result = app.query({"mode": "inquiry", "question": "Does AC-2 override PS-4?"})
    assert result["kernel"]["status"] == "UNRESOLVED_MULTIPLE_CONTROL_BINDINGS"
    assert result["kernel"]["semantic_bindings"] == []
    assert result["kernel"]["executable_warrant"] is None
    assert "one control at a time" in result["answer"]


def test_cli_query_uses_plain_english_inquiry_route() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "judgment_compilation", "query", "Why did the chicken cross the road?"],
        cwd=ROOT.parent, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["route"] == "DETERMINISTIC_PLAIN_ENGLISH_INQUIRY"
    assert payload["kernel"]["status"] == "UNRESOLVED_OUTSIDE_COMPILED_SEMANTICS"
