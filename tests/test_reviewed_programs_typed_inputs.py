import json
import subprocess
from pathlib import Path

import pytest

from judgment_compilation.document_programs import ReviewedDocumentProgramError, ReviewedDocumentPrograms
from judgment_compilation.nist import build_pack


STAGE_ROOT = Path(__file__).parents[1]
UI = STAGE_ROOT / "judgment_compilation" / "static" / "index.html"
SP800_30 = "nist-sp-800-30r1-table-g5"
SP800_108 = "nist-sp-800-108-counter-mode-capacity-guard"


def test_staged_ui_keeps_reviewed_program_execution_on_the_json_api():
    source = UI.read_text(encoding="utf-8")
    assert 'id="reviewedPrograms"' in source
    assert 'mode:"reviewed_programs"' in source
    assert 'fetch(path,options)' in source


def _sp800_30_request():
    return {
        "request_id": "typed-sp80030-request-001",
        "scenario_id": "typed-sp80030-scenario-001",
        "entities": {"subject-1": "assessment_subject"},
        "facts": [
            {"id": "initiation", "predicate": "likelihood_of_threat_event_initiation_or_occurrence",
             "arguments": {"assessment_subject": "subject-1"}, "value": "Moderate"},
            {"id": "impact", "predicate": "likelihood_threat_events_result_in_adverse_impacts",
             "arguments": {"assessment_subject": "subject-1"}, "value": "Moderate"},
        ],
        "bindings": {"lookup": {"assessment_subject": ["subject-1"]}},
    }


def _sp800_108_request(n=4, r=2):
    return {
        "request_id": "typed-sp800108-request-001",
        "scenario_id": "typed-sp800108-scenario-001",
        "entities": {"invocation-a": "system"},
        "facts": [
            {"id": "mode", "predicate": "counter_mode_established",
             "arguments": {"invocation": "invocation-a"}, "value": True},
            {"id": "n", "predicate": "counter_mode_iteration_count",
             "arguments": {"invocation": "invocation-a"}, "value": n},
            {"id": "r", "predicate": "counter_width_bits",
             "arguments": {"invocation": "invocation-a"}, "value": r},
        ],
        "bindings": {"strict-capacity-boundary": {"invocation": ["invocation-a"]}},
    }


@pytest.fixture(scope="module")
def programs():
    return ReviewedDocumentPrograms(build_pack()["semantic_pack"])


def test_typed_examples_reach_the_unchanged_reviewed_program_boundary(programs):
    sp800_30 = programs.execute(SP800_30, _sp800_30_request())["execution"]["execution"]["execution"]
    assert sp800_30["status"] == "COMPLETE"
    assert sp800_30["outputs"][0]["value"] == "Moderate"

    sp800_108 = programs.execute(SP800_108, _sp800_108_request())["execution"]["execution"]["execution"]
    assert sp800_108["status"] == "COMPLETE"
    assert sp800_108["outputs"][0]["value"] is True


@pytest.mark.parametrize("value", ["4", -1, 2**64])
def test_python_boundary_rejects_malformed_or_overflow_unsigned_values(programs, value):
    with pytest.raises(ReviewedDocumentProgramError):
        programs.execute(SP800_108, _sp800_108_request(n=value))
