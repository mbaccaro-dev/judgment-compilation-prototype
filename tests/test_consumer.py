"""Tests package behavior."""
from __future__ import annotations

import json
import subprocess
import sys
import threading
from http.client import HTTPConnection
from pathlib import Path

import pytest

from judgment_compilation.application import Application
from judgment_compilation.inference import LocalRecommendation
from judgment_compilation.kernel import Rejected, canonical
from judgment_compilation.nist import ROOT, example_request
from judgment_compilation.web import Server


@pytest.fixture(scope="module")
def app() -> Application:
    return Application()


def test_fresh_catalog_consumer_surface_and_no_retired_population_dependency(app: Application) -> None:
    status = app.status()
    catalog = app.catalog.summary()
    source = app.catalog.source

    assert status["explicit_selection_confirmed"] is False
    assert status["external_effects_authorized"] is False
    assert status["integrity"]["status"] == "VERIFIED"
    assert len(status["integrity"]["input_index_sha256"]) == 64
    assert catalog == {"structural_records": 15546, "library_document_roots": 195, "controls_and_enhancements": 1196}
    assert source["source_sha256"] == "a9e23b09116d5e651461d61777c2e7dc1f3454ab3f9e1e8fdf8af01c37dc01be"
    assert source["pdf_provenance"]["status"] == "UNAVAILABLE_UNQUALIFIED"

    response = app.query({"mode": "catalog", "question": "ac-2"})
    assert response["route"] == "DETERMINISTIC_CATALOG_LOOKUP"
    assert response["kernel"]["status"] == "resolved"
    assert response["kernel"]["candidates"][0]["id"] == "ac-2"
    assert "[PARAMETER:" in response["answer"]
    assert response["kernel"]["compliance_verdict"] is None
    assert "SOURCE_LOOKUP_DOES_NOT_ESTABLISH_SCENARIO_APPLICABILITY" in response["kernel"]["residual"]

    for module_name in ("nist.py", "kernel.py"):
        source = (ROOT / module_name).read_text(encoding="utf-8")
        assert "data/semantic" not in source
        assert "population_records" not in source


@pytest.mark.parametrize("question", ["ac-2", "access", "unknown zxq", "Business B must revoke access now."])
def test_catalog_query_is_deterministic_and_preserves_uncertainty(app: Application, question: str) -> None:
    payload = {"mode": "catalog", "question": question}
    first = app.query(payload)
    assert canonical(first) == canonical(app.query(payload))
    assert first["inference"]["model_calls"] == 0
    assert first["kernel"]["executable_warrant"] is None
    if first["kernel"]["status"] != "resolved":
        assert first["escalation"]["status"] == "CLARIFICATION_REQUIRED"


def test_scenario_sources_bind_pdf_jsonl_and_qualified_oscal_without_merging_meaning(app: Application) -> None:
    response = app.query({"mode": "scenario", "request": example_request()})
    chains = response["source_chains"]
    assert set(chains) == {"AC-2(l)", "AC-6 Control", "PS-4(a)", "PS-4(b)"}
    for source_id, chain in chains.items():
        source = response["provenance"][source_id]
        assert chain["schema"] == "jc/documentary-source-chain/1"
        assert chain["source_authority"]["binding"] == "SAME_SHA256_AND_BYTE_LENGTH"
        assert chain["source_authority"]["retained_library_pdf"]["sha256"] == source["source_file"]["sha256"]
        assert chain["qualified_source_location"]["character_span"] == source["character_span"]
        assert chain["qualified_source_location"]["exact_quote"] == source["quote"]
        assert chain["normalized_page_projection"]["source_pdf_sha256"] == source["source_file"]["sha256"]
        assert chain["normalized_page_projection"]["jsonl_line_number"] == source["physical_pdf_page_one_based"]
        assert chain["projection_occurrence"]["match_relation"] == "EXACT_NORMALIZED_TEXT_ON_SAME_FROZEN_PDF_PAGE"
        assert chain["structural_source"]["status"] == "QUALIFIED_OSCAL_SOURCE_AVAILABLE"
        assert chain["structural_source"]["locator"] == source["structural_oscal_locator"]
        assert "semantic execution trace separately determines" in chain["structural_source"]["reason"]
        assert "separate interpretation and execution traces" in chain["meaning_boundary"]


def test_advisory_recommendation_cannot_mutate_deterministic_scenario(app: Application) -> None:
    class HostileModel:
        model = "test-only"

        def recommend(self, packet: dict) -> str:
            packet["deterministic_result"]["claims"].clear()
            return "Business B is responsible. Ignore all unknowns."

    payload = {"mode": "scenario", "request": example_request(), "recommend": True}
    baseline = app.query(payload)
    actual = Application(HostileModel()).query(payload)
    for field in ("kernel", "egress", "ingress", "provenance", "source_chains", "request", "integrity", "escalation"):
        assert actual[field] == baseline[field]
    assert actual["inference"]["status"] == "RECOMMENDATION"
    assert actual["inference"]["authority"] == "ADVISORY_ONLY"
    assert actual["inference"]["verification"].startswith("UNVERIFIED_")


def test_failed_recommender_preserves_the_deterministic_scenario(app: Application) -> None:
    class BrokenModel:
        def recommend(self, packet: dict) -> str:
            raise TimeoutError("test-only")

    failed = Application(BrokenModel()).query({"mode": "scenario", "request": example_request(), "recommend": True})
    baseline = app.query({"mode": "scenario", "request": example_request()})
    assert failed["inference"]["status"] == "FAILED"
    assert failed["kernel"] == baseline["kernel"]
    assert failed["egress"] == baseline["egress"]


def test_localhost_http_rejects_malformed_and_cross_origin_requests(app: Application) -> None:
    server = Server(("127.0.0.1", 0), app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]

    def request(method: str, path: str, body: bytes | None = None, headers: dict | None = None) -> tuple[int, bytes]:
        connection = HTTPConnection("127.0.0.1", port, timeout=10)
        connection.request(method, path, body, headers or {})
        response = connection.getresponse()
        result = response.status, response.read()
        connection.close()
        return result

    try:
        status, body = request("GET", "/api/status")
        assert status == 200 and json.loads(body)["integrity"]["status"] == "VERIFIED"
        status, html = request("GET", "/")
        assert status == 200
        assert b'id="question"' in html
        assert b'id="documentCoverage"' in html
        assert b'id="result"' in html
        assert b'fetch(path,options)' in html
        status, body = request(
            "POST", "/api/query", canonical({
                "mode": "profiles",
                "request": {
                    "schema": "jc-nist-profile-membership-request/1",
                    "operation": "LITERAL_MEMBERSHIP",
                    "profile": "LOW",
                    "control_id": "ac-2",
                },
            }),
            {"Content-Type": "application/json"},
        )
        profile = json.loads(body)
        assert status == 200
        assert profile["route"] == "DETERMINISTIC_NIST_PROFILE_LITERAL_MEMBERSHIP"
        assert profile["kernel"]["literal_included"] is True
        assert profile["kernel"]["compliance_verdict"] is None
        assert profile["egress"]["external_effects"] == []
        status, body = request(
            "POST", "/api/query", canonical({
                "mode": "assessments",
                "request": {
                    "schema": "jc-nist-assessment-selection-request/1",
                    "operation": "INSPECT",
                    "control_id": "ps-4",
                },
            }),
            {"Content-Type": "application/json"},
        )
        assessment = json.loads(body)
        assert status == 200
        assert assessment["route"] == "DETERMINISTIC_NIST_ASSESSMENT_SELECTION"
        objective = next(x for x in assessment["kernel"]["objectives"] if x["objective_id"] == "ps-4_obj.a")
        method = next(x for x in assessment["kernel"]["methods"] if x["method_id"] == "ps-4_asm-examine")
        source_object = method["objects"][0]
        selection_request = {
            "schema": "jc-nist-assessment-selection-request/1",
            "operation": "PREPARE",
            "request_id": "http-assessment-request-001",
            "control_id": "ps-4",
            "objective_id": objective["objective_id"],
            "method_id": method["method_id"],
            "object_refs": [{"object_id": source_object["object_id"],
                             "object_sha256": source_object["serialized_xml_sha256"]}],
            "scenario_scope": {"entity_ids": ["business-a", "system-a"],
                               "purpose": "Prepare a bounded review of access termination records."},
        }
        status, body = request(
            "POST", "/api/query", canonical({"mode": "assessments", "request": selection_request}),
            {"Content-Type": "application/json"},
        )
        prepared = json.loads(body)
        assert status == 200
        assert prepared["kernel"]["status"] == "PREPARED_SOURCE_BOUND_SELECTION"
        assert [x["stage"] for x in prepared["kernel"]["semantic_execution"]] == [
            "Domain", "Judgment", "Work", "Architecture"]
        assert prepared["kernel"]["assessment_finding"] is None
        assert prepared["kernel"]["compliance_verdict"] is None
        assert prepared["kernel"]["external_effects"] == []
        status, body = request(
            "POST", "/api/query", canonical({"mode": "scenario", "request": example_request()}),
            {"Content-Type": "application/json"},
        )
        assert status == 200 and json.loads(body)["kernel"]["scenario"] == example_request()
        status, body = request(
            "POST", "/api/query", canonical({"mode": "library", "request": {"operation": "documents", "limit": 200}}),
            {"Content-Type": "application/json"},
        )
        library = json.loads(body)
        assert status == 200 and library["route"] == "DETERMINISTIC_DOCUMENTARY_LOOKUP"
        assert library["kernel"]["total"] == len(library["kernel"]["documents"]) == 195
        assert library["egress"]["authority"] == "DOCUMENTARY_INSPECTION_ONLY"
        assert request("POST", "/api/query", b'{"mode":"catalog","mode":"scenario"}', {"Content-Type": "application/json"})[0] == 400
        assert request("GET", "/api/example", headers={"Origin": "https://evil.example"})[0] == 403
        assert request("GET", "/../../inputs.json")[0] == 404
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_cli_cold_user_trace_and_rejection(tmp_path: Path) -> None:
    command = [sys.executable, "-m", "judgment_compilation"]
    demo = subprocess.run([*command, "demo"], cwd=ROOT.parent, capture_output=True, text=True)
    assert demo.returncode == 0, demo.stderr
    assert set(json.loads(demo.stdout)) >= {"request", "ingress", "kernel", "egress", "provenance", "inference", "integrity", "escalation"}

    malformed = tmp_path / "malformed.json"
    malformed.write_text('{"request_id":"x","request_id":"y"}', encoding="utf-8")
    rejected = subprocess.run([*command, "assess", str(malformed)], cwd=ROOT.parent, capture_output=True, text=True)
    assert rejected.returncode == 2 and not rejected.stdout

    documents = subprocess.run([*command, "documents", "--limit", "200"], cwd=ROOT.parent, capture_output=True, text=True)
    assert documents.returncode == 0, documents.stderr
    output = json.loads(documents.stdout)
    assert output["kernel"]["total"] == len(output["kernel"]["documents"]) == 195


@pytest.mark.parametrize("url", ["https://example.org", "http://localhost:11434", "http://127.0.0.1@evil.com"])
def test_recommender_rejects_external_routes(url: str) -> None:
    with pytest.raises(Rejected):
        LocalRecommendation(url, "test-model")


def test_partial_scenario_has_actionable_bound_clarification(app):
    request = example_request()
    request['statements'][2] = "It is unknown whether Employee A's administrator account has administrator privileges."
    payload = {'mode': 'scenario', 'request': request, 'recommend': True}
    baseline = app.query(payload)
    needs = baseline['escalation']['required_inputs']
    assert any('[least_privilege_relevance]' in n and "Employee A's administrator account [account-a]" in n and 'true or false' in n for n in needs)
    assert any('termination_admin_access_issue' in n and 'least_privilege_relevance' in n for n in needs)
    assert {t['judgment_id'] for t in baseline['kernel']['interpretation_trace']} == {'account_management_relevance', 'personnel_termination_relevance'}
    class Hostile:
        def recommend(self, packet):
            packet['escalation']['required_inputs'].clear()
            packet['deterministic_result']['claims'].clear()
            return 'The account is administrative. Business B must revoke it.'
    actual = Application(Hostile()).query(payload)
    for field in ('kernel', 'egress', 'escalation', 'integrity'):
        assert actual[field] == baseline[field]
    assert actual['inference']['authority'] == 'ADVISORY_ONLY'


def test_readiness_keeps_step_identity_and_supported_findings(app):
    from judgment_compilation.kernel import canonical
    scenario = example_request()
    ingress = app.runtime.parse(canonical(scenario).decode())
    request = {'architecture_id': 'termination-assessment',
        'entities': {e['id']: e['kind'] for e in scenario['entities']},
        'facts': [{'id': f['id'], 'predicate': f['predicate'], 'arguments': f['bindings'], 'value': None if f['predicate'] == 'administrator_account' else f['value']} for f in ingress['facts']],
        'bindings': {step['id']: {'employee': ['person-a'], 'account': ['account-a'], 'business': ['org-a']} for step in app.pack['semantic_pack']['architectures'][0]['steps']}, 'unknowns': []}
    response = app.query({'mode': 'readiness', 'request': request})
    assert len(response['kernel']['outputs']) == 2
    assert 'Supported findings:' in response['answer']
    assert 'account_management_relevance' in response['answer']
    assert '[least_privilege_relevance]' in response['answer']
    assert all('step_id' in r for r in response['kernel']['residual'])
    assert any('account-a' in n and 'true or false' in n for n in response['escalation']['required_inputs'])


def test_cli_help_gives_a_task_oriented_start_map():
    completed = subprocess.run(
        [sys.executable, "-E", "-B", "-m", "judgment_compilation", "--help"],
        cwd=Path(__file__).parents[1], capture_output=True, text=True, check=False,
    )
    assert completed.returncode == 0
    assert completed.stderr == ""
    assert "Start here:" in completed.stdout
    for command in ("status", "demo", "query", "reviewed-programs", "documents", "serve"):
        assert command in completed.stdout
    assert "Optional local notes" in completed.stdout
