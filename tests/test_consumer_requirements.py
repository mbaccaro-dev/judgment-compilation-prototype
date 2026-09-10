"""Tests package behavior."""
from copy import deepcopy
from http.client import HTTPConnection
import json
from pathlib import Path
import subprocess
import sys
import threading

import pytest
from judgment_compilation.application import Application
from judgment_compilation.kernel import canonical, digest
from judgment_compilation.nist_requirements import REQUEST_SCHEMA
from judgment_compilation.web import Server

@pytest.fixture(scope="module")
def app():
    return Application()

def inspect(app):
    return app.query({"mode": "requirements", "request": {
        "schema": REQUEST_SCHEMA, "operation": "inspect", "statement_id": "ps-4_smt.a"}})

def instance_request(app):
    result = inspect(app)["kernel"]
    template = result["template"]
    scope = {"organization_id": "Business A", "system_id": "Employee A administrator account"}
    return {"schema": REQUEST_SCHEMA, "operation": "instantiate", "statement_id": template["statement_id"],
        "source_sha256": result["source_sha256"], "template_sha256": template["template_sha256"],
        "scope": scope, "parameters": [{"parameter_id": p["parameter_id"], "control_id": template["control_id"],
            "source_sha256": result["source_sha256"], "scope": deepcopy(scope), "values": ["4 hours"],
            "evidence_refs": ["owner-supplied termination policy section 3"]} for p in template["parameters"]]}

def test_inspection_preserves_condition_and_honest_source_ceiling(app):
    result = inspect(app)
    assert "Upon termination of individual employment:" in result["answer"]
    assert "Disable system access within" in result["answer"]
    assert "[PARAMETER:" in result["answer"]
    assert result["kernel"]["applicability"] is None
    assert result["provenance"]["pdf_provenance"] is None
    assert result["egress"]["type"] == "DETERMINISTIC_DERIVATION"
    assert result["egress"]["result_sha256"] == digest(result["kernel"])
    assert result["escalation"]["status"] == "CLARIFICATION_REQUIRED"
    assert canonical(result) == canonical(inspect(app))

def test_binding_completion_preserves_scope_and_never_decides_applicability(app):
    request = instance_request(app)
    result = app.query({"mode": "requirements", "request": request})
    assert result["kernel"]["status"] == "INSTANTIATED"
    assert result["kernel"]["instance"]["scope"] == request["scope"]
    assert "caller supplied" in result["answer"]
    assert result["kernel"]["compliance_verdict"] is None
    assert result["egress"]["request_sha256"] == digest(request)
    assert result["egress"]["instance_sha256"] == result["kernel"]["instance"]["instance_sha256"]
    assert result["escalation"]["status"] == "CLARIFICATION_REQUIRED"
    missing = deepcopy(request); missing["parameters"] = []
    unresolved = app.query({"mode": "requirements", "request": missing})
    assert unresolved["kernel"]["status"] == "UNRESOLVED"
    assert unresolved["kernel"]["instance"] is None
    assert any(r["reason"] == "MISSING_PARAMETER" for r in unresolved["escalation"]["unresolved"])
    foreign = deepcopy(request); foreign["parameters"][0]["scope"]["organization_id"] = "Business B"
    with pytest.raises(ValueError, match="foreign parameter scope"):
        app.query({"mode": "requirements", "request": foreign})

def test_advice_cannot_replace_compiler_result_or_scope(app):
    class Hostile:
        model = "test-only"
        def recommend(self, packet):
            packet["deterministic_result"]["instance"]["scope"]["organization_id"] = "Business B"
            packet["deterministic_result"]["compliance_verdict"] = True
            return "Unverified test recommendation"
    request = instance_request(app)
    payload = {"mode": "requirements", "request": request, "recommend": True}
    expected = app.query(payload)
    actual = Application(Hostile()).query(payload)
    for key in ("request", "ingress", "kernel", "egress", "provenance", "integrity", "escalation"):
        assert actual[key] == expected[key]
    assert actual["inference"]["type"] == "AI_INFERENCE"
    assert actual["inference"]["authority"] == "ADVISORY_ONLY"

def test_cold_cli_inspect_instantiate_and_reject_stale_template(app, tmp_path):
    command = [sys.executable, "-E", "-B", "-m", "judgment_compilation"]
    cwd = Path(__file__).resolve().parents[1]
    def run(*args):
        return subprocess.run(command + list(args), cwd=cwd, capture_output=True, text=True, timeout=30)
    listing = run("requirements", "--control", "ps-4", "--limit", "2")
    assert listing.returncode == 0, listing.stderr
    assert len(json.loads(listing.stdout)["kernel"]["templates"]) == 2
    view = run("requirement", "ps-4_smt.a")
    assert view.returncode == 0, view.stderr
    assert json.loads(view.stdout)["kernel"]["status"] == "INSPECTED"
    path = tmp_path / "request.json"
    request = instance_request(app); path.write_text(json.dumps(request), encoding="utf-8")
    complete = run("instantiate", str(path))
    assert complete.returncode == 0, complete.stderr
    assert json.loads(complete.stdout)["kernel"]["status"] == "INSTANTIATED"
    request["template_sha256"] = "0" * 64; path.write_text(json.dumps(request), encoding="utf-8")
    rejected = run("instantiate", str(path))
    assert rejected.returncode == 2 and not rejected.stdout
    assert "template mismatch" in rejected.stderr

def test_http_requirement_interface_and_gui_controls(app):
    server = Server(("127.0.0.1", 0), app)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        connection = HTTPConnection("127.0.0.1", server.server_address[1], timeout=10)
        payload = {"mode": "requirements", "request": instance_request(app)}
        connection.request("POST", "/api/query", canonical(payload), {"Content-Type": "application/json"})
        response = connection.getresponse(); raw = response.read()
        assert response.status == 200
        assert json.loads(raw) == app.query(payload)
        discovery = {"mode": "requirements", "request": {"schema": REQUEST_SCHEMA, "operation": "list", "control_id": "ac-2.2", "limit": 2}}
        connection.request("POST", "/api/query", canonical(discovery), {"Content-Type": "application/json"})
        response = connection.getresponse()
        assert response.status == 200 and json.loads(response.read()) == app.query(discovery)
        connection.request("GET", "/")
        response = connection.getresponse(); html = response.read().decode()
        assert response.status == 200
        assert 'id="question"' in html and 'id="explore"' in html
        assert 'id="result"' in html and 'mode:"requirements"' in html
        connection.close()
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=3)


def test_requirement_discovery_pages_exact_filter_and_rejection(app):
    request = {"schema": REQUEST_SCHEMA, "operation": "list", "control_id": "ps-4", "offset": 0, "limit": 2}
    first = app.query({"mode": "requirements", "request": request})
    page = first["kernel"]
    assert page["total_templates"] == 2138 and page["matched_templates"] > 2
    assert len(page["templates"]) == 2
    assert all(t["control_id"] == "ps-4" for t in page["templates"])
    assert first["egress"]["result_sha256"] == digest(page)
    assert canonical(first) == canonical(app.query({"mode": "requirements", "request": request}))
    second = app.query({"mode": "requirements", "request": {**request, "offset": 2}})["kernel"]
    assert not {t["statement_id"] for t in page["templates"]} & {t["statement_id"] for t in second["templates"]}
    row = page["templates"][0]
    detail = app.query({"mode": "requirements", "request": {"schema": REQUEST_SCHEMA, "operation": "inspect", "statement_id": row["statement_id"]}})
    assert detail["kernel"]["template"]["template_sha256"] == row["template_sha256"]
    for invalid in ({"limit": 101}, {"offset": True}, {"schema": "invented"}, {"authority": "compliant"}):
        with pytest.raises(ValueError):
            app.query({"mode": "requirements", "request": {**request, **invalid}})
    missing = app.query({"mode": "requirements", "request": {**request, "control_id": "invented"}})
    assert missing["kernel"]["templates"] == []


def test_choice_guidance_preserves_source_identity_and_missing_values(app):
    result = app.query({"mode": "requirements", "request": {"schema": REQUEST_SCHEMA, "operation": "inspect", "statement_id": "ac-2.2_smt"}})
    template = result["kernel"]["template"]
    selection = next(p for p in template["parameters"] if p["kind"] == "SELECTION")
    assert "Allowed selection count: one" in result["answer"]
    for choice in selection["choice_templates"]:
        assert choice["choice_sha256"] in result["answer"]
    assert "Source choice: remove" in result["answer"] and "Source choice: disable" in result["answer"]
    assert result["kernel"]["instance"] is None
    assert result["inference"]["model_calls"] == 0
