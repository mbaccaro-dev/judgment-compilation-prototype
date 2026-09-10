"""Tests package behavior."""
from __future__ import annotations

import json
import threading
from http.client import HTTPConnection

from judgment_compilation.application import Application
from judgment_compilation.kernel import canonical
from judgment_compilation.web import Server


def test_workflow_explanation_uses_the_existing_read_only_program_api() -> None:
    server = Server(("127.0.0.1", 0), Application())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]

    def request(method: str, path: str, body: bytes | None = None) -> tuple[int, bytes]:
        connection = HTTPConnection("127.0.0.1", port, timeout=10)
        connection.request(method, path, body, {"Content-Type": "application/json"} if body else {})
        response = connection.getresponse()
        result = response.status, response.read()
        connection.close()
        return result

    try:
        status, html = request("GET", "/")
        assert status == 200
        for text in (
            b'id="explore"',
            b'id="semanticProgram"',
            b'id="documentCoverage"',
            b'Fully reviewed documents: 0 of ',
            b'limit:200',
            b'mode:"semantic_program"',
            b'architecture_id:"termination-assessment"',
            b'id="result"',
        ):
            assert text in html

        status, body = request(
            "POST",
            "/api/query",
            canonical({"mode": "semantic_program", "request": {"architecture_id": "termination-assessment"}}),
        )
        response = json.loads(body)
        assert status == 200
        assert response["route"] == "DETERMINISTIC_ADMITTED_SEMANTIC_PROGRAM_INSPECTION"
        assert response["kernel"]["architecture"]["ordered_steps"]
        assert response["kernel"]["work"]
        assert response["kernel"]["judgments"]
        assert len(response["kernel"]["composed_program"]["program_sha256"]) == 64
        assert response["kernel"]["external_effects"] == []
        assert response["inference"]["model_calls"] == 0

        status, body = request("POST", "/api/query", canonical({"mode": "inquiry", "question": "ac-2"}))
        assert status == 200
        assert json.loads(body)["route"] == "DETERMINISTIC_PLAIN_ENGLISH_INQUIRY"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
