"""Tests package behavior."""
from pathlib import Path
import shutil
import subprocess

import pytest


GUI = Path(__file__).parents[1] / "judgment_compilation" / "static" / "index.html"


def _html() -> str:
    return GUI.read_text(encoding="utf-8")


def test_gui_is_one_plain_self_contained_page() -> None:
    html = _html()
    assert html.count("<script>") == 1
    assert "<link" not in html and "src=" not in html
    for framework in ("React", "Vue", "Angular", "Bootstrap", "Tailwind"):
        assert framework not in html


def test_gui_exposes_the_small_public_task_surface() -> None:
    html = _html()
    for element_id in (
        "question", "explore", "status", "reviewedPrograms", "documentCoverage",
        "semanticProgram", "semanticProgress", "sourceAccounting", "sourceMappings",
        "auditRequirementDispositions", "ps4aTiming", "result",
    ):
        assert f'id="{element_id}"' in html


def test_gui_reports_reviewed_slice_counts() -> None:
    html = _html()
    assert "Fully reviewed documents: 0 of " in html
    assert "status.retained_library.document_count" in html
    assert "library.kernel.total_documents" not in html
    assert "Documents with reviewed checks" in html
    assert "Documents without reviewed checks" in html
    assert "limit:200" in html


def test_gui_uses_the_local_json_api_directly() -> None:
    html = _html()
    assert 'fetch(path,options)' in html
    assert 'request("/api/status")' in html
    assert 'request("/api/query"' in html
    assert 'result.textContent=show(data)' in html
    assert 'document.getElementById("ps4aTimingTrace").textContent=message' in html
    assert 'result.textContent=message' in html

def test_every_gui_control_is_wired() -> None:
    html = _html()
    for element_id, event in (
        ("ask", "onsubmit"),
        ("status", "onclick"),
        ("reviewedPrograms", "onclick"),
        ("documentCoverage", "onclick"),
        ("semanticProgram", "onclick"),
        ("semanticProgress", "onclick"),
        ("sourceAccounting", "onclick"),
        ("sourceMappings", "onclick"),
        ("auditRequirementDispositions", "onclick"),
        ("ps4aTiming", "onclick"),
    ):
        assert f'document.getElementById("{element_id}").{event}=' in html


def test_gui_inline_javascript_parses() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for the JavaScript syntax check")
    script = _html().split("<script>", 1)[1].split("</script>", 1)[0]
    result = subprocess.run(
        [node, "--check", "-"],
        input=script,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
