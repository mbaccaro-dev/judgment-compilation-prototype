"""Tests package behavior."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys

import pytest

from judgment_compilation.application import Application
from judgment_compilation.kernel import Rejected, digest
from judgment_compilation.semantic_contracts import execute_architecture


class FakeRawSemanticCompiler:
    def __init__(self, summary):
        self._summary = deepcopy(summary)
        self.calls = 0

    def summary(self):
        self.calls += 1
        return deepcopy(self._summary)


def raw_summary():
    return {
        'documentary_coverage': {
            'document_count': 195,
            'physical_page_count': 15478,
            'source_manifest_sha256': '1' * 64,
        },
        'proposed_candidates': {
            'domain_count': 101,
            'judgment_count': 202,
            'work_count': 303,
            'architecture_count': 404,
        },
        'admitted_semantics': {
            'domain_count': 0,
            'judgment_count': 0,
            'work_count': 0,
            'architecture_count': 0,
        },
        'uncovered_document_count': 7,
        'claim_ceiling': 'RAW_CANDIDATES_REQUIRE_INTERPRETATION_QUALIFICATION',
        'external_effects': [],
    }


def progress_app(compiler):
    """Avoid normal startup so this test proves the scan is only on demand."""
    app = Application.__new__(Application)
    app._raw_semantic_compiler = compiler
    app.recommender = None
    app.integrity = {'status': 'TEST_ONLY'}
    app.interpretation_admission = {'standing': 'TEST_ONLY'}
    app.pack = {'fact_templates': []}
    return app


def test_normal_startup_and_status_leave_the_full_library_scan_dormant():
    compiler = FakeRawSemanticCompiler(raw_summary())
    app = Application(executor=execute_architecture, raw_semantic_compiler=compiler)

    assert compiler.calls == 0
    app.status()
    assert compiler.calls == 0


def test_progress_is_lazy_hash_bound_and_plain_about_candidate_status():
    compiler = FakeRawSemanticCompiler(raw_summary())
    app = progress_app(compiler)

    assert compiler.calls == 0
    actual = app.query({'mode': 'semantic_progress'})

    assert compiler.calls == 1
    assert actual['route'] == 'DETERMINISTIC_RAW_SEMANTIC_PROGRESS'
    assert actual['kernel'] == raw_summary()
    assert actual['integrity']['result_sha256'] == digest(raw_summary())
    assert actual['egress']['result_sha256'] == digest(raw_summary())
    assert actual['egress']['external_effects'] == []
    assert actual['inference']['model_calls'] == 0
    assert actual['interpretation_trace']['qualification_required'] is True
    assert 'Scanned 195 documents and 15478 PDF pages.' in actual['answer']
    assert 'Potential source matches: Domain 101; Judgment 202; Work 303; Architecture 404.' in actual['answer']
    assert 'Reviewed definitions: Domain 0; Judgment 0; Work 0; Architecture 0.' in actual['answer']
    assert actual['escalation']['status'] == 'CLARIFICATION_REQUIRED'


def test_progress_never_invents_a_missing_stack_count_or_allows_extra_fields():
    summary = raw_summary()
    summary['proposed_candidates'].pop('work_count')
    summary['admitted_semantics'].pop('architecture_count')
    app = progress_app(FakeRawSemanticCompiler(summary))

    actual = app.query({'mode': 'semantic_progress'})

    assert 'Work not reported by this scan' in actual['answer']
    assert 'Architecture not reported by this scan' in actual['answer']
    with pytest.raises(Rejected):
        app.query({'mode': 'semantic_progress', 'recommend': False})


def test_cli_uses_the_explicit_on_demand_mode(monkeypatch, capsys):
    import judgment_compilation.application as application_module
    import judgment_compilation.cli as cli

    class FakeApplication:
        def __init__(self, recommender=None):
            assert recommender is None

        def query(self, request):
            assert request == {'mode': 'semantic_progress'}
            return {'route': 'DETERMINISTIC_RAW_SEMANTIC_PROGRESS'}

    monkeypatch.setattr(application_module, 'Application', FakeApplication)
    monkeypatch.setattr(sys, 'argv', ['jc', 'semantic-progress'])
    assert cli.main() == 0
    assert json.loads(capsys.readouterr().out) == {'route': 'DETERMINISTIC_RAW_SEMANTIC_PROGRESS'}


def test_loopback_page_offers_a_plain_on_demand_progress_view():
    html = (Path(__file__).resolve().parents[1] /
            'judgment_compilation/static/index.html').read_text(encoding='utf-8')
    assert 'Library scan' in html
    assert 'Review status may take a moment.' in html
    assert 'id="semanticProgress"' in html
    assert 'mode:"semantic_progress"' in html
    assert 'result.textContent=data.answer' in html
