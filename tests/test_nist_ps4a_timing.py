"""Tests package behavior."""
from copy import deepcopy
from http.client import HTTPConnection
import json
from pathlib import Path
import sys
import threading

import pytest

from judgment_compilation.application import Application
from judgment_compilation.kernel import canonical, digest
from judgment_compilation.nist import build_pack, ps4a_timing_example_request
from judgment_compilation.nist_admission import admit_pack_interpretation_bundle, interpretation_subject
from judgment_compilation.interpretation_qualification import InterpretationQualificationError
from judgment_compilation.rust_adapter import RustExecutor
from judgment_compilation.semantic_contracts import execute_architecture
from judgment_compilation._native import BINARY_PATH, BINARY_SHA256
from judgment_compilation.web import Server

ROOT = Path(__file__).resolve().parents[1] / 'judgment_compilation'


@pytest.fixture(scope='module')
def pack():
    return build_pack()


@pytest.fixture
def app(pack):
    value = Application.__new__(Application)
    value.pack = deepcopy(pack)
    value.executor = execute_architecture
    value.integrity = {'status': 'TEST_REFERENCE_NOT_INSTALLED_PACKAGE'}
    value.interpretation_admission = {'standing': 'TEST_REFERENCE_PROPOSAL_NOT_ADMITTED'}
    value.recommender = None
    return value


def ask(app, request=None):
    return app.query({'mode': 'ps4a_timing', 'request': request or ps4a_timing_example_request()})


@pytest.mark.parametrize('elapsed,allowed,within', [(0, 0, True), (14400, 14400, True), (14401, 14400, False), (2147483647, 0, False)])
def test_ps4a_numeric_comparison_has_complete_intermediate_json(app, elapsed, allowed, within):
    request = ps4a_timing_example_request()
    request['facts'][1]['value'] = elapsed
    request['facts'][2]['value'] = allowed
    before = canonical(request)
    out = ask(app, request)
    assert canonical(request) == before
    assert out['route'] == 'DETERMINISTIC_NIST_PS4A_ACCESS_DISABLE_TIMING'
    assert out['kernel']['status'] == 'RESOLVED'
    assert out['kernel']['execution']['status'] == 'COMPLETE'
    comparison = next(row for row in out['kernel']['execution']['outputs'] if row['predicate'] == 'within_ps4a_allowed_period')
    assert comparison['value'] is within
    assert out['ingress']['request'] == request
    assert out['ingress']['semantic_request']['bindings']['compare']['employee'] == ['employee-a']
    assert out['kernel']['compliance_verdict'] is None and out['kernel']['external_effects'] == []
    assert out['egress']['claim_ids'] == [claim['id'] for claim in out['kernel']['claims']]
    assert canonical(out) == canonical(ask(app, request))


@pytest.mark.parametrize('variant', ['missing', 'null', 'conflict', 'unknown', 'foreign_account'])
def test_missing_conflicting_or_identity_mismatched_inputs_do_not_produce_a_ps4a_result(app, variant):
    request = ps4a_timing_example_request()
    if variant == 'missing':
        request['facts'].pop(2)
    elif variant == 'null':
        request['facts'][2]['value'] = None
    elif variant == 'conflict':
        request['facts'].append({**deepcopy(request['facts'][2]), 'id': 'contradiction', 'value': 1})
    elif variant == 'unknown':
        request['unknowns'] = ['The supplied duration basis is unknown.']
    else:
        request['entities'].append({'id': 'account-b', 'alias': 'Other account', 'kind': 'account'})
        request['facts'][2]['arguments']['account'] = 'account-b'
    out = ask(app, request)
    assert out['kernel']['status'] == 'UNRESOLVED'
    assert out['kernel']['execution']['status'] == 'UNRESOLVED'
    assert not any(row['predicate'] in ('ps4a_within_supplied_period', 'ps4a_exceeds_supplied_period') for row in out['kernel']['execution']['outputs'])
    assert out['escalation']['status'] == 'CLARIFICATION_REQUIRED'


@pytest.mark.parametrize('variant', ['source', 'statement', 'negative', 'float', 'bool_integer', 'english_duration', 'derived', 'scope_identity', 'evidence'])
def test_ps4a_ingress_rejects_invention_or_unsupported_time_forms(app, variant):
    request = ps4a_timing_example_request()
    if variant == 'source': request['source_sha256'] = '0' * 64
    elif variant == 'statement': request['statement_id'] = 'ps-4_smt.b'
    elif variant == 'negative': request['facts'][1]['value'] = -1
    elif variant == 'float': request['facts'][1]['value'] = 1.5
    elif variant == 'bool_integer': request['facts'][1]['value'] = True
    elif variant == 'english_duration': request['facts'][1]['value'] = 'four hours'
    elif variant == 'derived': request['facts'][1]['predicate'] = 'within_ps4a_allowed_period'
    elif variant == 'scope_identity': request['scope']['employee'] = 'account-a'
    else: request['facts'][2]['evidence_refs'] = []
    with pytest.raises(ValueError):
        ask(app, request)


def test_false_caller_scope_is_not_a_compliance_or_satisfaction_result(app):
    request = ps4a_timing_example_request(); request['facts'][0]['value'] = False
    out = ask(app, request)
    assert out['kernel']['status'] == 'NOT_APPLICABLE'
    assert out['kernel']['execution']['outputs'] == []
    assert out['kernel']['compliance_verdict'] is None
    assert out['kernel']['authority_ceiling']['control_satisfaction_determination'] is False


def test_ps4a_pack_change_is_unadmitted_and_proposal_is_hash_bound(pack):
    admission = json.loads((ROOT / 'data/compiled/interpretation_admission.json').read_text(encoding='utf-8'))
    admitted = admit_pack_interpretation_bundle(pack, admission)
    assert admitted['standing'] == 'SOURCE_REVIEWED'
    changed_pack = deepcopy(pack)
    changed_pack['authority_ceiling']['compliance_determination'] = True
    with pytest.raises(InterpretationQualificationError, match='reviewed pack digest mismatch'):
        admit_pack_interpretation_bundle(changed_pack, admission)
    tampered = deepcopy(admission); tampered['pack_sha256'] = digest(changed_pack)
    with pytest.raises(InterpretationQualificationError, match='reviewed interpretation subject mismatch'):
        admit_pack_interpretation_bundle(changed_pack, tampered)
    proposal = json.loads((ROOT / 'data/compiled/ps4a_timing_interpretation_proposal.json').read_text(encoding='utf-8'))
    assert proposal['standing'] == 'PROPOSED_UNREVIEWED_NOT_ADMITTED'
    assert proposal['pack_sha256'] == digest(pack)
    assert proposal['interpretation_subject_sha256'] == digest(interpretation_subject(pack))
    assert proposal['required_independent_review']['decision_required'] == 'REVIEW_CONFIRMED'
    assert proposal['claim']['interpretation']['mapping']['work_ids'] == ['compare_ps4a_access_disable_period']


def test_generic_rust_compare_matches_python_for_ps4a(app):
    package = __import__('judgment_compilation')
    native = RustExecutor(Path(package.__file__).resolve().parent / BINARY_PATH, BINARY_SHA256)
    python_out = ask(app)
    native_execution = native(app.pack['semantic_pack'], 'ps4a-access-disable-timing', python_out['ingress']['semantic_request'])
    assert canonical(native_execution) == canonical(python_out['kernel']['execution'])


def test_cli_and_loopback_gui_route_to_the_same_ps4a_result(app, tmp_path, monkeypatch, capsys):
    request = ps4a_timing_example_request()
    request_path = tmp_path / 'ps4a.json'; request_path.write_text(json.dumps(request), encoding='utf-8')
    import judgment_compilation.application as application_module
    import judgment_compilation.cli as cli
    monkeypatch.setattr(application_module, 'Application', lambda recommender=None: app)
    monkeypatch.setattr(sys, 'argv', ['jc', 'ps4a-timing', str(request_path)])
    assert cli.main() == 0
    cli_result = json.loads(capsys.readouterr().out)
    server = Server(('127.0.0.1', 0), app)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        connection = HTTPConnection('127.0.0.1', server.server_address[1], timeout=10)
        connection.request('POST', '/api/query', canonical({'mode': 'ps4a_timing', 'request': request}), {'Content-Type': 'application/json'})
        response = connection.getresponse(); gui_result = json.loads(response.read()); connection.close()
        assert response.status == 200
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=3)
    assert canonical(cli_result) == canonical(gui_result)


def test_loopback_ui_exposes_the_exact_ps4a_example_and_mode(app):
    server = Server(('127.0.0.1', 0), app)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        connection = HTTPConnection('127.0.0.1', server.server_address[1], timeout=10)
        connection.request('GET', '/')
        response = connection.getresponse(); page = response.read().decode(); connection.close()
        assert response.status == 200
        assert 'How fast was access disabled?' in page
        assert 'id="ps4aTimingInput"' in page and 'readonly' in page
        assert 'request("/api/ps4a-timing-example")' in page
        assert 'body:JSON.stringify({mode:"ps4a_timing",request:example})' in page
        assert 'id="ps4aTimingTrace"' in page

        connection = HTTPConnection('127.0.0.1', server.server_address[1], timeout=10)
        connection.request('GET', '/api/ps4a-timing-example')
        response = connection.getresponse(); example = json.loads(response.read()); connection.close()
        assert response.status == 200
        assert example == ps4a_timing_example_request()

        connection = HTTPConnection('127.0.0.1', server.server_address[1], timeout=10)
        connection.request('POST', '/api/query', canonical({'mode': 'ps4a_timing', 'request': example}), {'Content-Type': 'application/json'})
        response = connection.getresponse(); ui_result = json.loads(response.read()); connection.close()
        assert response.status == 200
        assert canonical(ui_result) == canonical(ask(app, example))
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=3)
