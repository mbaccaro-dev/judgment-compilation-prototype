"""Tests package behavior."""
from copy import deepcopy
from pathlib import Path
import pytest
from judgment_compilation.application import Application
from judgment_compilation.nist import example_request
from judgment_compilation.rust_adapter import RustExecutor
from judgment_compilation.semantic_contracts import canonical, execute_architecture, SemanticContractError
from test_semantic_contracts import fixture, request

from judgment_compilation._native import BINARY_PATH, BINARY_SHA256
BINARY = Path(__file__).resolve().parents[1] / 'judgment_compilation' / BINARY_PATH

@pytest.fixture(scope='module')
def native():
    return RustExecutor(BINARY, BINARY_SHA256)

@pytest.mark.parametrize('variant', ['positive', 'missing', 'ambiguous', 'unknown', 'conflict', 'false', 'unicode', 'user_unknown'])
def test_actual_native_contract_matches_python(native, variant):
    p, r = fixture(), request()
    r['bindings'] = {'first': {'target': ['a']}, 'second': {'target': ['a']}}
    if variant == 'missing': r['facts'] = []
    if variant == 'ambiguous': r['bindings']['first']['target'] = ['a', 'b']
    if variant == 'unknown': r['facts'][0]['value'] = None
    if variant == 'conflict': r['facts'].append({**r['facts'][0], 'id': 'f2', 'value': False})
    if variant == 'false': r['facts'][0]['value'] = False
    if variant == 'unicode':
        r['entities']['employé'] = r['entities'].pop('a')
        r['facts'][0]['arguments']['subject'] = 'employé'
        for b in r['bindings'].values(): b['target'] = ['employé']
    if variant == 'user_unknown': r['unknowns'] = ['Account ownership remains unknown.']
    expected = execute_architecture(p, 'review-flow', r)
    assert canonical(native(p, 'review-flow', r)) == canonical(expected)
    assert canonical(native(p, 'review-flow', r)) == canonical(expected)

@pytest.mark.parametrize('binding', [None, [], 1.5, {'target': 'a'}, {'target': ['absent']}, {'foreign': ['a']}])
def test_actual_native_rejects_hidden_bad_bindings(native, binding):
    r = request(); r['facts'] = []
    r['bindings'] = {'first': {'target': ['a']}, 'second': binding}
    with pytest.raises(SemanticContractError): native(fixture(), 'review-flow', r)

@pytest.fixture(scope='module')
def applications(native):
    return Application(executor=execute_architecture), Application(executor=native)

@pytest.mark.parametrize('variant', ['positive', 'conflict', 'unknown', 'identity', 'partial_unknown', 'partial_missing', 'known_and_unknown'])
def test_full_native_scenario_matches_reference(applications, variant):
    reference, native_app = applications
    r = example_request()
    if variant == 'conflict': r['statements'].append("Employee A no longer has access through Employee A's administrator account.")
    if variant == 'unknown': r['unknowns'].append('It is unknown whether employment actually ended.')
    if variant == 'identity':
        r['request_id'] += '-second'; r['scenario_id'] += '-second'
    if variant in ('partial_unknown', 'partial_missing', 'known_and_unknown'):
        if variant != 'known_and_unknown':
            r['statements'].pop(2)
        if variant != 'partial_missing':
            r['statements'].append("It is unknown whether Employee A's administrator account has administrator privileges.")
    payload = {'mode': 'scenario', 'request': r}
    expected = reference.query(deepcopy(payload))
    actual = native_app.query(deepcopy(payload))
    assert canonical(actual) == canonical(expected)
    assert actual['kernel']['responsibility_determination'] is None
    assert actual['kernel']['external_effects'] == []


def test_application_defaults_to_pinned_native_engine():
    app = Application()
    assert app.status()['execution_engine'] == {'implementation': 'RUST_NATIVE', 'binary_sha256': BINARY_SHA256}
    payload = {'mode': 'scenario', 'request': example_request()}
    assert canonical(app.query(payload)) == canonical(Application(executor=execute_architecture).query(payload))
