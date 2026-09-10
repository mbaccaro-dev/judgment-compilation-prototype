"""Tests package behavior."""
import hashlib
import json
import subprocess
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import patch
import pytest
from judgment_compilation.rust_adapter import RustExecutor
from judgment_compilation.semantic_contracts import execute_architecture, SemanticContractError
from test_semantic_contracts import fixture, request


@pytest.fixture
def transport(tmp_path):
    binary = tmp_path / 'executor.exe'
    binary.write_bytes(b'test-only-binary-identity')
    executor = RustExecutor(binary, hashlib.sha256(binary.read_bytes()).hexdigest())
    pack, req = fixture(), request()
    req['bindings'] = {'first': {'target': ['a']}, 'second': {'target': ['a']}}
    result = execute_architecture(pack, 'review-flow', req)
    return executor, pack, req, result


def reply(result):
    return SimpleNamespace(returncode=0, stderr=b'', stdout=json.dumps({'ok': True, 'result': result}).encode())


def test_transport_preserves_exact_semantics_and_launches_no_shell(transport):
    executor, pack, req, result = transport
    with patch('judgment_compilation.rust_adapter.subprocess.run', return_value=reply(result)) as run:
        assert executor(pack, 'review-flow', req) == result
        args, kwargs = run.call_args
        assert args[0] == [str(executor.executable)]
        assert kwargs['shell'] is False
        assert set(kwargs['env']) <= {'SystemRoot', 'WINDIR', 'TEMP', 'TMP'}
        assert json.loads(kwargs['input']) == {'operation': 'execute_architecture', 'pack': pack,
            'architecture_id': 'review-flow', 'request': req}


@pytest.mark.parametrize('change', [
    {'pack_sha256': '0'*64}, {'request_sha256': '0'*64}, {'architecture_id': 'foreign'},
    {'claim_ceiling': 'COMPLIANCE'}, {'compliance_verdict': True},
    {'responsibility_determination': 'Business A'}, {'external_effects': ['revoke']},
    {'status': 'COMPLIANT'}, {'invented_claim': 'approved'},
])
def test_replay_authority_and_extra_fields_rejected(transport, change):
    executor, pack, req, result = transport
    bad = deepcopy(result); bad.update(change)
    with patch('judgment_compilation.rust_adapter.subprocess.run', return_value=reply(bad)):
        with pytest.raises(SemanticContractError): executor(pack, 'review-flow', req)


@pytest.mark.parametrize('stdout', [b'{"ok":true,"ok":true,"result":{}}', b'{"ok":true,"result":NaN}',
    b'{"ok":true,"result":{}}\n{"ok":true}', b'not JSON', b'', b'{"ok":1,"result":{}}'])
def test_invalid_wire_output_rejected(transport, stdout):
    executor, pack, req, _ = transport
    with patch('judgment_compilation.rust_adapter.subprocess.run', return_value=SimpleNamespace(returncode=0,stderr=b'',stdout=stdout)):
        with pytest.raises(SemanticContractError): executor(pack, 'review-flow', req)


def test_timeout_and_crash_do_not_fall_back(transport):
    executor, pack, req, _ = transport
    with patch('judgment_compilation.rust_adapter.subprocess.run', side_effect=subprocess.TimeoutExpired('executor', 15)):
        with pytest.raises(SemanticContractError): executor(pack, 'review-flow', req)
    with patch('judgment_compilation.rust_adapter.subprocess.run', return_value=SimpleNamespace(returncode=2,stderr=b'error',stdout=b'')):
        with pytest.raises(SemanticContractError): executor(pack, 'review-flow', req)


def test_changed_executable_rejected_before_process(transport):
    executor, pack, req, _ = transport
    executor.executable.write_bytes(b'changed')
    with patch('judgment_compilation.rust_adapter.subprocess.run') as run:
        with pytest.raises(SemanticContractError): executor(pack, 'review-flow', req)
        run.assert_not_called()
