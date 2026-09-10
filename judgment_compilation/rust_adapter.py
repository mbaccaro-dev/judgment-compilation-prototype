"""Runs the included Rust engine."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
from .semantic_contracts import CEILING, SemanticContractError, canonical, digest

LIMIT = 16 * 1024 * 1024


def _reject(reason):
    raise SemanticContractError(reason)


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            _reject('duplicate native response key')
        result[key] = value
    return result


class RustExecutor:
    def __init__(self, executable, expected_sha256, timeout=15):
        self.executable = Path(executable).resolve(strict=True)
        if type(expected_sha256) is not str or len(expected_sha256) != 64:
            _reject('native executable digest required')
        if not 0 < timeout <= 60:
            _reject('invalid native timeout')
        self.expected_sha256 = expected_sha256
        self.timeout = timeout
        self._verify()

    def _verify(self):
        if not self.executable.is_file() or hashlib.sha256(self.executable.read_bytes()).hexdigest() != self.expected_sha256:
            _reject('native executable integrity')

    def __call__(self, pack, architecture_id, request):
        self._verify()
        packet = canonical({'operation': 'execute_architecture', 'pack': pack,
                            'architecture_id': architecture_id, 'request': request})
        if len(packet) > LIMIT:
            _reject('native request size')
        # No shell, provider configuration or inherited credential environment.
        env = {k: os.environ[k] for k in ('SystemRoot', 'WINDIR', 'TEMP', 'TMP') if k in os.environ}
        try:
            completed = subprocess.run([str(self.executable)], input=packet + b'\n',
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=self.timeout,
                cwd=self.executable.parent, env=env, shell=False,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SemanticContractError('native execution unavailable or timed out') from exc
        if completed.returncode != 0 or completed.stderr or not 0 < len(completed.stdout) <= LIMIT:
            _reject('native execution rejected; no result released')
        try:
            envelope = json.loads(completed.stdout, object_pairs_hook=_pairs,
                parse_constant=lambda _: _reject('nonfinite native response'))
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            raise SemanticContractError('invalid native response') from exc
        if type(envelope) is not dict or set(envelope) != {'ok', 'result'} or envelope['ok'] is not True:
            _reject('invalid native envelope')
        result = envelope['result']
        fields = {'architecture_id', 'architecture_coordinate', 'status', 'steps', 'outputs', 'unknowns', 'support_graph',
                  'pack_sha256', 'request_sha256', 'claim_ceiling', 'compliance_verdict',
                  'responsibility_determination', 'external_effects'}
        if type(result) is not dict or set(result) != fields:
            _reject('invalid native result fields')
        if (result['architecture_id'] != architecture_id or result['pack_sha256'] != digest(pack)
                or result['request_sha256'] != digest(request)
                or canonical(result['unknowns']) != canonical(request.get('unknowns', []))):
            _reject('native result request or pack binding')
        if (result['claim_ceiling'] != CEILING or result['compliance_verdict'] is not None
                or result['responsibility_determination'] is not None or result['external_effects'] != []):
            _reject('native result authority')
        if result['status'] not in ('COMPLETE', 'UNRESOLVED'):
            _reject('invalid native result status')
        return result
