"""Tests package behavior."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import runpy
import struct
import sys

import pytest

from judgment_compilation import _native
from judgment_compilation.semantic_contracts import SemanticContractError, canonical, execute_architecture
from judgment_compilation.rust_adapter import RustExecutor
from test_semantic_contracts import fixture, request


WINDOWS_64 = sys.platform == 'win32' and struct.calcsize('P') == 8


def assert_reference_parity(executor):
    pack, semantic_request = fixture(), request()
    semantic_request['bindings'] = {
        'first': {'target': ['a']},
        'second': {'target': ['a']},
    }
    assert canonical(executor(deepcopy(pack), 'review-flow', deepcopy(semantic_request))) == canonical(
        execute_architecture(pack, 'review-flow', semantic_request)
    )


@pytest.mark.parametrize('platform', ['linux', 'darwin'])
def test_non_windows_selects_explicit_python_reference(monkeypatch, platform):
    monkeypatch.setattr(_native.sys, 'platform', platform)
    executor = _native.load_native_executor()
    assert isinstance(executor, _native.PythonReferenceExecutor)
    assert executor.execution_engine == {
        'implementation': 'PYTHON_REFERENCE',
        'platform': 'Linux/macOS Python engine',
    }
    assert_reference_parity(executor)


@pytest.mark.parametrize('platform', ['ios', 'emscripten', 'unknown'])
def test_unqualified_platforms_fail_closed(monkeypatch, platform):
    monkeypatch.setattr(_native.sys, 'platform', platform)
    with pytest.raises(SemanticContractError, match='Unsupported platform'):
        _native.load_native_executor()


@pytest.mark.skipif(not WINDOWS_64, reason='requires the current supported Windows native target')
def test_current_windows_loader_uses_verified_native_binary():
    executor = _native.load_native_executor()
    assert isinstance(executor, RustExecutor)
    assert executor.execution_engine == {
        'implementation': 'RUST_NATIVE',
        'binary_sha256': _native.BINARY_SHA256,
    }
    assert_reference_parity(executor)


@pytest.mark.skipif(not WINDOWS_64, reason='requires the current supported Windows native target')
@pytest.mark.parametrize(
    ('name', 'value'),
    [
        ('BINARY_PATH', 'native/windows-x86_64/missing.exe'),
        ('BINARY_SHA256', '0' * 64),
    ],
)
def test_current_windows_missing_or_drifted_binary_fails_closed(monkeypatch, name, value):
    monkeypatch.setattr(_native, name, value)
    with pytest.raises(SemanticContractError, match='native executable integrity'):
        _native.load_native_executor()


def test_package_data_includes_native_only_for_windows_64(monkeypatch, tmp_path):
    root = tmp_path / 'consumer'
    package = root / 'judgment_compilation'
    (package / 'data' / 'library').mkdir(parents=True)
    (package / 'static').mkdir()
    (package / 'static' / 'index.html').write_bytes(b'ok')

    def write_json(relative, value):
        raw = json.dumps(value, sort_keys=True).encode('utf-8')
        (package / relative).write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    inputs_sha256 = write_json('inputs.json', {})
    manifest_sha256 = write_json('data/library/manifest.json', {'files': []})
    native = b'local-native-fixture'
    native_path = package / _native.BINARY_PATH
    native_path.parent.mkdir(parents=True)
    native_path.write_bytes(native)
    (package / '_pins.py').write_text(f"INPUT_INDEX_SHA256 = '{inputs_sha256}'\n", encoding='utf-8')
    (package / 'library.py').write_text(f"MANIFEST_SHA256 = '{manifest_sha256}'\n", encoding='utf-8')
    (package / '_native.py').write_text(
        "BINARY_PATH = 'native/windows-x86_64/judgment_kernel.exe'\n"
        f"BINARY_SHA256 = '{hashlib.sha256(native).hexdigest()}'\n"
        f'BINARY_BYTES = {len(native)}\n', encoding='utf-8')
    (package / 'document_programs.py').write_text('_PACKAGES = {}\n', encoding='utf-8')
    source = Path(__file__).resolve().parents[1] / 'setup.py'
    (root / 'setup.py').write_text(source.read_text(encoding='utf-8'), encoding='utf-8')
    setup = runpy.run_path(str(root / 'setup.py'))
    monkeypatch.setattr(setup['sys'], 'platform', 'win32')
    monkeypatch.setattr(setup['struct'], 'calcsize', lambda _: 8)
    assert _native.BINARY_PATH in setup['package_files']()

    monkeypatch.setattr(setup['sys'], 'platform', 'linux')
    assert _native.BINARY_PATH not in setup['package_files']()


def test_source_manifest_retains_rust_consumer_source():
    manifest = (Path(__file__).resolve().parents[1] / 'MANIFEST.in').read_text(encoding='utf-8')
    for name in ('Cargo.toml', 'Cargo.lock', 'src/lib.rs', 'src/main.rs'):
        assert f'rust/judgment_kernel/{name}' in manifest
