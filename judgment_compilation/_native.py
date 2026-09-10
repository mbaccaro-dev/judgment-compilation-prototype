"""Selects the execution engine for the current platform."""
from pathlib import Path
import struct
import sys
from .rust_adapter import RustExecutor
from .semantic_contracts import SemanticContractError, execute_architecture

BINARY_PATH = 'native/windows-x86_64/judgment_kernel.exe'
BINARY_SHA256 = 'ecf33996c2eb7fc4617e629046a67f76f2ddf83c78427834374027baa440fd06'
BINARY_BYTES = 702464

PYTHON_REFERENCE_ENGINE = {
    'implementation': 'PYTHON_REFERENCE',
    'platform': 'Linux/macOS Python engine',
}


class PythonReferenceExecutor:
    execution_engine = PYTHON_REFERENCE_ENGINE

    def __call__(self, pack, architecture_id, request):
        return execute_architecture(pack, architecture_id, request)

def load_native_executor():
    if sys.platform in {'linux', 'darwin'}:
        return PythonReferenceExecutor()
    if sys.platform != 'win32':
        raise SemanticContractError(
            f"Unsupported platform {sys.platform!r}. Supported platforms are 64-bit Windows, Linux, and macOS."
        )
    if struct.calcsize('P') != 8:
        raise SemanticContractError('This native build requires 64-bit Windows.')
    try:
        executor = RustExecutor(Path(__file__).resolve().parent / BINARY_PATH, BINARY_SHA256)
    except OSError as exc:
        raise SemanticContractError('native executable integrity') from exc
    executor.execution_engine = {
        'implementation': 'RUST_NATIVE',
        'binary_sha256': BINARY_SHA256,
    }
    return executor
