"""Verifies package files and hashes."""
from pathlib import Path
import hashlib
from .kernel import require, strict_json
from ._pins import INPUT_INDEX_SHA256


def verify_inputs(root: Path) -> dict:
    root = root.resolve()
    raw = (root / 'inputs.json').read_bytes()
    require(hashlib.sha256(raw).hexdigest() == INPUT_INDEX_SHA256, 'input index drift')
    inputs = strict_json(raw.decode('utf-8'))
    for relative, expected in inputs.items():
        path = (root / relative).resolve()
        require(path.is_relative_to(root) and not Path(relative).is_absolute(), 'input escapes package')
        data = path.read_bytes()
        require(len(data) == expected['bytes'] and hashlib.sha256(data).hexdigest() == expected['sha256'], 'input drift: ' + relative)
    return {'status': 'VERIFIED', 'input_index_sha256': INPUT_INDEX_SHA256, 'file_count': len(inputs)}
