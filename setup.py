"""Package the manifest-listed product files."""
from pathlib import Path
import ast, hashlib, json, struct, sys

ROOT = Path(__file__).resolve().parent
PACKAGE = ROOT / 'judgment_compilation'

def pin(filename, key):
    tree = ast.parse((PACKAGE / filename).read_text(encoding='utf-8-sig'))
    values = [ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
              and any(isinstance(t, ast.Name) and t.id == key for t in n.targets)]
    if len(values) != 1:
        raise ValueError('missing or ambiguous build pin')
    return values[0]

def load(relative, expected):
    raw = (PACKAGE / relative).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('build manifest drift: ' + relative)
    return json.loads(raw)

def supports_windows_native():
    return sys.platform == 'win32' and struct.calcsize('P') == 8


def package_files():
    inputs = load('inputs.json', pin('_pins.py', 'INPUT_INDEX_SHA256'))
    library = load('data/library/manifest.json', pin('library.py', 'MANIFEST_SHA256'))
    required = dict(inputs)
    if supports_windows_native():
        required[pin('_native.py', 'BINARY_PATH')] = {
            'bytes': pin('_native.py', 'BINARY_BYTES'),
            'sha256': pin('_native.py', 'BINARY_SHA256'),
        }
    for package in pin('document_programs.py', '_PACKAGES').values():
        required['data/reviewed_document_packages/' + package['file']] = {
            'bytes': package['bytes'], 'sha256': package['sha256']}
    required.update({'data/library/' + d['path']: d for d in library['files']})
    for relative, descriptor in required.items():
        path = (PACKAGE / relative).resolve()
        if Path(relative).is_absolute() or not path.is_relative_to(PACKAGE.resolve()) or (PACKAGE / relative).is_symlink():
            raise ValueError('unsafe package data path')
        raw = path.read_bytes()
        if len(raw) != descriptor['bytes'] or hashlib.sha256(raw).hexdigest() != descriptor['sha256']:
            raise ValueError('build input drift: ' + relative)
    return sorted(set(required) | {'inputs.json', 'data/library/manifest.json', 'static/index.html'})


def reviewed_document_package_count():
    """Return the number of reviewed runnable document packages without importing them."""
    tree = ast.parse((PACKAGE / 'document_programs.py').read_text(encoding='utf-8'))
    values = [ast.literal_eval(node.value) for node in tree.body
              if isinstance(node, ast.Assign)
              and any(isinstance(target, ast.Name) and target.id == '_PACKAGES'
                      for target in node.targets)]
    if len(values) != 1 or type(values[0]) is not dict:
        raise ValueError('missing or ambiguous reviewed document package index')
    return len(values[0])

if __name__ == '__main__':
    from setuptools import setup
    from setuptools.command.bdist_wheel import bdist_wheel

    class NativeWheel(bdist_wheel):
        def finalize_options(self):
            super().finalize_options()
            self.root_is_pure = False

        def get_tag(self):
            return 'py3', 'none', 'win_amd64'

    release_files = ['LICENSE.md', 'THIRD_PARTY_NOTICES.md'] + [path.relative_to(ROOT).as_posix() for path in sorted((ROOT / 'THIRD_PARTY_LICENSES').rglob('*')) if path.is_file()]
    options = {'package_data': {'judgment_compilation': package_files()}, 'include_package_data': False, 'license_files': release_files}
    if supports_windows_native():
        options['cmdclass'] = {'bdist_wheel': NativeWheel}
    setup(**options)
