"""Tests package behavior."""
from pathlib import Path
import pytest
from judgment_compilation import nist
from judgment_compilation._pins import PACK_SHA256
from judgment_compilation.kernel import Rejected, digest
from judgment_compilation.nist_catalog import CatalogError


@pytest.fixture(scope="module")
def warm_pack():
    pack = nist.build_pack()
    assert digest(pack) == PACK_SHA256
    return pack


def test_warm_pack_reuses_compilation_but_detaches_callers(warm_pack, monkeypatch):
    def unexpected_recompile(*args, **kwargs):
        pytest.fail("unchanged frozen bytes caused a repeated compilation")
    monkeypatch.setattr(nist, "_build_pack", unexpected_recompile)
    first = nist.build_pack()
    first["semantic_pack"]["judgments"].clear()
    first["sources"].clear()
    assert nist.build_pack() == warm_pack


@pytest.mark.parametrize("filename,error", [
    ("NIST.SP.800-53r5.pdf", Rejected),
    ("NIST_SP-800-53_rev5_catalog_v1.5.0.xml", Rejected),
    ("manifest.json", CatalogError),
])
def test_warm_pack_rejects_same_length_source_drift(warm_pack, monkeypatch, filename, error):
    original = Path.read_bytes
    def changed(path):
        data = original(path)
        return bytes([data[0] ^ 1]) + data[1:] if path.name == filename else data
    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(error):
        nist.build_pack()


def test_warm_pack_does_not_supply_a_missing_alternate_root(warm_pack, tmp_path):
    with pytest.raises(FileNotFoundError):
        nist.build_pack(tmp_path / "judgment_compilation")
