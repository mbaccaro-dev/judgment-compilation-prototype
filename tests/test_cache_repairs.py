import hashlib

import pytest

from judgment_compilation.kernel import canonical, Rejected
from judgment_compilation.library import DocumentLibrary
import judgment_compilation.document_programs as document_programs
from judgment_compilation.document_programs import (
    ReviewedDocumentProgramError,
    ReviewedDocumentPrograms,
)
from judgment_compilation.nist import build_pack


@pytest.fixture
def small_library(tmp_path):
    documents, files = [], []

    def save(path, raw):
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        descriptor = {
            "path": path,
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
        files.append(descriptor)
        return descriptor

    pid = "Publication 1"
    text = "Straße account. Other context."
    pdf = save("doc.pdf", b"frozen source")
    page = {
        "pub_id": pid,
        "source_sha256": pdf["sha256"],
        "pdf_page_index": 0,
        "pdf_page_number": 1,
        "text": text,
        "char_count": len(text),
        "text_sha256": hashlib.sha256(text.encode()).hexdigest(),
    }
    extraction = {}
    for view in ("plain", "layout", "coverage"):
        extraction[view] = save(
            f"{view}.jsonl", canonical(dict(page, view=view)) + b"\n"
        )
    documents.append(
        {
            "publication_id": pid,
            "title": pid,
            "page_count": 1,
            "pdf": pdf,
            "extraction": extraction,
            "publication_metadata": {"revision": "1"},
        }
    )
    manifest = {
        "documents": documents,
        "files": files,
        "document_count": 1,
        "physical_page_count": 1,
        "corpus_id": "fixture",
        "corpus_release": "frozen-1",
        "coverage_ceiling": "EXTRACTED_TEXT_ONLY",
    }
    raw = canonical(manifest)
    (tmp_path / "manifest.json").write_bytes(raw)
    return DocumentLibrary(tmp_path, hashlib.sha256(raw).hexdigest())


def _source_record(library):
    pdf = library.documents["Publication 1"]["pdf"]
    quote = "Straße account"
    return {
        "source-1": {
            "source_file": pdf,
            "physical_pdf_page_one_based": 1,
            "physical_pdf_page_index_zero_based": 0,
            "quote": quote,
            "quote_sha256": hashlib.sha256(quote.encode()).hexdigest(),
            "character_span": {
                "interval": "HALF_OPEN",
                "unit": "UNICODE_CODE_POINT",
                "start": 0,
                "end": 14,
            },
        }
    }


def test_page_cache_reuses_parsed_page_but_returns_identical_data(
    small_library, monkeypatch
):
    calls = []
    original = small_library._pages

    def counted(doc, view):
        calls.append(view)
        return original(doc, view)

    monkeypatch.setattr(small_library, "_pages", counted)
    first = small_library.page("Publication 1", 1)
    second = small_library.page("Publication 1", 1)
    assert first == second
    assert calls == ["plain", "coverage"]


def test_page_cache_rejects_post_cache_file_drift(small_library):
    small_library.page("Publication 1", 1)
    descriptor = small_library.documents["Publication 1"]["extraction"]["plain"]
    small_library._path(descriptor).write_bytes(b"tampered")
    with pytest.raises(Rejected, match="library input drift"):
        small_library.page("Publication 1", 1)


def test_page_cache_rejects_post_cache_manifest_drift(small_library):
    small_library.page("Publication 1", 1)
    manifest = small_library.root / "manifest.json"
    manifest.write_bytes(manifest.read_bytes() + b"\n")
    with pytest.raises(Rejected, match="library manifest drift"):
        small_library.page("Publication 1", 1)


def test_verify_rejects_manifest_tamper(small_library):
    manifest = small_library.root / "manifest.json"
    manifest.write_bytes(manifest.read_bytes() + b"\n")
    with pytest.raises(Rejected, match="library manifest drift"):
        small_library.verify()


def test_bind_provenance_cache_reauthenticates_after_source_drift(small_library):
    sources = _source_record(small_library)
    small_library.bind_provenance_chains(sources)
    descriptor = small_library.documents["Publication 1"]["extraction"]["plain"]
    small_library._path(descriptor).write_bytes(b"tampered")
    with pytest.raises(Rejected, match="library input drift"):
        small_library.bind_provenance_chains(sources)


def test_reviewed_inspect_avoids_repeat_materialization_and_decomposition(monkeypatch):
    programs = ReviewedDocumentPrograms(build_pack()["semantic_pack"])
    monkeypatch.setattr(programs, "_source_citations", lambda package, digest: [])
    calls = {"materialize": 0, "decompose": 0}
    original_materialize = document_programs.materialize_reviewed_batch
    original_decompose = document_programs.decompose_reviewed_batch

    def counted_materialize(*args, **kwargs):
        calls["materialize"] += 1
        return original_materialize(*args, **kwargs)

    def counted_decompose(*args, **kwargs):
        calls["decompose"] += 1
        return original_decompose(*args, **kwargs)

    monkeypatch.setattr(document_programs, "materialize_reviewed_batch", counted_materialize)
    monkeypatch.setattr(document_programs, "decompose_reviewed_batch", counted_decompose)
    first = programs.inspect("nist-sp-800-100-page-39")
    second = programs.inspect("nist-sp-800-100-page-39")
    assert first == second
    assert calls == {"materialize": 1, "decompose": 1}


def test_reviewed_inspect_rejects_package_registry_drift(monkeypatch):
    programs = ReviewedDocumentPrograms(build_pack()["semantic_pack"])
    monkeypatch.setattr(programs, "_source_citations", lambda package, digest: [])
    package_id = "nist-sp-800-100-page-39"
    original = document_programs._PACKAGES[package_id]["sha256"]
    programs.inspect(package_id)
    document_programs._PACKAGES[package_id]["sha256"] = "0" * 64
    try:
        with pytest.raises(ReviewedDocumentProgramError, match="package hash mismatch"):
            programs.inspect(package_id)
    finally:
        document_programs._PACKAGES[package_id]["sha256"] = original


def test_reviewed_execute_avoids_repeat_definition_context_build(monkeypatch):
    programs = ReviewedDocumentPrograms(build_pack()["semantic_pack"])
    monkeypatch.setattr(programs, "_source_citations", lambda package, digest: [])
    calls = 0
    original_context = programs._definition_context

    def counted_context(base, materialized):
        nonlocal calls
        calls += 1
        return original_context(base, materialized)

    monkeypatch.setattr(programs, "_definition_context", counted_context)
    request = {
        "request_id": "cache-request-001",
        "scenario_id": "cache-scenario-001",
        "entities": {"org-a": "organization"},
        "facts": [
            {
                "id": "needs-a",
                "predicate": "needs_assessment_conducted",
                "arguments": {"organization": "org-a"},
                "value": True,
            },
            {
                "id": "strategy",
                "predicate": "strategy_developed",
                "arguments": {"organization": "org-a"},
                "value": True,
            },
        ],
        "bindings": {"evaluate_named_prerequisite_facts": {"organization": ["org-a"]}},
        "unknowns": [],
    }
    first = programs.execute("nist-sp-800-100-page-39", request)
    second = programs.execute("nist-sp-800-100-page-39", request)
    assert first == second
    assert calls == 1


def test_reviewed_inspect_rejects_base_pack_drift(monkeypatch):
    programs = ReviewedDocumentPrograms(build_pack()["semantic_pack"])
    monkeypatch.setattr(programs, "_source_citations", lambda package, digest: [])
    programs.inspect("nist-sp-800-100-page-39")
    programs.base["domain"][0]["label"] += " changed"
    with pytest.raises(ReviewedDocumentProgramError, match="base semantic pack drift"):
        programs.inspect("nist-sp-800-100-page-39")
