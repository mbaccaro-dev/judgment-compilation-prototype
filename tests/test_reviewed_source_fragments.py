"""Tests package behavior."""
from hashlib import sha256
import pytest
from judgment_compilation.document_programs import ReviewedDocumentPrograms, ReviewedDocumentProgramError
from judgment_compilation.kernel import canonical, digest, Rejected
from judgment_compilation.library import DocumentLibrary
from judgment_compilation.nist import build_pack


@pytest.fixture
def long_source(tmp_path):
    # Includes a whole whitespace chunk and Unicode code points at boundaries.
    text = "A" + " " * 2100 + "\n".join(
        f"Clause {i}: preserve original source evidence α." for i in range(70))
    files = []
    def save(name, raw):
        (tmp_path / name).write_bytes(raw)
        descriptor = {"path": name, "bytes": len(raw), "sha256": sha256(raw).hexdigest()}
        files.append(descriptor)
        return descriptor
    pdf = save("source.pdf", b"fixture source bytes")
    page = {"pub_id": "Publication 1", "source_sha256": pdf["sha256"],
            "pdf_page_index": 0, "pdf_page_number": 1, "text": text,
            "char_count": len(text), "text_sha256": sha256(text.encode()).hexdigest()}
    extraction = {view: save(view + ".jsonl", canonical(dict(page, view=view)) + b"\n")
                  for view in ("plain", "layout", "coverage")}
    manifest = {"documents": [{"publication_id": "Publication 1", "title": "Fixture",
                "page_count": 1, "pdf": pdf, "extraction": extraction,
                "publication_metadata": {"revision": "1"}}], "files": files,
                "document_count": 1, "physical_page_count": 1, "corpus_id": "fixture",
                "corpus_release": "frozen-1", "coverage_ceiling": "EXTRACTED_TEXT_ONLY"}
    raw = canonical(manifest)
    (tmp_path / "manifest.json").write_bytes(raw)
    library = DocumentLibrary(tmp_path, sha256(raw).hexdigest())
    anchor = {"source_id": "Publication 1",
              "locator": f"retained-nist://fixture/sha256/{pdf['sha256']}/pdf-page-index/0/char/0:{len(text)}",
              "quote_sha256": sha256(text.encode()).hexdigest()}
    package = {"sources": [{"publication_id": "Publication 1", "source_file": pdf}],
               "support": anchor}
    programs = ReviewedDocumentPrograms(build_pack()["semantic_pack"], library)
    return programs, package, text, tmp_path


def test_long_anchor_fragments_cover_every_non_whitespace_character(long_source):
    programs, package, text, _root = long_source
    citations = programs._source_citations(package, digest(package))
    assert len(citations) > 1
    covered = set()
    for item in citations:
        assert item["semantic_locator"] == package["support"]["locator"]
        assert item["semantic_quote_sha256"] == package["support"]["quote_sha256"]
        citation = item["citation"]
        start, end = citation["provenance"]["character_span"]
        quote = citation["claim"]["text"]
        assert quote == text[start:end] and 0 < len(quote) <= 1000
        assert not quote[0].isspace() and not quote[-1].isspace()
        assert not covered.intersection(range(start, end))
        covered.update(range(start, end))
        assert citation["returned_occurrences"] == citation["total_occurrences"]
        assert citation["truncated"] is False
    assert {i for i, char in enumerate(text) if not char.isspace()} <= covered


def test_long_anchor_rejects_bad_full_quote_hash_before_fragmenting(long_source):
    programs, package, _text, _root = long_source
    package["support"]["quote_sha256"] = "0" * 64
    with pytest.raises(ReviewedDocumentProgramError, match="quote drift"):
        programs._source_citations(package, digest(package))


def test_cached_fragments_reject_retained_input_drift(long_source):
    programs, package, _text, root = long_source
    programs._source_citations(package, digest(package))
    source = root / "source.pdf"
    data = source.read_bytes()
    source.write_bytes(bytes([data[0] ^ 1]) + data[1:])
    with pytest.raises(Rejected, match="library input drift"):
        programs._source_citations(package, digest(package))
