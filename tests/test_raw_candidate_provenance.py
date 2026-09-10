"""Tests package behavior."""
from copy import deepcopy
import hashlib
import json

import pytest

import judgment_compilation.raw_candidate_provenance as provenance_module
from judgment_compilation.raw_candidate_provenance import (
    CANDIDATE_STATUS,
    NOT_ADMITTED,
    OCCURRENCE_SCOPE,
    OccurrenceInventoryCache,
    RAW_CLAIM_KIND,
    SCHEMA,
    RawCandidateProvenanceError,
    corpus_accounting,
    digest,
    normalized_spans,
    recompute_occurrence_inventory,
    validate_raw_candidate,
)
from judgment_compilation.documentary_projection import DocumentaryProjection


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _write(root, relative, raw, files):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    descriptor = {"path": relative, "bytes": len(raw), "sha256": _sha(raw)}
    files.append(descriptor)
    return descriptor


@pytest.fixture
def raw_library(tmp_path):
    files, documents = [], []
    for index, text in enumerate(("Alpha support. Alpha support.", "ALPHA\nsupport."), 1):
        publication_id = f"DOC-{index}"
        pdf = _write(tmp_path, f"pdf/{index}.pdf", f"pdf-{index}".encode(), files)
        page = {
            "pub_id": publication_id,
            "source_sha256": pdf["sha256"],
            "pdf_page_index": 0,
            "pdf_page_number": 1,
            "view": "plain",
            "text": text,
            "char_count": len(text),
            "text_sha256": _sha(text.encode()),
        }
        plain = _write(tmp_path, f"pages/{index}/plain.jsonl",
                       (json.dumps(page, sort_keys=True) + "\n").encode(), files)
        layout = _write(tmp_path, f"pages/{index}/layout.jsonl",
                        (json.dumps({**page, "view": "layout"}, sort_keys=True) + "\n").encode(), files)
        coverage = {
            "pub_id": publication_id,
            "source_sha256": pdf["sha256"],
            "pdf_page_index": 0,
            "pdf_page_number": 1,
            "coverage_status": "DUAL_VIEW",
            "plain_text_sha256": page["text_sha256"],
            "layout_text_sha256": page["text_sha256"],
        }
        coverage_file = _write(tmp_path, f"pages/{index}/coverage.jsonl",
                               (json.dumps(coverage, sort_keys=True) + "\n").encode(), files)
        documents.append({
            "document_index": index,
            "publication_id": publication_id,
            "title": publication_id,
            "page_count": 1,
            "encrypted": False,
            "pdf": pdf,
            "extraction": {"plain": plain, "layout": layout, "coverage": coverage_file},
            "coverage_status_counts": {"DUAL_VIEW": 1},
            "publication_metadata": {},
            "interpretation_status": "DOCUMENTARY_SOURCE_ONLY_NOT_COMPILED_JUDGMENT",
        })
    manifest = {
        "schema_version": "1",
        "corpus_id": "fixture-corpus",
        "corpus_release": "fixture-r1",
        "coverage_ceiling": "DOCUMENTARY_ONLY",
        "document_count": 2,
        "physical_page_count": 2,
        "documents": documents,
        "files": files,
    }
    raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    (tmp_path / "manifest.json").write_bytes(raw)
    return tmp_path, _sha(raw), documents


def _candidate(root, manifest_sha256, documents):
    text = "Alpha support"
    source = documents[0]["pdf"]["sha256"]
    page_hash = _sha(b"Alpha support. Alpha support.")
    quote_hash = _sha(text.encode())
    provenance = {
        "publication_id": "DOC-1",
        "source_pdf_sha256": source,
        "physical_pdf_page_index": 0,
        "view": "plain",
        "page_text_sha256": page_hash,
        "character_span": [0, len(text)],
        "exact_quote": text,
        "exact_quote_sha256": quote_hash,
        "normalized_quote_sha256": _sha(normalized_spans(text)[0].encode()),
    }
    claim = {"kind": RAW_CLAIM_KIND, "text": text, "text_sha256": quote_hash}
    edge = {
        "id": "candidate-support-1",
        "candidate_id": "raw-candidate-1",
        "claim_text_sha256": quote_hash,
        "provenance_sha256": digest(provenance),
    }
    return {
        "schema": SCHEMA,
        "candidate_id": "raw-candidate-1",
        "candidate_status": CANDIDATE_STATUS,
        "semantic_admission_status": NOT_ADMITTED,
        "interpretation_status": "DOCUMENTARY_SOURCE_ONLY_NOT_COMPILED_JUDGMENT",
        "context": {"corpus_id": "fixture-corpus", "corpus_release": "fixture-r1",
                    "manifest_sha256": manifest_sha256},
        "claim": claim,
        "provenance": provenance,
        "occurrence_inventory": recompute_occurrence_inventory(text, root, manifest_sha256),
        "support_edges": [edge],
        "support_graph_sha256": digest([edge]),
        "claim_ceiling": "RAW_DOCUMENT_AND_EXTRACTION_IDENTITY_ONLY;NO_SEMANTIC_ADMISSION_OR_TRUTH",
    }


def test_valid_candidate_recomputes_all_occurrences_and_corpus_accounting(raw_library):
    root, manifest_sha256, documents = raw_library
    candidate = _candidate(root, manifest_sha256, documents)
    validated = validate_raw_candidate(candidate, root, manifest_sha256,
                                       expected_support_edges=candidate["support_edges"])
    assert validated == candidate
    assert candidate["occurrence_inventory"]["scope"] == OCCURRENCE_SCOPE
    assert candidate["occurrence_inventory"]["count"] == 3
    assert corpus_accounting(root, manifest_sha256) == {
        "status": "VERIFIED_RAW_CORPUS_ACCOUNTING",
        "manifest_sha256": manifest_sha256,
        "corpus_id": "fixture-corpus",
        "corpus_release": "fixture-r1",
        "document_count": 2,
        "physical_page_count": 2,
        "claim_ceiling": "RAW_DOCUMENT_AND_EXTRACTION_IDENTITY_ONLY;NO_SEMANTIC_ADMISSION_OR_TRUTH",
    }


def test_occurrence_cache_prepares_many_unique_quotes_in_one_normalized_page_pass(
        raw_library, monkeypatch):
    root, manifest_sha256, _documents = raw_library
    quotes = ("Alpha support", "support", "Alpha")
    expected = {
        quote: recompute_occurrence_inventory(quote, root, manifest_sha256)
        for quote in quotes
    }
    page_texts = {"Alpha support. Alpha support.", "ALPHA\nsupport."}
    normalizations = 0
    original = provenance_module.normalized_spans

    def counted(text):
        nonlocal normalizations
        if text in page_texts:
            normalizations += 1
        return original(text)

    monkeypatch.setattr(provenance_module, "normalized_spans", counted)
    cache = OccurrenceInventoryCache(root, manifest_sha256)
    assert cache.prepare(quotes) == expected
    # Three different candidate texts use one page traversal and normalize each
    # plain page once.  A per-candidate scan would produce six normalizations.
    assert normalizations == 2
    assert [cache.inventory(quote) for quote in quotes] == [expected[quote] for quote in quotes]
    assert normalizations == 2
    assert cache.corpus_binding == {
        "root": str(root.resolve()),
        "manifest_sha256": manifest_sha256,
        "corpus_id": "fixture-corpus",
        "corpus_release": "fixture-r1",
        "physical_page_count": 2,
    }


def test_occurrence_cache_invalidates_on_bound_plain_corpus_drift(raw_library):
    root, manifest_sha256, _documents = raw_library
    cache = OccurrenceInventoryCache(root, manifest_sha256)
    assert cache.inventory("Alpha support")["count"] == 3
    page = root / "pages/1/plain.jsonl"
    page.write_bytes(b"drifted plain-page input")
    with pytest.raises(Exception, match="drift"):
        cache.inventory("Alpha support")


def test_occurrence_cache_rejects_a_different_corpus_identity(raw_library, tmp_path):
    root, manifest_sha256, _documents = raw_library
    cache = OccurrenceInventoryCache(root, manifest_sha256)
    with pytest.raises(RawCandidateProvenanceError, match="corpus identity"):
        recompute_occurrence_inventory("Alpha support", tmp_path / "other-corpus", manifest_sha256,
                                       occurrence_cache=cache)


@pytest.mark.parametrize("mutate", [
    lambda c: c["provenance"].update(publication_id="DOC-2"),
    lambda c: c["provenance"].update(source_pdf_sha256="0" * 64),
    lambda c: c["provenance"].update(physical_pdf_page_index=1),
    lambda c: c["provenance"].update(character_span=[1, 14]),
    lambda c: c["provenance"].update(exact_quote="forged quote"),
    lambda c: c["claim"].update(text="changed semantic claim"),
    lambda c: c["context"].update(corpus_id="other-corpus"),
    lambda c: c.update(scenario_id="other-scenario"),
    lambda c: c.update(candidate_status="ADMITTED"),
    lambda c: c.update(semantic_admission_status="ADMITTED"),
    lambda c: c.pop("interpretation_status"),
    lambda c: c["occurrence_inventory"].update(count=2),
    lambda c: c["provenance"].update(storage_handle="pages/1/plain.jsonl"),
])
def test_raw_candidate_rejects_identity_replay_admission_and_storage_substitution(raw_library, mutate):
    root, manifest_sha256, documents = raw_library
    candidate = _candidate(root, manifest_sha256, documents)
    mutate(candidate)
    with pytest.raises(RawCandidateProvenanceError):
        validate_raw_candidate(candidate, root, manifest_sha256)


def test_support_graph_must_bind_the_candidate_and_external_graph(raw_library):
    root, manifest_sha256, documents = raw_library
    candidate = _candidate(root, manifest_sha256, documents)
    graph = deepcopy(candidate["support_edges"])
    assert validate_raw_candidate(candidate, root, manifest_sha256,
                                  expected_support_edges=graph) == candidate
    candidate["support_edges"][0]["claim_text_sha256"] = "0" * 64
    candidate["support_graph_sha256"] = digest(candidate["support_edges"])
    with pytest.raises(RawCandidateProvenanceError, match="support edge claim"):
        validate_raw_candidate(candidate, root, manifest_sha256, expected_support_edges=graph)


def test_external_support_graph_drift_is_rejected_even_when_candidate_is_unchanged(raw_library):
    root, manifest_sha256, documents = raw_library
    candidate = _candidate(root, manifest_sha256, documents)
    graph = deepcopy(candidate["support_edges"])
    graph[0]["id"] = "altered-edge"
    with pytest.raises(RawCandidateProvenanceError, match="support graph differs"):
        validate_raw_candidate(candidate, root, manifest_sha256, expected_support_edges=graph)
