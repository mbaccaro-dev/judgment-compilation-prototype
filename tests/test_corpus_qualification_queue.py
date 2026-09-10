from copy import deepcopy

import pytest

import judgment_compilation.corpus_qualification_queue as queue_module
import judgment_compilation.raw_judgment_candidates as raw_judgment_module
import judgment_compilation.raw_semantic_compiler as raw_compiler_module
from judgment_compilation.corpus_qualification_queue import (
    CEILING, REVIEW_STATE, CorpusQualificationQueueError,
    build_corpus_qualification_queue, compact_entry_from_raw_record,
    iter_document_qualification_shards, plan_corpus_qualification_shards,
    queue_sha256, rederive_compact_entries, rederive_compact_entry, serialize_queue,
    validate_compact_entry, validate_compact_shard,
)
from judgment_compilation.raw_semantic_compiler import RawSemanticCompiler


def _records():
    compiler = RawSemanticCompiler()
    return [next(compiler.iter_candidates(stacks=(stack,), limit=1))
            for stack in ("DOMAIN", "JUDGMENT", "WORK")]


class _Projection:
    def __init__(self, publication_id):
        self.publication_id = publication_id

    def summary(self):
        return {"corpus_id": "fixture-corpus", "corpus_release": "fixture-release",
                "manifest_sha256": "f" * 64, "document_count": 1,
                "physical_page_count": 3}

    def iter_documents(self):
        yield {"publication_id": self.publication_id, "document_index": 1,
               "page_count": 3}


class _FakeCompiler:
    def __init__(self, records):
        self.records = [deepcopy(record) for record in records]
        self.projection = _Projection(self.records[0]["raw_candidate"].get(
            "document", self.records[0]["raw_candidate"].get("source"))["publication_id"])
        self.calls = 0
        self.provenance_calls = 0
        self.batch_provenance_calls = 0
        self.requests = []

    def iter_candidates(self, *, publication_id=None, stacks=None, **_ignored):
        self.calls += 1
        self.requests.append((publication_id, stacks))
        for record in self.records:
            raw = record["raw_candidate"]
            source = raw.get("document", raw.get("source"))
            if publication_id is not None and source["publication_id"] != publication_id:
                continue
            if stacks is not None and record["stack"] not in stacks:
                continue
            yield deepcopy(record)

    def validate_candidate_provenance(self, record):
        self.provenance_calls += 1
        return deepcopy(record)

    def validate_candidate_provenance_many(self, records):
        self.batch_provenance_calls += 1
        return [deepcopy(record) for record in records]


class _LegacyCompiler(_FakeCompiler):
    """Existing stacks-only compiler port retained for queue compatibility."""

    def iter_candidates(self, *, stacks=None):
        yield from super().iter_candidates(publication_id=None, stacks=stacks)


def test_production_planner_streams_once_in_compact_bounded_shards():
    compiler = _FakeCompiler(_records())
    planner = plan_corpus_qualification_shards(compiler, shard_size=1)
    shards = list(planner.iter_shards())

    assert compiler.calls == 1
    assert [shard["entry_count"] for shard in shards] == [1, 1, 1]
    assert all(validate_compact_shard(shard) == shard for shard in shards)
    assert all("raw_record" not in entry for shard in shards for entry in shard["entries"])
    assert all(entry["review_state"] == REVIEW_STATE for shard in shards for entry in shard["entries"])
    assert all(entry["claim_ceiling"] == CEILING for shard in shards for entry in shard["entries"])
    assert all("exact_quote" not in entry["source"] for shard in shards for entry in shard["entries"])

    summary = planner.summary()
    assert summary["proposed_candidate_count"] == 3
    assert summary["documents"][0]["pending_review_count"] == 3
    assert summary["documents"][0]["stack_counts"] == {"DOMAIN": 1, "JUDGMENT": 1, "WORK": 1, "ARCHITECTURE": 0}
    repeat = plan_corpus_qualification_shards(_FakeCompiler(_records()), shard_size=1)
    repeat_shards = list(repeat.iter_shards())
    assert [item["shard_id"] for item in shards] == [item["shard_id"] for item in repeat_shards]
    assert summary["compact_entry_stream_sha256"] == repeat.summary()["compact_entry_stream_sha256"]
    with pytest.raises(CorpusQualificationQueueError):
        list(planner.iter_shards())


def test_compact_entry_rederives_and_rejects_source_tampering():
    record = _records()[0]
    compiler = _FakeCompiler([record])
    entry = compact_entry_from_raw_record(record)
    assert rederive_compact_entry(compiler, entry) == entry
    assert compiler.batch_provenance_calls == 1
    assert compiler.provenance_calls == 0
    assert compiler.requests == [(entry["source"]["publication_id"], (entry["stack"],))]

    tampered = deepcopy(entry)
    tampered["source"]["page_text_sha256"] = "0" * 64
    with pytest.raises(CorpusQualificationQueueError):
        validate_compact_entry(tampered)
    with pytest.raises(CorpusQualificationQueueError):
        rederive_compact_entry(compiler, tampered)

    promoted = deepcopy(entry)
    promoted["review_state"] = "QUALIFIED"
    with pytest.raises(CorpusQualificationQueueError):
        validate_compact_entry(promoted)


def test_compact_entry_rederivation_keeps_legacy_compiler_port_compatibility():
    record = _records()[0]
    compiler = _LegacyCompiler([record])
    entry = compact_entry_from_raw_record(record)

    assert rederive_compact_entry(compiler, entry) == entry
    assert compiler.requests == [(None, (entry["stack"],))]
    assert compiler.batch_provenance_calls == 1


def test_compact_package_uses_one_batch_provenance_port_call():
    records = _records()
    compiler = _FakeCompiler(records)
    entries = [compact_entry_from_raw_record(record) for record in records]

    assert rederive_compact_entries(compiler, entries) == entries
    assert compiler.batch_provenance_calls == 1
    assert compiler.provenance_calls == 0


def test_document_local_shards_are_deterministic_and_compact():
    records = _records()
    publication_id = records[0]["raw_candidate"]["document"]["publication_id"]
    first = list(iter_document_qualification_shards(_FakeCompiler(records), publication_id, shard_size=2))
    second = list(iter_document_qualification_shards(_FakeCompiler(records), publication_id, shard_size=2))
    assert [shard["shard_id"] for shard in first] == [shard["shard_id"] for shard in second]
    assert all(shard["scope"] == "DOCUMENT:" + publication_id for shard in first)
    assert all("raw_record" not in entry for shard in first for entry in shard["entries"])


def test_fixture_builder_is_order_stable_lossless_and_capped():
    records = _records()
    forward = build_corpus_qualification_queue(records, shard_size=2)
    reverse = build_corpus_qualification_queue(list(reversed(records)), shard_size=2)
    assert serialize_queue(forward) == serialize_queue(reverse)
    assert queue_sha256(forward) == forward["queue_sha256"]
    assert forward["proposed_candidate_count"] == 3

    old_limit = queue_module.MAX_IN_MEMORY_RECORDS
    queue_module.MAX_IN_MEMORY_RECORDS = 1
    try:
        with pytest.raises(CorpusQualificationQueueError, match="in-memory"):
            build_corpus_qualification_queue(records[:2], shard_size=1)
    finally:
        queue_module.MAX_IN_MEMORY_RECORDS = old_limit


def test_bounded_real_corpus_smoke_keeps_only_a_compact_reference():
    record = next(RawSemanticCompiler().iter_candidates(limit=1))
    entry = compact_entry_from_raw_record(record)
    assert entry["candidate_id"] == record["candidate_id"]
    assert entry["raw_record_sha256"]
    assert entry["source"]["source_id"].startswith("raw-source:")
    assert "raw_record" not in entry and "exact_quote" not in entry["source"]


def test_judgment_publication_filter_preserves_candidates_without_foreign_page_reads(
        monkeypatch):
    """A document-scoped replay must select before, rather than after, page reads."""
    target = "NIST-SP-800-target"
    foreign = "NIST-SP-800-foreign"

    def page(publication_id, text):
        return {
            "record_type": "PAGE", "view": "plain", "document_index": 1,
            "publication_id": publication_id, "pdf_page_index": 0,
            "pdf_page_number": 1, "source_file": {"path": publication_id},
            "source_sha256": publication_id + "-sha",
            "extracted_file": {"path": publication_id + ".jsonl"},
            "text": text, "text_sha256": publication_id + "-text-sha",
            "manifest_sha256": "f" * 64,
        }

    class _PageProjection:
        instances = []

        def __init__(self, *_args):
            self.read_publications = []
            self.__class__.instances.append(self)

        def iter_pages(self, *, view, publication_id=None):
            assert view == "plain"
            pages = {
                target: page(target, "The agency shall retain the record."),
                foreign: page(foreign, "The agency must document the exception."),
            }
            selected = pages if publication_id is None else {publication_id: pages[publication_id]}
            for item in selected.values():
                self.read_publications.append(item["publication_id"])
                yield item

    monkeypatch.setattr(raw_judgment_module, "DocumentaryProjection", _PageProjection)
    full = list(raw_judgment_module.iter_raw_judgment_candidates(
        root="fixture-root", manifest_sha256="f" * 64))
    filtered = list(raw_judgment_module.iter_raw_judgment_candidates(
        root="fixture-root", manifest_sha256="f" * 64, publication_id=target))
    assert filtered == [candidate for candidate in full
                        if candidate["source"]["publication_id"] == target]
    assert _PageProjection.instances[-1].read_publications == [target]

    compiler = RawSemanticCompiler.__new__(RawSemanticCompiler)
    compiler.root = "fixture-root"
    compiler.manifest_sha256 = "f" * 64
    requests = []

    def fake_judgments(*, root, manifest_sha256, publication_id=None):
        requests.append((root, manifest_sha256, publication_id))
        return iter(filtered)

    monkeypatch.setattr(raw_compiler_module, "iter_raw_judgment_candidates", fake_judgments)
    rows = list(compiler.iter_candidates(publication_id=target, stacks=("JUDGMENT",)))
    assert [row["candidate_id"] for row in rows] == [candidate["candidate_id"] for candidate in filtered]
    assert compiler._rederive_raw("JUDGMENT", filtered[0]["candidate_id"], target) == filtered[0]
    assert requests == [("fixture-root", "f" * 64, target),
                        ("fixture-root", "f" * 64, target)]
