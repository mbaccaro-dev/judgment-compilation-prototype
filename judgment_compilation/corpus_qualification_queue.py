"""Groups source matches for review."""
from __future__ import annotations

from hashlib import sha256
import inspect
import json
from typing import Any, Iterable, Iterator

from .raw_program_graphs import source_id
from .raw_semantic_compiler import (CEILING as COMPILER_CEILING,
    NOT_ADMITTED_SEMANTICS, RECORD_TYPE, SCHEMA as COMPILER_SCHEMA,
    RawSemanticCompiler)

SCHEMA = "jc/corpus-qualification-queue/1"
COMPACT_ENTRY_SCHEMA = "jc/corpus-qualification-entry/1"
SHARD_SCHEMA = "jc/corpus-qualification-shard/1"
STREAM_SUMMARY_SCHEMA = "jc/corpus-qualification-stream-summary/1"
STATUS = "HELD_RAW_PROPOSALS_PENDING_REVIEW"
REVIEW_STATE = "RAW_PROPOSAL_PENDING_REVIEW"
STACKS = ("DOMAIN", "JUDGMENT", "WORK", "ARCHITECTURE")
MAX_IN_MEMORY_RECORDS = 1_000  # Limit records kept in memory.
MAX_SHARD_SIZE = 10_000
CEILING = ("DETERMINISTIC_SOURCE_BOUND_RAW_REVIEW_PLANNING_ONLY;NO_SEMANTIC_"
    "QUALIFICATION_OR_ADMISSION_OR_EXECUTABLE_APPLICABILITY_OR_COMPLIANCE_OR_"
    "RESPONSIBILITY_OR_EXTERNAL_EFFECT")

class CorpusQualificationQueueError(ValueError):
    """Raised when queue inputs or source records do not match."""

def canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise CorpusQualificationQueueError("invalid canonical queue JSON") from exc

def digest(value: Any) -> str:
    return sha256(canonical(value)).hexdigest()

def _copy(value: Any) -> Any:
    return json.loads(canonical(value))

def _need(condition: bool, message: str) -> None:
    if not condition:
        raise CorpusQualificationQueueError(message)

def _text(value: Any) -> bool:
    return type(value) is str and bool(value)

def _source_from_record(record: dict[str, Any]) -> dict[str, Any]:
    raw = record["raw_candidate"]
    try:
        if record["stack"] == "JUDGMENT":
            supplied = raw["source"]
            span = supplied["character_span"]
            source = {"publication_id": supplied["publication_id"],
                "source_pdf_sha256": supplied["source_sha256"],
                "physical_pdf_page_index": supplied["pdf_page_index"],
                "page_text_sha256": supplied["page_text_sha256"],
                "manifest_sha256": supplied["manifest_sha256"],
                "character_span": [span["start"], span["end"]],
                "exact_quote": supplied["exact_quote"],
                "exact_quote_sha256": supplied["exact_quote_sha256"]}
        else:
            source = {"publication_id": raw["document"]["publication_id"],
                "source_pdf_sha256": raw["document"]["pdf_sha256"],
                "physical_pdf_page_index": raw["physical_page_index"],
                "page_text_sha256": raw["page_text_sha256"],
                "manifest_sha256": raw["manifest_sha256"],
                "character_span": raw["character_span"], "exact_quote": raw["exact_quote"],
                "exact_quote_sha256": raw["exact_quote_sha256"]}
        source["source_id"] = source_id(source)
        return source
    except (KeyError, TypeError, ValueError) as exc:
        raise CorpusQualificationQueueError("raw record has invalid source binding") from exc

def _validate_raw_record(record: dict[str, Any]) -> None:
    _need(type(record) is dict, "raw record must be an object")
    required = {"schema", "record_type", "stack", "candidate_id", "raw_candidate",
        "semantic_admission_status", "provenance_validation", "claim_ceiling"}
    _need(set(record) == required, "raw record outer shape drifted")
    try:
        RawSemanticCompiler._validate_record_shape(record)
    except (KeyError, TypeError, ValueError) as exc:
        raise CorpusQualificationQueueError("raw compiler record is not held raw input") from exc
    _need(record["schema"] == COMPILER_SCHEMA and record["record_type"] == RECORD_TYPE,
        "raw compiler identity drifted")
    _need(record["stack"] in STACKS and record["semantic_admission_status"] == NOT_ADMITTED_SEMANTICS,
        "raw record is not a held proposal")
    _need(record["claim_ceiling"] == COMPILER_CEILING, "raw record ceiling drifted")
    _source_from_record(record)

def _compact_source(source: dict[str, Any]) -> dict[str, Any]:
    return {"source_id": source["source_id"], "source_integrity_sha256": source["source_id"].split(":", 1)[1],
        "manifest_sha256": source["manifest_sha256"], "publication_id": source["publication_id"],
        "source_pdf_sha256": source["source_pdf_sha256"],
        "physical_pdf_page_index": source["physical_pdf_page_index"],
        "page_text_sha256": source["page_text_sha256"], "character_span": _copy(source["character_span"]),
        "exact_quote_sha256": sha256(source["exact_quote"].encode("utf-8")).hexdigest()}

def compact_entry_from_raw_record(record: dict[str, Any]) -> dict[str, Any]:
    """Retain candidate and source identities, hashes, and no raw-record copy."""
    _validate_raw_record(record)
    entry = {"schema": COMPACT_ENTRY_SCHEMA, "review_state": REVIEW_STATE,
        "stack": record["stack"], "candidate_id": record["candidate_id"],
        "raw_record_sha256": digest(record), "source": _compact_source(_source_from_record(record)),
        "claim_ceiling": CEILING}
    entry["entry_id"] = "raw-qualification-entry:" + digest(entry)
    return entry

def validate_compact_entry(entry: dict[str, Any]) -> dict[str, Any]:
    expected = {"schema", "review_state", "stack", "candidate_id", "raw_record_sha256",
        "source", "claim_ceiling", "entry_id"}
    _need(type(entry) is dict and set(entry) == expected, "compact entry shape drifted")
    _need(entry["schema"] == COMPACT_ENTRY_SCHEMA and entry["review_state"] == REVIEW_STATE,
        "compact entry standing drifted")
    _need(entry["stack"] in STACKS and _text(entry["candidate_id"]), "invalid candidate identity")
    _need(_text(entry["raw_record_sha256"]) and len(entry["raw_record_sha256"]) == 64,
        "invalid raw record hash")
    _need(entry["claim_ceiling"] == CEILING, "compact entry ceiling drifted")
    source = entry["source"]
    source_keys = {"source_id", "source_integrity_sha256", "manifest_sha256", "publication_id", "source_pdf_sha256", "physical_pdf_page_index",
        "page_text_sha256", "character_span", "exact_quote_sha256"}
    _need(type(source) is dict and set(source) == source_keys, "compact source shape drifted")
    for key in source_keys - {"physical_pdf_page_index", "character_span"}:
        _need(_text(source[key]), "invalid compact source field")
    _need(type(source["physical_pdf_page_index"]) is int and source["physical_pdf_page_index"] >= 0,
        "invalid compact source page")
    _need(type(source["character_span"]) is list and len(source["character_span"]) == 2 and
        all(type(x) is int and x >= 0 for x in source["character_span"]) and
        source["character_span"][0] < source["character_span"][1], "invalid compact source span")
    _need(source["source_id"] == "raw-source:" + source["source_integrity_sha256"],
        "compact source integrity drifted")
    _need(len(source["exact_quote_sha256"]) == 64, "invalid compact quote hash")
    _need(entry["entry_id"] == "raw-qualification-entry:" + digest(
        {key: value for key, value in entry.items() if key != "entry_id"}), "compact entry identity drifted")
    return _copy(entry)

def rederive_compact_entries(compiler: Any, entries: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rebuild a bounded package and batch provenance when the port supports it."""

    expected_entries = [validate_compact_entry(entry) for entry in entries]
    _need(expected_entries, "at least one compact entry required")
    iterator = compiler.iter_candidates
    try:
        parameters = inspect.signature(iterator).parameters.values()
        supports_publication_id = any(
            parameter.name == "publication_id" or
            parameter.kind is inspect.Parameter.VAR_KEYWORD
            for parameter in parameters)
    except (TypeError, ValueError):
        # An opaque compiler port is treated as current; its call can still
        # Reject any wider source reproduction.
        supports_publication_id = True
    found_entries: list[dict[str, Any]] = []
    for expected in expected_entries:
        selection = {"stacks": (expected["stack"],)}
        if supports_publication_id:
            selection["publication_id"] = expected["source"]["publication_id"]
        found = [record for record in iterator(**selection)
                 if record.get("candidate_id") == expected["candidate_id"]]
        _need(len(found) == 1, "candidate cannot be uniquely rederived")
        found_entries.append(found[0])
    if hasattr(compiler, "validate_candidate_provenance_many"):
        compiler.validate_candidate_provenance_many(found_entries)
    elif hasattr(compiler, "validate_candidate_provenance"):
        for found in found_entries:
            compiler.validate_candidate_provenance(found)
    rebuilt_entries = [compact_entry_from_raw_record(found) for found in found_entries]
    for rebuilt, expected in zip(rebuilt_entries, expected_entries):
        _need(canonical(rebuilt) == canonical(expected),
              "compact entry no longer matches raw source")
    return rebuilt_entries


def rederive_compact_entry(compiler: Any, entry: dict[str, Any]) -> dict[str, Any]:
    """Single-entry compatibility wrapper for package-aware rederivation."""

    return rederive_compact_entries(compiler, [entry])[0]

def _make_shard(entries: list[dict[str, Any]], ordinal: int, scope: str) -> dict[str, Any]:
    _need(entries and len(entries) <= MAX_SHARD_SIZE, "invalid shard entry count")
    copied = [validate_compact_entry(entry) for entry in entries]
    _need(len({entry["entry_id"] for entry in copied}) == len(copied), "duplicate compact entry")
    shard = {"schema": SHARD_SCHEMA, "status": STATUS, "review_state": REVIEW_STATE,
        "scope": scope, "ordinal": ordinal, "entry_count": len(copied),
        "entry_stream_sha256": sha256(b"".join(canonical(x) + b"\n" for x in copied)).hexdigest(),
        "entries": copied, "claim_ceiling": CEILING}
    shard["shard_id"] = "raw-qualification-shard:" + digest(shard)
    return shard

def validate_compact_shard(shard: dict[str, Any]) -> dict[str, Any]:
    expected = {"schema", "status", "review_state", "scope", "ordinal", "entry_count",
        "entry_stream_sha256", "entries", "claim_ceiling", "shard_id"}
    _need(type(shard) is dict and set(shard) == expected, "shard shape drifted")
    _need(shard["schema"] == SHARD_SCHEMA and shard["status"] == STATUS and
        shard["review_state"] == REVIEW_STATE and shard["claim_ceiling"] == CEILING,
        "shard standing drifted")
    _need(_text(shard["scope"]) and type(shard["ordinal"]) is int and shard["ordinal"] >= 0,
        "invalid shard locator")
    _need(type(shard["entries"]) is list and 0 < len(shard["entries"]) <= MAX_SHARD_SIZE and
        shard["entry_count"] == len(shard["entries"]), "shard count drifted")
    entries = [validate_compact_entry(entry) for entry in shard["entries"]]
    _need(shard["entry_stream_sha256"] == sha256(b"".join(canonical(x) + b"\n" for x in entries)).hexdigest(),
        "shard entry stream drifted")
    _need(shard["shard_id"] == "raw-qualification-shard:" + digest(
        {key: value for key, value in shard.items() if key != "shard_id"}), "shard identity drifted")
    return _copy(shard)

def _documents_from_projection(compiler: Any) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    projection = getattr(compiler, "projection", None)
    _need(projection is not None and hasattr(projection, "summary") and hasattr(projection, "iter_documents"),
        "compiler does not expose documentary projection")
    summary = projection.summary()
    fields = {"corpus_id", "corpus_release", "manifest_sha256", "document_count", "physical_page_count"}
    _need(type(summary) is dict and fields <= set(summary), "projection summary drifted")
    docs: dict[str, dict[str, Any]] = {}
    for doc in projection.iter_documents():
        publication_id = doc["publication_id"]
        _need(publication_id not in docs, "projection duplicates publication id")
        docs[publication_id] = {"publication_id": publication_id, "document_index": doc["document_index"],
            "page_count": doc["page_count"], "pending_review_count": 0,
            "stack_counts": {stack: 0 for stack in STACKS}}
    _need(len(docs) == summary["document_count"], "projection document coverage drifted")
    return docs, {key: summary[key] for key in fields}

class CorpusQualificationShardPlanner:
    """Create at most one bounded shard from one compiler pass."""
    def __init__(self, compiler: Any | None = None, *, shard_size: int = 500) -> None:
        _need(type(shard_size) is int and 0 < shard_size <= MAX_SHARD_SIZE,
            "shard size exceeds bounded production limit")
        self.compiler = compiler if compiler is not None else RawSemanticCompiler()
        self.shard_size = shard_size
        self._documents, self._coverage = _documents_from_projection(self.compiler)
        self._started = self._completed = False
        self._entry_count = 0
        self._stream = sha256()
    def iter_shards(self) -> Iterator[dict[str, Any]]:
        _need(not self._started, "planner may only stream the corpus once")
        self._started = True
        entries: list[dict[str, Any]] = []
        ordinal = 0
        for record in self.compiler.iter_candidates():
            entry = compact_entry_from_raw_record(record)
            publication_id = entry["source"]["publication_id"]
            _need(publication_id in self._documents, "raw candidate document missing from projection")
            self._documents[publication_id]["pending_review_count"] += 1
            self._documents[publication_id]["stack_counts"][entry["stack"]] += 1
            self._entry_count += 1
            self._stream.update(canonical(entry) + b"\n")
            entries.append(entry)
            if len(entries) == self.shard_size:
                yield _make_shard(entries, ordinal, "CORPUS")
                ordinal, entries = ordinal + 1, []
        if entries:
            yield _make_shard(entries, ordinal, "CORPUS")
        self._completed = True
    def summary(self) -> dict[str, Any]:
        _need(self._completed, "consume the one-pass shard stream before requesting summary")
        return {"schema": STREAM_SUMMARY_SCHEMA, "status": STATUS, "review_state": REVIEW_STATE,
            "documentary_coverage": _copy(self._coverage), "documents": sorted(
                (_copy(doc) for doc in self._documents.values()), key=lambda x: (x["document_index"], x["publication_id"])),
            "proposed_candidate_count": self._entry_count,
            "compact_entry_stream_sha256": self._stream.hexdigest(), "shard_size": self.shard_size,
            "claim_ceiling": CEILING}

def plan_corpus_qualification_shards(compiler: Any | None = None, *, shard_size: int = 500) -> CorpusQualificationShardPlanner:
    return CorpusQualificationShardPlanner(compiler, shard_size=shard_size)

def build_corpus_qualification_queue_from_compiler(compiler: Any | None = None, *, shard_size: int = 500) -> CorpusQualificationShardPlanner:
    """Build a queue with the bounded shard planner."""
    return plan_corpus_qualification_shards(compiler, shard_size=shard_size)

def iter_document_qualification_shards(compiler: Any, publication_id: str, *, shard_size: int = 500) -> Iterator[dict[str, Any]]:
    _need(_text(publication_id) and type(shard_size) is int and 0 < shard_size <= MAX_SHARD_SIZE,
        "invalid document shard request")
    entries: list[dict[str, Any]] = []
    ordinal = 0
    for record in compiler.iter_candidates(publication_id=publication_id):
        entry = compact_entry_from_raw_record(record)
        _need(entry["source"]["publication_id"] == publication_id, "compiler document filter drifted")
        entries.append(entry)
        if len(entries) == shard_size:
            yield _make_shard(entries, ordinal, "DOCUMENT:" + publication_id)
            ordinal, entries = ordinal + 1, []
    if entries:
        yield _make_shard(entries, ordinal, "DOCUMENT:" + publication_id)

# Builds small records used by the tests.
def _normalise_records(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    result, seen = [], {}
    for record in records:
        _need(len(result) < MAX_IN_MEMORY_RECORDS, "fixture queue exceeds in-memory record limit")
        _validate_raw_record(record)
        item, item_hash = _copy(record), digest(record)
        prior = seen.get(item["candidate_id"])
        if prior is None:
            seen[item["candidate_id"]] = item_hash
            result.append(item)
        else:
            _need(prior == item_hash, "candidate id collision with distinct raw records")
    return result

def build_corpus_qualification_queue(records: Iterable[dict[str, Any]], *, document_coverage: Iterable[dict[str, Any]] | None = None, shard_size: int = 100) -> dict[str, Any]:
    """Capped embedded-record queue for small fixtures only."""
    _need(type(shard_size) is int and 0 < shard_size <= MAX_IN_MEMORY_RECORDS, "invalid fixture shard size")
    raw = _normalise_records(records)
    ordered = sorted(raw, key=lambda record: (compact_entry_from_raw_record(record)["source"]["publication_id"],
        compact_entry_from_raw_record(record)["source"]["physical_pdf_page_index"], record["stack"], record["candidate_id"]))
    entries = [{"review_state": REVIEW_STATE, "raw_record": record, "raw_record_sha256": digest(record)} for record in ordered]
    actual: dict[str, dict[str, Any]] = {}
    for record in ordered:
        source = _source_from_record(record); pub = source["publication_id"]
        item = actual.setdefault(pub, {"publication_id": pub, "pending_review_count": 0,
            "stack_counts": {stack: 0 for stack in STACKS}})
        item["pending_review_count"] += 1; item["stack_counts"][record["stack"]] += 1
    if document_coverage is not None:
        provided = {item["publication_id"] for item in document_coverage}
        _need(provided == set(actual), "document coverage does not match raw records")
    shards = []
    for start in range(0, len(entries), shard_size):
        members = entries[start:start + shard_size]
        shards.append({"ordinal": len(shards), "entry_count": len(members), "entries": members,
            "entry_ids_sha256": digest([member["raw_record"]["candidate_id"] for member in members])})
    queue = {"schema": SCHEMA, "status": STATUS, "review_state": REVIEW_STATE, "claim_ceiling": CEILING,
        "proposed_candidate_count": len(entries), "documents": sorted(actual.values(), key=lambda x: x["publication_id"]),
        "shard_size": shard_size, "shards": shards}
    queue["queue_sha256"] = digest(queue)
    return validate_corpus_qualification_queue(queue)

def validate_corpus_qualification_queue(queue: dict[str, Any]) -> dict[str, Any]:
    keys = {"schema", "status", "review_state", "claim_ceiling", "proposed_candidate_count", "documents", "shard_size", "shards", "queue_sha256"}
    _need(type(queue) is dict and set(queue) == keys and queue["schema"] == SCHEMA and queue["status"] == STATUS and
        queue["review_state"] == REVIEW_STATE and queue["claim_ceiling"] == CEILING, "fixture queue standing drifted")
    records = []
    for ordinal, shard in enumerate(queue["shards"]):
        _need(set(shard) == {"ordinal", "entry_count", "entries", "entry_ids_sha256"} and shard["ordinal"] == ordinal and
            shard["entry_count"] == len(shard["entries"]) <= queue["shard_size"], "fixture shard drifted")
        for entry in shard["entries"]:
            _need(set(entry) == {"review_state", "raw_record", "raw_record_sha256"} and entry["review_state"] == REVIEW_STATE,
                "fixture entry state drifted")
            _validate_raw_record(entry["raw_record"])
            _need(entry["raw_record_sha256"] == digest(entry["raw_record"]), "fixture raw record hash drifted")
            records.append(entry["raw_record"])
    _need(len(records) == queue["proposed_candidate_count"] <= MAX_IN_MEMORY_RECORDS, "fixture queue count drifted")
    _need(queue["queue_sha256"] == digest({key: value for key, value in queue.items() if key != "queue_sha256"}), "fixture queue hash drifted")
    return _copy(queue)

def serialize_queue(queue: dict[str, Any]) -> bytes:
    return canonical(validate_corpus_qualification_queue(queue))

def queue_sha256(queue: dict[str, Any]) -> str:
    return validate_corpus_qualification_queue(queue)["queue_sha256"]
