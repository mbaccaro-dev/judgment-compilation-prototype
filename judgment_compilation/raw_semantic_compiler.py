"""Scans document text and reports source matches."""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Iterator

from .documentary_projection import DEFAULT_ROOT, MANIFEST_SHA256, DocumentaryProjection
from .raw_candidate_provenance import (
    CANDIDATE_STATUS,
    NOT_ADMITTED,
    OCCURRENCE_SCOPE,
    RAW_CLAIM_KIND,
    SCHEMA as PROVENANCE_SCHEMA,
    canonical as provenance_canonical,
    digest as provenance_digest,
    normalized_spans,
    OccurrenceInventoryCache,
    recompute_occurrence_inventory,
    validate_raw_candidate,
)
from .raw_domain_candidates import (
    RawDomainCandidateError,
    RawDomainCandidates,
    canonical as domain_canonical,
)
from .raw_judgment_candidates import (
    RawJudgmentCandidateError,
    iter_raw_judgment_candidates,
)
from .raw_work_architecture_candidates import (
    RawWorkArchitectureCandidateError,
    RawWorkArchitectureCandidates,
)


SCHEMA = "jc/raw-semantic-compiler/1"
RECORD_TYPE = "RAW_SEMANTIC_CANDIDATE"
PROPOSED = "PROPOSED_INTERPRETATION"
NOT_ADMITTED_SEMANTICS = "NOT_ADMITTED"
CEILING = (
    "FULL_RETAINED_LIBRARY_DOCUMENTARY_ACCOUNTING_AND_RAW_CANDIDATES_ONLY;"
    "NO_SEMANTIC_ADMISSION_OR_EXECUTABLE_APPLICABILITY_OR_COMPLIANCE_OR_"
    "RESPONSIBILITY_OR_EXTERNAL_EFFECT"
)
PROVENANCE_SCOPE = (
    "ON_DEMAND_EXACT_QUOTE_PROVENANCE_VALIDATION_AGAINST_FULL_FROZEN_PLAIN_"
    "PAGE_CORPUS;RAW_GENERATOR_PATTERN_AND_STATUS_REDERIVED_ON_VALIDATION"
)


class RawSemanticCompilerError(ValueError):
    """A raw candidate or its full-library accounting is invalid."""


def canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise RawSemanticCompilerError("invalid canonical compiler JSON") from exc


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise RawSemanticCompilerError(message)


def _raw_id(stack: str, candidate: dict[str, Any]) -> str:
    key = "source_candidate_id" if stack == "DOMAIN" else "candidate_id"
    value = candidate.get(key)
    _need(type(value) is str and value, "raw candidate identity missing")
    return value


class RawSemanticCompiler:
    """Scan the retained library for source matches without writing an index."""

    def __init__(self, root: Path | str = DEFAULT_ROOT,
                 manifest_sha256: str = MANIFEST_SHA256,
                 reviewed_program_index=None):
        self.root = Path(root).resolve()
        self.manifest_sha256 = manifest_sha256
        _need(reviewed_program_index is None or callable(reviewed_program_index),
              "reviewed program index provider must be callable or null")
        self._reviewed_program_index = reviewed_program_index
        try:
            self.projection = DocumentaryProjection(self.root, manifest_sha256)
            self.occurrence_cache = OccurrenceInventoryCache(self.root, manifest_sha256)
            self.domain = RawDomainCandidates(self.root, manifest_sha256)
            self.work_architecture = RawWorkArchitectureCandidates(
                self.root, manifest_sha256)
        except Exception as exc:
            raise RawSemanticCompilerError(str(exc)) from exc

    @staticmethod
    def _pipeline_record(stack: str, raw_candidate: dict[str, Any]) -> dict[str, Any]:
        _need(stack in {"DOMAIN", "JUDGMENT", "WORK", "ARCHITECTURE"},
              "unknown raw candidate stack")
        candidate_id = _raw_id(stack, raw_candidate)
        return {
            "schema": SCHEMA,
            "record_type": RECORD_TYPE,
            "stack": stack,
            "candidate_id": candidate_id,
            "raw_candidate": deepcopy(raw_candidate),
            "semantic_admission_status": NOT_ADMITTED_SEMANTICS,
            "provenance_validation": {
                "status": "AVAILABLE_ON_DEMAND_NOT_BULK_ATTESTED",
                "validator_schema": PROVENANCE_SCHEMA,
                "scope": PROVENANCE_SCOPE,
                "occurrence_scope": OCCURRENCE_SCOPE,
            },
            "claim_ceiling": CEILING,
        }

    def _raw_stream(self, stack: str, publication_id: str | None = None) -> Iterator[dict[str, Any]]:
        if stack == "DOMAIN":
            yield from self.domain.iter_candidates(publication_id=publication_id)
            return
        if stack == "JUDGMENT":
            try:
                for candidate in iter_raw_judgment_candidates(
                    root=self.root, manifest_sha256=self.manifest_sha256,
                    publication_id=publication_id,
                ):
                    _need(publication_id is None or
                          candidate["source"]["publication_id"] == publication_id,
                          "judgment publication filter drifted")
                    yield candidate
                return
            except RawJudgmentCandidateError as exc:
                raise RawSemanticCompilerError(str(exc)) from exc
        _need(stack in {"WORK", "ARCHITECTURE"}, "unknown raw candidate stack")
        try:
            for candidate in self.work_architecture.iter_candidates(publication_id=publication_id):
                candidate_stack = ("WORK" if candidate["candidate_kind"] == "WORK_OPERATION_INTERFACE"
                                   else "ARCHITECTURE")
                if candidate_stack == stack:
                    yield candidate
        except RawWorkArchitectureCandidateError as exc:
            raise RawSemanticCompilerError(str(exc)) from exc

    def iter_candidates(self, *, publication_id: str | None = None,
                        stacks: tuple[str, ...] | None = None,
                        offset: int = 0, limit: int | None = None) -> Iterator[dict[str, Any]]:
        """Yield stable pages of proposed candidates, never admitted semantics."""

        _need(type(offset) is int and offset >= 0, "offset must be a nonnegative integer")
        _need(limit is None or (type(limit) is int and limit >= 0),
              "limit must be a nonnegative integer or null")
        available = ("DOMAIN", "JUDGMENT", "WORK", "ARCHITECTURE")
        selected = available if stacks is None else stacks
        _need(type(selected) is tuple and selected and
              all(type(stack) is str and stack in available for stack in selected) and
              len(set(selected)) == len(selected),
              "stacks must be a nonempty unique tuple of known stack names")
        emitted = 0
        skipped = 0
        for stack in selected:
            for raw_candidate in self._raw_stream(stack, publication_id):
                if skipped < offset:
                    skipped += 1
                    continue
                if limit is not None and emitted >= limit:
                    return
                emitted += 1
                yield self._pipeline_record(stack, raw_candidate)

    @staticmethod
    def _raw_publication_id(stack: str, candidate: dict[str, Any]) -> str:
        if stack in {"DOMAIN", "WORK", "ARCHITECTURE"}:
            value = candidate.get("document", {}).get("publication_id")
        else:
            value = candidate.get("source", {}).get("publication_id")
        _need(type(value) is str and value, "raw candidate publication identity missing")
        return value

    @staticmethod
    def _coverage_report(raw_summary: Any, reviewed_program_index: Any) -> dict[str, Any]:
        """Join source-match counts with the reviewed package index."""
        _need(type(raw_summary) is dict, "raw summary required for publication coverage")
        coverage = raw_summary.get("documentary_coverage")
        rows = raw_summary.get("per_document")
        _need(type(coverage) is dict and type(rows) is list,
              "raw summary documentary rows required for publication coverage")
        manifest_sha256 = coverage.get("manifest_sha256")
        document_count = coverage.get("document_count")
        _need(type(manifest_sha256) is str and len(manifest_sha256) == 64 and
              all(char in "0123456789abcdef" for char in manifest_sha256) and
              type(document_count) is int and document_count >= 0,
              "raw summary documentary identity required for publication coverage")
        _need(len(rows) == document_count, "raw summary publication cardinality drift")

        documents: dict[str, dict[str, Any]] = {}
        for row in rows:
            publication_id = row.get("publication_id") if type(row) is dict else None
            _need(type(publication_id) is str and publication_id,
                  "raw summary publication identity missing")
            _need(publication_id not in documents,
                  "duplicate raw summary publication identity")
            _need(row.get("manifest_sha256") == manifest_sha256,
                  "raw summary publication manifest identity drift")
            _need(type(row.get("source_file")) is dict and
                  type(row.get("extraction_files")) is dict and
                  type(row.get("raw_candidate_evidence_sha256")) is str,
                  "raw summary publication source or extraction evidence missing")
            documents[publication_id] = deepcopy(row)

        _need(type(reviewed_program_index) is dict,
              "reviewed document package index required for publication coverage")
        _need(reviewed_program_index.get("schema") == "jc/reviewed-document-package-index/1" and
              reviewed_program_index.get("status") == "SOURCE_BOUND_NOT_EXECUTED" and
              reviewed_program_index.get("external_effects") == [],
              "reviewed document package index standing invalid")
        packages = reviewed_program_index.get("packages")
        _need(type(packages) is list, "reviewed document package registry required")
        packages_by_publication: dict[str, list[dict[str, str]]] = {
            publication_id: [] for publication_id in documents
        }
        package_ids: set[str] = set()
        for package in packages:
            package_id = package.get("id") if type(package) is dict else None
            publication_id = package.get("publication_id") if type(package) is dict else None
            package_sha256 = package.get("sha256") if type(package) is dict else None
            _need(type(package_id) is str and package_id,
                  "reviewed document package identity missing")
            _need(package_id not in package_ids,
                  "duplicate reviewed document package identity")
            _need(type(publication_id) is str and publication_id in documents,
                  "reviewed document package publication identity mismatches retained library")
            _need(type(package_sha256) is str and len(package_sha256) == 64 and
                  all(char in "0123456789abcdef" for char in package_sha256),
                  "reviewed document package evidence hash missing")
            package_ids.add(package_id)
            packages_by_publication[publication_id].append({
                "package_id": package_id,
                "package_sha256": package_sha256,
            })

        publications = []
        for publication_id, raw_row in sorted(
                documents.items(), key=lambda item: (item[1]["document_index"], item[0])):
            registered = sorted(packages_by_publication[publication_id], key=lambda item: item["package_id"])
            publications.append({
                "publication_id": publication_id,
                "document_index": raw_row["document_index"],
                "source_extraction_status": {
                    "manifest_sha256": raw_row["manifest_sha256"],
                    "source_file": deepcopy(raw_row["source_file"]),
                    "extraction_files": deepcopy(raw_row["extraction_files"]),
                    "coverage_status_counts": deepcopy(raw_row["coverage_status_counts"]),
                    "interpretation_status": raw_row["interpretation_status"],
                },
                "raw_candidates": {
                    name: raw_row[name]
                    for name in (
                        "domain_proposed_candidate_count", "judgment_proposed_candidate_count",
                        "work_proposed_candidate_count", "architecture_proposed_candidate_count",
                        "proposed_candidate_count", "raw_candidate_evidence_sha256",
                    )
                },
                "registered_reviewed_document_packages": registered,
                "semantic_disposition": {
                    "raw_candidates": NOT_ADMITTED_SEMANTICS,
                    "reviewed_passages": (
                        "SOURCE_REVIEWED_PASSAGES_ONLY" if registered
                        else "NO_REVIEWED_DOCUMENT_PACKAGE_REGISTERED"
                    ),
                    "whole_document_semantic_completion": "NOT_ESTABLISHED",
                    "reason": (
                        "RAW_CANDIDATES_REQUIRE_SEPARATE_INTERPRETATION_QUALIFICATION_AND_"
                        "REVIEWED_PASSAGES_DO_NOT_COMPLETE_A_DOCUMENT"
                    ),
                },
                "executable_applicability": {
                    "status": "NOT_ESTABLISHED_FOR_WHOLE_DOCUMENT",
                    "reason": (
                        "REGISTERED_REVIEWED_PACKAGES_ARE_BOUNDED_SOURCE_PASSAGES_AND_DO_NOT_"
                        "ESTABLISH_WHOLE_DOCUMENT_APPLICABILITY"
                    ),
                },
            })
        report = {
            "schema": "jc/raw-semantic-publication-coverage/1",
            "status": "FULL_RETAINED_LIBRARY_PUBLICATION_DISPOSITION_ACCOUNTED",
            "manifest_sha256": manifest_sha256,
            "raw_summary_sha256": sha256(canonical(raw_summary)).hexdigest(),
            "reviewed_document_package_index_sha256": sha256(
                canonical(reviewed_program_index)).hexdigest(),
            "publication_count": len(publications),
            "registered_reviewed_package_count": len(package_ids),
            "registered_reviewed_package_ids": sorted(package_ids),
            "publications": publications,
            "full_library_semantic_compilation": "INCOMPLETE",
            "residual": "FULL_LIBRARY_EXECUTABLE_SEMANTIC_COMPILATION_INCOMPLETE",
            "claim_ceiling": CEILING,
            "external_effects": [],
        }
        return report

    def summary(self) -> dict[str, Any]:
        """Account for all 195 PDFs without storing a candidate population."""

        documents: dict[str, dict[str, Any]] = {}
        try:
            for document in self.projection.iter_documents():
                publication_id = document["publication_id"]
                _need(publication_id not in documents,
                      "duplicate retained document publication identity")
                documents[publication_id] = {
                    "publication_id": publication_id,
                    "document_index": document["document_index"],
                    "physical_page_count": document["page_count"],
                    "manifest_sha256": document["manifest_sha256"],
                    "source_file": deepcopy(document["source_file"]),
                    "extraction_files": deepcopy(document["extraction_files"]),
                    "coverage_status_counts": deepcopy(document["coverage_status_counts"]),
                    "interpretation_status": document["interpretation_status"],
                    "domain_proposed_candidate_count": 0,
                    "judgment_proposed_candidate_count": 0,
                    "work_proposed_candidate_count": 0,
                    "architecture_proposed_candidate_count": 0,
                }
        except Exception as exc:
            raise RawSemanticCompilerError(str(exc)) from exc

        counts = {"DOMAIN": 0, "JUDGMENT": 0, "WORK": 0, "ARCHITECTURE": 0}
        stream_hash = sha256()
        document_stream_hashes = {publication_id: sha256() for publication_id in documents}
        count_keys = {
            "DOMAIN": "domain_proposed_candidate_count",
            "JUDGMENT": "judgment_proposed_candidate_count",
            "WORK": "work_proposed_candidate_count",
            "ARCHITECTURE": "architecture_proposed_candidate_count",
        }
        for stack in ("DOMAIN", "JUDGMENT", "WORK", "ARCHITECTURE"):
            for raw_candidate in self._raw_stream(stack):
                publication_id = self._raw_publication_id(stack, raw_candidate)
                _need(publication_id in documents, "raw candidate escaped retained document set")
                key = count_keys[stack]
                documents[publication_id][key] += 1
                counts[stack] += 1
                record = canonical(self._pipeline_record(stack, raw_candidate))
                stream_hash.update(record)
                stream_hash.update(b"\n")
                document_stream_hashes[publication_id].update(record)
                document_stream_hashes[publication_id].update(b"\n")

        projection_summary = self.projection.summary()
        _need(len(documents) == projection_summary["document_count"], "document accounting drift")
        _need(sum(row["physical_page_count"] for row in documents.values()) ==
              projection_summary["physical_page_count"], "page accounting drift")
        per_document = []
        for row in sorted(documents.values(), key=lambda item: (item["document_index"], item["publication_id"])):
            row = dict(row)
            row["proposed_candidate_count"] = (
                row["domain_proposed_candidate_count"] + row["judgment_proposed_candidate_count"] +
                row["work_proposed_candidate_count"] + row["architecture_proposed_candidate_count"]
            )
            row["raw_candidate_evidence_sha256"] = document_stream_hashes[
                row["publication_id"]].hexdigest()
            per_document.append(row)
        uncovered = [row["publication_id"] for row in per_document
                     if row["proposed_candidate_count"] == 0]
        result = {
            "schema": SCHEMA,
            "status": "FULL_LIBRARY_DOCUMENTARY_ACCOUNTED_RAW_CANDIDATES_ONLY",
            "documentary_coverage": {
                "manifest_sha256": self.manifest_sha256,
                "corpus_id": projection_summary["corpus_id"],
                "corpus_release": projection_summary["corpus_release"],
                "document_count": projection_summary["document_count"],
                "physical_page_count": projection_summary["physical_page_count"],
            },
            "proposed_candidates": {
                "domain_count": counts["DOMAIN"],
                "judgment_count": counts["JUDGMENT"],
                "work_count": counts["WORK"],
                "architecture_count": counts["ARCHITECTURE"],
                "total_count": sum(counts.values()),
                "ordered_stream_sha256": stream_hash.hexdigest(),
            },
            "admitted_semantics": {
                "domain_count": 0,
                "judgment_count": 0,
                "work_count": 0,
                "architecture_count": 0,
                "total_count": 0,
                "reason": "SEPARATE_INTERPRETATION_QUALIFICATION_HAS_NOT_ADMITTED_RAW_CANDIDATES",
            },
            "capability_status": {
                "judgment_decomposition": "NOT_IMPLEMENTED_BY_RAW_CANDIDATE_COMPILER",
                "work_decomposition": "NOT_IMPLEMENTED_BY_RAW_CANDIDATE_COMPILER",
                "architecture_decomposition": "NOT_IMPLEMENTED_BY_RAW_CANDIDATE_COMPILER",
                "architecture_composition": "NOT_IMPLEMENTED_BY_RAW_CANDIDATE_COMPILER",
                "executable_inquiry_program": "NOT_IMPLEMENTED_BY_RAW_CANDIDATE_COMPILER",
            },
            "capability_limitations": {
                "judgment_decomposition": "RAW_JUDGMENT_SIGNALS_HAVE_NO_QUALIFIED_RELATION_OR_EXECUTABLE_INTERFACE",
                "work_decomposition": "RAW_WORK_SIGNALS_HAVE_NO_QUALIFIED_OPERATION_INTERFACE_OR_IMPLEMENTATION",
                "architecture_decomposition": "RAW_ARCHITECTURE_SIGNALS_HAVE_NO_QUALIFIED_COMPOSITION_OR_EXECUTABLE_PROGRAM",
                "architecture_composition": "RAW_ARCHITECTURE_SIGNALS_HAVE_NO_QUALIFIED_COMPOSITION_OR_EXECUTABLE_PROGRAM",
                "executable_inquiry_program": "RAW_CANDIDATES_NEVER_CREATE_AN_EXECUTABLE_INQUIRY_PROGRAM",
            },
            "per_document": per_document,
            "uncovered_document_count": len(uncovered),
            "uncovered_document_ids": uncovered,
            "claim_ceiling": CEILING,
            "external_effects": [],
        }
        if self._reviewed_program_index is not None:
            try:
                index = self._reviewed_program_index()
            except Exception as exc:
                raise RawSemanticCompilerError(
                    "reviewed document package index unavailable for publication coverage"
                ) from exc
            result["publication_coverage"] = self._coverage_report(result, index)
        return result

    def _provenance_adapter(self, record: dict[str, Any]) -> dict[str, Any]:
        """Map one source-match row to the provenance validator format."""

        self._validate_record_shape(record)
        stack = record["stack"]
        raw = record["raw_candidate"]
        publication_id = self._raw_publication_id(stack, raw)
        if stack in {"DOMAIN", "WORK", "ARCHITECTURE"}:
            source = {
                "source_pdf_sha256": raw["document"]["pdf_sha256"],
                "physical_pdf_page_index": raw["physical_page_index"],
                "page_text_sha256": raw["page_text_sha256"],
                "character_span": raw["character_span"],
                "exact_quote": raw["exact_quote"],
                "exact_quote_sha256": raw["exact_quote_sha256"],
                # Compute the validator's case-folded text hash.
                "normalized_quote_sha256": None,
            }
        else:
            source = {
                "source_pdf_sha256": raw["source"]["source_sha256"],
                "physical_pdf_page_index": raw["source"]["pdf_page_index"],
                "page_text_sha256": raw["source"]["page_text_sha256"],
                "character_span": [raw["source"]["character_span"]["start"],
                                   raw["source"]["character_span"]["end"]],
                "exact_quote": raw["source"]["exact_quote"],
                "exact_quote_sha256": raw["source"]["exact_quote_sha256"],
                "normalized_quote_sha256": None,
            }
        # The source adapter uses its declared text normalizer.
        source["normalized_quote_sha256"] = sha256(
            normalized_spans(source["exact_quote"])[0].encode("utf-8")
        ).hexdigest()
        summary = self.projection.summary()
        candidate_id = "raw-provenance-adapter:" + record["candidate_id"]
        provenance = {"publication_id": publication_id, "view": "plain", **source}
        claim = {
            "kind": RAW_CLAIM_KIND,
            "text": source["exact_quote"],
            "text_sha256": source["exact_quote_sha256"],
        }
        edge = {
            "id": "source-support:" + candidate_id,
            "candidate_id": candidate_id,
            "claim_text_sha256": claim["text_sha256"],
            "provenance_sha256": provenance_digest(provenance),
        }
        return {
            "schema": PROVENANCE_SCHEMA,
            "candidate_id": candidate_id,
            "candidate_status": CANDIDATE_STATUS,
            "semantic_admission_status": NOT_ADMITTED,
            "interpretation_status": self.projection.documents[publication_id]["interpretation_status"],
            "context": {
                "corpus_id": summary["corpus_id"],
                "corpus_release": summary["corpus_release"],
                "manifest_sha256": self.manifest_sha256,
            },
            "claim": claim,
            "provenance": provenance,
            "occurrence_inventory": recompute_occurrence_inventory(
                claim["text"], self.root, self.manifest_sha256,
                occurrence_cache=self.occurrence_cache),
            "support_edges": [edge],
            "support_graph_sha256": provenance_digest([edge]),
            "claim_ceiling": "RAW_DOCUMENT_AND_EXTRACTION_IDENTITY_ONLY;NO_SEMANTIC_ADMISSION_OR_TRUTH",
        }

    @staticmethod
    def _raw_exact_quote(record: dict[str, Any]) -> str:
        """Extract the claim text without interpreting its source schema."""

        raw = record["raw_candidate"]
        quote = (raw["exact_quote"] if record["stack"] in {"DOMAIN", "WORK", "ARCHITECTURE"}
                 else raw["source"]["exact_quote"])
        _need(type(quote) is str and quote, "raw candidate exact quote missing")
        return quote

    @staticmethod
    def _validate_record_shape(record: dict[str, Any]) -> None:
        _need(type(record) is dict and set(record) == {
            "schema", "record_type", "stack", "candidate_id", "raw_candidate",
            "semantic_admission_status", "provenance_validation", "claim_ceiling",
        }, "unsupported compiler record shape")
        _need(record["schema"] == SCHEMA and record["record_type"] == RECORD_TYPE,
              "compiler record identity mismatch")
        _need(record["stack"] in {"DOMAIN", "JUDGMENT", "WORK", "ARCHITECTURE"},
              "invalid compiler stack")
        _need(record["semantic_admission_status"] == NOT_ADMITTED_SEMANTICS,
              "raw compiler cannot admit semantics")
        _need(record["claim_ceiling"] == CEILING, "compiler record ceiling mismatch")
        _need(record["candidate_id"] == _raw_id(record["stack"], record["raw_candidate"]),
              "compiler record raw identity mismatch")
        expected_validation = {
            "status": "AVAILABLE_ON_DEMAND_NOT_BULK_ATTESTED",
            "validator_schema": PROVENANCE_SCHEMA,
            "scope": PROVENANCE_SCOPE,
            "occurrence_scope": OCCURRENCE_SCOPE,
        }
        _need(record["provenance_validation"] == expected_validation,
              "compiler provenance-validation declaration changed")

    def _rederive_raw(self, stack: str, candidate_id: str,
                      publication_id: str | None = None) -> dict[str, Any]:
        if stack == "DOMAIN":
            for candidate in self.domain.iter_candidates(publication_id=publication_id):
                if candidate["source_candidate_id"] == candidate_id:
                    return candidate
        elif stack == "JUDGMENT":
            for candidate in self._raw_stream("JUDGMENT", publication_id):
                if candidate["candidate_id"] == candidate_id:
                    return candidate
        else:
            for candidate in self._raw_stream(stack, publication_id):
                if candidate["candidate_id"] == candidate_id:
                    return candidate
        raise RawSemanticCompilerError("raw candidate no longer rederives from frozen corpus")

    def validate_candidate_provenance_many(self, records: Any) -> list[dict[str, Any]]:
        """Verify a document package and its exact quote locations."""

        _need(type(records) in {list, tuple} and records,
              "nonempty compiler record sequence required")
        frozen = list(records)
        for record in frozen:
            self._validate_record_shape(record)
            try:
                actual = record["raw_candidate"]
                expected = self._rederive_raw(
                    record["stack"], record["candidate_id"],
                    self._raw_publication_id(record["stack"], actual),
                )
            except (RawDomainCandidateError, RawJudgmentCandidateError,
                    RawWorkArchitectureCandidateError) as exc:
                raise RawSemanticCompilerError(str(exc)) from exc
            comparison = domain_canonical if record["stack"] == "DOMAIN" else canonical
            _need(comparison(actual) == comparison(expected),
                  "raw candidate does not rederive from frozen corpus")
        # This is the amortization boundary: all exact, distinct claim texts
        # are prepared before any per-record adapter is checked.
        quotes = [self._raw_exact_quote(record) for record in frozen]
        if not self.occurrence_cache.has_all(quotes):
            self.occurrence_cache.prepare(quotes)
        for record in frozen:
            adapter = self._provenance_adapter(record)
            try:
                validate_raw_candidate(adapter, self.root, self.manifest_sha256,
                                       expected_support_edges=adapter["support_edges"],
                                       occurrence_cache=self.occurrence_cache)
            except Exception as exc:
                raise RawSemanticCompilerError(str(exc)) from exc
        return [deepcopy(json.loads(provenance_canonical(record))) for record in frozen]

    def validate_candidate_provenance(self, record: dict[str, Any]) -> dict[str, Any]:
        """Single-record compatibility wrapper for batch provenance validation."""

        return self.validate_candidate_provenance_many([record])[0]


__all__ = [
    "CEILING", "MANIFEST_SHA256", "NOT_ADMITTED_SEMANTICS", "PROPOSED",
    "PROVENANCE_SCOPE", "RECORD_TYPE", "SCHEMA", "RawSemanticCompiler",
    "RawSemanticCompilerError", "canonical",
]
