"""Loads and runs reviewed document checks."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import re
from typing import Any

from .kernel import strict_json
from .library import DocumentLibrary
from .qualified_definition_builder import recompose_qualified_definition
from .qualified_domain_builder import recompose_qualified_domain
from .qualified_predicate_builder import recompose_qualified_predicate
from .qualified_program_builder import execute_qualified_program
from .qualified_source_builder import recompose_qualified_source
from .reviewed_batch_materializer import (
    decompose_reviewed_batch, materialize_reviewed_batch,
    recompose_entity_kind_extensions,
)
from .semantic_contracts import digest, validate_semantic_pack


ROOT = Path(__file__).resolve().parent
PACKAGE_SCHEMA = "jc/reviewed-batch-input/4"
INDEX_SCHEMA = "jc/reviewed-document-package-index/1"
CEILING = (
    "SOURCE_REVIEWED_DOCUMENT_PROGRAM_ONLY;NO_PACK_ADMISSION_OR_SELECTION_OR_"
    "COMPLIANCE_OR_RESPONSIBILITY_OR_EXTERNAL_EFFECT"
)
_PACKAGES = {
    "nist-sp-800-100-page-39": {
        "file": "nist_sp_800_100_page_39.jc.json",
        "bytes": 37816,
        "sha256": "3e0b3c3baf72439f55b1de4d41daeed3b0b68dcc8e80a48db72b81a71cc7e7ec",
        "publication_id": "NIST SP 800-100-upd1",
        "title": "SP 800-100 page 39 named awareness-and-training prerequisite facts",
        "scope": (
            "Evaluates only whether a needs assessment and a strategy are both supplied as true "
            "for the same organization. It does not establish all prerequisites, adequacy, "
            "applicability, compliance, responsibility, or permission to implement."
        ),
    },
    "nist-sp-800-101-recovery-activity": {
        "file": "nist_sp_800_101_recovery_activity.jc.json",
        "bytes": 38846,
        "sha256": "e4dd0602408d391104df566555f40c226b031d27cd1493a577efff12aa0146f5",
        "publication_id": "NIST SP 800-101r1",
        "title": "SP 800-101 same-activity mobile-device recovery fact co-occurrence",
        "scope": (
            "Evaluates only whether three supplied facts are true for one identical recovery activity "
            "and mobile device. It does not establish recovery, forensic soundness, accepted methods, "
            "compliance, responsibility, legal sufficiency, authorization, or an external effect."
        ),
    },
    "nist-sp-800-30r1-table-g5": {
        "file": "nist_sp_800_30r1_table_g5.jc.json",
        "bytes": 35164,
        "sha256": "ca0273a808da03eaca0e7e4e0f96ad52674b51fd70754ef505119d4a70594b6e",
        "publication_id": "NIST SP 800-30r1",
        "title": "SP 800-30r1 Table G-5 overall likelihood lookup",
        "scope": (
            "Maps two caller-supplied Table G-5 likelihood labels to the table's overall-"
            "likelihood label for the same assessment subject. It does not establish that the "
            "input labels are correct, determine risk, claim compliance, assign responsibility, "
            "authorize an action, or cause an external effect."
        ),
    },
    "nist-sp-800-108-counter-mode-capacity-guard": {
        "file": "nist_sp_800_108_counter_mode_capacity_guard.jc.json",
        "bytes": 38100,
        "sha256": "2a26cc74f11ca27962c099b5be1303551a0f930d9629cb9034c3d7fd764f254c",
        "publication_id": "NIST SP 800-108r1-upd1",
        "title": "SP 800-108 Counter Mode strict n/r capacity-boundary guard",
        "scope": (
            "Evaluates only a caller-established Counter Mode strict n > (2^r - 1) boundary "
            "for typed n/r and r in 1..32. An exceedance maps only to the source-scoped "
            "error-indicator-and-stop disposition. It does not execute a KDF/PRF or establish "
            "output correctness, compliance, responsibility, authorization, or an external effect."
        ),
    },
    "nist-sp-800-111-centralized-management": {
        "file": "nist_sp_800_111_centralized_management.jc.json",
        "bytes": 48863,
        "sha256": "9a21ed9de9f1de06823d3add2d779c7dfe0fa14967bb8270c0d4a7f8b169fa74",
        "publication_id": "NIST SP 800-111",
        "title": "SP 800-111 centralized-management recommendation applicability",
        "scope": (
            "Evaluates only whether the source recommendation applies to one supplied "
            "storage-encryption deployment after its standalone and very-small-scale exceptions. "
            "Very-small-scale is a caller-supplied fact; no threshold is invented. EXCLUDED only "
            "means this recommendation does not apply under the supplied facts. It does not establish "
            "a prohibition, authorization, compliance, responsibility, or an external effect."
        ),
    },
    "nist-sp-800-150-tlp-table-3-3": {
        "file": "nist_sp_800_150_tlp_table_3_3.jc.json",
        "bytes": 30271,
        "sha256": "5a4fcc61dbae7b78adc5cbbee26034ef7a00f5801ba3c1a8170a422d267506af",
        "publication_id": "NIST SP 800-150",
        "title": "SP 800-150 Table 3-3 source-scoped TLP sharing dispositions",
        "scope": (
            "Maps a caller-supplied TLP color to the frozen Table 3-3 disposition for one "
            "organization. AMBER retains the own-organization or need-to-know clients/customers "
            "restriction for protection or prevention of further harm. Concrete additional "
            "limits remain unresolved. No actual recipient, release, authorization, compliance, "
            "responsibility, or external effect is determined."
        ),
    },
    "nist-sp-800-37r2-p1-assignment-entry": {
        "file": "nist_sp_800_37r2_p1_assignment_entry.jc.json",
        "bytes": 48546,
        "sha256": "cc3f4446525405496c018d3ddb18c7cf929abadd885f87956f5520d4f3cb668f",
        "publication_id": "NIST SP 800-37r2",
        "title": "SP 800-37r2 P-1 reported documented role-assignment entry",
        "scope": (
            "Combines two caller-supplied reports for the same record, person and role into "
            "a reported documented assignment entry. It does not establish actual assignment, "
            "document validity, completeness, cardinality, authority, P-1 completion, "
            "compliance, responsibility, authorization, or an external effect."
        ),
    },
    "nist-sp-800-145-section-2-caller-reports": {
        "file": "nist_sp_800_145_section_2_caller_reports.jc.json",
        "bytes": 386719,
        "sha256": "94d3a7837871e26c73961a0ebd334765a74dc086c23416c479ab2568ec0ee036",
        "publication_id": "NIST SP 800-145",
        "title": "SP 800-145 Section 2 independently scoped caller reports",
        "scope": (
            "Preserves nineteen caller-supplied reports for one selected service as "
            "CALLER_REPORTED_TRUE or CALLER_REPORTED_FALSE, with independent unresolved "
            "missing, unknown or conflicting inputs. It does not establish the reported "
            "facts, a NIST essential characteristic, cloud-service classification, "
            "compliance, responsibility, authorization, or an external effect."
        ),
    },
}


class ReviewedDocumentProgramError(ValueError):
    """A reviewed document package or its execution request is invalid."""


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise ReviewedDocumentProgramError(message)


class ReviewedDocumentPrograms:
    """Loads and runs reviewed document checks."""

    def __init__(self, base_semantic_pack: Any, library: Any = None):
        self.base = validate_semantic_pack(base_semantic_pack)
        self.library = library if library is not None else DocumentLibrary()
        self._citation_cache: dict[str, list[dict]] = {}
        # These are bounded to the registered reviewed packages below and
        # remain an in-process speed layer.  The package and base hashes are
        # part of every key, so a changed input cannot reuse old construction.
        self._materialized_cache: dict[tuple[str, str], dict] = {}
        self._definition_context_cache: dict[tuple[str, str], dict] = {}
        self._base_semantic_pack_sha256 = digest(self.base)

    @staticmethod
    def _record(package_id: Any) -> dict:
        _need(type(package_id) is str and package_id in _PACKAGES,
              "unknown reviewed document package")
        return deepcopy(_PACKAGES[package_id])

    @staticmethod
    def _load(package_id: str) -> tuple[dict, dict]:
        record = ReviewedDocumentPrograms._record(package_id)
        path = ROOT / "data" / "reviewed_document_packages" / record["file"]
        raw = path.read_bytes()
        _need(len(raw) == record["bytes"] and sha256(raw).hexdigest() == record["sha256"],
              "reviewed document package hash mismatch")
        try:
            # Exact byte count and checksum were verified above. Keep the request
            # default unchanged while bounding this pinned artifact by its registry.
            package = strict_json(raw.decode("utf-8"), max_chars=record["bytes"])
        except (UnicodeDecodeError, ValueError) as exc:
            raise ReviewedDocumentProgramError("reviewed document package is not strict JSON") from exc
        _need(type(package) is dict, "reviewed document package must be an object")
        _need(package.get("schema") == PACKAGE_SCHEMA,
              "unsupported reviewed document package schema")
        return record, package

    def _verified_base_sha256(self) -> str:
        """Reject same-process base-pack mutation before using cached work."""
        try:
            observed = digest(self.base)
        except Exception as exc:
            raise ReviewedDocumentProgramError(
                "base semantic pack integrity check failed"
            ) from exc
        _need(observed == self._base_semantic_pack_sha256,
              "base semantic pack drift")
        return observed

    def _replayed_materialized(self, package: dict,
                               package_sha256: str) -> tuple[dict, str]:
        base_sha256 = self._verified_base_sha256()
        key = (package_sha256, base_sha256)
        cached = self._materialized_cache.get(key)
        if cached is None:
            try:
                materialized = materialize_reviewed_batch(self.base, package)
                decompose_reviewed_batch(self.base, materialized)
            except ValueError as exc:
                raise ReviewedDocumentProgramError(
                    "reviewed document package did not replay through the qualified builders"
                ) from exc
            self._materialized_cache[key] = deepcopy(materialized)
            cached = materialized
        return deepcopy(cached), base_sha256

    def _cached_definition_context(self, materialized: dict,
                                   package_sha256: str,
                                   base_sha256: str) -> dict:
        key = (package_sha256, base_sha256)
        cached = self._definition_context_cache.get(key)
        if cached is None:
            cached = self._definition_context(self.base, materialized)
            self._definition_context_cache[key] = deepcopy(cached)
        return deepcopy(cached)

    def index(self) -> dict:
        return {
            "schema": INDEX_SCHEMA,
            "status": "SOURCE_BOUND_NOT_EXECUTED",
            "packages": [
                {"id": package_id, **deepcopy(record)}
                for package_id, record in sorted(_PACKAGES.items())
            ],
            "source_format_policy": {
                "oscal": "USED_WHEN_A_QUALIFIED_SOURCE_NATIVE_OSCAL_RECORD_EXISTS",
                "common_package": PACKAGE_SCHEMA,
                "original_pdf_remains_source_authority": True,
            },
            "claim_ceiling": CEILING,
            "external_effects": [],
        }

    def _source_citations(self, package: dict, package_sha256: str) -> list[dict]:
        """Replay every unique semantic-support locator into exact library evidence."""
        if package_sha256 in self._citation_cache:
            # The first replay verifies every retained file while building the
            # complete occurrence inventory.  Re-authenticate that corpus
            # before reusing the inventory in this process.
            self.library.verify()
            return deepcopy(self._citation_cache[package_sha256])
        sources = {item["publication_id"]: item for item in package["sources"]}
        supports: dict[tuple[str, str, str], dict] = {}

        def visit(value: Any) -> None:
            if type(value) is dict:
                if all(type(value.get(key)) is str and value.get(key)
                       for key in ("source_id", "locator", "quote_sha256")):
                    key = (value["source_id"], value["locator"], value["quote_sha256"])
                    supports[key] = value
                for child in value.values():
                    visit(child)
            elif type(value) is list:
                for child in value:
                    visit(child)

        visit(package)
        _need(bool(supports), "reviewed document package has no semantic source support")
        pending = []
        pattern = re.compile(
            r"^retained-nist://[^/]+/sha256/([0-9a-f]{64})/"
            r"pdf-page-index/(\d+)/char/(\d+):(\d+)$"
        )
        for (source_id, locator, expected_quote_sha256), _support in sorted(supports.items()):
            source = sources.get(source_id)
            _need(type(source) is dict, "semantic support source is not registered")
            match = pattern.fullmatch(locator)
            _need(match is not None, "unsupported reviewed semantic source locator")
            source_sha256, page_index_text, start_text, end_text = match.groups()
            _need(source_sha256 == source["source_file"]["sha256"],
                  "semantic support locator source drift")
            page_number = int(page_index_text) + 1
            start, end = int(start_text), int(end_text)
            page = self.library.page(source_id, page_number, "plain")
            _need(page["source_file"]["sha256"] == source_sha256,
                  "reviewed source PDF does not match retained library")
            text = page["page"]["text"]
            _need(0 <= start < end <= len(text), "semantic support span is outside its page")
            exact_quote = text[start:end]
            _need(sha256(exact_quote.encode("utf-8")).hexdigest() == expected_quote_sha256,
                  "semantic support quote drift")
            # Keep the full semantic anchor verified above. Native documentary
            # citations have a 1000-character limit, so long anchors are covered
            # by exact adjacent fragments with non-whitespace boundaries.
            spans = [(start, end)]
            if len(exact_quote) > 1000:
                spans = []
                for chunk_start in range(start, end, 1000):
                    chunk_end = min(chunk_start + 1000, end)
                    while chunk_start < chunk_end and text[chunk_start].isspace():
                        chunk_start += 1
                    while chunk_start < chunk_end and text[chunk_end - 1].isspace():
                        chunk_end -= 1
                    if chunk_start < chunk_end:
                        spans.append((chunk_start, chunk_end))
                _need(bool(spans), "semantic support contains no citable text")
            for chunk_start, chunk_end in spans:
                pending.append({
                    "source_id": source_id,
                    "semantic_locator": locator,
                    "semantic_quote_sha256": expected_quote_sha256,
                    "request": {"publication_id": source_id, "page_number": page_number,
                                "character_span": [chunk_start, chunk_end],
                                "exact_quote": text[chunk_start:chunk_end]},
                })
        bound = self.library.cite_many([item["request"] for item in pending])
        citations = [{
            "source_id": item["source_id"],
            "semantic_locator": item["semantic_locator"],
            "semantic_quote_sha256": item["semantic_quote_sha256"],
            "citation": citation,
        } for item, citation in zip(pending, bound)]
        self._citation_cache[package_sha256] = deepcopy(citations)
        return citations

    def inspect(self, package_id: Any) -> dict:
        record, package = self._load(package_id)
        materialized, _base_sha256 = self._replayed_materialized(
            package, record["sha256"])
        return {
            "schema": INDEX_SCHEMA,
            "status": "SOURCE_REVIEWED_PROGRAM_READY",
            "package": {"id": package_id, **record},
            "package_sha256": record["sha256"],
            "materialized": materialized,
            "source_citations": self._source_citations(package, record["sha256"]),
            "claim_ceiling": CEILING,
            "external_effects": [],
        }

    @staticmethod
    def _definition_context(base: dict, materialized: dict) -> dict:
        context = deepcopy(base)
        for candidate in materialized["qualified_source_candidates"]:
            context = recompose_qualified_source(context, candidate)
        context = recompose_entity_kind_extensions(
            context, materialized["entity_kind_extensions"]
        )
        for candidate in materialized["qualified_predicate_candidates"]:
            context = recompose_qualified_predicate(context, candidate)
        for candidate in materialized["qualified_domain_candidates"]:
            context = recompose_qualified_domain(context, candidate)
        for candidate in materialized["reviewed_definition_candidates"]:
            context = recompose_qualified_definition(context, candidate)
        return context

    def execute(self, package_id: Any, request: Any) -> dict:
        _need(type(request) is dict, "reviewed document program request required")
        _need(
            type(request.get("request_id")) is str and request["request_id"].strip(),
            "reviewed document program request_id required",
        )
        _need(
            type(request.get("scenario_id")) is str and request["scenario_id"].strip(),
            "reviewed document program scenario_id required",
        )
        identity = {
            "request_id": request["request_id"],
            "scenario_id": request["scenario_id"],
        }
        execution_request = deepcopy(request)
        for field in identity:
            execution_request.pop(field)
        inspected = self.inspect(package_id)
        materialized = inspected["materialized"]
        base_sha256 = self._verified_base_sha256()
        context = self._cached_definition_context(
            materialized, inspected["package_sha256"], base_sha256)
        try:
            result = execute_qualified_program(context, materialized["program"], execution_request)
        except ValueError as exc:
            raise ReviewedDocumentProgramError("reviewed document program request rejected") from exc
        result = {
            **result,
            **identity,
            "request_sha256": digest(request),
        }
        result["result_sha256"] = digest(result)
        response = {
            "schema": INDEX_SCHEMA,
            "status": result["status"],
            "package_id": package_id,
            "package_sha256": inspected["package_sha256"],
            **identity,
            "request_sha256": digest(request),
            "program_sha256": materialized["program"]["program_sha256"],
            "execution": result,
            "source_citations": inspected["source_citations"],
            "scope": inspected["package"]["scope"],
            "claim_ceiling": CEILING,
            "external_effects": [],
        }
        response["result_sha256"] = digest(response)
        return response


__all__ = [
    "CEILING", "INDEX_SCHEMA", "PACKAGE_SCHEMA", "ReviewedDocumentProgramError",
    "ReviewedDocumentPrograms",
]
