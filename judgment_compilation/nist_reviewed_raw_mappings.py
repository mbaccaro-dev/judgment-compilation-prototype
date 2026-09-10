"""Lists source matches for the reviewed NIST controls."""
from __future__ import annotations
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import re
import unicodedata
from typing import Any

from .documentary_projection import DEFAULT_ROOT, MANIFEST_SHA256, DocumentaryProjection
from .nist_source import TARGETS, frozen_inputs, normalized, provenance_inventory
from .raw_domain_candidates import RawDomainCandidates
from .raw_work_architecture_candidates import RawWorkArchitectureCandidates
from .raw_judgment_candidates import _PATTERNS, _candidate as judgment_candidate
from .sc7_direct_external_connection_family import build_definition as build_sc7_definition
from .source_mappings import _SPECS as REVIEWED_SOURCE_SPECS

SCHEMA = "jc/nist-reviewed-raw-mappings/1"
SOURCE_PUBLICATION_ID = "NIST SP 800-53r5-upd1"
SOURCE_PDF_SHA256 = "fc63bcd61715d0181dd8e85998b1e6201ae3515fc6626102101cab1841e11ec6"
CEILING = ("EXACT_CURRENT_SOURCE_BOUND_INVENTORY_ONLY;RAW_CANDIDATES_REMAIN_"
           "UNADMITTED;NO_GENERAL_SEMANTIC_COMPILATION_OR_APPLICABILITY_OR_"
           "COMPLIANCE_OR_RESPONSIBILITY_OR_EXTERNAL_EFFECT")
MISSING_INTERFACES = ("INTERPRETATION_QUALIFICATION", "DOMAIN_PRODUCER",
                      "JUDGMENT_PRODUCER", "WORK_PRODUCER", "ARCHITECTURE_PRODUCER")


class NistReviewedRawMappingsError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _digest(value: Any) -> str:
    return sha256(_canonical(value)).hexdigest()


def _need(condition: bool, reason: str) -> None:
    if not condition:
        raise NistReviewedRawMappingsError(reason)


def _plain(value: str) -> str:
    _need(type(value) is str, "quote must be text")
    return " ".join(unicodedata.normalize("NFC", value).split())


def _quote_locator(candidate: dict[str, Any], stack: str) -> dict[str, Any]:
    if stack == "JUDGMENT":
        source = candidate["source"]
        return {"candidate_id": candidate["candidate_id"], "stack": stack,
                "character_span": deepcopy(source["character_span"]),
                "exact_quote": source["exact_quote"],
                "exact_quote_sha256": source["exact_quote_sha256"],
                "status": candidate["status"], "admission_status": "UNRESOLVED",
                "semantic_coordinate": None}
    span = candidate["character_span"]
    candidate_id = candidate.get("source_candidate_id") or candidate.get("candidate_id")
    _need(type(candidate_id) is str, "raw candidate identity missing")
    return {"candidate_id": candidate_id,
            "stack": stack,
            "character_span": {"start": span[0], "end": span[1],
                                "unit": "UNICODE_CODE_POINT", "interval": "HALF_OPEN"},
            "exact_quote": candidate["exact_quote"],
            "exact_quote_sha256": candidate["exact_quote_sha256"],
            "status": candidate["interpretation_status"],
            "admission_status": candidate["admission_status"],
            "semantic_coordinate": candidate.get("semantic_coordinate")}


def _raw_for_page(page: dict[str, Any], domain: RawDomainCandidates,
                  work: RawWorkArchitectureCandidates) -> dict[str, list[dict[str, Any]]]:
    result = {"DOMAIN": list(domain._page_candidates(page)), "JUDGMENT": [],
              "WORK": [], "ARCHITECTURE": []}
    work_rows = list(work._page_candidates(page))
    result["WORK"] = [r for r in work_rows if r["candidate_kind"] == "WORK_OPERATION_INTERFACE"]
    result["ARCHITECTURE"] = [r for r in work_rows if r["candidate_kind"] == "ARCHITECTURE_COMPOSITION"]
    for pattern_id, kind, pattern in _PATTERNS:
        for match in pattern.finditer(page["text"]):
            result["JUDGMENT"].append(judgment_candidate(page, pattern_id, kind, match))
    return result


def _matches(raw: dict[str, list[dict[str, Any]]], quote: str) -> dict[str, list[dict[str, Any]]]:
    wanted = _plain(quote)
    return {stack: [_quote_locator(row, stack) for row in rows
                    if _plain(row.get("exact_quote", row.get("source", {}).get("exact_quote", ""))) == wanted]
            for stack, rows in raw.items()}


def _surfaces(reviewed: bool, interface_ids: dict[str, Any] | None = None) -> dict[str, Any]:
    return {stack: {"status": "EXISTING_REVIEWED_CONNECTOR" if reviewed else "NO_RAW_TO_TYPED_CONNECTOR",
                    "can_map_reviewed_source": reviewed,
                    "raw_candidate_qualification": "MISSING",
                    **({"interface_ids": deepcopy(interface_ids.get(stack, []))} if interface_ids else {})}
            for stack in ("DOMAIN", "JUDGMENT", "WORK", "ARCHITECTURE")}


def _normalized_with_map(value: str) -> tuple[str, list[int]]:
    chars, offsets = [], []
    for token in re.finditer(r"\S+", value):
        gap = value[offsets[-1] + 1:token.start()] if offsets else ""
        hyphen_break = bool(chars and chars[-1] == "-" and ("\n" in gap or "\r" in gap))
        if chars and not hyphen_break:
            chars.append(" "); offsets.append(token.start() - 1)
        chars.extend(token.group()); offsets.extend(range(token.start(), token.end()))
    return "".join(chars), offsets


def _pdf_support(page: dict[str, Any], quote: str) -> dict[str, Any] | None:
    text, offsets = _normalized_with_map(page["text"])
    wanted = normalized(quote)
    at = text.find(wanted)
    if at < 0 or not offsets or at + len(wanted) > len(offsets):
        return None
    start, end = offsets[at], offsets[at + len(wanted) - 1] + 1
    exact = page["text"][start:end]
    _need(normalized(exact) == wanted, "PDF quote lift-back mismatch")
    return {"source_file": deepcopy(page["source_file"]),
            "pdf_page_index": page["pdf_page_index"], "pdf_page_number": page["pdf_page_number"],
            "page_text_sha256": page["text_sha256"],
            "character_span": {"start": start, "end": end, "unit": "UNICODE_CODE_POINT", "interval": "HALF_OPEN"},
            "exact_quote": exact, "exact_quote_sha256": _digest(exact),
            "normalized_quote_sha256": _digest(normalized(exact))}


def _pack_row(label: str, source: dict[str, Any], pages: dict[tuple[str, int], dict[str, Any]],
              raw: dict[tuple[str, int], dict[str, list[dict[str, Any]]]]) -> dict[str, Any]:
    _need(label in REVIEWED_SOURCE_SPECS, "reviewed source specification missing")
    _need(source["source_file"]["sha256"] == SOURCE_PDF_SHA256, "reviewed PDF drift")
    key = (SOURCE_PDF_SHA256, source["physical_pdf_page_index_zero_based"])
    _need(key in pages, "reviewed page missing")
    candidates = raw[key]
    return {"source_id": label, "review_status": "REVIEWED_BOUNDED_PACK",
            "reviewed_source_span": {"source_file": deepcopy(source["source_file"]),
                                      "pdf_page_index": source["physical_pdf_page_index_zero_based"],
                                      "pdf_page_number": source["physical_pdf_page_one_based"],
                                      "page_text_sha256": source["extracted_page_text_sha256"],
                                      "character_span": deepcopy(source["character_span"]),
                                      "exact_quote": source["quote"],
                                      "exact_quote_sha256": source["quote_sha256"],
                                      "normalized_quote_sha256": source["normalized_quote_sha256"]},
            "raw_candidate_matches": _matches(candidates, source["quote"]),
            "raw_candidate_counts_on_reviewed_page": {k: len(v) for k, v in candidates.items()},
            "stack_surfaces": _surfaces(True),
            "source_mapping_spec": deepcopy(REVIEWED_SOURCE_SPECS[label]),
            "admission": "EXISTING_REVIEWED_PACK_ONLY;RAW_MATCHES_REMAIN_UNADMITTED"}


def _sc7_rows(definition: dict[str, Any], pages: dict[tuple[str, int], dict[str, Any]],
              raw: dict[tuple[str, int], dict[str, list[dict[str, Any]]]]) -> list[dict[str, Any]]:
    result = []
    for control in definition["controls"]:
        quote = control["skeleton"]
        for role in control["domain_parameter_roles"]:
            quote = quote.replace(f"<PARAMETER_{role['slot']}>",
                                  "[Assignment: organization-defined " + role["label"] + "]")
        support = key = None
        for candidate_key, page in pages.items():
            if candidate_key[0] == SOURCE_PDF_SHA256 and (found := _pdf_support(page, quote)):
                support, key = found, candidate_key
                break
        candidates = raw.get(key, {s: [] for s in ("DOMAIN", "JUDGMENT", "WORK", "ARCHITECTURE")})
        interface_ids = {"DOMAIN": [r["id"] for r in control["domain_parameter_roles"]],
                         "JUDGMENT": [control["judgment"]["id"]], "WORK": [control["work"]["id"]],
                         "ARCHITECTURE": [control["architecture"]["id"]]}
        result.append({"source_id": control["statement_id"],
                       "review_status": "REVIEWED_EXACT_TEMPLATE_FAMILY",
                       "reviewed_source_span": {"source_file": {"sha256": control["source"]["source_sha256"]},
                                                 "xml_id": control["source"]["xml_id"],
                                                 "xml_locator": control["source"]["xml_locator"],
                                                 "template_sha256": control["template_sha256"],
                                                 "rendered_quote": quote, "pdf_projection_support": support},
                       "raw_candidate_matches": _matches(candidates, quote),
                       "raw_candidate_counts_on_reviewed_page": {s: len(v) for s, v in candidates.items()},
                       "stack_surfaces": _surfaces(True, interface_ids),
                       "source_mapping_spec": {"family_id": "sc-7-direct-external-connection",
                                               "template_sha256": control["template_sha256"],
                                               "policy_semantic_mapping": "NOT_ADMITTED"},
                       "admission": "EXACT_TEMPLATE_INSTANTIATION_ONLY;RAW_MATCHES_REMAIN_UNADMITTED"})
    return result


def build_nist_reviewed_raw_mappings(root: Path | str = DEFAULT_ROOT,
                                     manifest_sha256: str = MANIFEST_SHA256,
                                     source_root: Path | str | None = None) -> dict[str, Any]:
    library_root = Path(root).resolve()
    source_base = Path(source_root).resolve() if source_root else Path(__file__).resolve().parent
    reviewed = provenance_inventory(frozen_inputs(source_base), source_base)
    projection = DocumentaryProjection(library_root, manifest_sha256)
    wanted = {s["physical_pdf_page_index_zero_based"] for s in reviewed.values()} | {329, 330}
    pages = {}
    for page in projection.iter_pages(view="plain", publication_id=SOURCE_PUBLICATION_ID):
        if page["pdf_page_index"] in wanted:
            _need(page["source_sha256"] == SOURCE_PDF_SHA256, "documentary PDF drift")
            pages[(page["source_sha256"], page["pdf_page_index"])] = page
    domain, work = RawDomainCandidates(library_root, manifest_sha256), RawWorkArchitectureCandidates(library_root, manifest_sha256)
    raw = {key: _raw_for_page(page, domain, work) for key, page in pages.items()}
    rows = [_pack_row(label, reviewed[label], pages, raw) for label, *_ in TARGETS]
    rows.extend(_sc7_rows(build_sc7_definition(), pages, raw))
    body = {"schema": SCHEMA, "manifest_sha256": manifest_sha256,
            "documentary_corpus": SOURCE_PUBLICATION_ID, "source_pdf_sha256": SOURCE_PDF_SHA256,
            "reviewed_source_count": len(rows), "rows": rows,
            "missing_interfaces": list(MISSING_INTERFACES),
            "raw_candidate_policy": {"matching": "NFC whitespace equality after exact same-page source binding",
                                     "nearby_lexical_signals": "RETAINED_AS_UNRESOLVED_CONTEXT_ONLY",
                                     "admission": "NOT_ADMITTED", "semantic_coordinates": 0,
                                     "external_effects": []},
            "explicit_selection_confirmed": False, "coverage_ceiling": CEILING, "external_effects": []}
    body["index_sha256"] = _digest(body)
    return body


def validate_nist_reviewed_raw_mappings(value: Any, **kwargs: Any) -> dict[str, Any]:
    _need(type(value) is dict, "inventory must be an object")
    supplied = deepcopy(value); index = supplied.pop("index_sha256", None)
    _need(type(index) is str and _digest(supplied) == index, "inventory digest mismatch")
    expected = build_nist_reviewed_raw_mappings(**kwargs)
    _need(value == expected, "inventory does not match current source and raw generators")
    return deepcopy(expected)


build_inventory = build_nist_reviewed_raw_mappings
validate_inventory = validate_nist_reviewed_raw_mappings


