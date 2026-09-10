"""Builds the reviewed PS-4(a) check record."""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from judgment_compilation.nist import build_pack, ps4a_timing_example_request
from judgment_compilation.semantic_contracts import canonical, digest
from judgment_compilation.semantic_node_composition import (
    compose_architecture_program,
    decompose_architecture,
    decompose_judgment,
    decompose_work,
    execute_composed_program,
    rebind_architecture,
    rebind_judgment,
    rebind_work,
    SemanticNodeCompositionError,
)
from judgment_compilation.source_mappings import _SPECS


SCHEMA = "jc/nist-reviewed-composition-evidence/1"
STATUS = "SOURCE_BOUND_NOT_EXECUTED"
ARCHITECTURE_ID = "ps4a-access-disable-timing"
SOURCE_ID = "PS-4(a)"
JUDGMENT_IDS = (
    "ps4a_timing_scope",
    "ps4a_within_supplied_period",
    "ps4a_exceeds_supplied_period",
)
WORK_IDS = (
    "apply:ps4a_timing_scope",
    "compare_ps4a_access_disable_period",
    "apply:ps4a_within_supplied_period",
    "apply:ps4a_exceeds_supplied_period",
)
CLAIM_CEILING = (
    "SOURCE_BOUND_COMPOSITION_EXAMPLE_ONLY;SUPPLIED_INTEGER_"
    "COMPARISON;NO_EVENT_EVIDENCE_OR_APPLICABILITY_OR_CONTROL_SATISFACTION_"
    "OR_COMPLIANCE_OR_RESPONSIBILITY_OR_EXTERNAL_EFFECT"
)


def semantic_request_from_example(request: dict[str, Any] | None = None) -> dict[str, Any]:
    """Translate the checked timing ingress to the composer request shape."""
    source = ps4a_timing_example_request() if request is None else deepcopy(request)
    return {
        "entities": {row["id"]: row["kind"] for row in source["entities"]},
        "facts": [
            {key: value for key, value in fact.items() if key != "evidence_refs"}
            for fact in source["facts"]
        ],
        "unknowns": deepcopy(source["unknowns"]),
        "bindings": {
            step: {role: [entity_id] for role, entity_id in source["scope"].items()}
            for step in ("scope", "compare", "within", "exceeds")
        },
    }


def _reviewed_source_binding(pack: dict[str, Any]) -> dict[str, Any]:
    source = pack["sources"][SOURCE_ID]
    spec = _SPECS[SOURCE_ID]
    if source["structural_oscal_locator"] != spec["structural_oscal_locator"]:
        raise ValueError("PS-4(a) structural source locator drift")
    if source["oscal_source_file"]["sha256"] != "a9e23b09116d5e651461d61777c2e7dc1f3454ab3f9e1e8fdf8af01c37dc01be":
        raise ValueError("PS-4(a) OSCAL source digest drift")
    return {
        "source_id": SOURCE_ID,
        "statement_id": spec["statement_id"],
        "template_sha256": spec["template_sha256"],
        "structural_oscal_locator": source["structural_oscal_locator"],
        "source_sha256": source["oscal_source_file"]["sha256"],
        "pdf_source_sha256": source["source_file"]["sha256"],
        "physical_pdf_page_one_based": source["physical_pdf_page_one_based"],
        "printed_page_label": source["printed_page_label"],
        "character_span": deepcopy(source["character_span"]),
        "quote_sha256": source["quote_sha256"],
        "normalized_quote_sha256": source["normalized_quote_sha256"],
        "quote": source["quote"],
    }


def _assert_reviewed_family(pack: dict[str, Any]) -> None:
    semantic = pack["semantic_pack"]
    judgment_index = {row["id"]: row for row in semantic["judgments"]}
    for judgment_id in JUDGMENT_IDS:
        row = judgment_index[judgment_id]
        if row["source_ids"] != [SOURCE_ID]:
            raise ValueError("PS-4(a) Judgment support drift")
        if SOURCE_ID not in pack["interpretations"][judgment_id]["source_selection_reason"]:
            raise ValueError("PS-4(a) Judgment interpretation support missing")
    comparison = "compare_ps4a_access_disable_period"
    if SOURCE_ID not in pack["work_interpretations"][comparison]["source_selection_reason"]:
        raise ValueError("PS-4(a) Work interpretation support missing")


def build_composition_evidence() -> dict[str, Any]:
    """Build and verify the PS-4(a) example graph."""
    pack = build_pack()
    before = canonical(pack)
    _assert_reviewed_family(pack)
    semantic = pack["semantic_pack"]

    judgments = [decompose_judgment(semantic, identifier) for identifier in JUDGMENT_IDS]
    works = [decompose_work(semantic, identifier) for identifier in WORK_IDS]
    architecture = decompose_architecture(semantic, ARCHITECTURE_ID)
    rebound_judgments = [rebind_judgment(semantic, parts) for parts in judgments]
    rebound_works = [rebind_work(semantic, parts) for parts in works]
    rebound_architecture = rebind_architecture(semantic, architecture)
    if canonical(judgments) != canonical(rebound_judgments):
        raise SemanticNodeCompositionError("Judgment decomposition is not lossless")
    if canonical(works) != canonical(rebound_works):
        raise SemanticNodeCompositionError("Work decomposition is not lossless")
    if canonical(architecture) != canonical(rebound_architecture):
        raise SemanticNodeCompositionError("Architecture decomposition is not lossless")

    composition = compose_architecture_program(semantic, ARCHITECTURE_ID)
    execution = execute_composed_program(
        semantic, composition, semantic_request_from_example()
    )
    if canonical(pack) != before:
        raise SemanticNodeCompositionError("composition changed the source pack")
    body = {
        "schema": SCHEMA,
        "status": STATUS,
        "pack_sha256": digest(pack),
        "source": _reviewed_source_binding(pack),
        "judgment_ids": list(JUDGMENT_IDS),
        "work_ids": list(WORK_IDS),
        "architecture_id": ARCHITECTURE_ID,
        "decomposed": {
            "judgments": judgments,
            "work": works,
            "architecture": architecture,
        },
        "recomposed": {
            "judgments": rebound_judgments,
            "work": rebound_works,
            "architecture": rebound_architecture,
            "composition": composition,
        },
        "execution": execution,
        "interpretation_limits": [
            "The scenario values and evidence references are caller supplied.",
            "The result is an integer comparison only; timestamps and event evidence are not inferred.",
            "No applicability, control satisfaction, compliance, responsibility, or action is determined.",
        ],
        "claim_ceiling": CLAIM_CEILING,
        "explicit_selection_confirmed": False,
        "external_effects": [],
    }
    body_sha256 = digest(body)
    return {**body, "evidence_id": f"nist-composition:{body_sha256}", "evidence_sha256": body_sha256}


__all__ = [
    "ARCHITECTURE_ID", "CLAIM_CEILING", "JUDGMENT_IDS", "SCHEMA", "SOURCE_ID",
    "STATUS", "WORK_IDS", "build_composition_evidence", "semantic_request_from_example",
]

