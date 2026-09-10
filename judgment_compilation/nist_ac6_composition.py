"""Builds the reviewed AC-6 check record."""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from judgment_compilation.nist import build_pack
from judgment_compilation.semantic_contracts import canonical, digest
from judgment_compilation.semantic_node_composition import (
    SemanticNodeCompositionError, compose_architecture_program, decompose_architecture,
    decompose_judgment, decompose_work, execute_composed_program, rebind_architecture,
    rebind_judgment, rebind_work,
)
from judgment_compilation.source_mappings import _SPECS

SCHEMA = "jc/nist-reviewed-composition-evidence/1"
STATUS = "SOURCE_BOUND_NOT_EXECUTED"
ARCHITECTURE_ID = "termination-assessment"
SOURCE_ID = "AC-6 Control"
JUDGMENT_IDS = ("least_privilege_relevance",)
WORK_IDS = ("apply:least_privilege_relevance",)
CLAIM_CEILING = (
    "SOURCE_BOUND_AC6_REVIEW_SELECTION_EXAMPLE_ONLY;SUPPLIED_TYPED_"
    "SCENARIO_FACTS;NO_AUTHORIZATION_DETERMINATION;NO_ACCESS_PURPOSE_DETERMINATION;"
    "NO_ASSIGNED_TASK_NECESSITY_DETERMINATION;NO_APPLICABILITY_OR_CONTROL_SATISFACTION_OR_"
    "COMPLIANCE_OR_RESPONSIBILITY_OR_EXTERNAL_EFFECT"
)


def semantic_request_from_example(request: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return a typed fictional scenario for the admitted AC-6 review selector."""
    result = {
        "entities": {"org-a": "organization", "person-a": "person", "account-a": "account"},
        "facts": [
            {"id": "employment-ended", "predicate": "employment_terminated", "arguments": {"employee": "person-a", "business": "org-a"}, "value": True},
            {"id": "account-of-person", "predicate": "account_of", "arguments": {"account": "account-a", "employee": "person-a"}, "value": True},
            {"id": "administrator-account", "predicate": "administrator_account", "arguments": {"account": "account-a"}, "value": True},
            {"id": "continued-access", "predicate": "access_continues", "arguments": {"employee": "person-a", "account": "account-a"}, "value": True},
        ],
        "unknowns": [],
        "bindings": {step: {"employee": ["person-a"], "account": ["account-a"], "business": ["org-a"]}
                     for step in ("account_management_relevance", "least_privilege_relevance", "personnel_termination_relevance", "termination_admin_access_issue")},
    }
    return result if request is None else deepcopy(request)


def _reviewed_source_binding(pack: dict[str, Any]) -> dict[str, Any]:
    source, spec = pack["sources"][SOURCE_ID], _SPECS[SOURCE_ID]
    if source["structural_oscal_locator"] != spec["structural_oscal_locator"]:
        raise ValueError("AC-6 structural source locator drift")
    if source["oscal_source_file"]["sha256"] != "a9e23b09116d5e651461d61777c2e7dc1f3454ab3f9e1e8fdf8af01c37dc01be":
        raise ValueError("AC-6 OSCAL source digest drift")
    return {"source_id": SOURCE_ID, "statement_id": spec["statement_id"], "template_sha256": spec["template_sha256"],
            "structural_oscal_locator": source["structural_oscal_locator"], "source_sha256": source["oscal_source_file"]["sha256"],
            "pdf_source_sha256": source["source_file"]["sha256"], "physical_pdf_page_one_based": source["physical_pdf_page_one_based"],
            "printed_page_label": source["printed_page_label"], "character_span": deepcopy(source["character_span"]),
            "quote_sha256": source["quote_sha256"], "normalized_quote_sha256": source["normalized_quote_sha256"], "quote": source["quote"]}


def _assert_reviewed_family(pack: dict[str, Any]) -> None:
    semantic = pack["semantic_pack"]
    judgment = next(row for row in semantic["judgments"] if row["id"] == JUDGMENT_IDS[0])
    wording = pack["interpretations"][JUDGMENT_IDS[0]]["source_selection_reason"]
    if judgment["source_ids"] != [SOURCE_ID] or SOURCE_ID not in wording:
        raise ValueError("AC-6 Judgment support drift")
    if "Necessity and authorization remain unverified." not in wording[SOURCE_ID]:
        raise ValueError("AC-6 interpretation limit drift")


def _selected_ac6_step(execution: dict[str, Any]) -> dict[str, Any]:
    return next(deepcopy(step) for step in execution["execution"]["steps"] if step["step_id"] == JUDGMENT_IDS[0])


def build_composition_evidence() -> dict[str, Any]:
    """Build and verify the AC-6 example graph."""
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
    execution = execute_composed_program(semantic, composition, semantic_request_from_example())
    ac6_step = _selected_ac6_step(execution)
    if ac6_step["status"] != "APPLIED" or ac6_step["output"] is None:
        raise SemanticNodeCompositionError("complete AC-6 example did not select the admitted warrant")
    if canonical(pack) != before:
        raise SemanticNodeCompositionError("composition changed the source pack")
    body = {"schema": SCHEMA, "status": STATUS, "pack_sha256": digest(pack), "source": _reviewed_source_binding(pack),
            "judgment_ids": list(JUDGMENT_IDS), "work_ids": list(WORK_IDS), "architecture_id": ARCHITECTURE_ID,
            "decomposed": {"judgments": judgments, "work": works, "architecture": architecture},
            "recomposed": {"judgments": rebound_judgments, "work": rebound_works, "architecture": rebound_architecture, "composition": composition},
            "execution": execution, "selected_ac6_step": ac6_step,
            "interpretation_limits": ["The scenario facts are caller supplied and only select the admitted AC-6 review warrant.", "Authorization, access purpose, and necessity for an assigned organizational task remain unverified.", "No applicability, control satisfaction, compliance, responsibility, or action is determined."],
            "claim_ceiling": CLAIM_CEILING, "explicit_selection_confirmed": False, "external_effects": []}
    body_sha256 = digest(body)
    return {**body, "evidence_id": f"nist-composition:{body_sha256}", "evidence_sha256": body_sha256}


__all__ = ["ARCHITECTURE_ID", "CLAIM_CEILING", "JUDGMENT_IDS", "SCHEMA", "SOURCE_ID", "STATUS", "WORK_IDS", "build_composition_evidence", "semantic_request_from_example"]
