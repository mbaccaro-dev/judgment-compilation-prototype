"""Builds follow-up questions from missing inputs."""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from .kernel import canonical, digest, require
from .operation_interfaces import operation_interfaces
from .semantic_contracts import validate_semantic_pack

SCHEMA = "jc/inquiry-plan/1"
CLASSES = frozenset({
    "MISSING_FACT", "CONFLICTING_FACTS", "UNKNOWN_VALUE",
    "UNBOUND_PARAMETER", "UNBOUND_ROLE", "AMBIGUOUS_ROLE",
    "MISSING_SEMANTIC_MAPPING", "UNSUPPORTED_OPERATION",
    "MISSING_AUTHORITY", "DEPENDENCY_BLOCKED",
})

_CLASS = {
    "MISSING_FACT": "MISSING_FACT",
    "MISSING_EVIDENCE": "MISSING_FACT",
    "CONFLICTING_FACTS": "CONFLICTING_FACTS",
    "UNKNOWN_EVIDENCE": "UNKNOWN_VALUE",
    "USER_DECLARED_UNKNOWN": "UNKNOWN_VALUE",
    "MISSING_PARAMETER": "UNBOUND_PARAMETER",
    "MISSING_BINDING": "UNBOUND_ROLE",
    "AMBIGUOUS_BINDING": "AMBIGUOUS_ROLE",
    "AMBIGUOUS_DERIVED_RESULT": "AMBIGUOUS_ROLE",
    "AMBIGUOUS_STATEMENT": "MISSING_SEMANTIC_MAPPING",
    "UNSUPPORTED_STATEMENT": "MISSING_SEMANTIC_MAPPING",
    "REQUIREMENT_TO_POLICY_SEMANTICS_NOT_ADMITTED": "MISSING_SEMANTIC_MAPPING",
    "MISSING_SEMANTIC_MAPPING": "MISSING_SEMANTIC_MAPPING",
    "UNSUPPORTED_REQUEST": "UNSUPPORTED_OPERATION",
    "NO_APPLICABLE_JUDGMENT": "UNSUPPORTED_OPERATION",
    "UNRESOLVED": "DEPENDENCY_BLOCKED",
    "BLOCKED": "DEPENDENCY_BLOCKED",
    "CONFLICTING_JUDGMENTS": "MISSING_AUTHORITY",
    "SCOPE_LIMIT": "MISSING_AUTHORITY",
    "RESPONSIBILITY_AND_TERMINATION_BINDINGS_UNRESOLVED": "MISSING_AUTHORITY",
    "EVIDENCE_AND_AUTHORITY_CEILING": "MISSING_AUTHORITY",
    "DEPENDENCY_UNRESOLVED_OR_NOT_APPLICABLE": "DEPENDENCY_BLOCKED",
    "CANDIDATE_APPLICABILITY_UNRESOLVED": "DEPENDENCY_BLOCKED",
}


def _reason_class(reason: str) -> str:
    require(reason in _CLASS, f"unsupported residual reason: {reason}")
    return _CLASS[reason]


def _prompt(kind: str, row: dict[str, Any]) -> str:
    subject = row.get("predicate") or row.get("binding") or row.get("operand")
    if kind == "MISSING_FACT":
        return f"Supply qualified evidence for {subject}." if subject else "Supply the missing qualified fact or evidence."
    if kind == "CONFLICTING_FACTS":
        return f"Resolve the contradictory qualified values for {subject}." if subject else "Resolve the contradictory qualified evidence."
    if kind == "UNKNOWN_VALUE":
        return f"Provide a known qualified value for {subject}." if subject else "Provide the declared unknown value and its exact scope."
    if kind == "UNBOUND_PARAMETER":
        return f"Bind the source-defined parameter {subject}." if subject else "Bind the missing source-defined parameter."
    if kind == "UNBOUND_ROLE":
        return f"Identify exactly one entity for role {subject}." if subject else "Identify the missing typed role."
    if kind == "AMBIGUOUS_ROLE":
        return f"Select exactly one qualified entity for role {subject}." if subject else "Disambiguate the typed role or derived value."
    if kind == "MISSING_SEMANTIC_MAPPING":
        return "Qualify an exact source-to-semantic mapping for this statement."
    if kind == "UNSUPPORTED_OPERATION":
        return "Select an admitted operation or add a separately reviewed executable contract."
    if kind == "MISSING_AUTHORITY":
        return "Provide explicit qualified authority for the requested conclusion, precedence, or action."
    return "Resolve the named prerequisite before retrying the dependent operation."


def _leaf_rows(value: Any):
    """Yield typed residual leaves while preserving their enclosing reason."""
    if type(value) is dict:
        yield value
        for key in ("details",):
            if key in value:
                yield from _leaf_rows(value[key])
    elif type(value) is list:
        for item in value:
            yield from _leaf_rows(item)


class InquiryPlanner:
    def __init__(self, pack: dict, *, requirement_disposition_index_sha256: str | None = None):
        self._pack = deepcopy(pack)
        semantic = validate_semantic_pack(self._pack["semantic_pack"])
        require(digest(self._pack) == self._pack.get("pack_sha256", digest(self._pack)), "pack self-binding mismatch")
        self._interfaces = operation_interfaces(semantic)
        if requirement_disposition_index_sha256 is not None:
            require(type(requirement_disposition_index_sha256) is str and len(requirement_disposition_index_sha256) == 64,
                    "invalid requirement disposition binding")
        self._disposition_sha256 = requirement_disposition_index_sha256

    def plan(self, result: dict) -> dict:
        result = deepcopy(result)
        require(type(result) is dict, "deterministic result required")
        claimed_hash = result.get("canonical_kernel_result_hash")
        require(type(claimed_hash) is str and len(claimed_hash) == 64, "kernel result hash required")
        body = deepcopy(result)
        body.pop("canonical_kernel_result_hash")
        require(digest(body) == claimed_hash, "kernel result integrity")
        expected_binding = {"id": self._pack["id"], "version": self._pack["version"], "sha256": digest(self._pack)}
        require(result.get("pack_binding") == expected_binding, "foreign semantic pack result")
        require(result.get("external_effects") == [] and result.get("compliance_verdict") is None and
                result.get("responsibility_determination") is None, "result exceeds planner authority")

        inquiries: dict[bytes, dict[str, Any]] = {}

        def add(raw: dict[str, Any], *, claim_id=None, execution_index=None, step_id=None):
            reason = raw.get("reason")
            if type(reason) is not str:
                return
            kind = _reason_class(reason)
            record = {
                "class": kind,
                "reason": reason,
                "claim_id": claim_id,
                "execution_index": execution_index,
                "step_id": step_id,
                "predicate": raw.get("predicate"),
                "arguments": deepcopy(raw.get("arguments")),
                "binding": raw.get("binding"),
                "candidates": deepcopy(raw.get("candidates", [])),
                "fact_ids": deepcopy(raw.get("fact_ids", [])),
                "blocked_steps": deepcopy(raw.get("steps", [])),
                "question": _prompt(kind, raw),
                "resolution_authority": "CALLER_OR_SEPARATELY_QUALIFIED_INTERPRETATION",
                "automatic_resolution": False,
            }
            key = canonical(record)
            inquiries[key] = record

        for claim in result.get("claims", []):
            if claim.get("type") == "UNRESOLVED":
                add(claim, claim_id=claim.get("id"), step_id=claim.get("step_id"))
                for row in _leaf_rows(claim.get("residuals", [])):
                    add(row, claim_id=claim.get("id"), step_id=claim.get("step_id"))

        applied_steps, unresolved_steps, not_applicable_steps = [], [], []
        for execution_index, execution in enumerate(result.get("semantic_execution", [])):
            for step in execution["result"]["steps"]:
                locator = {"execution_index": execution_index, "step_id": step["step_id"], "work_id": step["work_id"]}
                if step["status"] == "APPLIED":
                    applied_steps.append(locator)
                elif step["status"] == "NOT_APPLICABLE":
                    not_applicable_steps.append(locator)
                else:
                    unresolved_steps.append(locator)
                    for row in _leaf_rows(step.get("residuals", [])):
                        add(row, execution_index=execution_index, step_id=step["step_id"])

        ordered = []
        for index, key in enumerate(sorted(inquiries), 1):
            record = inquiries[key]
            require(record["class"] in CLASSES, "unsupported inquiry class")
            ordered.append({"id": f"inquiry:{index}:" + digest(record)[:16], **record})

        claims = result.get("claims", [])
        partition = {
            "unaffected_applied_claim_ids": sorted(c["id"] for c in claims if c.get("type") == "DETERMINISTIC_DERIVATION"),
            "blocked_or_unresolved_claim_ids": sorted(c["id"] for c in claims if c.get("type") == "UNRESOLVED"),
            "applied_steps": sorted(applied_steps, key=canonical),
            "unresolved_or_blocked_steps": sorted(unresolved_steps, key=canonical),
            "not_applicable_steps": sorted(not_applicable_steps, key=canonical),
        }
        plan = {
            "schema": SCHEMA,
            "bindings": {
                "request_id": result["request_id"],
                "scenario_id": result["scenario_id"],
                "canonical_ingress_hash": result["canonical_ingress_hash"],
                "canonical_kernel_result_hash": claimed_hash,
                "pack": expected_binding,
                "operation_interfaces_sha256": digest(self._interfaces),
                "requirement_disposition_index_sha256": self._disposition_sha256,
            },
            "target": {"question": result["scenario"]["question"], "scope": "EXACT_REQUEST_ONLY"},
            "inquiries": ordered,
            "conclusion_partition": partition,
            "status": "CLARIFICATION_REQUIRED" if ordered else "NO_MATERIAL_UNKNOWN",
            "authority": "DETERMINISTIC_CLARIFICATION_PLAN_ONLY",
            "model_calls": 0,
            "external_effects_requested": [],
            "external_effects_authorized": [],
            "external_effects_executed": [],
        }
        plan["plan_sha256"] = digest(plan)
        return plan
