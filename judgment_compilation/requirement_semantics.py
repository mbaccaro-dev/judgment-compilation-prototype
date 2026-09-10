"""Connects OSCAL requirement records to compiled checks."""
from __future__ import annotations

from copy import deepcopy

from .kernel import digest, require
from .nist_requirements import Requirements
from .semantic_contracts import coordinate, semantic_coordinate, validate_semantic_pack


SCHEMA = "jc/requirement-semantic-execution/1"
CEILING = (
    "SOURCE_REQUIREMENT_INSTANTIATION_ONLY;"
    "NO_POLICY_SEMANTIC_MAPPING_OR_APPLICABILITY_OR_SATISFACTION_OR_COMPLIANCE_OR_EFFECT"
)
CLAIM_TYPES = {
    "SOURCE_BOUND",
    "SCENARIO_FACT",
    "DETERMINISTIC_DERIVATION",
    "AI_INFERENCE",
    "UNRESOLVED",
}


class RequirementSemanticError(ValueError):
    """Raised when a document result cannot be linked to a check."""


class RequirementSemanticRuntime:
    """Compose the exact requirements engine through the four stack roles."""

    def __init__(self, requirements: Requirements, catalog, semantic_pack: dict) -> None:
        self.requirements = requirements
        self.catalog = catalog
        self.semantic_pack = validate_semantic_pack(semantic_pack)
        self._definitions = self._bind_definitions()

    def _bind_definitions(self) -> dict:
        wanted = {
            "judgment": (semantic_coordinate("judgment", [0]), "Judgment warrant"),
            "work": (semantic_coordinate("work", [0]), "Contract execution"),
            "architecture": (
                semantic_coordinate("architecture", [0]),
                "Dependency and flow composition",
            ),
        }
        definitions = {}
        for stack, (semantic_id, label) in wanted.items():
            matches = [
                row
                for row in self.semantic_pack["semantic_capital"][stack]
                if row["coordinate"] == semantic_id and row["label"] == label
            ]
            require(len(matches) == 1, "required semantic definition is not cardinality one")
            definitions[stack] = deepcopy(matches[0])
        return definitions

    @staticmethod
    def _claim(claim_id, claim_type, text, value, support_ids=()):
        require(claim_type in CLAIM_TYPES, "unsupported claim type")
        return {
            "id": claim_id,
            "type": claim_type,
            "text": text,
            "value": deepcopy(value),
            "support_ids": sorted(support_ids),
        }

    def _control_record(self, result):
        template = result.get("template")
        if template is None:
            return None
        lookup = self.catalog.ask(control_id=template["control_id"])
        require(lookup["status"] == "resolved", "requirement control has no unique catalog identity")
        record = lookup["candidates"][0]
        require(
            record["source_sha256"] == result["source_sha256"]
            and record["id"] == template["control_id"],
            "requirement and Domain source identities disagree",
        )
        return record

    def _warrant_instantiation(self, result):
        """Warrant only the transformation, never the policy's meaning."""
        if result["status"] == "READY_TO_INSTANTIATE":
            return "WARRANTED_EXACT_SOURCE_TEMPLATE_INSTANTIATION"
        if result["status"] == "INSPECTED":
            return "SOURCE_TEMPLATE_INSPECTED_NO_INSTANCE"
        return "UNRESOLVED"

    def execute(self, request: dict) -> dict:
        preparation = self.requirements.prepare(request)
        result = preparation["result"]
        control = self._control_record(result)
        request_sha256 = result["request_sha256"]
        source_claim_id = None
        scenario_claim_id = None
        claims = []

        template = result.get("template")
        if template is not None:
            source_claim_id = "source-template:" + template["template_sha256"]
            claims.append(self._claim(
                source_claim_id,
                "SOURCE_BOUND",
                template["source"]["serialized_xml"],
                {
                    "statement_id": template["statement_id"],
                    "control_id": template["control_id"],
                    "source_sha256": result["source_sha256"],
                    "template_sha256": template["template_sha256"],
                    "xml_locator": template["source"]["xml_locator"],
                    "domain_identity": {
                        "path": deepcopy(control["domain_path"]),
                        "coordinate": coordinate(control["domain_path"]),
                    },
                },
            ))

        if request.get("operation") == "instantiate":
            scenario_value = {
                "scope": deepcopy(request["scope"]),
                "parameters": deepcopy(sorted(request["parameters"], key=lambda row: row["parameter_id"])),
            }
            scenario_claim_id = "scenario-bindings:" + digest(scenario_value)
            claims.append(self._claim(
                scenario_claim_id,
                "SCENARIO_FACT",
                "Caller-supplied scope and parameter bindings; substantive validity is unverified.",
                scenario_value,
            ))

        domain_status = "BOUND" if control is not None else "UNRESOLVED"
        operation_warrant = self.requirements.operation_warrant(preparation)
        judgment_claim = deepcopy(operation_warrant["claim"])
        judgment_status = judgment_claim["value"]["status"]
        require(judgment_status == self._warrant_instantiation(result),
                "produced Judgment receipt disagrees with the prepared operation")
        judgment_claim_id = judgment_claim["id"]
        claims.append(judgment_claim)

        result = self.requirements.execute_prepared(preparation, operation_warrant)
        work_status = result["status"]
        architecture_status = "COMPLETE" if result["status"] in {"INSPECTED", "INSTANTIATED"} else "UNRESOLVED"

        if result["status"] == "INSTANTIATED":
            require(source_claim_id and scenario_claim_id, "instantiation lacks source or scenario support")
            work_claim_id = "requirement-instance:" + result["instance"]["instance_sha256"]
            work_type = "DETERMINISTIC_DERIVATION"
            work_text = "The exact selected source requirement template was instantiated with the supplied bindings."
            work_value = {
                "instance_sha256": result["instance"]["instance_sha256"],
                "status": "INSTANTIATED",
            }
        elif result["status"] == "INSPECTED":
            require(source_claim_id, "inspection lacks source support")
            work_claim_id = "requirement-inspection:" + template["template_sha256"]
            work_type = "DETERMINISTIC_DERIVATION"
            work_text = "The exact selected source requirement template was inspected without instantiation."
            work_value = {
                "template_sha256": template["template_sha256"],
                "status": "INSPECTED",
            }
        else:
            work_claim_id = "requirement-operation-unresolved:" + digest({
                "request_sha256": request_sha256,
                "residuals": result.get("residuals", []),
            })
            work_type = "UNRESOLVED"
            work_text = "The documentary requirement operation stopped with unresolved bindings."
            work_value = {
                "status": "UNRESOLVED",
                "residuals": deepcopy(result.get("residuals", [])),
            }
        claims.append(self._claim(
            work_claim_id,
            work_type,
            work_text,
            work_value,
            [judgment_claim_id],
        ))

        architecture_claim_id = "documentary-requirement-flow:" + digest({
            "request_sha256": request_sha256,
            "judgment_claim_id": judgment_claim_id,
            "work_claim_id": work_claim_id,
            "status": architecture_status,
        })
        claims.append(self._claim(
            architecture_claim_id,
            "DETERMINISTIC_DERIVATION",
            "The four-stage documentary requirement flow preserved the operation result and its unresolved boundary.",
            {
                "status": architecture_status,
                "requirement_operation_status": result["status"],
            },
            [judgment_claim_id, work_claim_id],
        ))

        unresolved_claim_id = "unresolved-policy-semantics:" + request_sha256
        claims.append(self._claim(
            unresolved_claim_id,
            "UNRESOLVED",
            "No independently admitted mapping turns this arbitrary source requirement into an applicability, satisfaction, compliance, precedence, responsibility, or effect conclusion.",
            {
                "reason": "REQUIREMENT_TO_POLICY_SEMANTICS_NOT_ADMITTED",
                "applicability": None,
                "satisfaction": None,
                "compliance_verdict": None,
            },
            [architecture_claim_id],
        ))

        relationships = {
            judgment_claim_id: "SUPPORTS_INSTANTIATION_WARRANT",
            work_claim_id: "SUPPORTS_REQUIREMENT_OPERATION",
            architecture_claim_id: "SUPPORTS_DOCUMENTARY_FLOW",
            unresolved_claim_id: "SUPPORTS_UNRESOLVED_POLICY_BOUNDARY",
        }
        support_graph = sorted(
            (
                {
                    "from_claim_id": support_id,
                    "to_claim_id": claim["id"],
                    "relationship": relationships[claim["id"]],
                }
                for claim in claims
                if claim["id"] in relationships
                for support_id in claim["support_ids"]
            ),
            key=lambda edge: (edge["to_claim_id"], edge["from_claim_id"], edge["relationship"]),
        )

        domain_outputs = [source_claim_id] if source_claim_id else []
        judgment_inputs = [x for x in (source_claim_id, scenario_claim_id) if x]
        judgment_outputs = [judgment_claim_id]
        work_inputs = [judgment_claim_id]
        work_outputs = [work_claim_id]
        architecture_inputs = [request_sha256, judgment_claim_id, work_claim_id]
        architecture_outputs = [architecture_claim_id, unresolved_claim_id]
        definitions = {
            "domain": {
                "coordinate": coordinate(control["domain_path"]) if control else None,
                "label": control["title"] if control else None,
                "identity": control["id"] if control else None,
                "kind": control["kind"] if control else None,
            },
            **deepcopy(self._definitions),
        }
        stages = [
            {
                "stack": "DOMAIN",
                "semantic_coordinate": definitions["domain"]["coordinate"],
                "producer": "nist_requirements.Requirements._template",
                "operation": "BIND_EXACT_SOURCE_REQUIREMENT",
                "status": domain_status,
                "input_ids": [request_sha256],
                "output_ids": domain_outputs,
            },
            {
                "stack": "JUDGMENT",
                "semantic_coordinate": definitions["judgment"]["coordinate"],
                "producer": "nist_requirements.Requirements.operation_warrant",
                "operation": "WARRANT_EXACT_TEMPLATE_INSTANTIATION_ONLY",
                "status": judgment_status,
                "input_ids": judgment_inputs,
                "output_ids": judgment_outputs,
            },
            {
                "stack": "WORK",
                "semantic_coordinate": definitions["work"]["coordinate"],
                "producer": "nist_requirements.Requirements.execute_prepared",
                "operation": "INSPECT_OR_INSTANTIATE_SOURCE_REQUIREMENT",
                "status": work_status,
                "input_ids": work_inputs,
                "output_ids": work_outputs,
            },
            {
                "stack": "ARCHITECTURE",
                "semantic_coordinate": definitions["architecture"]["coordinate"],
                "producer": "requirement_semantics.RequirementSemanticRuntime.execute",
                "operation": "COMPOSE_DOCUMENTARY_REQUIREMENT_FLOW",
                "status": architecture_status,
                "input_ids": architecture_inputs,
                "output_ids": architecture_outputs,
            },
        ]
        semantic_execution = {
            "schema": SCHEMA,
            "execution_id": "requirement-semantic-execution:" + digest({
                "request_sha256": request_sha256,
                "result_status": result["status"],
                "claims": claims,
                "support_graph": support_graph,
            }),
            "request_sha256": request_sha256,
            "definitions": definitions,
            "stages": stages,
            "claims": claims,
            "support_graph": support_graph,
            "policy_semantic_mapping": {
                "status": "NOT_ADMITTED",
                "residual": "REQUIREMENT_TO_POLICY_SEMANTICS_NOT_ADMITTED",
            },
            "authority_ceiling": CEILING,
            "external_effects": [],
        }
        result["semantic_execution"] = semantic_execution
        return result
