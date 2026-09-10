"""Builds checks for the SC-7(25) and SC-7(27) statements."""
from __future__ import annotations

from copy import deepcopy

from .kernel import canonical, digest
from .nist_requirements import REQUEST_SCHEMA, RequirementError, Requirements


SCHEMA = "jc/sc-7-direct-external-connection-family/1"
FAMILY_ID = "sc-7-direct-external-connection"
SOURCE_SKELETON = (
    "Prohibit the direct connection of <PARAMETER_1> to an external network "
    "without the use of <PARAMETER_2>."
)
CEILING = (
    "EXACT_SOURCE_REQUIREMENT_INSTANTIATION_ONLY;"
    "NO_APPLICABILITY_OR_VIOLATION_OR_COMPLIANCE_OR_RESPONSIBILITY_OR_ACTION"
)
POLICY_SEMANTIC_RESIDUAL = "REQUIREMENT_TO_POLICY_SEMANTICS_NOT_ADMITTED"

# These identities and labels are source checks, not an interpretation of their
# values.  Slot order is part of the source statement and is never inferred from
# a caller value.
_CONTROLS = (
    {
        "statement_id": "sc-7.25_smt",
        "control_id": "sc-7.25",
        "template_sha256": "a49d3576cdb23dc03bb87398eb6558f52d82e6bfdc4febba3993ddd9c2298986",
        "parameters": (
            ("sc-07.25_odp.01", "direct_connection_subject", "unclassified national security system"),
            ("sc-07.25_odp.02", "boundary_protection_device", "boundary protection device"),
        ),
    },
    {
        "statement_id": "sc-7.27_smt",
        "control_id": "sc-7.27",
        "template_sha256": "e3384bbbc7d08f730a3c0aefbc9fe4684e3441913ab668258459f9035f3ecc7b",
        "parameters": (
            ("sc-07.27_odp.01", "direct_connection_subject", "unclassified, non-national security system"),
            ("sc-07.27_odp.02", "boundary_protection_device", "boundary protection device"),
        ),
    },
)


class DirectExternalConnectionFamilyError(ValueError):
    """A source template, definition, or caller binding crossed this family."""


def _need(condition, reason):
    if not condition:
        raise DirectExternalConnectionFamilyError(reason)


def _reader(requirements):
    _need(isinstance(requirements, Requirements), "requirements reader required")
    return requirements


def _request(statement_id):
    return {"schema": REQUEST_SCHEMA, "operation": "inspect", "statement_id": statement_id}


def _statement_tokens(template):
    blocks = template.get("blocks")
    _need(type(blocks) is list and len(blocks) == 1, "unsupported statement block count")
    tokens = blocks[0].get("tokens") if type(blocks[0]) is dict else None
    _need(type(tokens) is list and len(tokens) == 5, "unsupported direct-connection grammar")
    expected = (
        ("SOURCE_TEXT", "Prohibit the direct connection of "),
        ("PARAMETER", None),
        ("SOURCE_TEXT", " to an external network without the use of "),
        ("PARAMETER", None),
        ("SOURCE_TEXT", "."),
    )
    for token, (kind, text) in zip(tokens, expected):
        _need(type(token) is dict and token.get("kind") == kind, "source token kind/order drift")
        if text is not None:
            _need(token.get("text") == text, "source text drift")
    return tokens


def _control_definition(requirements, expected):
    inspected = requirements.ask(_request(expected["statement_id"]))
    _need(inspected.get("status") == "INSPECTED", "source statement unavailable")
    template = inspected.get("template")
    _need(type(template) is dict, "source template unavailable")
    _need(template.get("statement_id") == expected["statement_id"], "foreign statement template")
    _need(template.get("control_id") == expected["control_id"], "foreign source control")
    _need(template.get("template_sha256") == expected["template_sha256"], "source template hash drift")
    _need(template.get("grammar_status") == "SUPPORTED", "unsupported source template grammar")
    source = template.get("source")
    _need(type(source) is dict and source.get("xml_id") == expected["statement_id"], "source identity drift")
    _need(type(source.get("source_sha256")) is str and len(source["source_sha256"]) == 64,
          "source checksum unavailable")
    tokens = _statement_tokens(template)
    expected_parameters = expected["parameters"]
    _need(template.get("root_parameter_ids") == [row[0] for row in expected_parameters],
          "source parameter order drift")
    definitions = template.get("parameters")
    _need(type(definitions) is list and len(definitions) == len(expected_parameters),
          "source parameter cardinality drift")
    by_id = {row.get("parameter_id"): row for row in definitions if type(row) is dict}
    _need(len(by_id) == len(definitions), "duplicate or malformed source parameter")

    parameter_roles = []
    for slot, (parameter_id, role_id, label) in enumerate(expected_parameters, 1):
        row = by_id.get(parameter_id)
        _need(type(row) is dict, "source parameter identity drift")
        _need(row.get("control_id") == expected["control_id"], "cross-control parameter binding")
        _need(row.get("declaration_control_id") == expected["control_id"], "parameter declaration control drift")
        _need(row.get("kind") == "ASSIGNMENT" and row.get("label") == label,
              "parameter declaration meaning drift")
        parameter_source = row.get("source")
        _need(type(parameter_source) is dict
              and parameter_source.get("xml_id") == parameter_id
              and parameter_source.get("source_sha256") == source["source_sha256"],
              "parameter provenance drift")
        _need(tokens[(slot * 2) - 1].get("parameter_id") == parameter_id,
              "statement parameter slot drift")
        parameter_roles.append({
            "id": f"domain:{expected['statement_id']}:slot:{slot}",
            "stack": "DOMAIN",
            "slot": slot,
            "role": role_id,
            "parameter_id": parameter_id,
            "label": label,
            "value_ceiling": row["value_ceiling"],
            "declaration": deepcopy(parameter_source),
        })

    return {
        "statement_id": expected["statement_id"],
        "control_id": expected["control_id"],
        "template_sha256": expected["template_sha256"],
        "source": deepcopy(source),
        "skeleton": SOURCE_SKELETON,
        "domain_parameter_roles": parameter_roles,
        "judgment": {
            "id": f"judgment:{expected['statement_id']}:exact-template-instantiation",
            "stack": "JUDGMENT",
            "operation": "WARRANT_EXACT_TEMPLATE_INSTANTIATION_ONLY",
        },
        "work": {
            "id": f"work:{expected['statement_id']}:instantiate-and-validate",
            "stack": "WORK",
            "operation": "VALIDATE_AND_INSTANTIATE_EXACT_TEMPLATE",
        },
        "architecture": {
            "id": f"architecture:{expected['statement_id']}:source-binding-flow",
            "stack": "ARCHITECTURE",
            "steps": ["DOMAIN", "JUDGMENT", "WORK", "ARCHITECTURE"],
        },
    }


def build_definition(requirements=None):
    """Rebuild the definition from current checksum-gated OSCAL bytes."""
    reader = _reader(requirements or Requirements())
    controls = [_control_definition(reader, expected) for expected in _CONTROLS]
    definition = {
        "schema": SCHEMA,
        "family_id": FAMILY_ID,
        "source_skeleton": SOURCE_SKELETON,
        "controls": controls,
        "authority_ceiling": CEILING,
        "policy_semantic_mapping": {
            "status": "NOT_ADMITTED",
            "residual": POLICY_SEMANTIC_RESIDUAL,
        },
        "external_effects": [],
    }
    definition["definition_sha256"] = digest(definition)
    return definition


def validate_definition(candidate, requirements=None):
    """Reject every non-identical source binding, including a slot swap."""
    expected = build_definition(requirements)
    _need(type(candidate) is dict and canonical(candidate) == canonical(expected),
          "direct external connection definition drift")
    return deepcopy(expected)


def _definition_for_statement(definition, statement_id):
    matches = [row for row in definition["controls"] if row["statement_id"] == statement_id]
    _need(len(matches) == 1, "unsupported direct external connection statement")
    return matches[0]


def instantiate(request, requirements=None):
    """Execute the sealed Domain/Judgment/Work/Architecture documentary flow."""
    _need(type(request) is dict and request.get("operation") == "instantiate", "instantiate request required")
    reader = _reader(requirements or Requirements())
    definition = build_definition(reader)
    control = _definition_for_statement(definition, request.get("statement_id"))
    _need(request.get("template_sha256") == control["template_sha256"], "foreign template binding")
    _need(request.get("source_sha256") == control["source"]["source_sha256"], "foreign source binding")

    try:
        preparation = reader.prepare(deepcopy(request))
        warrant = reader.operation_warrant(preparation)
        result = reader.execute_prepared(preparation, warrant)
    except RequirementError as exc:
        raise DirectExternalConnectionFamilyError(str(exc)) from exc

    _need(result.get("template", {}).get("template_sha256") == control["template_sha256"],
          "prepared template drift")
    _need(result.get("source_sha256") == control["source"]["source_sha256"], "prepared source drift")
    status = result.get("status")
    _need(status in {"INSTANTIATED", "UNRESOLVED"}, "unexpected requirement work status")
    judgment_status = warrant["claim"]["value"]["status"]
    work_status = "APPLIED" if status == "INSTANTIATED" else "UNRESOLVED"
    architecture_status = "COMPLETE" if status == "INSTANTIATED" else "UNRESOLVED"
    stages = [
        {"stack": "DOMAIN", "definition_ids": [role["id"] for role in control["domain_parameter_roles"]]},
        {"stack": "JUDGMENT", "definition_id": control["judgment"]["id"], "status": judgment_status},
        {"stack": "WORK", "definition_id": control["work"]["id"], "status": work_status},
        {"stack": "ARCHITECTURE", "definition_id": control["architecture"]["id"], "status": architecture_status},
    ]
    execution = {
        "schema": SCHEMA,
        "family_id": FAMILY_ID,
        "definition_sha256": definition["definition_sha256"],
        "request_sha256": digest(request),
        "status": status,
        "definition": control,
        "stages": stages,
        "judgment_warrant": deepcopy(warrant),
        "work_result": deepcopy(result),
        "authority_ceiling": CEILING,
        "applicability": None,
        "violation": None,
        "compliance_verdict": None,
        "responsibility": None,
        "action": None,
        "policy_semantic_mapping": deepcopy(definition["policy_semantic_mapping"]),
        "external_effects": [],
    }
    execution["execution_sha256"] = digest(execution)
    return execution
