"""Runs a reviewed finite table lookup."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from itertools import product
import json
from typing import Any, Mapping, Sequence


SCHEMA = "jc/finite-enum-table-lookup/1"
OPERATION = "FINITE_ENUM_TABLE_LOOKUP"
CLAIM_CEILING = (
    "SOURCE_BOUND_FINITE_ENUM_RELATION_LOOKUP_ONLY;"
    "NO_SOURCE_INTERPRETATION_OR_COMPLIANCE_OR_RESPONSIBILITY_OR_EXTERNAL_EFFECT"
)


class FiniteEnumTableLookupError(ValueError):
    """The declared lookup program is not a complete finite relation."""


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise FiniteEnumTableLookupError(message)


def _text(value: Any) -> bool:
    return (
        type(value) is str
        and bool(value)
        and value.strip() == value
        and len(value) <= 4096
        and not any(ord(char) < 32 for char in value)
    )


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise FiniteEnumTableLookupError("program is not canonical JSON data") from exc


def _digest(value: Any) -> str:
    return sha256(_canonical(value)).hexdigest()


def _schema(value: Any) -> dict[str, Any]:
    _need(type(value) is dict and set(value) == {"id", "values"}, "invalid enum schema")
    _need(_text(value["id"]), "invalid enum schema id")
    values = value["values"]
    _need(type(values) is list and values, "enum schema needs an ordered nonempty vocabulary")
    _need(all(_text(item) for item in values) and len(values) == len(set(values)), "invalid enum vocabulary")
    return deepcopy(value)


def _input_ports(value: Any) -> list[dict[str, Any]]:
    _need(type(value) is list and len(value) >= 2, "at least two input ports are required")
    ports: list[dict[str, Any]] = []
    for port in value:
        _need(type(port) is dict and set(port) == {"id", "enum_schema"}, "invalid input port")
        _need(_text(port["id"]), "invalid input port id")
        ports.append({"id": port["id"], "enum_schema": _schema(port["enum_schema"])})
    ids = [port["id"] for port in ports]
    _need(ids == sorted(ids) and len(ids) == len(set(ids)), "input ports must use canonical unique ordering")
    _need(len({port["enum_schema"]["id"] for port in ports}) == len(ports), "input enum schema ids must be unique")
    return ports


def _relation(
    relation: Any, ports: list[dict[str, Any]], output_schema: dict[str, Any]
) -> list[dict[str, Any]]:
    _need(type(relation) is list, "relation must be a list")
    port_ids = [port["id"] for port in ports]
    expected_cells = [
        dict(zip(port_ids, values, strict=True))
        for values in product(*(port["enum_schema"]["values"] for port in ports))
    ]
    _need(len(relation) == len(expected_cells), "relation must have exact Cartesian coverage")
    checked: list[dict[str, Any]] = []
    for expected_inputs, cell in zip(expected_cells, relation, strict=True):
        _need(type(cell) is dict and set(cell) == {"inputs", "output"}, "invalid relation cell")
        _need(type(cell["inputs"]) is dict and cell["inputs"] == expected_inputs,
              "relation cells must use canonical declared-port ordering")
        _need(cell["output"] in output_schema["values"], "relation output is outside declared enum domain")
        checked.append(deepcopy(cell))
    return checked


def _body(
    operation_id: Any,
    input_ports: Any,
    output_schema: Any,
    relation: Any,
    provenance: Any,
) -> dict[str, Any]:
    _need(_text(operation_id), "invalid operation id")
    ports = _input_ports(input_ports)
    output = _schema(output_schema)
    _need(output["id"] not in {port["enum_schema"]["id"] for port in ports},
          "output enum schema must be distinct from every input schema")
    _need(type(provenance) is dict and provenance, "provenance binding is required")
    provenance_copy = deepcopy(provenance)
    _canonical(provenance_copy)
    checked_relation = _relation(relation, ports, output)
    relation_binding = {
        "input_ports": ports,
        "output_enum_schema": output,
        "relation": checked_relation,
    }
    return {
        "schema": SCHEMA,
        "operation": OPERATION,
        "operation_id": operation_id,
        "input_ports": ports,
        "output_enum_schema": output,
        "relation": checked_relation,
        "relation_sha256": _digest(relation_binding),
        "provenance": provenance_copy,
        "provenance_sha256": _digest(provenance_copy),
        "claim_ceiling": CLAIM_CEILING,
        "external_effects": [],
    }


def build_reviewed_program(
    operation_id: Any,
    input_ports: Any,
    output_schema: Any,
    relation: Any,
    provenance: Any,
) -> dict[str, Any]:
    """Construct one reviewed data-only program after complete relation validation."""
    body = _body(operation_id, input_ports, output_schema, relation, provenance)
    program_sha256 = _digest(body)
    return {**body, "program_id": f"finite-enum-table:{program_sha256}", "program_sha256": program_sha256}


def validate_reviewed_program(program: Any) -> dict[str, Any]:
    """Revalidate every sealed relation and provenance binding before execution."""
    _need(type(program) is dict, "program must be an object")
    required = {
        "schema", "operation", "operation_id", "input_ports", "output_enum_schema", "relation",
        "relation_sha256", "provenance", "provenance_sha256", "claim_ceiling", "external_effects",
        "program_id", "program_sha256",
    }
    _need(set(program) == required, "unsupported finite enum program shape")
    _need(program["schema"] == SCHEMA and program["operation"] == OPERATION, "unsupported operation")
    _need(program["claim_ceiling"] == CLAIM_CEILING and program["external_effects"] == [],
          "program ceiling or effects drift")
    body = _body(
        program["operation_id"], program["input_ports"], program["output_enum_schema"],
        program["relation"], program["provenance"],
    )
    _need(program["relation_sha256"] == body["relation_sha256"], "relation digest mismatch")
    _need(program["provenance_sha256"] == body["provenance_sha256"], "provenance digest mismatch")
    expected = _digest(body)
    _need(program["program_sha256"] == expected and program["program_id"] == f"finite-enum-table:{expected}",
          "program digest mismatch")
    return {**body, "program_id": program["program_id"], "program_sha256": program["program_sha256"]}


def evaluate_reviewed_program(
    program: Any, observations: Any, *, expected_program_sha256: str | None = None
) -> dict[str, Any]:
    """Evaluate exact observed enum inputs, preserving uncertainty as unresolved."""
    checked = validate_reviewed_program(program)
    if expected_program_sha256 is not None:
        _need(type(expected_program_sha256) is str and checked["program_sha256"] == expected_program_sha256,
              "program differs from its reviewed binding")
    residuals: list[dict[str, Any]] = []
    observed: dict[str, str] = {}
    if type(observations) is not dict:
        residuals.append({"reason": "MALFORMED_INPUT", "input": None})
        observations = {}
    port_ids = [port["id"] for port in checked["input_ports"]]
    for extra in sorted(set(observations) - set(port_ids)):
        residuals.append({"reason": "UNKNOWN_INPUT_PORT", "input": extra})
    for port in checked["input_ports"]:
        port_id = port["id"]
        values = observations.get(port_id)
        if values is None:
            residuals.append({"reason": "MISSING_INPUT", "input": port_id})
            continue
        if type(values) is not list:
            residuals.append({"reason": "MALFORMED_INPUT", "input": port_id})
            continue
        if not values:
            residuals.append({"reason": "MISSING_INPUT", "input": port_id})
            continue
        if len(values) != 1:
            residuals.append({"reason": "CONFLICTING_INPUT", "input": port_id, "candidates": deepcopy(values)})
            continue
        value = values[0]
        if value is None:
            residuals.append({"reason": "UNKNOWN_INPUT", "input": port_id})
            continue
        if value not in port["enum_schema"]["values"]:
            residuals.append({"reason": "UNKNOWN_ENUM_VALUE", "input": port_id, "value": deepcopy(value)})
            continue
        observed[port_id] = value
    if residuals:
        return {
            "operation": OPERATION, "operation_id": checked["operation_id"], "status": "UNRESOLVED",
            "output": None, "residuals": residuals, "program_sha256": checked["program_sha256"],
            "relation_sha256": checked["relation_sha256"], "provenance_sha256": checked["provenance_sha256"],
            "provenance": deepcopy(checked["provenance"]), "claim_ceiling": CLAIM_CEILING,
            "external_effects": [],
        }
    cell = next(item for item in checked["relation"] if item["inputs"] == observed)
    return {
        "operation": OPERATION, "operation_id": checked["operation_id"], "status": "COMPLETE",
        "output": cell["output"], "residuals": [], "program_sha256": checked["program_sha256"],
        "relation_sha256": checked["relation_sha256"], "provenance_sha256": checked["provenance_sha256"],
        "provenance": deepcopy(checked["provenance"]), "claim_ceiling": CLAIM_CEILING,
        "external_effects": [],
    }


__all__ = [
    "CLAIM_CEILING", "FiniteEnumTableLookupError", "OPERATION", "SCHEMA",
    "build_reviewed_program", "evaluate_reviewed_program", "validate_reviewed_program",
]
