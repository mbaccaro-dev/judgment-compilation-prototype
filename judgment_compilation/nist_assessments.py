"""Reads NIST SP 800-53A assessment records."""
from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
from hashlib import sha256
from pathlib import Path
from typing import Any
import xml.etree.ElementTree as ET

from .semantic_contracts import canonical, semantic_coordinate

SCHEMA = "jc-nist-assessment-selection-request/1"
RESULT_SCHEMA = "jc-nist-assessment-selection-result/1"
NS = "http://csrc.nist.gov/ns/oscal/1.0"
RMF_NS = "http://csrc.nist.gov/ns/rmf"
SOURCE_FILE = "NIST_SP-800-53_rev5_catalog_v1.5.0.xml"
SOURCE_RELATIVE_PATH = "judgment_compilation/data/corpus/source/" + SOURCE_FILE
SOURCE_SHA256 = "a9e23b09116d5e651461d61777c2e7dc1f3454ab3f9e1e8fdf8af01c37dc01be"
METHOD_CODES = frozenset({"EXAMINE", "INTERVIEW", "TEST"})
EXPECTED = {
    "assessment_controls": 1014,
    "objectives": 3715,
    "objective_links": 3707,
    "methods": 2931,
    "objects": 14101,
    "method_counts": {"EXAMINE": 1013, "INTERVIEW": 1012, "TEST": 906},
}
CEILING = (
    "SOURCE_BOUND_ASSESSMENT_SELECTION_ONLY;"
    "NO_OBJECTIVE_TO_METHOD_OR_OBJECT_SUITABILITY_OR_EVIDENCE_SUFFICIENCY_OR_"
    "ASSESSMENT_PERFORMANCE_OR_FINDING_OR_CONTROL_SATISFACTION_OR_COMPLIANCE_OR_EFFECT"
)


class AssessmentError(ValueError):
    """Pinned assessment source or a selection request is invalid."""


def _need(condition: bool, reason: str) -> None:
    if not condition:
        raise AssessmentError(reason)


def _digest(value: Any) -> str:
    return sha256(canonical(value)).hexdigest()


def _local(element: ET.Element) -> str:
    return element.tag.rsplit("}", 1)[-1]


def _normalise(value: str | None) -> str:
    return " ".join((value or "").split())


def _render(element: ET.Element) -> str:
    fragments: list[str] = []

    def visit(node: ET.Element) -> None:
        if node.text:
            fragments.append(node.text)
        for child in list(node):
            if _local(child) == "insert":
                kind = (child.get("type") or "insert").upper()
                identity = child.get("id-ref") or "UNQUALIFIED"
                fragments.append(
                    f"[PARAMETER: {identity}]" if kind == "PARAM"
                    else f"[INSERT {kind}: {identity}]"
                )
            else:
                visit(child)
            if child.tail:
                fragments.append(child.tail)

    visit(element)
    return _normalise("".join(fragments))


def _locators(root: ET.Element) -> dict[int, str]:
    result: dict[int, str] = {}

    def visit(node: ET.Element, path: str) -> None:
        result[id(node)] = path
        counts: dict[str, int] = {}
        for child in list(node):
            name = _local(child)
            counts[name] = counts.get(name, 0) + 1
            visit(child, f"{path}/*[local-name()='{name}'][{counts[name]}]")

    visit(root, "/*[local-name()='catalog'][1]")
    return result


def _source_record(element: ET.Element, locators: dict[int, str]) -> dict[str, Any]:
    serialised = ET.tostring(element, encoding="utf-8")
    return {
        "xml_locator": locators[id(element)],
        "serialized_xml_sha256": sha256(serialised).hexdigest(),
    }


def _properties(element: ET.Element, name: str) -> list[dict[str, Any]]:
    return [dict(sorted(child.attrib.items())) for child in list(element)
            if _local(child) == "prop" and child.get("name") == name]


def _paragraph(element: ET.Element, locators: dict[int, str], ordinal: int,
               object_id: str | None = None) -> dict[str, Any]:
    text = _render(element)
    record = {
        "ordinal": ordinal,
        "exact_text": text,
        "exact_text_sha256": sha256(text.encode("utf-8")).hexdigest(),
        **_source_record(element, locators),
    }
    if object_id is not None:
        record["object_id"] = object_id
    return record


def _objective(element: ET.Element, parent_id: str | None,
               locators: dict[int, str]) -> dict[str, Any]:
    objective_id = element.get("id")
    _need(type(objective_id) is str and bool(objective_id), "assessment objective requires an ID")
    allowed = {"prop", "p", "part", "link"}
    _need(all(_local(child) in allowed for child in list(element)), "unsupported assessment objective grammar")
    _need(all(_local(child) != "part" or child.get("name") == "assessment-objective"
              for child in list(element)), "unsupported nested assessment objective part")
    labels = _properties(element, "label")
    _need(len(labels) <= 1, "assessment objective has duplicate labels")
    paragraphs = [_paragraph(child, locators, ordinal)
                  for ordinal, child in enumerate(
                      (c for c in list(element) if _local(c) == "p"), 1)]
    parameter_refs = []
    for paragraph in (c for c in list(element) if _local(c) == "p"):
        for node in paragraph.iter():
            if _local(node) == "insert" and node.get("type") == "param":
                parameter_refs.append({"id_ref": node.get("id-ref"), **_source_record(node, locators)})
    links = []
    for child in (c for c in list(element) if _local(c) == "link"):
        _need(child.get("rel") == "assessment-for", "unsupported assessment objective link relation")
        links.append({"raw_href": child.get("href"), **_source_record(child, locators)})
    return {
        "objective_id": objective_id,
        "parent_objective_id": parent_id,
        "raw_label": labels[0].get("value") if labels else None,
        "paragraphs": paragraphs,
        "parameter_refs": parameter_refs,
        "assessment_for": links,
        **_source_record(element, locators),
    }


def _method(element: ET.Element, locators: dict[int, str]) -> dict[str, Any]:
    method_id = element.get("id")
    _need(type(method_id) is str and bool(method_id), "assessment method requires an ID")
    _need(all(_local(child) in {"prop", "part"} for child in list(element)),
          "unsupported assessment method grammar")
    _need(all(_local(child) != "part" or child.get("name") == "assessment-objects"
              for child in list(element)), "unsupported assessment method part")
    method_props = _properties(element, "method")
    _need(len(method_props) == 1 and method_props[0].get("ns") == RMF_NS
          and method_props[0].get("value") in METHOD_CODES, "invalid assessment method property")
    labels = _properties(element, "label")
    _need(len(labels) <= 1, "assessment method has duplicate labels")
    object_parts = [child for child in list(element)
                    if _local(child) == "part" and child.get("name") == "assessment-objects"]
    _need(len(object_parts) == 1 and all(_local(child) == "p" for child in list(object_parts[0])),
          "assessment method requires one supported assessment-objects part")
    objects = []
    for ordinal, paragraph in enumerate(list(object_parts[0]), 1):
        object_id = f"{method_id}:object:{ordinal}"
        objects.append(_paragraph(paragraph, locators, ordinal, object_id))
    _need(bool(objects), "assessment method has no source objects")
    return {
        "method_id": method_id,
        "method_code": method_props[0]["value"],
        "raw_label": labels[0].get("value") if labels else None,
        "objects": objects,
        "objects_part": _source_record(object_parts[0], locators),
        **_source_record(element, locators),
    }


@lru_cache(maxsize=4)
def _compile(source_path_text: str, observed_source_sha256: str) -> dict[str, Any]:
    source_path = Path(source_path_text)
    raw = source_path.read_bytes()
    actual_source_sha256 = sha256(raw).hexdigest()
    _need(actual_source_sha256 == observed_source_sha256 == SOURCE_SHA256,
          "assessment source checksum drift")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise AssessmentError("assessment source is not valid XML") from exc
    _need(root.tag == f"{{{NS}}}catalog", "unsupported assessment source root or namespace")
    locators = _locators(root)
    units: dict[str, dict[str, Any]] = {}
    objective_ids: set[str] = set()
    method_ids: set[str] = set()
    method_counts = {code: 0 for code in sorted(METHOD_CODES)}
    total_links = total_objects = 0

    for control in (node for node in root.iter() if _local(node) == "control"):
        control_id = control.get("id")
        direct = list(control)
        roots = [node for node in direct
                 if _local(node) == "part" and node.get("name") == "assessment-objective"]
        methods = [node for node in direct
                   if _local(node) == "part" and node.get("name") == "assessment-method"]
        if not roots and not methods:
            continue
        _need(type(control_id) is str and bool(control_id), "assessment owner requires a control ID")
        _need(control_id not in units and len(roots) == 1 and bool(methods),
              "assessment owner grammar or identity is ambiguous")
        objectives: dict[str, dict[str, Any]] = {}

        def walk_objective(node: ET.Element, parent_id: str | None) -> None:
            nonlocal total_links
            record = _objective(node, parent_id, locators)
            oid = record["objective_id"]
            _need(oid not in objective_ids and oid not in objectives, "duplicate assessment objective ID")
            objective_ids.add(oid); objectives[oid] = record
            total_links += len(record["assessment_for"])
            for child in list(node):
                if _local(child) == "part":
                    walk_objective(child, oid)

        walk_objective(roots[0], None)
        method_records: dict[str, dict[str, Any]] = {}
        for node in methods:
            record = _method(node, locators)
            mid = record["method_id"]
            _need(mid not in method_ids and mid not in method_records, "duplicate assessment method ID")
            method_ids.add(mid); method_records[mid] = record
            method_counts[record["method_code"]] += 1
            total_objects += len(record["objects"])
        units[control_id] = {
            "control_id": control_id,
            "objectives": objectives,
            "methods": method_records,
            **_source_record(control, locators),
        }

    actual = {
        "assessment_controls": len(units), "objectives": len(objective_ids),
        "objective_links": total_links, "methods": len(method_ids),
        "objects": total_objects, "method_counts": method_counts,
    }
    _need(actual == EXPECTED, "assessment source population or grammar drift")
    return {"units": units, "summary": actual}


def _control_owner(record_id: str, records: dict[str, Any]) -> str | None:
    seen: set[str] = set()
    current = record_id
    while current in records and current not in seen:
        seen.add(current)
        record = records[current]
        if record.get("kind") in {"control", "subcontrol"}:
            return current
        current = record.get("parent_id")
    return None


class Assessments:
    """Inspect and bind exact potential assessment records without findings."""

    def __init__(self, catalog, root: Path | None = None):
        package_root = Path(root).resolve() if root is not None else Path(__file__).resolve().parent
        source_path = package_root / "data" / "corpus" / "source" / SOURCE_FILE
        observed_source_sha256 = sha256(source_path.read_bytes()).hexdigest()
        compiled = _compile(str(source_path.resolve()), observed_source_sha256)
        self._units = compiled["units"]
        self._summary = compiled["summary"]
        self._records = catalog.payload["records"]
        self._catalog_source = deepcopy(catalog.payload["source"])
        for control_id in self._units:
            _need(control_id in self._records and
                  self._records[control_id].get("kind") in {"control", "subcontrol"},
                  "assessment control is missing or ambiguous in pinned catalog")

    def summary(self) -> dict[str, Any]:
        return {**deepcopy(self._summary), "source_sha256": SOURCE_SHA256, "ceiling": CEILING}

    def _unit(self, control_id: Any) -> dict[str, Any]:
        _need(type(control_id) is str and bool(control_id) and control_id == control_id.strip()
              and control_id == control_id.lower(), "control ID must be exact lowercase source identity")
        _need(control_id in self._units, "control has no supported assessment structure")
        return self._units[control_id]

    def _links(self, unit: dict[str, Any]) -> list[dict[str, Any]]:
        result = []
        for objective in unit["objectives"].values():
            for link in objective["assessment_for"]:
                raw_href = link.get("raw_href")
                target = raw_href[1:] if type(raw_href) is str and raw_href.startswith("#") else None
                target_owner = _control_owner(target, self._records) if target else None
                if target_owner is None:
                    status = "UNRESOLVED_TARGET"
                elif target_owner == unit["control_id"]:
                    status = "RESOLVED_SAME_CONTROL_SOURCE_IDENTITY"
                else:
                    status = "RESOLVED_CROSS_CONTROL_IDENTITY_INTERPRETATION_UNRESOLVED"
                result.append({
                    "objective_id": objective["objective_id"], **deepcopy(link),
                    "target_identity": target, "target_owner": target_owner,
                    "resolution_status": status,
                })
        return result

    @staticmethod
    def _seal_stage(stage: str, payload: dict[str, Any]) -> dict[str, Any]:
        record = {"stage": stage, **deepcopy(payload)}
        record["result_sha256"] = _digest(record)
        return record

    @staticmethod
    def _verify_stage(record: Any, expected_stage: str) -> None:
        _need(type(record) is dict and record.get("stage") == expected_stage,
              f"{expected_stage} stage receipt required")
        supplied = record.get("result_sha256")
        body = {key: deepcopy(value) for key, value in record.items()
                if key != "result_sha256"}
        _need(type(supplied) is str and supplied == _digest(body),
              f"{expected_stage} stage receipt integrity failure")

    def bind_source_identities(self, unit: dict[str, Any], objective: dict[str, Any],
                               method: dict[str, Any], selected: list[dict[str, Any]],
                               scope: dict[str, Any]) -> dict[str, Any]:
        return self._seal_stage("Domain", {
            "producer": "nist_assessments.Assessments.bind_source_identities",
            "control_identity": {
                "control_id": unit["control_id"],
                "coordinate": deepcopy(self._records[unit["control_id"]]["coordinate"]),
            },
            "objective_id": objective["objective_id"],
            "objective_serialized_xml_sha256": objective["serialized_xml_sha256"],
            "method_id": method["method_id"],
            "method_serialized_xml_sha256": method["serialized_xml_sha256"],
            "object_refs": [
                {"object_id": item["object_id"],
                 "object_sha256": item["serialized_xml_sha256"]}
                for item in selected
            ],
            "scenario_scope": deepcopy(scope),
        })

    def warrant_structural_selection(self, domain_receipt: dict[str, Any]) -> dict[str, Any]:
        self._verify_stage(domain_receipt, "Domain")
        return self._seal_stage("Judgment", {
            "producer": "nist_assessments.Assessments.warrant_structural_selection",
            "semantic_coordinate": semantic_coordinate("judgment", [0]),
            "input_domain_sha256": domain_receipt["result_sha256"],
            "warrant": "SAME_CONTROL_AND_SELECTED_METHOD_MEMBERSHIP_WITH_EXACT_SOURCE_HASH",
            "relation_basis": "CALLER_SELECTED_WITHIN_SAME_CONTROL",
            "objective_method_suitability": "UNRESOLVED",
        })

    def bind_selection(self, domain_receipt: dict[str, Any],
                       judgment_receipt: dict[str, Any]) -> dict[str, Any]:
        self._verify_stage(domain_receipt, "Domain")
        self._verify_stage(judgment_receipt, "Judgment")
        _need(
            judgment_receipt.get("input_domain_sha256") == domain_receipt["result_sha256"]
            and judgment_receipt.get("warrant") ==
            "SAME_CONTROL_AND_SELECTED_METHOD_MEMBERSHIP_WITH_EXACT_SOURCE_HASH",
            "work rejected missing, altered, or foreign structural-selection warrant",
        )
        return self._seal_stage("Work", {
            "producer": "nist_assessments.Assessments.bind_selection",
            "semantic_coordinate": semantic_coordinate("work", [0]),
            "input_domain_sha256": domain_receipt["result_sha256"],
            "input_judgment_sha256": judgment_receipt["result_sha256"],
            "operation": "PREPARE_SOURCE_BOUND_ASSESSMENT_SELECTION",
            "selected_object_count": len(domain_receipt["object_refs"]),
            "selected_object_refs": deepcopy(domain_receipt["object_refs"]),
        })

    def compose_selection(self, domain_receipt: dict[str, Any],
                          judgment_receipt: dict[str, Any], work_receipt: dict[str, Any],
                          residuals: list[dict[str, Any]]) -> dict[str, Any]:
        self._verify_stage(domain_receipt, "Domain")
        self._verify_stage(judgment_receipt, "Judgment")
        self._verify_stage(work_receipt, "Work")
        _need(
            work_receipt.get("input_domain_sha256") == domain_receipt["result_sha256"]
            and work_receipt.get("input_judgment_sha256") == judgment_receipt["result_sha256"],
            "architecture rejected disconnected assessment operation receipts",
        )
        return self._seal_stage("Architecture", {
            "producer": "nist_assessments.Assessments.compose_selection",
            "semantic_coordinate": semantic_coordinate("architecture", [0]),
            "depends_on": [
                {"stage": "Domain", "result_sha256": domain_receipt["result_sha256"]},
                {"stage": "Judgment", "result_sha256": judgment_receipt["result_sha256"]},
                {"stage": "Work", "result_sha256": work_receipt["result_sha256"]},
            ],
            "preserved_residuals": deepcopy(residuals),
        })

    def inspect(self, request: dict[str, Any]) -> dict[str, Any]:
        _need(type(request) is dict and set(request) == {"schema", "operation", "control_id"},
              "unexpected or missing assessment inspection fields")
        _need(request["schema"] == SCHEMA and request["operation"] == "INSPECT",
              "unsupported assessment inspection schema or operation")
        unit = self._unit(request["control_id"])
        control = self._records[unit["control_id"]]
        links = self._links(unit)
        return {
            "schema": RESULT_SCHEMA, "status": "INSPECTED_SOURCE_STRUCTURE",
            "request": deepcopy(request), "request_sha256": _digest(request),
            "source": {"relative_path": SOURCE_RELATIVE_PATH, "source_sha256": SOURCE_SHA256,
                       "catalog_uuid": self._catalog_source["catalog_uuid"]},
            "control": {"control_id": unit["control_id"], "title": control.get("title"),
                        "kind": control["kind"], "coordinate": deepcopy(control["coordinate"]),
                        "xml_locator": unit["xml_locator"],
                        "serialized_xml_sha256": unit["serialized_xml_sha256"]},
            "objectives": deepcopy(list(unit["objectives"].values())),
            "methods": deepcopy(list(unit["methods"].values())),
            "assessment_for": links,
            "relationship_ceiling": "SOURCE_RECORDED_LINK_IDENTITY_ONLY;SEMANTIC_CORRECTNESS_NOT_ESTABLISHED",
            "residuals": [
                {"reason": "OBJECTIVE_TO_SPECIFIC_METHOD_OBJECT_SUITABILITY_NOT_ESTABLISHED"},
                {"reason": "ASSESSMENT_PERFORMANCE_NOT_ESTABLISHED"},
                {"reason": "DETERMINATION_RESULT_NOT_ESTABLISHED"},
                {"reason": "CONTROL_SATISFACTION_NOT_DETERMINED"},
                {"reason": "COMPLIANCE_NOT_DETERMINED"},
            ],
            "assessment_finding": None, "compliance_verdict": None,
            "responsibility_determination": None, "external_effects": [],
            "authority_ceiling": CEILING,
        }

    def prepare(self, request: dict[str, Any]) -> dict[str, Any]:
        expected = {"schema", "operation", "request_id", "control_id", "objective_id",
                    "method_id", "object_refs", "scenario_scope"}
        _need(type(request) is dict and set(request) == expected,
              "unexpected or missing assessment selection fields")
        _need(request["schema"] == SCHEMA and request["operation"] == "PREPARE",
              "unsupported assessment selection schema or operation")
        _need(type(request["request_id"]) is str and 0 < len(request["request_id"]) <= 200,
              "assessment request identity required")
        unit = self._unit(request["control_id"])
        objective = unit["objectives"].get(request["objective_id"])
        method = unit["methods"].get(request["method_id"])
        _need(objective is not None, "objective does not belong to requested control")
        _need(method is not None, "method does not belong to requested control")
        scope = request["scenario_scope"]
        _need(type(scope) is dict and set(scope) == {"entity_ids", "purpose"},
              "scenario scope requires exact entity_ids and purpose fields")
        ids = scope["entity_ids"]
        _need(type(ids) is list and 0 < len(ids) <= 128 and
              all(type(value) is str and 0 < len(value) <= 200 for value in ids)
              and len(set(ids)) == len(ids), "scenario entity identities must be explicit and unique")
        _need(type(scope["purpose"]) is str and 0 < len(scope["purpose"]) <= 2000,
              "scenario purpose required")
        refs = request["object_refs"]
        _need(type(refs) is list and 0 < len(refs) <= 64, "one or more assessment object references required")
        source_objects = {item["object_id"]: item for item in method["objects"]}
        selected = []
        seen: set[str] = set()
        for ref in refs:
            _need(type(ref) is dict and set(ref) == {"object_id", "object_sha256"},
                  "assessment object reference requires exact ID and hash")
            object_id = ref["object_id"]
            _need(type(object_id) is str and object_id in source_objects,
                  "assessment object does not belong to selected method")
            _need(object_id not in seen, "duplicate assessment object reference")
            seen.add(object_id)
            source_object = source_objects[object_id]
            _need(ref["object_sha256"] == source_object["serialized_xml_sha256"],
                  "assessment object hash mismatch")
            selected.append(deepcopy(source_object))

        links = [row for row in self._links(unit) if row["objective_id"] == objective["objective_id"]]
        residuals = [
            {"reason": "OBJECTIVE_TO_SELECTED_METHOD_OBJECT_SUITABILITY_NOT_ESTABLISHED",
             "depends_on": ["objective_id", "method_id", "object_refs"]},
            {"reason": "CALLER_SCOPE_NOT_INDEPENDENTLY_VERIFIED", "depends_on": ["scenario_scope"]},
            {"reason": "ASSESSMENT_PERFORMANCE_NOT_ESTABLISHED", "depends_on": ["execution_evidence"]},
            {"reason": "EVIDENCE_AUTHENTICITY_RELEVANCE_AND_SUFFICIENCY_NOT_ESTABLISHED",
             "depends_on": ["evidence_records", "objective_method_interpretation"]},
            {"reason": "DETERMINATION_RESULT_NOT_ESTABLISHED", "depends_on": ["assessment_results"]},
            {"reason": "CONTROL_SATISFACTION_NOT_DETERMINED", "depends_on": ["determination_results"]},
            {"reason": "COMPLIANCE_NOT_DETERMINED", "depends_on": ["applicability", "control_satisfaction"]},
        ]
        domain_receipt = self.bind_source_identities(unit, objective, method, selected, scope)
        judgment_receipt = self.warrant_structural_selection(domain_receipt)
        work_receipt = self.bind_selection(domain_receipt, judgment_receipt)
        architecture_receipt = self.compose_selection(
            domain_receipt, judgment_receipt, work_receipt, residuals)
        semantic_execution = [domain_receipt, judgment_receipt, work_receipt, architecture_receipt]
        support_graph = [
            {"from": "pinned_catalog_source", "to": "control_objective_method_identity"},
            {"from": "control_objective_method_identity", "to": "structural_selection_warrant"},
            {"from": "exact_object_hashes", "to": "structural_selection_warrant"},
            {"from": "structural_selection_warrant", "to": "prepared_selection_claim"},
        ]
        claim_text = (
            f"Request {request['request_id']} selects objective {objective['objective_id']}, "
            f"method {method['method_id']}, and {len(selected)} exact source assessment object(s) "
            f"under {unit['control_id']} for preparation only."
        )
        return {
            "schema": RESULT_SCHEMA, "status": "PREPARED_SOURCE_BOUND_SELECTION",
            "request": deepcopy(request), "request_sha256": _digest(request),
            "source": {"relative_path": SOURCE_RELATIVE_PATH, "source_sha256": SOURCE_SHA256,
                       "catalog_uuid": self._catalog_source["catalog_uuid"]},
            "control": {"control_id": unit["control_id"],
                        "coordinate": deepcopy(self._records[unit["control_id"]]["coordinate"])},
            "objective": deepcopy(objective), "assessment_for": links,
            "method": {key: deepcopy(value) for key, value in method.items() if key != "objects"},
            "selected_objects": selected,
            "relation_basis": "CALLER_SELECTED_WITHIN_SAME_CONTROL",
            "selection_warrant": semantic_execution[1]["warrant"],
            "semantic_execution": semantic_execution,
            "support_graph": support_graph, "support_graph_sha256": _digest(support_graph),
            "residuals": residuals,
            "claim": {"id": "assessment-selection:" + request["request_id"] + ":" + _digest(request)[:16],
                      "type": "DETERMINISTIC_DERIVATION", "text": claim_text,
                      "support": {"source_sha256": SOURCE_SHA256,
                                  "objective_serialized_xml_sha256": objective["serialized_xml_sha256"],
                                  "method_serialized_xml_sha256": method["serialized_xml_sha256"],
                                  "object_serialized_xml_sha256": [item["serialized_xml_sha256"] for item in selected]}},
            "assessment_finding": None, "compliance_verdict": None,
            "responsibility_determination": None, "external_effects": [],
            "authority_ceiling": CEILING,
        }

    def ask(self, request: dict[str, Any]) -> dict[str, Any]:
        _need(type(request) is dict, "assessment request object required")
        if request.get("operation") == "INSPECT":
            return self.inspect(request)
        if request.get("operation") == "PREPARE":
            return self.prepare(request)
        raise AssessmentError("unsupported assessment operation")
