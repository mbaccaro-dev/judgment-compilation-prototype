"""Checks control IDs in the included NIST profiles."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any
import xml.etree.ElementTree as ET

from .semantic_contracts import canonical, semantic_coordinate

SCHEMA = "jc-nist-profile-membership-request/1"
RESULT_SCHEMA = "jc-nist-profile-membership-result/1"
NS = "http://csrc.nist.gov/ns/oscal/1.0"
CEILING = (
    "SOURCE_PROFILE_INCLUDE_MEMBERSHIP_ONLY;"
    "NO_RESOLVED_PROFILE_COMPOSITION_OR_APPLICABILITY_OR_SATISFACTION_OR_"
    "COMPLIANCE_OR_PRECEDENCE_OR_RESPONSIBILITY_OR_EFFECT"
)
PROFILE_FILES = {
    "HIGH": ("NIST_SP-800-53_rev5_HIGH-baseline_profile_v1.5.0.xml", "87b8c84863e6f8edf8f9326847f1e2ea59bd5fa30d3c72d3a0ffd917c723c4e8", 370),
    "MODERATE": ("NIST_SP-800-53_rev5_MODERATE-baseline_profile_v1.5.0.xml", "4865e63183c155dce7ffb6c05923cab7b3150c7c16ee7fff201fc881b551c3bd", 287),
    "LOW": ("NIST_SP-800-53_rev5_LOW-baseline_profile_v1.5.0.xml", "ccc5a4f73f5ebc77197bef5320872eaeb9de600ecfc02fdd91570fae167f30dc", 149),
    "PRIVACY": ("NIST_SP-800-53_rev5_PRIVACY-baseline_profile_v1.5.0.xml", "03b0d4be07e8077125e0283d70d726d6397ba9f692def4153754d0b5f7cc9d29", 96),
}
CONTROL_ID = re.compile(r"[a-z]{2}-[1-9][0-9]*(?:\.[1-9][0-9]*)?")
CATALOG_CONTROL_KINDS = frozenset({"control", "subcontrol"})


class ProfileError(ValueError):
    """Pinned profile bytes or a membership request are invalid."""


def _need(condition: bool, reason: str) -> None:
    if not condition:
        raise ProfileError(reason)


def _digest(value: Any) -> str:
    return sha256(canonical(value)).hexdigest()


def _locators(root: ET.Element) -> dict[int, str]:
    result: dict[int, str] = {}

    def visit(node: ET.Element, path: str) -> None:
        result[id(node)] = path
        counts: dict[str, int] = {}
        for child in list(node):
            name = child.tag.rsplit("}", 1)[-1]
            counts[name] = counts.get(name, 0) + 1
            visit(child, f"{path}/*[local-name()='{name}'][{counts[name]}]")

    visit(root, "/*[local-name()='profile'][1]")
    return result


def _one(parent: ET.Element, name: str) -> ET.Element:
    matches = parent.findall(f"{{{NS}}}{name}")
    _need(len(matches) == 1, f"profile requires exactly one {name}")
    return matches[0]


def _text(parent: ET.Element, name: str) -> str:
    value = " ".join("".join(_one(parent, name).itertext()).split())
    _need(bool(value), f"profile {name} is empty")
    return value


def _parse_profile(path: Path, key: str, expected_sha256: str, expected_count: int,
                   catalog_records: dict[str, Any]) -> dict[str, Any]:
    raw = path.read_bytes()
    actual_sha256 = sha256(raw).hexdigest()
    _need(actual_sha256 == expected_sha256, f"{key} profile checksum drift")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ProfileError(f"{key} profile is not valid XML") from exc
    _need(root.tag == f"{{{NS}}}profile", "unsupported profile root or namespace")
    _need(set(root.attrib) == {"uuid"} and bool(root.get("uuid")), "invalid profile identity")
    direct = [child.tag.rsplit("}", 1)[-1] for child in list(root)]
    _need(direct == ["metadata", "import", "merge", "back-matter"], "unsupported profile top-level grammar")
    locators = _locators(root)

    metadata = _one(root, "metadata")
    title = _text(metadata, "title")
    version = _text(metadata, "version")
    oscal_version = _text(metadata, "oscal-version")

    import_node = _one(root, "import")
    _need(set(import_node.attrib) == {"href"}, "unsupported import attributes")
    href = import_node.get("href", "")
    _need(href.startswith("#") and len(href) > 1, "profile import must reference one local resource")
    _need([c.tag.rsplit("}", 1)[-1] for c in list(import_node)] == ["include-controls"],
          "unsupported import selection grammar")
    include = _one(import_node, "include-controls")
    _need(not include.attrib, "unsupported include-controls attributes")
    selectors = list(include)
    _need(bool(selectors) and all(s.tag == f"{{{NS}}}with-id" and not s.attrib and not list(s) for s in selectors),
          "unsupported profile selector grammar")
    rows = []
    seen: set[str] = set()
    for ordinal, selector in enumerate(selectors, 1):
        control_id = (selector.text or "")
        _need(control_id == control_id.strip() and CONTROL_ID.fullmatch(control_id) is not None,
              "profile selector is not an exact canonical control ID")
        _need(control_id not in seen, "duplicate profile selector")
        seen.add(control_id)
        _need(control_id in catalog_records and catalog_records[control_id].get("kind") in CATALOG_CONTROL_KINDS,
              "profile selector is missing or ambiguous in the pinned catalog")
        rows.append({
            "ordinal": ordinal,
            "control_id": control_id,
            "xml_locator": locators[id(selector)],
            "exact_text": control_id,
            "exact_text_sha256": sha256(control_id.encode("utf-8")).hexdigest(),
            "catalog_coordinate": deepcopy(catalog_records[control_id]["coordinate"]),
        })
    _need(len(rows) == expected_count, f"{key} profile selector count drift")

    merge = _one(root, "merge")
    _need(not merge.attrib and [c.tag.rsplit("}", 1)[-1] for c in list(merge)] == ["as-is"]
          and _text(merge, "as-is") == "true", "unsupported profile merge grammar")

    back_matter = _one(root, "back-matter")
    resources = back_matter.findall(f"{{{NS}}}resource")
    fragment = href[1:]
    matches = [resource for resource in resources if resource.get("uuid") == fragment]
    _need(len(matches) == 1, "profile import fragment does not resolve to exactly one local resource")
    resource = matches[0]
    rlinks = []
    for rlink in resource.findall(f"{{{NS}}}rlink"):
        _need(set(rlink.attrib) == {"media-type", "href"} and not list(rlink), "unsupported resource link grammar")
        rlinks.append({"media_type": rlink.get("media-type"), "href": rlink.get("href"),
                       "xml_locator": locators[id(rlink)]})
    _need(bool(rlinks), "profile import resource has no catalog links")
    inventory_sha256 = _digest(rows)
    anomalies = []
    if key == "HIGH" and "5.1.1" in title and version == "5.2.0":
        anomalies.append({"type": "SOURCE_METADATA_INCONSISTENCY", "field": "title_vs_version",
                          "title_text": title, "metadata_version": version})
    return {
        "profile_key": key,
        "profile_uuid": root.get("uuid"),
        "source_relative_path": "judgment_compilation/data/corpus/source/" + path.name,
        "source_sha256": actual_sha256,
        "title": title,
        "metadata_version": version,
        "oscal_version": oscal_version,
        "import": {
            "href": href,
            "xml_locator": locators[id(import_node)],
            "fragment_resource_status": "RESOLVED_LOCAL_RESOURCE",
            "resource_uuid": fragment,
            "resource_xml_locator": locators[id(resource)],
            "resource_links": rlinks,
            "resource_link_to_frozen_catalog_status": "NOT_ESTABLISHED",
        },
        "merge": {"as_is": True, "xml_locator": locators[id(merge)]},
        "selectors": rows,
        "selection_count": len(rows),
        "selection_inventory_sha256": inventory_sha256,
        "grammar_status": "SUPPORTED_EXACT_LITERAL_INCLUDE_SUBSET",
        "anomalies": anomalies,
    }


class Profiles:
    """Compile and query all four exact profile selector inventories."""

    def __init__(self, catalog, root: Path | None = None):
        package_root = Path(root).resolve() if root is not None else Path(__file__).resolve().parent
        source_root = package_root / "data" / "corpus" / "source"
        payload = catalog.payload
        records = payload["records"]
        self.catalog_source = deepcopy(payload["source"])
        self._profiles = {
            key: _parse_profile(source_root / filename, key, expected_hash, count, records)
            for key, (filename, expected_hash, count) in PROFILE_FILES.items()
        }
        self._records = deepcopy(records)

    def summary(self) -> dict[str, Any]:
        return {
            "profiles": len(self._profiles),
            "literal_selection_rows": sum(p["selection_count"] for p in self._profiles.values()),
            "unique_control_ids": len({r["control_id"] for p in self._profiles.values() for r in p["selectors"]}),
            "counts": {key: self._profiles[key]["selection_count"] for key in PROFILE_FILES},
            "ceiling": CEILING,
        }

    def accounting(self) -> dict[str, Any]:
        """Return source identities and selector counts."""
        summary = self.summary()
        return {
            "profile_count": summary["profiles"],
            "literal_selection_rows": summary["literal_selection_rows"],
            "unique_control_ids": summary["unique_control_ids"],
            "per_profile_counts": deepcopy(summary["counts"]),
            "source_identities": [
                {
                    "profile_key": key,
                    "source_relative_path": self._profiles[key]["source_relative_path"],
                    "source_sha256": self._profiles[key]["source_sha256"],
                    "selection_count": self._profiles[key]["selection_count"],
                    "selection_inventory_sha256": self._profiles[key]["selection_inventory_sha256"],
                }
                for key in PROFILE_FILES
            ],
            "selector_rows_embedded": False,
            "coverage_ceiling": CEILING,
        }

    def ask(self, request: dict[str, Any]) -> dict[str, Any]:
        _need(type(request) is dict and set(request) == {"schema", "operation", "profile", "control_id"},
              "unexpected or missing profile query fields")
        _need(request["schema"] == SCHEMA and request["operation"] == "LITERAL_MEMBERSHIP",
              "unsupported profile request schema or operation")
        profile_key = request["profile"]
        control_id = request["control_id"]
        _need(type(profile_key) is str and profile_key in PROFILE_FILES, "unknown or noncanonical profile key")
        _need(type(control_id) is str and CONTROL_ID.fullmatch(control_id) is not None,
              "control ID must be exact lowercase canonical syntax")
        profile = self._profiles[profile_key]
        request_sha256 = _digest(request)
        residuals = [
            {"reason": "PROFILE_COMPOSITION_NOT_RESOLVED"},
            {"reason": "POLICY_APPLICABILITY_NOT_DETERMINED"},
            {"reason": "COMPLIANCE_NOT_DETERMINED"},
        ]
        record = self._records.get(control_id)
        if record is None or record.get("kind") not in CATALOG_CONTROL_KINDS:
            return {
                "schema": RESULT_SCHEMA, "status": "UNRESOLVED", "request": deepcopy(request),
                "request_sha256": request_sha256, "literal_included": None,
                "matching_selectors": [], "profile": deepcopy(profile), "control": None,
                "semantic_execution": [],
                "residuals": [{"reason": "CONTROL_ID_NOT_IN_PINNED_CATALOG"}, *residuals],
                "claim": None, "authority_ceiling": CEILING, "compliance_verdict": None,
                "responsibility_determination": None, "external_effects": [],
            }
        matches = [row for row in profile["selectors"] if row["control_id"] == control_id]
        included = bool(matches)
        support = ({"kind": "MATCHING_EXACT_SELECTORS", "selectors": deepcopy(matches)} if included else
                   {"kind": "COMPLETE_EXACT_SELECTOR_INVENTORY", "selection_count": profile["selection_count"],
                    "selection_inventory_sha256": profile["selection_inventory_sha256"]})
        claim_text = f"{control_id} is {'literally selected' if included else 'not literally selected'} by the pinned {profile_key} profile include-controls inventory."
        semantic_execution = [
            {"stage": "Domain", "producer": "nist_profiles.Profiles.ask:bind_exact_source_identities",
             "profile_identity": {"profile_key": profile_key, "profile_uuid": profile["profile_uuid"],
                                  "source_sha256": profile["source_sha256"]},
             "control_identity": {"control_id": control_id, "coordinate": deepcopy(record["coordinate"])}},
            {"stage": "Judgment", "producer": "nist_profiles.Profiles.ask:warrant_literal_membership_test",
             "semantic_coordinate": semantic_coordinate("judgment", [0]),
             "warrant": "EXACT_ID_EQUALITY_OVER_COMPLETE_PINNED_SELECTOR_INVENTORY",
             "support_inputs": [profile["source_sha256"], profile["selection_inventory_sha256"],
                                self.catalog_source["source_sha256"]]},
            {"stage": "Work", "producer": "nist_profiles.Profiles.ask:compare_exact_identifier",
             "semantic_coordinate": semantic_coordinate("work", [0]),
             "operation": "LITERAL_MEMBERSHIP", "result": included, "support": support},
            {"stage": "Architecture", "producer": "nist_profiles.Profiles.ask:compose_source_bound_result",
             "semantic_coordinate": semantic_coordinate("architecture", [0]),
             "depends_on": ["Domain", "Judgment", "Work"],
             "preserved_residuals": deepcopy(residuals)},
        ]
        support_graph = [
            {"from": "profile_source", "to": "literal_membership_warrant"},
            {"from": "catalog_control_identity", "to": "literal_membership_warrant"},
            {"from": "literal_membership_warrant", "to": "exact_identifier_comparison"},
            {"from": "exact_identifier_comparison", "to": "source_bound_claim"},
        ]
        return {
            "schema": RESULT_SCHEMA, "status": "RESOLVED", "request": deepcopy(request),
            "request_sha256": request_sha256, "literal_included": included,
            "matching_selectors": deepcopy(matches),
            "profile": {k: deepcopy(v) for k, v in profile.items() if k != "selectors"},
            "control": {"id": control_id, "title": record.get("title"),
                        "kind": record["kind"],
                        "coordinate": deepcopy(record["coordinate"]),
                        "catalog_uuid": self.catalog_source["catalog_uuid"],
                        "catalog_source_sha256": self.catalog_source["source_sha256"]},
            "semantic_execution": semantic_execution,
            "support_graph": support_graph, "support_graph_sha256": _digest(support_graph),
            "residuals": residuals,
            "claim": {"id": "profile-membership:" + profile_key.lower() + ":" + control_id,
                      "type": "DETERMINISTIC_DERIVATION", "text": claim_text,
                      "support": support},
            "authority_ceiling": CEILING, "compliance_verdict": None,
            "responsibility_determination": None, "external_effects": [],
        }
