"""Builds the structural catalog from NIST OSCAL XML."""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Iterable
import xml.etree.ElementTree as ET

from .semantic_contracts import coordinate


SOURCE_RELATIVE_PATH = Path(
    "judgment_compilation/data/corpus/source/"
    "NIST_SP-800-53_rev5_catalog_v1.5.0.xml"
)
MANIFEST_RELATIVE_PATH = Path("judgment_compilation/data/library/manifest.json")
SOURCE_SHA256 = "a9e23b09116d5e651461d61777c2e7dc1f3454ab3f9e1e8fdf8af01c37dc01be"
MANIFEST_SHA256 = 'a11f0668efbde0ccfe7dcc6f12e6e7e4bf549193d68a409ebc06dc087599ce11'
OSCAL_NAMESPACE = "http://csrc.nist.gov/ns/oscal/1.0"
CATALOG_CEILING = (
    "LEXICAL_SOURCE_EXTRACTION_ONLY;"
    "NO_COMPLIANCE_OR_SEMANTIC_INTERPRETATION_OR_EXECUTABLE_WARRANT"
)
SELF_CONSISTENCY_NOTICE = (
    "Catalog digest validation establishes only local payload self-consistency; "
    "it does not establish external authority, acceptance, or compliance."
)


class CatalogError(ValueError):
    """Raised when the pinned, source-only catalog cannot be compiled."""


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(value: Any) -> str:
    return sha256(_canonical(value).encode("utf-8")).hexdigest()


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _normalise(text: str | None) -> str:
    return " ".join((text or "").split())


def _render_text(element: ET.Element) -> str:
    """Render source text with parameter markers in source order."""

    fragments: list[str] = []

    def visit(node: ET.Element) -> None:
        if node.text:
            fragments.append(node.text)
        for child in list(node):
            if _local_name(child.tag) == "insert":
                insert_type = (child.get("type") or "insert").upper()
                identifier = child.get("id-ref") or "UNQUALIFIED"
                marker = (
                    f"[PARAMETER: {identifier}]"
                    if insert_type == "PARAM"
                    else f"[INSERT {insert_type}: {identifier}]"
                )
                fragments.append(marker)
            visit(child)
            if child.tail:
                fragments.append(child.tail)

    visit(element)
    return "".join(fragments)


def _project_root(root: Path | str | None) -> Path:
    candidate = Path(root).resolve() if root is not None else Path(__file__).resolve().parents[1]
    if not (candidate / "judgment_compilation").is_dir():
        raise CatalogError("root must be the Judgment Compilation project root")
    return candidate


def _element_locators(root: ET.Element) -> dict[int, str]:
    """Return deterministic, namespace-independent XPath-like locators."""

    locators: dict[int, str] = {}

    def visit(element: ET.Element, locator: str) -> None:
        locators[id(element)] = locator
        seen: dict[str, int] = {}
        for child in list(element):
            local = _local_name(child.tag)
            seen[local] = seen.get(local, 0) + 1
            visit(child, f"{locator}/*[local-name()='{local}'][{seen[local]}]")

    visit(root, f"/*[local-name()='{_local_name(root.tag)}'][1]")
    return locators


def _direct_title(element: ET.Element) -> str | None:
    for child in list(element):
        if _local_name(child.tag) == "title":
            value = _normalise("".join(child.itertext()))
            return value or None
    return None


def _aliases(element: ET.Element, title: str | None) -> list[str]:
    aliases: set[str] = set()
    if title:
        aliases.add(title)
    for child in list(element):
        if _local_name(child.tag) != "prop":
            continue
        if child.get("name") in {"label", "alt-label", "identifier"}:
            value = _normalise(child.get("value") or "".join(child.itertext()))
            if value:
                aliases.add(value)
    return sorted(aliases, key=str.casefold)


def _inserts(element: ET.Element, locators: dict[int, str]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for descendant in element.iter():
        if _local_name(descendant.tag) != "insert":
            continue
        attributes = dict(sorted(descendant.attrib.items()))
        items.append(
            {
                "xml_locator": locators[id(descendant)],
                "type": descendant.get("type"),
                "id_ref": descendant.get("id-ref"),
                "attributes": attributes,
                "text": _normalise("".join(descendant.itertext())),
            }
        )
    return items


def _structural_children(element: ET.Element) -> Iterable[ET.Element]:
    for child in list(element):
        if _local_name(child.tag) in {"group", "control", "part", "param"}:
            yield child


def _selected_library_document(manifest: dict[str, Any]) -> dict[str, Any]:
    documents = manifest.get("documents")
    if not isinstance(documents, list) or len(documents) != 195:
        raise CatalogError("library manifest must contain exactly 195 documents")
    selected = [
        document
        for document in documents
        if document.get("publication_id") == "NIST SP 800-53r5-upd1"
    ]
    if len(selected) != 1:
        raise CatalogError("library manifest target NIST SP 800-53r5-upd1 is not cardinality one")
    document = selected[0]
    if document.get("document_index") != 150:
        raise CatalogError("library manifest target has unexpected document index")
    return {
        "document_index": document["document_index"],
        "publication_id": document["publication_id"],
        "title": document.get("title"),
        "manifest_document_sha256": _digest(document),
    }


def _library_document_branches(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Expose the pinned 195-document library spine without importing its PDFs."""

    documents = manifest.get("documents")
    if not isinstance(documents, list) or len(documents) != 195:
        raise CatalogError("library manifest must contain exactly 195 documents")
    indexes = [document.get("document_index") for document in documents]
    if indexes != list(range(1, 196)):
        raise CatalogError("library manifest document indexes must be the pinned 1..195 spine")
    return [
        {
            "document_index": document["document_index"],
            "publication_id": document.get("publication_id"),
            "title": document.get("title"),
            "domain_path": [document["document_index"]],
            "coordinate": coordinate([document["document_index"]]),
        }
        for document in documents
    ]


def verified_catalog_inputs(root: Path | str | None = None) -> tuple[bytes, bytes]:
    """Reauthenticate both catalog inputs from current bytes on every call."""
    project_root = _project_root(root)
    source_path = project_root / SOURCE_RELATIVE_PATH
    manifest_path = project_root / MANIFEST_RELATIVE_PATH
    if not source_path.is_file() or not manifest_path.is_file():
        raise CatalogError("the fixed source XML and library manifest must both exist")
    source_bytes = source_path.read_bytes()
    if sha256(source_bytes).hexdigest() != SOURCE_SHA256:
        raise CatalogError("the fixed OSCAL XML checksum does not match")
    manifest_bytes = manifest_path.read_bytes()
    if sha256(manifest_bytes).hexdigest() != MANIFEST_SHA256:
        raise CatalogError("the fixed library manifest checksum does not match")
    return source_bytes, manifest_bytes


def compile_catalog(root: Path | str | None = None) -> dict[str, Any]:
    """Compile the pinned OSCAL XML into structural records."""

    source_bytes, manifest_bytes = verified_catalog_inputs(root)
    actual_sha256 = sha256(source_bytes).hexdigest()
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
        xml_root = ET.fromstring(source_bytes)
    except (ET.ParseError, json.JSONDecodeError) as error:
        raise CatalogError("the fixed source inputs cannot be parsed") from error
    if xml_root.tag != f"{{{OSCAL_NAMESPACE}}}catalog":
        raise CatalogError("the fixed source is not an OSCAL catalog in the expected namespace")

    document = _selected_library_document(manifest)
    library_branches = _library_document_branches(manifest)
    locators = _element_locators(xml_root)
    records: dict[str, dict[str, Any]] = {}
    links: list[dict[str, str]] = []
    group_keys: list[str] = []
    control_keys: list[str] = []

    def record_node(
        element: ET.Element,
        parent_key: str | None,
        parent_path: list[int],
        position: int,
        parent_kind: str | None,
    ) -> str:
        element_name = _local_name(element.tag)
        kind = "subcontrol" if element_name == "control" and parent_kind in {"control", "subcontrol"} else {
            "group": "group",
            "control": "control",
            "part": "part",
            "param": "parameter",
        }[element_name]
        locator = locators[id(element)]
        oscal_id = element.get("id")
        record_id = oscal_id or f"xml:{sha256(locator.encode('utf-8')).hexdigest()[:24]}"
        if record_id in records:
            raise CatalogError(f"duplicate structural record id: {record_id}")
        domain_path = [*parent_path, position]
        title = _direct_title(element)
        record: dict[str, Any] = {
            "id": record_id,
            "oscal_id": oscal_id,
            "kind": kind,
            "parent_id": parent_key,
            "children": [],
            "xml_locator": locator,
            "source_sha256": actual_sha256,
            "attributes": dict(sorted(element.attrib.items())),
            "title": title,
            "aliases": _aliases(element, title),
            "text": "".join(element.itertext()),
            "normalized_text": _normalise("".join(element.itertext())),
            "rendered_text": _render_text(element),
            "inserts": _inserts(element, locators),
            "domain_path": domain_path,
            "coordinate": coordinate(domain_path),
            "normalized_record_sha256": None,
        }
        records[record_id] = record
        if parent_key is not None:
            records[parent_key]["children"].append(record_id)
            links.append({"parent_id": parent_key, "child_id": record_id})
        if kind == "group":
            group_keys.append(record_id)
        if kind in {"control", "subcontrol"}:
            control_keys.append(record_id)
        for child_position, child in enumerate(_structural_children(element), start=1):
            record_node(child, record_id, domain_path, child_position, kind)
        hashable = dict(record)
        hashable.pop("normalized_record_sha256")
        record["normalized_record_sha256"] = _digest(hashable)
        return record_id

    for top_position, child in enumerate(_structural_children(xml_root), start=1):
        if _local_name(child.tag) != "group":
            raise CatalogError("catalog has an unexpected top-level structural element")
        record_node(child, None, [document["document_index"]], top_position, None)

    metadata = xml_root.find(f"{{{OSCAL_NAMESPACE}}}metadata")
    source = {
        "source_type": "frozen_oscal_xml",
        "source_relative_path": SOURCE_RELATIVE_PATH.as_posix(),
        "source_sha256": actual_sha256,
        "library_manifest_relative_path": MANIFEST_RELATIVE_PATH.as_posix(),
        "library_manifest_sha256": MANIFEST_SHA256,
        "namespace": OSCAL_NAMESPACE,
        "catalog_uuid": xml_root.get("uuid"),
        "catalog_title": _direct_title(metadata) if metadata is not None else None,
        "catalog_version": _normalise(
            "".join(metadata.find(f"{{{OSCAL_NAMESPACE}}}version").itertext())
        ) if metadata is not None and metadata.find(f"{{{OSCAL_NAMESPACE}}}version") is not None else None,
        "library_document": document,
        "pdf_provenance": {
            "status": "UNAVAILABLE_UNQUALIFIED",
            "reason": (
                "The selected library PDF branch is not asserted to be byte or "
                "version equivalent to this OSCAL XML source."
            ),
        },
    }
    result: dict[str, Any] = {
        "schema": "jc/nist-oscal-catalog/1",
        "ceiling": CATALOG_CEILING,
        "source": source,
        "domain_paths": {
            "root": [],
            "library_document_count": 195,
            "library_documents": library_branches,
            "selected_library_document": [document["document_index"]],
        },
        "groups": [records[key] for key in group_keys],
        "controls": [records[key] for key in control_keys],
        "records": records,
        "parent_child_links": links,
        "executable_warrant": None,
        "compliance_verdict": None,
    }
    result["catalog_sha256"] = _digest(result)
    return result


class Catalog:
    """Detached query wrapper with local self-consistency validation only."""

    def __init__(self, payload: dict[str, Any]) -> None:
        if not isinstance(payload, dict):
            raise CatalogError("payload must be a mapping")
        if payload.get("schema") != "jc/nist-oscal-catalog/1":
            raise CatalogError("payload is not a nist OSCAL catalog")
        supplied_digest = payload.get("catalog_sha256")
        hashable_payload = dict(payload)
        hashable_payload.pop("catalog_sha256", None)
        if not isinstance(supplied_digest, str) or supplied_digest != _digest(hashable_payload):
            raise CatalogError("catalog payload digest is not self-consistent")
        supplied_source = payload.get("source")
        if not isinstance(supplied_source, dict) or (
            supplied_source.get("source_sha256") != SOURCE_SHA256
            or supplied_source.get("library_manifest_sha256") != MANIFEST_SHA256
        ):
            raise CatalogError("catalog source provenance does not match the fixed pins")
        controls = payload.get("controls")
        if not isinstance(controls, list):
            raise CatalogError("catalog controls must be a list")
        self._payload = deepcopy(payload)
        self._controls: dict[str, dict[str, Any]] = {
            record["id"]: record
            for record in self._payload["controls"]
            if isinstance(record, dict) and "id" in record
        }
        self._source: dict[str, Any] = self._payload["source"]

    def summary(self) -> dict[str, int]:
        """Small immutable summary for status requests; no full catalog copy."""
        return {"structural_records": len(self._payload["records"]),
                "library_document_roots": self._payload["domain_paths"]["library_document_count"],
                "controls_and_enhancements": len(self._controls)}

    @property
    def payload(self) -> dict[str, Any]:
        """Return a detached payload copy; mutations cannot alter this catalog."""

        return deepcopy(self._payload)

    @property
    def controls(self) -> dict[str, dict[str, Any]]:
        """Return copies of the control records."""

        return deepcopy(self._controls)

    @property
    def source(self) -> dict[str, Any]:
        """Return detached fixed-source metadata."""

        return deepcopy(self._source)

    @classmethod
    def compile(cls, root: Path | str | None = None) -> "Catalog":
        return cls(compile_catalog(root))

    def ask(
        self,
        *,
        control_id: str | None = None,
        title: str | None = None,
    ) -> dict[str, Any]:
        """Query an exact control ID or title while preserving ambiguity."""

        if (control_id is None) == (title is None):
            raise CatalogError("provide exactly one of control_id or title")
        if control_id is not None:
            query = control_id.strip()
            candidates = [
                record
                for record in self._controls.values()
                if query.casefold() in {
                    str(record.get("id", "")).casefold(),
                    str(record.get("oscal_id", "")).casefold(),
                }
            ]
            query_kind = "control_id"
        else:
            query = title.strip() if title is not None else ""
            folded = query.casefold()
            candidates = [
                record
                for record in self._controls.values()
                if folded
                and folded in {
                    _normalise(str(record.get("title") or "")).casefold(),
                    *(_normalise(str(alias)).casefold() for alias in record.get("aliases", [])),
                }
            ]
            query_kind = "title"
        candidates.sort(key=lambda record: (record["domain_path"], record["id"]))
        status = "resolved" if len(candidates) == 1 else "ambiguous" if candidates else "not_found"
        return {
            "status": status,
            "query_kind": query_kind,
            "query": query,
            "candidates": deepcopy(candidates),
            "source": deepcopy(self._source),
            "ceiling": self._payload["ceiling"],
            "executable_warrant": None,
            "compliance_verdict": None,
            "self_consistency_notice": SELF_CONSISTENCY_NOTICE,
        }
