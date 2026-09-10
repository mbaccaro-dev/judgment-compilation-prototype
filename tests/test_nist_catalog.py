from __future__ import annotations

import json
from pathlib import Path
import shutil
import xml.etree.ElementTree as ET

import pytest

import judgment_compilation.nist_catalog as nist_catalog
from judgment_compilation.nist_catalog import (
    Catalog,
    CatalogError,
    MANIFEST_RELATIVE_PATH,
    SOURCE_RELATIVE_PATH,
    SOURCE_SHA256,
    compile_catalog,
)


def test_compile_catalog_preserves_pinned_source_structure() -> None:
    payload = compile_catalog()

    assert payload["source"]["source_sha256"] == SOURCE_SHA256
    assert payload["domain_paths"]["root"] == []
    assert payload["domain_paths"]["library_document_count"] == 195
    assert len(payload["domain_paths"]["library_documents"]) == 195
    assert payload["domain_paths"]["library_documents"][149]["domain_path"] == [150]
    assert payload["domain_paths"]["selected_library_document"] == [150]
    assert len(payload["groups"]) == 20
    assert len(payload["controls"]) == 1196
    assert sum(record["kind"] == "part" for record in payload["records"].values()) == 12730
    assert sum(record["kind"] == "parameter" for record in payload["records"].values()) == 1600

    ac_1 = payload["records"]["ac-1"]
    assert ac_1["xml_locator"].startswith("/*[local-name()='catalog'][1]")
    assert ac_1["normalized_record_sha256"]
    assert any(item["id_ref"] == "ac-1_prm_1" for item in ac_1["inserts"])
    assert "[PARAMETER: ac-1_prm_1]" in ac_1["rendered_text"]
    parameter = payload["records"]["ac-1_prm_1"]
    assert parameter["parent_id"] == "ac-1"
    assert parameter["kind"] == "parameter"


def test_catalog_queries_and_does_not_claim_pdf_or_executable_provenance() -> None:
    catalog = Catalog.compile()
    result = catalog.ask(control_id="AC-1")

    assert result["status"] == "resolved"
    assert result["candidates"][0]["id"] == "ac-1"
    assert result["executable_warrant"] is None
    assert result["compliance_verdict"] is None
    assert result["source"]["pdf_provenance"]["status"] == "UNAVAILABLE_UNQUALIFIED"

    title_result = catalog.ask(title=result["candidates"][0]["title"])
    assert title_result["status"] in {"resolved", "ambiguous"}
    assert any(record["id"] == "ac-1" for record in title_result["candidates"])


def test_catalog_requires_one_query_form() -> None:
    catalog = Catalog.compile()

    with pytest.raises(CatalogError):
        catalog.ask()
    with pytest.raises(CatalogError):
        catalog.ask(control_id="ac-1", title="Access Control Policy and Procedures")


def test_rendered_text_marks_insert_once_and_preserves_ordinary_tails() -> None:
    fixture = ET.fromstring(
        "<p>Opening <em>ordinary</em> tail <insert type='param' id-ref='fixture_prm'/> closing.</p>"
    )

    assert nist_catalog._render_text(fixture) == (
        "Opening ordinary tail [PARAMETER: fixture_prm] closing."
    )


def test_compile_catalog_rejects_valid_but_mutated_manifest_before_branch_use(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    source_target = project_root / SOURCE_RELATIVE_PATH
    manifest_target = project_root / MANIFEST_RELATIVE_PATH
    source_target.parent.mkdir(parents=True)
    manifest_target.parent.mkdir(parents=True)
    project_source = Path(__file__).resolve().parents[1] / SOURCE_RELATIVE_PATH
    project_manifest = Path(__file__).resolve().parents[1] / MANIFEST_RELATIVE_PATH
    shutil.copyfile(project_source, source_target)
    manifest = json.loads(project_manifest.read_text(encoding="utf-8"))
    manifest["documents"][0]["title"] += " mutated"
    manifest_target.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(CatalogError, match="manifest checksum"):
        compile_catalog(project_root)


def test_catalog_detaches_outputs_and_rejects_self_inconsistent_or_unpinned_payloads() -> None:
    payload = compile_catalog()
    catalog = Catalog(payload)
    first = catalog.ask(control_id="ac-1")
    first["candidates"][0]["title"] = "mutated result"
    first["source"]["source_sha256"] = "mutated source"
    exposed_controls = catalog.controls
    exposed_controls["ac-1"]["title"] = "mutated controls"
    exposed_payload = catalog.payload
    exposed_payload["records"]["ac-1"]["title"] = "mutated payload"

    later = catalog.ask(control_id="ac-1")
    assert later["candidates"][0]["title"] != "mutated result"
    assert later["candidates"][0]["title"] != "mutated controls"
    assert later["source"]["source_sha256"] == SOURCE_SHA256
    assert "does not establish external authority" in later["self_consistency_notice"]

    payload["catalog_sha256"] = "0" * 64
    with pytest.raises(CatalogError, match="self-consistent"):
        Catalog(payload)

    repinned_payload = compile_catalog()
    repinned_payload["source"]["source_sha256"] = "0" * 64
    hashable = dict(repinned_payload)
    hashable.pop("catalog_sha256")
    repinned_payload["catalog_sha256"] = nist_catalog._digest(hashable)
    with pytest.raises(CatalogError, match="source provenance"):
        Catalog(repinned_payload)
