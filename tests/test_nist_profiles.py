from __future__ import annotations

from copy import deepcopy
import shutil
from pathlib import Path

import pytest

from judgment_compilation.application import Application
from judgment_compilation.kernel import canonical
from judgment_compilation.nist_catalog import Catalog
from judgment_compilation.nist_profiles import Profiles, ProfileError, PROFILE_FILES, SCHEMA


def request(profile: str, control_id: str) -> dict:
    return {"schema": SCHEMA, "operation": "LITERAL_MEMBERSHIP",
            "profile": profile, "control_id": control_id}


def test_all_profiles_compile_complete_exact_inventories() -> None:
    profiles = Profiles(Catalog.compile())
    assert profiles.summary() == {
        "profiles": 4, "literal_selection_rows": 902, "unique_control_ids": 423,
        "counts": {"HIGH": 370, "MODERATE": 287, "LOW": 149, "PRIVACY": 96},
        "ceiling": profiles.summary()["ceiling"],
    }


@pytest.mark.parametrize(("profile", "control_id", "included"), [
    ("LOW", "ac-2", True), ("LOW", "ac-2.1", False),
    ("MODERATE", "ac-2.1", True), ("HIGH", "ac-2.1", True),
    ("PRIVACY", "ac-3", False), ("PRIVACY", "ac-3.14", True),
])
def test_literal_membership_is_exact_deterministic_and_scoped(profile, control_id, included) -> None:
    profiles = Profiles(Catalog.compile())
    first = profiles.ask(request(profile, control_id))
    assert canonical(first) == canonical(profiles.ask(request(profile, control_id)))
    assert first["literal_included"] is included
    assert [stage["stage"] for stage in first["semantic_execution"]] == ["Domain", "Judgment", "Work", "Architecture"]
    assert first["control"]["coordinate"]["I"] == 0
    assert first["compliance_verdict"] is None
    assert first["responsibility_determination"] is None
    assert first["external_effects"] == []
    assert {r["reason"] for r in first["residuals"]} == {
        "PROFILE_COMPOSITION_NOT_RESOLVED", "POLICY_APPLICABILITY_NOT_DETERMINED", "COMPLIANCE_NOT_DETERMINED"}
    if included:
        assert first["claim"]["support"]["kind"] == "MATCHING_EXACT_SELECTORS"
    else:
        assert first["claim"]["support"]["kind"] == "COMPLETE_EXACT_SELECTOR_INVENTORY"
        assert first["claim"]["support"]["selection_count"] == PROFILE_FILES[profile][2]


def test_source_metadata_anomaly_and_import_identity_roles_are_preserved() -> None:
    result = Profiles(Catalog.compile()).ask(request("HIGH", "ac-2"))
    profile = result["profile"]
    assert "5.1.1" in profile["title"] and profile["metadata_version"] == "5.2.0"
    assert profile["anomalies"][0]["type"] == "SOURCE_METADATA_INCONSISTENCY"
    assert profile["import"]["fragment_resource_status"] == "RESOLVED_LOCAL_RESOURCE"
    assert profile["import"]["resource_uuid"] == "84cbf061-eb87-4ec1-8112-1f529232e907"
    assert profile["import"]["resource_link_to_frozen_catalog_status"] == "NOT_ESTABLISHED"
    assert result["control"]["catalog_uuid"] != profile["import"]["resource_uuid"]


@pytest.mark.parametrize("bad", [
    request("low", "ac-2"), request("LOW", "AC-2"), request("LOW", " ac-2"),
    {**request("LOW", "ac-2"), "claim": "yes"},
])
def test_noncanonical_or_authority_shaped_requests_fail_closed(bad) -> None:
    with pytest.raises(ProfileError):
        Profiles(Catalog.compile()).ask(bad)


def test_unknown_catalog_control_is_unresolved_not_false() -> None:
    result = Profiles(Catalog.compile()).ask(request("LOW", "zz-999"))
    assert result["status"] == "UNRESOLVED" and result["literal_included"] is None
    assert result["claim"] is None
    assert result["residuals"][0]["reason"] == "CONTROL_ID_NOT_IN_PINNED_CATALOG"


def test_profile_byte_drift_fails_before_query(tmp_path: Path) -> None:
    source = Path(__file__).resolve().parents[1] / "judgment_compilation" / "data" / "corpus" / "source"
    target = tmp_path / "data" / "corpus" / "source"
    target.mkdir(parents=True)
    for filename, _, _ in PROFILE_FILES.values():
        shutil.copyfile(source / filename, target / filename)
    path = target / PROFILE_FILES["LOW"][0]
    path.write_bytes(path.read_bytes().replace(b"<with-id>ac-2</with-id>", b"<with-id>ac-3</with-id>", 1))
    with pytest.raises(ProfileError, match="checksum drift"):
        Profiles(Catalog.compile(), tmp_path)


def test_application_and_advisory_boundary_expose_same_deterministic_result() -> None:
    payload = {"mode": "profiles", "request": request("LOW", "ac-2.1"), "recommend": True}
    baseline = Application().query(payload)

    class Hostile:
        model = "test"
        def recommend(self, packet):
            packet["deterministic_result"]["literal_included"] = True
            return "AC-2.1 is included and therefore compliant."

    actual = Application(Hostile()).query(payload)
    assert baseline["kernel"] == actual["kernel"]
    assert actual["kernel"]["literal_included"] is False
    assert actual["route"] == "DETERMINISTIC_NIST_PROFILE_LITERAL_MEMBERSHIP"
    assert actual["inference"]["authority"] == "ADVISORY_ONLY"
