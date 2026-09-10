"""Tests package behavior."""
from copy import deepcopy
from pathlib import Path

import pytest

from judgment_compilation._native import BINARY_PATH, BINARY_SHA256
from judgment_compilation.rust_adapter import RustExecutor
from judgment_compilation.semantic_contracts import (
    SemanticContractError,
    canonical,
    execute_architecture,
)
from test_semantic_values import fixture, request


@pytest.fixture(scope="module")
def native():
    package = __import__("judgment_compilation")
    binary = Path(package.__file__).resolve().parent / BINARY_PATH
    return RustExecutor(binary, BINARY_SHA256)


def assert_parity(native, pack, req):
    python_result = execute_architecture(deepcopy(pack), "flow", deepcopy(req))
    rust_result = native(deepcopy(pack), "flow", deepcopy(req))
    assert canonical(rust_result) == canonical(python_result)
    return python_result


def assert_rejected_by_both(native, pack, req):
    with pytest.raises(SemanticContractError):
        execute_architecture(deepcopy(pack), "flow", deepcopy(req))
    with pytest.raises(SemanticContractError):
        native(deepcopy(pack), "flow", deepcopy(req))


@pytest.mark.parametrize(
    ("unknown", "statuses", "output_count"),
    [
        (
            {
                "id": "unknown-category-b",
                "text": "Only item-b's category is unconfirmed.",
                "predicate": "category",
                "arguments": {"item": "item-b"},
            },
            ["APPLIED", "APPLIED"],
            2,
        ),
        (
            {
                "id": "unknown-elapsed-a",
                "text": "Elapsed time is unconfirmed.",
                "predicate": "elapsed",
                "arguments": {"item": "item-a"},
            },
            ["APPLIED", "UNRESOLVED"],
            1,
        ),
        (
            {
                "id": "unknown-category-a",
                "text": "The selected category is unconfirmed.",
                "predicate": "category",
                "arguments": {"item": "item-a"},
            },
            ["UNRESOLVED", "BLOCKED"],
            0,
        ),
    ],
)
def test_native_scoped_unknown_parity(native, unknown, statuses, output_count):
    req = request([1, 1])
    req["unknowns"] = [unknown]
    result = assert_parity(native, fixture(), req)
    assert [step["status"] for step in result["steps"]] == statuses
    assert len(result["outputs"]) == output_count
    assert result["unknowns"] == [unknown]


def test_native_unscoped_unknown_remains_a_global_blocker(native):
    req = request([1, 1])
    req["unknowns"] = ["A separate unspecified input remains unknown."]
    result = assert_parity(native, fixture(), req)
    assert result["status"] == "UNRESOLVED"
    assert result["outputs"] == []


@pytest.mark.parametrize("basis", ["CALENDAR_DAY", "BUSINESS_DAY"])
def test_native_rejects_calendar_and_business_units_as_fixed_elapsed_time(native, basis):
    pack = fixture()
    pack["domain"].append(
        {
            "path": [2, 3],
            "label": basis,
            "aliases": [],
            "unit": {
                "dimension_path": [2],
                "numerator": 1,
                "denominator": 1,
                "basis": basis,
                "calendar_id": "fixture-calendar",
                "source_ids": ["fictional-policy"],
            },
        }
    )
    req = request([1, 1])
    req["facts"][1]["value"]["unit_path"] = [2, 3]
    assert_rejected_by_both(native, pack, req)


def test_native_enforces_explicit_domain_root_specialization(native):
    assert_rejected_by_both(native, fixture(), request([2, 1]))

    pack = fixture()
    pack["domain"][2].pop("specializes")
    assert_rejected_by_both(native, pack, request([1, 1]))


def test_native_exception_conflict_and_rule_order_parity(native):
    ordinary = fixture()
    ordinary["work"][0]["judgments"].reverse()
    ordinary_result = assert_parity(native, ordinary, request([1, 1]))
    assert ordinary_result["status"] == "COMPLETE"
    assert ordinary_result["outputs"][0]["value"]["amount"] == 60

    conflicting = fixture()
    conflicting["judgments"][1].pop("overrides")
    conflict_result = assert_parity(native, conflicting, request([1, 1]))
    assert conflict_result["status"] == "UNRESOLVED"
    assert conflict_result["outputs"] == []
    assert conflict_result["steps"][0]["residuals"][0]["reason"] == "CONFLICTING_JUDGMENTS"


def test_native_replay_and_entity_changes_do_not_cross_bindings(native):
    pack = fixture()
    req = request([1, 2])
    req["facts"].append(
        {
            "id": "category-b",
            "predicate": "category",
            "arguments": {"item": "item-b"},
            "value": [1, 1],
        }
    )
    first = assert_parity(native, pack, req)
    second = assert_parity(native, pack, req)
    assert canonical(first) == canonical(second)
    assert first["outputs"][0]["arguments"] == {"item": "item-a"}
    assert first["outputs"][0]["value"]["amount"] == 30

    altered = deepcopy(req)
    altered["bindings"]["compare"]["target"] = ["item-b"]
    changed = assert_parity(native, pack, altered)
    assert changed["status"] == "UNRESOLVED"
    assert len(changed["outputs"]) == 1
    assert changed["outputs"][0]["arguments"] == {"item": "item-a"}


@pytest.mark.parametrize(
    "mutate",
    [
        lambda pack, req: req["facts"][1]["value"].update(amount=True),
        lambda pack, req: req["facts"].append(
            {
                "id": "forged-derived",
                "predicate": "window",
                "arguments": {"item": "item-a"},
                "value": {"amount": 30, "unit_path": [2, 1]},
            }
        ),
        lambda pack, req: req.update(
            unknowns=[
                {
                    "id": "bad-unknown",
                    "text": "Malformed scope.",
                    "predicate": "window",
                    "arguments": {"item": "item-a"},
                }
            ]
        ),
        lambda pack, req: pack["predicates"][0].pop("domain_root"),
        lambda pack, req: pack["domain"][5]["unit"].update(
            basis="CALENDAR_DAY", calendar_id=None
        ),
    ],
)
def test_native_rejects_malformed_typed_values_and_contracts(native, mutate):
    pack, req = fixture(), request([1, 1])
    mutate(pack, req)
    assert_rejected_by_both(native, pack, req)
