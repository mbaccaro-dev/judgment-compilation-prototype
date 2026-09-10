from copy import deepcopy

import pytest

from judgment_compilation.interpretation_qualification import REVIEW_SCHEMA, digest, qualify_interpretation
from judgment_compilation.qualified_predicate_builder import (
    QualifiedPredicateBuilderError,
    compose_qualified_predicate,
    decompose_qualified_predicate,
    qualification_target,
    recompose_qualified_predicate,
)
from test_semantic_values import fixture


def _parts(**overrides):
    predicate = {
        "id": "reviewed-eligibility-fact",
        "roles": {"item": "purchase"},
        "origin": "INPUT",
        "input_kind": "SCENARIO_FACT",
        "value_type": "BOOLEAN",
    }
    predicate.update(overrides.pop("predicate", {}))
    parts = {
        "predicate": predicate,
        "fact_kind": {"scope": "SCENARIO_FACT"},
        "source_ids": ["fictional-policy"],
    }
    parts.update(overrides)
    return parts


def _qualification(parts, context, *, subject_id=None, source_index=None):
    source = context["sources"][0]
    source_index = source_index or {
        source["id"]: {
            "source_sha256": source["sha256"],
            "quote_sha256": digest("Fixture reviewed support."),
            "locator": "fixture#predicate",
        }
    }
    target = qualification_target(parts, context)
    subject_id = subject_id or f"predicate:{parts['predicate']['id']}"
    claim = {
        "id": "predicate-fixture-claim",
        "source_support": [{"source_id": source["id"], **source_index[source["id"]]}],
        "interpretation": {
            "rationale": "Independent fixture review binds exact predicate parts.",
            "mapping": {"subject_id": subject_id},
            "scope": {"fixture": "predicate"},
            "limits": ["Local held test fixture."],
            "negative_case": "Changed source, review, or parts must fail.",
        },
        "derivation_binding": {
            "subject_kind": "SEMANTIC_DEFINITION",
            "subject_id": subject_id,
            "target_contract_sha256": digest(target),
        },
    }
    review = {
        "schema": REVIEW_SCHEMA,
        "id": "predicate-fixture-review",
        "decision": "REVIEW_CONFIRMED",
        "reviewed_claim_sha256": digest(claim),
        "reviewer_evidence": ["fixture#independent-review"],
    }
    pins = {review["id"]: digest(review)}
    return qualify_interpretation(claim, review, source_index, target, review_pins=pins), source_index, pins


def _candidate(parts=None, context=None):
    context = fixture() if context is None else context
    parts = _parts() if parts is None else parts
    qualification, source_index, pins = _qualification(parts, context)
    return compose_qualified_predicate(parts, qualification, source_index=source_index, review_pins=pins, context=context)


def test_constructs_one_reviewed_predicate_successor_and_replays_deterministically():
    context = fixture()
    first = _candidate(context=context)
    second = _candidate(context=context)
    assert first == second
    assert decompose_qualified_predicate(first)["fact_kind"]["scope"] == "SCENARIO_FACT"
    successor = recompose_qualified_predicate(context, first)
    assert successor["predicates"][-1]["id"] == "reviewed-eligibility-fact"


@pytest.mark.parametrize("mutation", [
    lambda qualification: qualification.pop("review_evidence"),
    lambda qualification: qualification["claim"].__setitem__("id", "modified-claim"),
])
def test_rejects_missing_review_or_modified_claim(mutation):
    context = fixture()
    parts = _parts()
    qualification, source_index, pins = _qualification(parts, context)
    mutation(qualification)
    with pytest.raises(QualifiedPredicateBuilderError):
        compose_qualified_predicate(parts, qualification, source_index=source_index, review_pins=pins, context=context)


def test_rejects_bad_source_binding_and_identity_collision():
    context = fixture()
    parts = _parts()
    qualification, source_index, pins = _qualification(parts, context)
    bad_sources = deepcopy(source_index)
    bad_sources["fictional-policy"]["source_sha256"] = "0" * 64
    with pytest.raises(QualifiedPredicateBuilderError):
        compose_qualified_predicate(parts, qualification, source_index=bad_sources, review_pins=pins, context=context)
    successor = recompose_qualified_predicate(context, _candidate(context=context))
    with pytest.raises(QualifiedPredicateBuilderError):
        qualification_target(parts, successor)


@pytest.mark.parametrize("parts", [
    _parts(predicate={"value_type": "TEXT"}),
    _parts(fact_kind={"scope": "UNSCOPED"}),
    _parts(predicate={"roles": {"missing": "Claim"}}),
])
def test_rejects_invalid_value_type_scope_or_role(parts):
    with pytest.raises(QualifiedPredicateBuilderError):
        qualification_target(parts, fixture())


def test_rejects_wrong_review_subject_and_tampered_receipt():
    context = fixture()
    parts = _parts()
    qualification, source_index, pins = _qualification(parts, context, subject_id="predicate:wrong")
    with pytest.raises(QualifiedPredicateBuilderError):
        compose_qualified_predicate(parts, qualification, source_index=source_index, review_pins=pins, context=context)
    candidate = _candidate(context=context)
    candidate["qualified_parts"]["predicate"]["id"] = "changed"
    with pytest.raises(QualifiedPredicateBuilderError):
        decompose_qualified_predicate(candidate)
