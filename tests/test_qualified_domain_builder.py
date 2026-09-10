"""Tests package behavior."""
from copy import deepcopy

import pytest

from judgment_compilation.interpretation_qualification import REVIEW_SCHEMA, digest, qualify_interpretation
from test_semantic_values import fixture

from judgment_compilation.qualified_domain_builder import (
    QualifiedDomainBuilderError,
    compose_qualified_domain,
    decompose_qualified_domain,
    qualification_target,
    recompose_qualified_domain,
)


def _source_index():
    source = fixture()["sources"][0]
    quote = "Fictional independent source support."
    return {source["id"]: {"source_sha256": source["sha256"], "quote_sha256": digest(quote), "locator": "fictional#domain"}}


def _parts(kind):
    if kind == "DEFINITION":
        return {"definition": {"path": [3, 1], "label": "Candidate Domain", "aliases": ["candidate-domain"],
                               "specializes": [{"path": [3], "source_ids": ["fictional-policy"]}]},
                "occurrence": 0, "source_ids": ["fictional-policy"]}
    if kind == "INSTANCE":
        return {"instance": {"path": [1, 1], "occurrence": 3}, "source_ids": ["fictional-policy"]}
    return {"typed_value": {"predicate_id": "category", "value": [1, 1]}, "source_ids": ["fictional-policy"]}


def _qualification(kind, parts, context=None):
    context = fixture() if context is None else context
    sources = _source_index()
    target = qualification_target(kind, parts, context)
    subject_id = "domain:" + kind.lower() + ":" + digest({"root_id": context["root_id"], "parts": parts})
    claim = {
        "id": f"reviewed-{kind.lower()}", "source_support": [{"source_id": "fictional-policy", **sources["fictional-policy"]}],
        "interpretation": {"rationale": "Fixture review binds this exact Domain record.", "mapping": {"kind": kind},
                           "scope": {"fixture": "Domain"}, "limits": ["Source-reviewed fixture only."],
                           "negative_case": "Changed record or context requires a new review."},
        "derivation_binding": {"subject_kind": "DOMAIN_" + kind, "subject_id": subject_id,
                               "target_contract_sha256": digest(target)},
    }
    review = {"schema": REVIEW_SCHEMA, "id": f"review-{kind.lower()}", "decision": "REVIEW_CONFIRMED",
              "reviewed_claim_sha256": digest(claim), "reviewer_evidence": ["fixture#review"]}
    pins = {review["id"]: digest(review)}
    return qualify_interpretation(claim, review, sources, target, review_pins=pins), sources, pins


@pytest.mark.parametrize("kind", ["DEFINITION", "INSTANCE", "TYPED_VALUE"])
def test_reviewed_domain_contract_forms_are_held_lossless_and_effect_free(kind):
    context, before, parts = fixture(), None, _parts(kind)
    before = deepcopy(context)
    qualification, sources, pins = _qualification(kind, parts, context)
    candidate = compose_qualified_domain(kind, parts, qualification, source_index=sources, review_pins=pins, context=context)

    assert decompose_qualified_domain(candidate) == parts
    assert candidate["status"] == "SOURCE_BOUND_NOT_EXECUTED"
    assert candidate["external_effects"] == []
    assert context == before
    successor = recompose_qualified_domain(context, candidate)
    if kind == "DEFINITION":
        assert parts["definition"] in successor["domain"]
        relation = candidate["semantic_record"]["structural_neighborhood"]
        assert relation["coordinate"] == {"Gs": [0, 3], "L": 1, "I": 0}
        assert relation["implies_specialization"] is False
        assert relation["implies_precedence"] is False
        assert relation["implies_execution"] is False
        assert relation["implies_storage_meaning"] is False
    else:
        assert successor == context
        if kind == "INSTANCE":
            assert candidate["semantic_record"]["instance_coordinate"] == {"Gs": [0, 1], "L": 1, "I": 3}
            assert candidate["semantic_record"]["definition_coordinate"] == {"Gs": [0, 1], "L": 1, "I": 0}
            assert candidate["semantic_record"]["relation"] == "TYPED_INSTANCE_OF_DOMAIN_DEFINITION"


def test_review_or_source_context_coordinate_and_unsupported_handle_tampering_are_rejected():
    parts = _parts("DEFINITION")
    qualification, sources, pins = _qualification("DEFINITION", parts)
    with pytest.raises(QualifiedDomainBuilderError):
        compose_qualified_domain("DEFINITION", parts, {}, source_index=sources, review_pins=pins, context=fixture())

    changed = deepcopy(parts)
    changed["definition"]["storage_handle"] = "invented"
    changed_qualification, changed_sources, changed_pins = _qualification("DEFINITION", changed)
    with pytest.raises(QualifiedDomainBuilderError):
        compose_qualified_domain("DEFINITION", changed, changed_qualification, source_index=changed_sources,
                                 review_pins=changed_pins, context=fixture())

    typed = _parts("TYPED_VALUE")
    typed["typed_value"]["value"] = [2, 1]  # positional child, but not an explicit specialization of Merchandise
    typed_qualification, typed_sources, typed_pins = _qualification("TYPED_VALUE", typed)
    with pytest.raises(QualifiedDomainBuilderError):
        compose_qualified_domain("TYPED_VALUE", typed, typed_qualification, source_index=typed_sources,
                                 review_pins=typed_pins, context=fixture())

    instance_parts = _parts("INSTANCE")
    instance_qualification, instance_sources, instance_pins = _qualification("INSTANCE", instance_parts)
    candidate = compose_qualified_domain(
        "INSTANCE", instance_parts, instance_qualification,
        source_index=instance_sources, review_pins=instance_pins, context=fixture(),
    )
    candidate["qualified_parts"]["instance"]["occurrence"] = 4
    with pytest.raises(QualifiedDomainBuilderError):
        decompose_qualified_domain(candidate)
