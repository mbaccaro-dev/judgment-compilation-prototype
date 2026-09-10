"""Tests package behavior."""
from copy import deepcopy
from hashlib import sha256

import pytest

from judgment_compilation.interpretation_qualification import REVIEW_SCHEMA, digest as review_digest
from judgment_compilation.raw_candidate_admission import (
    AUTHORITY_CEILING, EFFECT_CEILING, RawCandidateAdmissionError,
    compile_reviewed_batch_entry, compile_reviewed_family_fragment, qualify_candidate_family_mapping,
    source_index_from_rederived_candidate, validate_candidate_admission_bundle,
)


class StaticRawCompiler:
    """Tiny deterministic stand-in for the already-tested raw rederivation port."""

    def __init__(self, record):
        self.record = deepcopy(record)

    def validate_candidate_provenance(self, record):
        if record != self.record:
            raise ValueError("candidate did not rederive")
        return deepcopy(self.record)


def raw_record():
    quote = "A fictional system records a stated retention period."
    return {
        "stack": "DOMAIN",
        "candidate_id": "raw-fixture-001",
        "raw_candidate": {
            "document": {"publication_id": "fixture-policy", "pdf_sha256": sha256(b"fixture-pdf").hexdigest()},
            "physical_page_index": 2,
            "character_span": [10, 10 + len(quote)],
            "exact_quote": quote,
            "exact_quote_sha256": sha256(quote.encode()).hexdigest(),
            "page_text_sha256": sha256(b"fixture-page").hexdigest(),
        },
    }


def raw_work_architecture_record(stack="WORK", source_sha=None, source_id="fixture-policy"):
    quote = "The organization reviews the documented process before the assessment."
    candidate_id = f"raw-{stack.lower()}-fixture-001"
    kind = "WORK_OPERATION_INTERFACE" if stack == "WORK" else "ARCHITECTURE_COMPOSITION"
    proposal = (
        {"proposed_operation_kind": "REVIEW", "input_bindings": None,
         "output_binding": None, "implementation": None, "execution_status": "UNRESOLVED"}
        if stack == "WORK" else
        {"proposed_composition_kind": "SEQUENCE", "upstream_operation": None,
         "downstream_operation": None, "branch_condition": None,
         "program": None, "execution_status": "UNRESOLVED"}
    )
    return {
        "stack": stack,
        "candidate_id": candidate_id,
        "raw_candidate": {
            "candidate_id": candidate_id,
            "interpretation_status": "PROPOSED_INTERPRETATION",
            "admission_status": "UNRESOLVED",
            "candidate_kind": kind,
            "document": {"publication_id": source_id,
                         "pdf_sha256": source_sha or sha256(b"fixture-pdf").hexdigest()},
            "physical_page_index": 2,
            "character_span": [10, 10 + len(quote)],
            "exact_quote": quote,
            "exact_quote_sha256": sha256(quote.encode()).hexdigest(),
            "page_text_sha256": sha256(b"fixture-page").hexdigest(),
            "proposal": proposal,
            "semantic_coordinate": None,
            "semantic_disposition": {"admission": "NOT_ADMITTED", "applicability": None,
                                     "compliance": None, "responsibility": None,
                                     "external_effects": []},
            "external_effects": [],
        },
    }


def qualified_mapping(stack="work", kind="definition"):
    family = f"{stack.upper()}_{kind.upper()}"
    parts = (
        {"definition": {"coordinate": {"Gs": [7], "L": 1},
                        "label": f"Reviewed {stack}", "aliases": [f"reviewed {stack}"]},
         "source_ids": ["fixture-policy"]}
        if kind == "definition" else
        {"node": {"id": f"reviewed-{stack}-node"}, "source_ids": ["fixture-policy"]}
    )
    target = {
        "schema": f"jc/qualified-{kind}-target/2",
        "stack": stack,
        "parts": parts,
        "predecessor_context_sha256": sha256(b"predecessor").hexdigest(),
    }
    return {
        "id": f"fixture-{stack}-{kind}-mapping",
        "rationale": "The exact source is reviewed before a typed source-reviewed target is constructed.",
        "mapping": {"semantic_role": f"{stack}-{kind}"},
        "scope": {"fixture": "work-architecture-admission"},
        "limits": ["This review does not admit or execute the target."],
        "negative_case": "A missing or changed source binding remains unresolved.",
        "target_contract": target,
        "family": family,
    }


def reviewed_qualified_bundle(stack="WORK", kind="definition", *, target=None, source_sha=None):
    mapping = qualified_mapping(stack.lower(), kind)
    if target is not None:
        mapping["target_contract"] = deepcopy(target)
    target = mapping["target_contract"]
    source_ids = target["parts"]["source_ids"]
    record = raw_work_architecture_record(
        stack, source_sha=source_sha, source_id=source_ids[0],
    )
    compiler = StaticRawCompiler(record)
    source_index = source_index_from_rederived_candidate(compiler, record)
    source_id, source = next(iter(source_index.items()))
    subject_id = (
        f"semantic-definition:{stack.lower()}:{review_digest(target['parts']['definition']['coordinate'])}"
        if kind == "definition" else target["parts"]["node"]["id"]
    )
    claim = {
        "id": mapping["id"],
        "source_support": [{"source_id": source_id, "source_sha256": source["source_sha256"],
                            "quote_sha256": source["quote_sha256"], "locator": source["locator"]}],
        "interpretation": {key: deepcopy(mapping[key])
                           for key in ("rationale", "mapping", "scope", "limits", "negative_case")},
        "derivation_binding": {"subject_kind": "SEMANTIC_DEFINITION", "subject_id": subject_id,
                               "target_contract_sha256": review_digest(target)},
    }
    review = {"schema": REVIEW_SCHEMA, "id": f"fixture-review-{stack.lower()}-{kind}",
              "decision": "REVIEW_CONFIRMED", "reviewed_claim_sha256": review_digest(claim),
              "reviewer_evidence": ["fixture-review#independent-check"]}
    mapping = {key: value for key, value in mapping.items() if key != "family"}
    bundle = qualify_candidate_family_mapping(
        compiler, record, f"{stack}_{kind.upper()}", mapping, review,
        review_pins={review["id"]: review_digest(review)},
    )
    return compiler, bundle


def definition_mapping():
    return {
        "id": "fixture-retention-definition",
        "rationale": "The reviewed fixture explicitly defines a bounded retention-period concept.",
        "mapping": {"concept": "retention_period", "kind": "typed duration concept"},
        "scope": {"fixture": "retention-policy"},
        "limits": ["Defines only a concept.", "Does not determine any action or entitlement."],
        "negative_case": "An absent duration remains unknown.",
        "target_contract": {
            "schema": "jc/raw-candidate-admission-target/1",
            "family": "EXPLICIT_DEFINITION",
            "subject": {"kind": "SEMANTIC_DEFINITION", "id": "fixture-retention-period"},
            "fragment": {"definitions": [{
                "id": "fixture-retention-period", "label": "Retention period",
                "aliases": ["retention period"],
                "definition": "A stated duration for retaining a record.",
            }]},
        },
    }


def judgment_mapping():
    return {
        "id": "fixture-retention-scope",
        "rationale": "The reviewed fixture supports only the stated scoped condition.",
        "mapping": {"premise": "record.kind is identified", "output": "retention scope is established"},
        "scope": {"fixture": "retention-policy", "condition": "identified record"},
        "limits": ["Establishes only the scoped condition.", "Does not establish permission or an external action."],
        "negative_case": "Unknown record kind remains unresolved.",
        "target_contract": {
            "schema": "jc/raw-candidate-admission-target/1",
            "family": "SCOPED_JUDGMENT",
            "subject": {"kind": "JUDGMENT", "id": "fixture-retention-scope"},
            "fragment": {"judgment": {
                "id": "fixture-retention-scope", "bindings": {"record": "record"},
                "premises": [{"predicate": "record_kind_known", "arguments": {"record": "record"}, "value": True}],
                "output": {"predicate": "retention_scope_established", "arguments": {"record": "record"}, "value": True},
                "residual": "Supply a unique record identity and kind.",
            }},
        },
    }


def reviewed_bundle(mapping):
    compiler = StaticRawCompiler(raw_record())
    source_index = source_index_from_rederived_candidate(compiler, raw_record())
    source_id, source = next(iter(source_index.items()))
    target = mapping["target_contract"]
    claim = {
        "id": mapping["id"],
        "source_support": [{"source_id": source_id, "source_sha256": source["source_sha256"],
                            "quote_sha256": source["quote_sha256"], "locator": source["locator"]}],
        "interpretation": {key: deepcopy(mapping[key]) for key in ("rationale", "mapping", "scope", "limits", "negative_case")},
        "derivation_binding": {"subject_kind": target["subject"]["kind"], "subject_id": target["subject"]["id"],
                               "target_contract_sha256": review_digest(target)},
    }
    review = {"schema": REVIEW_SCHEMA, "id": "fixture-review-001", "decision": "REVIEW_CONFIRMED",
              "reviewed_claim_sha256": review_digest(claim), "reviewer_evidence": ["fixture-review#checked"]}
    return compiler, qualify_candidate_family_mapping(
        compiler, raw_record(), target["family"], mapping, review,
        review_pins={review["id"]: review_digest(review)},
    )


def test_rederived_source_binds_pdf_page_span_quote_hash_and_raw_locator():
    source = next(iter(source_index_from_rederived_candidate(StaticRawCompiler(raw_record()), raw_record()).values()))
    assert source["physical_pdf_page_index"] == 2
    assert source["character_span"] == [10, 63]
    assert source["quote_sha256"] == sha256(raw_record()["raw_candidate"]["exact_quote"].encode()).hexdigest()
    assert "/page/2/span/10:63" in source["locator"]


@pytest.mark.parametrize("maker, expected_key", [(definition_mapping, "domain_definitions"), (judgment_mapping, "judgment")])
def test_reviewed_definition_and_scoped_judgment_compile_only_after_exact_review(maker, expected_key):
    compiler, bundle = reviewed_bundle(maker())
    validated = validate_candidate_admission_bundle(bundle, compiler)
    assert validated == bundle
    result = compile_reviewed_family_fragment(bundle, compiler)
    assert expected_key in result["fragment"]
    assert result["authority_ceiling"] == AUTHORITY_CEILING
    assert result["effect_ceiling"] == EFFECT_CEILING
    assert result["external_effects"] == []


@pytest.mark.parametrize("mutation", [
    lambda b: b["source_index"][next(iter(b["source_index"]))].update(locator="forged://locator"),
    lambda b: b["raw_candidate_record"]["raw_candidate"].update(exact_quote="forged"),
    lambda b: b.update(target_contract_sha256="0" * 64),
    lambda b: b["qualification"]["claim"]["source_support"][0].update(quote_sha256="0" * 64),
    lambda b: b.update(effect_ceiling="EXTERNAL_EFFECTS_PERMITTED"),
])
def test_changed_source_target_support_or_effect_ceiling_rejects(mutation):
    compiler, bundle = reviewed_bundle(definition_mapping())
    changed = deepcopy(bundle)
    mutation(changed)
    with pytest.raises(RawCandidateAdmissionError):
        validate_candidate_admission_bundle(changed, compiler)


@pytest.mark.parametrize("mutation", [
    lambda m: m["scope"].clear(),
    lambda m: m["mapping"].update(external_effect={"command": "revoke"}),
    lambda m: m["mapping"].update(result={"external_action": "revoke"}),
    lambda m: m["mapping"].update(authorization_verdict="GRANTED"),
    lambda m: m["mapping"].update(compliance_verdict="COMPLIANT"),
    lambda m: m["mapping"].update(responsibility_assignment="Business-A"),
])
def test_missing_scope_and_effect_or_definitive_verdict_fields_reject_before_review(mutation):
    candidate = judgment_mapping()
    mutation(candidate)
    compiler = StaticRawCompiler(raw_record())
    review = {"schema": REVIEW_SCHEMA, "id": "unused", "decision": "REVIEW_CONFIRMED",
              "reviewed_claim_sha256": "0" * 64, "reviewer_evidence": ["fixture"]}
    with pytest.raises(RawCandidateAdmissionError):
        qualify_candidate_family_mapping(compiler, raw_record(), "SCOPED_JUDGMENT", candidate, review,
                                         review_pins={review["id"]: review_digest(review)})


def test_authorized_access_and_credentials_revocation_requirement_are_semantic_text_not_effects():
    candidate = definition_mapping()
    candidate["mapping"] = {
        "concept": "authorized_access",
        "requirement": "credentials_revocation_required",
    }
    candidate["scope"]["requirement"] = "authorized access; credentials revocation required"
    candidate["target_contract"]["fragment"]["definitions"][0]["definition"] = (
        "Authorized access is constrained; credentials revocation is required by the policy."
    )
    compiler, bundle = reviewed_bundle(candidate)
    result = compile_reviewed_family_fragment(bundle, compiler)
    assert result["fragment"]["domain_definitions"][0]["definition"].startswith("Authorized access")


@pytest.mark.parametrize("predicate", [
    "authorization_granted", "permission_granted", "compliant",
    "responsibility_assigned", "external_effect_executed",
])
def test_review_cannot_compile_definitive_permission_compliance_responsibility_or_effect_output(predicate):
    candidate = judgment_mapping()
    candidate["target_contract"]["fragment"]["judgment"]["output"]["predicate"] = predicate
    compiler, bundle = reviewed_bundle(candidate)
    with pytest.raises(RawCandidateAdmissionError):
        compile_reviewed_family_fragment(bundle, compiler)


@pytest.mark.parametrize("stack", ["WORK", "ARCHITECTURE"])
def test_raw_work_or_architecture_source_adapter_is_document_bound_but_not_implicit_admission(stack):
    candidate = raw_work_architecture_record(stack)
    source = source_index_from_rederived_candidate(StaticRawCompiler(candidate), candidate)
    assert set(source) == {"fixture-policy"}
    assert source["fixture-policy"]["raw_candidate_id"] == candidate["candidate_id"]
    assert "/publication/fixture-policy/page/2/span/10:" in source["fixture-policy"]["locator"]


@pytest.mark.parametrize("stack,kind", [
    ("WORK", "definition"), ("WORK", "node"),
    ("ARCHITECTURE", "definition"), ("ARCHITECTURE", "node"),
])
def test_reviewed_work_architecture_target_compiles_only_to_existing_batch_entry(stack, kind):
    compiler, bundle = reviewed_qualified_bundle(stack, kind)
    entry = compile_reviewed_batch_entry(bundle, compiler)
    assert set(entry) == {"stack", "parts", "qualification", "source_index", "review_pins"}
    assert entry["stack"] == stack.lower()
    assert entry["source_index"] == bundle["source_index"]
    with pytest.raises(RawCandidateAdmissionError, match="batch entries"):
        compile_reviewed_family_fragment(bundle, compiler)


def test_reviewed_work_architecture_entries_feed_the_existing_batch_materializer_losslessly():
    from judgment_compilation.qualified_node_builder import qualification_target as node_target
    from judgment_compilation.semantic_contracts import validate_semantic_pack
    from test_reviewed_batch_materializer import MODULE, reviewed_batch

    initial, batch = reviewed_batch()
    context = deepcopy(initial)
    context["predicates"].append(deepcopy(batch["predicates"][0]["parts"]["predicate"]))
    context = validate_semantic_pack(context)
    context["domain"].append(deepcopy(batch["domain"][0]["parts"]["definition"]))
    context = validate_semantic_pack(context)
    for entry in batch["definitions"]:
        stack = entry["stack"]
        context["semantic_capital"][stack].append(deepcopy(entry["parts"]["definition"]))
        context = validate_semantic_pack(context)
    context["judgments"].append(deepcopy(batch["nodes"][0]["parts"]["node"]))
    context = validate_semantic_pack(context)

    source_sha = context["sources"][0]["sha256"]
    work_target = node_target("work", batch["nodes"][1]["parts"], context)
    work_compiler, work_bundle = reviewed_qualified_bundle(
        "WORK", "node", target=work_target, source_sha=source_sha,
    )
    batch["nodes"][1] = compile_reviewed_batch_entry(work_bundle, work_compiler)
    context["work"].append(deepcopy(batch["nodes"][1]["parts"]["node"]))
    context = validate_semantic_pack(context)

    architecture_target = node_target("architecture", batch["nodes"][2]["parts"], context)
    arch_compiler, arch_bundle = reviewed_qualified_bundle(
        "ARCHITECTURE", "node", target=architecture_target, source_sha=source_sha,
    )
    batch["nodes"][2] = compile_reviewed_batch_entry(arch_bundle, arch_compiler)

    materialized = MODULE.materialize_reviewed_batch(initial, batch)
    parts = MODULE.decompose_reviewed_batch(initial, materialized)
    assert MODULE.recompose_reviewed_batch(initial, parts) == materialized
    assert materialized["external_effects"] == []


@pytest.mark.parametrize("stack,family", [
    ("WORK", "ARCHITECTURE_NODE"),
    ("ARCHITECTURE", "WORK_DEFINITION"),
    ("WORK", "EXECUTABLE_COMPOSITION"),
    ("ARCHITECTURE", "EXPLICIT_DEFINITION"),
])
def test_work_architecture_cannot_cross_stack_or_use_legacy_family(stack, family):
    record = raw_work_architecture_record(stack)
    compiler = StaticRawCompiler(record)
    mapping = qualified_mapping(
        "architecture" if family.startswith("ARCHITECTURE") else "work",
        "node" if family.endswith("NODE") else "definition",
    )
    mapping = {key: value for key, value in mapping.items() if key != "family"}
    if family in {"EXECUTABLE_COMPOSITION", "EXPLICIT_DEFINITION"}:
        mapping = definition_mapping()
        mapping["target_contract"]["family"] = family
    review = {"schema": REVIEW_SCHEMA, "id": "unused", "decision": "REVIEW_CONFIRMED",
              "reviewed_claim_sha256": "0" * 64, "reviewer_evidence": ["fixture"]}
    with pytest.raises(RawCandidateAdmissionError):
        qualify_candidate_family_mapping(
            compiler, record, family, mapping, review,
            review_pins={review["id"]: review_digest(review)},
        )


@pytest.mark.parametrize("mutation", [
    lambda r: r["raw_candidate"].update(semantic_coordinate={"Gs": [1], "L": 1}),
    lambda r: r["raw_candidate"].update(candidate_kind="ARCHITECTURE_COMPOSITION"),
    lambda r: r["raw_candidate"]["proposal"].update(implementation="run"),
    lambda r: r["raw_candidate"].update(external_effects=["write"]),
    lambda r: r["raw_candidate"]["semantic_disposition"].update(admission="ADMITTED"),
])
def test_work_adapter_rejects_semantic_execution_or_effect_tampering(mutation):
    candidate = raw_work_architecture_record("WORK")
    mutation(candidate)
    with pytest.raises(RawCandidateAdmissionError):
        source_index_from_rederived_candidate(StaticRawCompiler(candidate), candidate)


@pytest.mark.parametrize("mutation", [
    lambda m: m["target_contract"]["fragment"]["judgment"].update(premises=[]),
    lambda m: m["target_contract"]["fragment"]["judgment"].update(residual=""),
])
def test_review_cannot_turn_an_omitted_condition_or_residual_into_a_fragment(mutation):
    candidate = judgment_mapping()
    mutation(candidate)
    compiler, bundle = reviewed_bundle(candidate)
    with pytest.raises(RawCandidateAdmissionError):
        compile_reviewed_family_fragment(bundle, compiler)
