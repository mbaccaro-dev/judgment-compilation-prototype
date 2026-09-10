"""Validates one reviewed source match."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import re
from typing import Any

from .interpretation_qualification import (
    InterpretationQualificationError,
    digest as qualification_digest,
    qualify_interpretation,
    validate_reviewed_interpretation,
)
from .operation_interfaces import operation_interfaces
from .raw_semantic_compiler import RawSemanticCompiler
from .semantic_contracts import validate_semantic_pack
from .semantic_family_compiler import (
    SemanticFamilyCompilationError,
    compile_elapsed_duration_family,
)


SCHEMA = "jc/raw-candidate-admission/1"
TARGET_SCHEMA = "jc/raw-candidate-admission-target/1"
STANDING = "SOURCE_REVIEWED"
SUPPORTED_FAMILIES = frozenset({
    "EXPLICIT_DEFINITION",
    "SCOPED_JUDGMENT",
    "ELAPSED_DURATION",
    "EXPLICIT_OVERRIDE",
    "EXECUTABLE_COMPOSITION",
    "WORK_DEFINITION",
    "WORK_NODE",
    "ARCHITECTURE_DEFINITION",
    "ARCHITECTURE_NODE",
})
_QUALIFIED_FAMILIES = frozenset({
    "WORK_DEFINITION", "WORK_NODE", "ARCHITECTURE_DEFINITION", "ARCHITECTURE_NODE",
})
AUTHORITY_CEILING = (
    "SOURCE_BOUND_FRAGMENT_ONLY;NO_COMPLIANCE_OR_RESPONSIBILITY_"
    "DETERMINATION_OR_EXTERNAL_EFFECT"
)
EFFECT_CEILING = "NO_EXTERNAL_EFFECTS"

_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]*$")
# These are *field* names, never ordinary words in source support,
# interpretation text, aliases, requirements, or predicates.  A source can
# correctly say "authorized access" or "credentials revocation required".
# Such language expresses a policy requirement or a state to evaluate; it does
# not authorize this runtime to perform anything.  The boundary below rejects
# only structures that try to carry an effect request/result or a definitive
# compliance, responsibility, permission, or authorization verdict.
_EFFECT_FIELD_NAMES = frozenset({
    "external_effect", "external_effects", "external_action", "external_actions",
    "effect_command", "effect_request", "external_effect_request",
    "external_effect_result", "action_command", "action_request", "action_result",
})
_DETERMINATION_FIELD_NAMES = frozenset({
    "authorization_verdict", "authorization_determination", "authorization_status",
    "permission_verdict", "permission_determination", "permission_status",
    "compliance_verdict", "compliance_determination", "compliance_status",
    "responsibility_verdict", "responsibility_determination",
    "responsibility_assignment", "responsibility_status",
})
_MAPPING_RESULT_FIELDS = frozenset({"action", "operation", "outcome", "result"})
_DEFINITIVE_OUTPUT_PREDICATES = frozenset({
    "authorized", "authorization_granted", "permission_granted", "compliant",
    "compliance_satisfied", "responsible_party", "responsibility_assigned",
    "external_effect_executed", "external_action_executed", "effect_completed",
    "action_completed",
})


class RawCandidateAdmissionError(ValueError):
    """Raised when a source match lacks a complete review record."""


def canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise RawCandidateAdmissionError("not canonical admission JSON") from exc


def digest(value: Any) -> str:
    return sha256(canonical(value)).hexdigest()


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise RawCandidateAdmissionError(message)


def _keys(value: Any, expected: set[str], message: str) -> None:
    _need(type(value) is dict and set(value) == expected, message)


def _text(value: Any, label: str) -> str:
    _need(type(value) is str and bool(value.strip()) and value == value.strip(),
          f"invalid {label}")
    return value


def _identifier(value: Any, label: str) -> str:
    value = _text(value, label)
    _need(_IDENTIFIER.fullmatch(value) is not None, f"invalid {label}")
    return value


def _sha(value: Any, label: str) -> str:
    _need(type(value) is str and len(value) == 64 and
          all(char in "0123456789abcdef" for char in value), f"invalid {label}")
    return value


def _field_name(value: Any) -> str:
    _need(type(value) is str and value.strip(), "invalid admission field name")
    return value.strip().replace("-", "_").replace(" ", "_").lower()


def _reject_effectful_fields(value: Any, *, reject_mapping_results: bool = False) -> None:
    """Reject effect and verdict *structures* without policing semantic prose."""
    if type(value) is list:
        for item in value:
            _reject_effectful_fields(item, reject_mapping_results=reject_mapping_results)
    elif type(value) is dict:
        for key, item in value.items():
            name = _field_name(key)
            _need(name not in _EFFECT_FIELD_NAMES,
                  "external effects are unsupported in an admission candidate")
            _need(name not in _DETERMINATION_FIELD_NAMES,
                  "definitive authorization, permission, compliance, or responsibility verdict is unsupported")
            _need(not (reject_mapping_results and name in _MAPPING_RESULT_FIELDS),
                  "effectful operation or result fields are unsupported in an interpretation mapping")
            _reject_effectful_fields(item, reject_mapping_results=reject_mapping_results)
    elif value is None or type(value) in {bool, int, float, str}:
        return
    else:
        raise RawCandidateAdmissionError("unsupported admission value")


def _reject_definitive_output_predicate(predicate: str) -> None:
    normalized = predicate.replace("-", "_").lower()
    _need(normalized not in _DEFINITIVE_OUTPUT_PREDICATES and
          not normalized.endswith(("_verdict", "_determination", "_assignment")),
          "definitive authorization, permission, compliance, responsibility, or effect output is unsupported")


def _raw_fields(record: dict[str, Any]) -> tuple[str, str, int, list[int], str, str, str]:
    """Read a stack-specific source adapter only after exact rederivation."""
    _need(type(record) is dict, "invalid raw compiler record")
    _need(record.get("stack") in {"DOMAIN", "JUDGMENT", "WORK", "ARCHITECTURE"},
          "unknown raw candidate stack")
    raw = record.get("raw_candidate")
    _need(type(raw) is dict, "missing raw candidate")
    if record["stack"] in {"DOMAIN", "WORK", "ARCHITECTURE"}:
        document = raw.get("document")
        _need(type(document) is dict, "missing documentary source binding")
        publication = _text(document.get("publication_id"), "publication identity")
        source_sha = _sha(document.get("pdf_sha256"), "source PDF hash")
        page = raw.get("physical_page_index")
        span = raw.get("character_span")
        quote = _text(raw.get("exact_quote"), "exact quote")
        quote_sha = _sha(raw.get("exact_quote_sha256"), "quote hash")
        page_sha = _sha(raw.get("page_text_sha256"), "page text hash")
        if record["stack"] in {"WORK", "ARCHITECTURE"}:
            expected_kind = (
                "WORK_OPERATION_INTERFACE" if record["stack"] == "WORK"
                else "ARCHITECTURE_COMPOSITION"
            )
            _need(raw.get("candidate_id") == record.get("candidate_id"),
                  "raw Work/Architecture candidate identity mismatch")
            _need(raw.get("interpretation_status") == "PROPOSED_INTERPRETATION" and
                  raw.get("admission_status") == "UNRESOLVED",
                  "raw Work/Architecture proposal standing changed")
            _need(raw.get("candidate_kind") == expected_kind,
                  "raw Work/Architecture candidate kind mismatch")
            _need(raw.get("semantic_coordinate") is None and raw.get("external_effects") == [],
                  "raw Work/Architecture proposal gained semantics or effects")
            disposition = raw.get("semantic_disposition")
            _need(type(disposition) is dict and disposition.get("admission") == "NOT_ADMITTED" and
                  disposition.get("applicability") is None and disposition.get("compliance") is None and
                  disposition.get("responsibility") is None and disposition.get("external_effects") == [],
                  "raw Work/Architecture semantic disposition changed")
            proposal = raw.get("proposal")
            if record["stack"] == "WORK":
                _need(type(proposal) is dict and proposal.get("implementation") is None and
                      proposal.get("execution_status") == "UNRESOLVED",
                      "raw Work proposal already carries an implementation")
            else:
                _need(type(proposal) is dict and proposal.get("program") is None and
                      proposal.get("execution_status") == "UNRESOLVED",
                      "raw Architecture proposal already carries a program")
    else:
        source = raw.get("source")
        _need(type(source) is dict, "missing judgment source binding")
        publication = _text(source.get("publication_id"), "publication identity")
        source_sha = _sha(source.get("source_sha256"), "source PDF hash")
        page = source.get("pdf_page_index")
        source_span = source.get("character_span")
        _need(type(source_span) is dict and set(source_span) == {"start", "end"},
              "invalid judgment character span")
        span = [source_span["start"], source_span["end"]]
        quote = _text(source.get("exact_quote"), "exact quote")
        quote_sha = _sha(source.get("exact_quote_sha256"), "quote hash")
        page_sha = _sha(source.get("page_text_sha256"), "page text hash")
    _need(type(page) is int and page >= 0, "invalid physical page index")
    _need(type(span) is list and len(span) == 2 and all(type(item) is int for item in span) and
          0 <= span[0] < span[1], "invalid exact character span")
    _need(sha256(quote.encode("utf-8")).hexdigest() == quote_sha,
          "exact quote hash mismatch")
    return publication, source_sha, page, list(span), quote, quote_sha, page_sha


def source_index_from_rederived_candidate(
        compiler: RawSemanticCompiler, record: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Build one source record after reproducing its source match."""
    _need(hasattr(compiler, "validate_candidate_provenance"),
          "raw compiler provenance validator required")
    rederived = compiler.validate_candidate_provenance(deepcopy(record))
    _need(canonical(rederived) == canonical(record),
          "raw compiler did not preserve the supplied candidate")
    publication, source_sha, page, span, quote, quote_sha, page_sha = _raw_fields(rederived)
    candidate_id = _text(rederived.get("candidate_id"), "raw candidate identity")
    source_id = (publication if rederived["stack"] in {"WORK", "ARCHITECTURE"}
                 else "raw-source:" + candidate_id)
    locator = f"raw-pdf://sha256/{source_sha}/publication/{publication}/page/{page}/span/{span[0]}:{span[1]}"
    return {source_id: {
        "source_sha256": source_sha,
        "quote_sha256": quote_sha,
        "locator": locator,
        "publication_id": publication,
        "physical_pdf_page_index": page,
        "character_span": span,
        "exact_quote": quote,
        "page_text_sha256": page_sha,
        "raw_candidate_id": candidate_id,
    }}


def _qualified_family_stack(family: str) -> str:
    return "work" if family.startswith("WORK_") else "architecture"


def _qualified_family_kind(family: str) -> str:
    return "definition" if family.endswith("_DEFINITION") else "node"


def _target_subject(family: str, target: dict[str, Any]) -> dict[str, str]:
    if family not in _QUALIFIED_FAMILIES:
        return deepcopy(target["subject"])
    stack = _qualified_family_stack(family)
    parts = target["parts"]
    if _qualified_family_kind(family) == "definition":
        subject_id = f"semantic-definition:{stack}:{qualification_digest(parts['definition']['coordinate'])}"
    else:
        subject_id = parts["node"]["id"]
    return {"kind": "SEMANTIC_DEFINITION", "id": subject_id}


def _validate_target_contract(family: str, target: Any) -> dict[str, Any]:
    _need(family in SUPPORTED_FAMILIES, "unsupported candidate family")
    if family in _QUALIFIED_FAMILIES:
        _keys(target, {"schema", "stack", "parts", "predecessor_context_sha256"},
              "unsupported qualified target contract shape")
        expected_stack = _qualified_family_stack(family)
        expected_schema = (
            "jc/qualified-definition-target/2"
            if _qualified_family_kind(family) == "definition"
            else "jc/qualified-node-target/2"
        )
        _need(target["schema"] == expected_schema and target["stack"] == expected_stack,
              "qualified target stack or schema mismatch")
        _sha(target["predecessor_context_sha256"], "qualified predecessor context hash")
        expected_parts = ({"definition", "source_ids"}
                          if _qualified_family_kind(family) == "definition"
                          else {"node", "source_ids"})
        _keys(target["parts"], expected_parts, "unsupported qualified target parts")
        source_ids = target["parts"]["source_ids"]
        _need(type(source_ids) is list and source_ids and
              len(source_ids) == len(set(source_ids)) and
              all(type(value) is str and value.strip() == value and value for value in source_ids),
              "qualified target source ids are invalid")
        if _qualified_family_kind(family) == "definition":
            definition = target["parts"]["definition"]
            _keys(definition, {"coordinate", "label", "aliases"},
                  "unsupported qualified definition")
        else:
            node = target["parts"]["node"]
            _need(type(node) is dict and type(node.get("id")) is str and node["id"].strip(),
                  "qualified node identity required")
        _reject_effectful_fields(target)
        return deepcopy(target)
    _keys(target, {"schema", "family", "subject", "fragment"},
          "unsupported target contract shape")
    _need(target["schema"] == TARGET_SCHEMA and target["family"] == family,
          "target contract family mismatch")
    _keys(target["subject"], {"kind", "id"}, "unsupported target subject shape")
    subject_kind = _text(target["subject"]["kind"], "target subject kind")
    _identifier(target["subject"]["id"], "target subject id")
    allowed_kind = {
        "EXPLICIT_DEFINITION": "SEMANTIC_DEFINITION",
        "SCOPED_JUDGMENT": "JUDGMENT",
        "ELAPSED_DURATION": "JUDGMENT",
        "EXPLICIT_OVERRIDE": "OVERRIDE",
        "EXECUTABLE_COMPOSITION": "WHOLE_SEMANTIC_PACK",
    }[family]
    _need(subject_kind == allowed_kind, "target subject kind does not fit candidate family")
    _need(type(target["fragment"]) is dict and bool(target["fragment"]),
          "target fragment required")
    _reject_effectful_fields(target["fragment"])
    return deepcopy(target)


def _validate_mapping(mapping: Any, family: str) -> dict[str, Any]:
    _keys(mapping, {"id", "rationale", "mapping", "scope", "limits", "negative_case", "target_contract"},
          "unsupported candidate-family mapping shape")
    _identifier(mapping["id"], "mapping id")
    _text(mapping["rationale"], "interpretation rationale")
    _need(type(mapping["mapping"]) is dict and bool(mapping["mapping"]),
          "semantic mapping required")
    _need(type(mapping["scope"]) is dict and bool(mapping["scope"]), "scope required")
    _need(type(mapping["limits"]) is list and bool(mapping["limits"]) and
          all(type(item) is str and item.strip() for item in mapping["limits"]),
          "interpretation limits required")
    _text(mapping["negative_case"], "negative case")
    target = _validate_target_contract(family, mapping["target_contract"])
    _reject_effectful_fields(mapping["mapping"], reject_mapping_results=True)
    _reject_effectful_fields(mapping["scope"])
    return {**deepcopy(mapping), "target_contract": target}


def _source_support(source_index: dict[str, dict[str, Any]]) -> list[dict[str, str]]:
    _need(type(source_index) is dict and len(source_index) == 1, "exactly one rederived source required")
    source_id, source = next(iter(source_index.items()))
    return [{"source_id": source_id, "source_sha256": source["source_sha256"],
             "quote_sha256": source["quote_sha256"], "locator": source["locator"]}]


def qualify_candidate_family_mapping(
        compiler: RawSemanticCompiler, record: dict[str, Any], family: str,
        mapping: dict[str, Any], review: dict[str, Any], *, review_pins: dict[str, str]) -> dict[str, Any]:
    """Bind one reviewed source interpretation to one exact target contract."""
    source_index = source_index_from_rederived_candidate(compiler, record)
    if record.get("stack") in {"WORK", "ARCHITECTURE"}:
        _need(family in _QUALIFIED_FAMILIES,
              "raw Work/Architecture candidates require a typed qualified family")
    elif family in _QUALIFIED_FAMILIES:
        raise RawCandidateAdmissionError(
            "qualified Work/Architecture family requires the matching raw stack"
        )
    mapping = _validate_mapping(mapping, family)
    target = mapping["target_contract"]
    if family in _QUALIFIED_FAMILIES:
        expected_raw_stack = _qualified_family_stack(family).upper()
        _need(record.get("stack") == expected_raw_stack,
              "raw candidate stack does not fit qualified family")
        _need(set(target["parts"]["source_ids"]) == set(source_index),
              "qualified target sources differ from rederived source")
    subject = _target_subject(family, target)
    claim = {
        "id": mapping["id"],
        "source_support": _source_support(source_index),
        "interpretation": {
            "rationale": mapping["rationale"], "mapping": deepcopy(mapping["mapping"]),
            "scope": deepcopy(mapping["scope"]), "limits": deepcopy(mapping["limits"]),
            "negative_case": mapping["negative_case"],
        },
        "derivation_binding": {
            "subject_kind": subject["kind"],
            "subject_id": subject["id"],
            "target_contract_sha256": qualification_digest(target),
        },
    }
    try:
        qualification = qualify_interpretation(claim, review, source_index, target,
                                                review_pins=review_pins)
    except InterpretationQualificationError as exc:
        raise RawCandidateAdmissionError(str(exc)) from exc
    return {
        "schema": SCHEMA,
        "standing": STANDING,
        "candidate_family": family,
        "raw_candidate_record": deepcopy(record),
        "raw_rederivation_sha256": digest(record),
        "source_index": deepcopy(source_index),
        "target_contract": target,
        "target_contract_sha256": qualification_digest(target),
        "qualification": qualification,
        "review_pins": deepcopy(review_pins),
        "authority_ceiling": AUTHORITY_CEILING,
        "effect_ceiling": EFFECT_CEILING,
        "external_effects": [],
    }


def validate_candidate_admission_bundle(
        bundle: dict[str, Any], compiler: RawSemanticCompiler) -> dict[str, Any]:
    """Verify a review bundle against the current source bytes."""
    _keys(bundle, {
        "schema", "standing", "candidate_family", "raw_candidate_record",
        "raw_rederivation_sha256", "source_index", "target_contract",
        "target_contract_sha256", "qualification", "review_pins",
        "authority_ceiling", "effect_ceiling", "external_effects",
    }, "unsupported candidate admission bundle shape")
    _need(bundle["schema"] == SCHEMA and bundle["standing"] == STANDING,
          "unsupported candidate admission standing")
    family = bundle["candidate_family"]
    _need(family in SUPPORTED_FAMILIES, "unsupported candidate family")
    raw_stack = bundle["raw_candidate_record"].get("stack")
    _need(not (raw_stack in {"WORK", "ARCHITECTURE"} and family not in _QUALIFIED_FAMILIES),
          "raw Work/Architecture candidates require a typed qualified family")
    _need(not (raw_stack not in {"WORK", "ARCHITECTURE"} and family in _QUALIFIED_FAMILIES),
          "qualified Work/Architecture family requires the matching raw stack")
    _need(bundle["authority_ceiling"] == AUTHORITY_CEILING and
          bundle["effect_ceiling"] == EFFECT_CEILING and bundle["external_effects"] == [],
          "admission authority or effect ceiling changed")
    _need(bundle["raw_rederivation_sha256"] == digest(bundle["raw_candidate_record"]),
          "raw candidate rederivation digest mismatch")
    expected_sources = source_index_from_rederived_candidate(compiler, bundle["raw_candidate_record"])
    _need(canonical(bundle["source_index"]) == canonical(expected_sources),
          "source binding changed")
    target = _validate_target_contract(family, bundle["target_contract"])
    _need(bundle["target_contract_sha256"] == qualification_digest(target),
          "target contract digest changed")
    try:
        qualification = validate_reviewed_interpretation(
            bundle["qualification"], expected_sources, target,
            review_pins=bundle["review_pins"],
        )
    except InterpretationQualificationError as exc:
        raise RawCandidateAdmissionError(str(exc)) from exc
    if family in _QUALIFIED_FAMILIES:
        _need(bundle["raw_candidate_record"].get("stack") == _qualified_family_stack(family).upper(),
              "raw candidate stack does not fit qualified family")
        _need(set(target["parts"]["source_ids"]) == set(expected_sources),
              "qualified target sources differ from rederived source")
    subject = _target_subject(family, target)
    expected_kind = subject["kind"]
    binding = qualification["claim"]["derivation_binding"]
    _need(binding == {
        "subject_kind": expected_kind,
        "subject_id": subject["id"],
        "target_contract_sha256": qualification_digest(target),
    }, "qualification target binding changed")
    _need(qualification["claim"]["source_support"] == _source_support(expected_sources),
          "qualification source support changed")
    return json.loads(canonical(bundle))


def _definition_fragment(target: dict[str, Any], source_id: str) -> dict[str, Any]:
    fragment = target["fragment"]
    _keys(fragment, {"definitions"}, "unsupported explicit-definition fragment")
    definitions = fragment["definitions"]
    _need(type(definitions) is list and bool(definitions), "definition rows required")
    result = []
    seen = set()
    for row in definitions:
        _keys(row, {"id", "label", "aliases", "definition"}, "unsupported definition row")
        definition_id = _identifier(row["id"], "definition id")
        _need(definition_id not in seen, "duplicate definition id")
        seen.add(definition_id)
        label = _text(row["label"], "definition label")
        aliases = row["aliases"]
        _need(type(aliases) is list and all(type(alias) is str and alias.strip() for alias in aliases) and
              len(set(aliases)) == len(aliases), "invalid definition aliases")
        result.append({"id": definition_id, "label": label, "aliases": deepcopy(aliases),
                       "definition": _text(row["definition"], "definition text"),
                       "source_ids": [source_id]})
    return {"family": "EXPLICIT_DEFINITION", "domain_definitions": result,
            "external_effects": []}


def _scoped_judgment_fragment(target: dict[str, Any], source_id: str) -> dict[str, Any]:
    fragment = target["fragment"]
    _keys(fragment, {"judgment"}, "unsupported scoped-judgment fragment")
    judgment = fragment["judgment"]
    _keys(judgment, {"id", "bindings", "premises", "output", "residual"},
          "unsupported scoped-judgment shape")
    _identifier(judgment["id"], "judgment id")
    _need(type(judgment["bindings"]) is dict and bool(judgment["bindings"]),
          "judgment bindings required")
    for role, kind in judgment["bindings"].items():
        _identifier(role, "judgment role")
        _identifier(kind, "judgment role kind")
    _need(type(judgment["premises"]) is list and bool(judgment["premises"]),
          "scoped judgment premises required")
    for clause in [*judgment["premises"], judgment["output"]]:
        _keys(clause, {"predicate", "arguments", "value"}, "unsupported judgment clause")
        predicate = _identifier(clause["predicate"], "judgment predicate")
        if clause is judgment["output"]:
            _reject_definitive_output_predicate(predicate)
        _need(type(clause["arguments"]) is dict and
              set(clause["arguments"]).issubset(judgment["bindings"]) and
              all(type(value) is str and value in judgment["bindings"] for value in clause["arguments"].values()),
              "judgment clause has unbound arguments")
    _text(judgment["residual"], "judgment residual")
    row = deepcopy(judgment)
    row["source_ids"] = [source_id]
    return {"family": "SCOPED_JUDGMENT", "judgment": row, "external_effects": []}


def compile_reviewed_family_fragment(
        bundle: dict[str, Any], compiler: RawSemanticCompiler) -> dict[str, Any]:
    """Compile the family named in a valid review bundle."""
    bundle = validate_candidate_admission_bundle(bundle, compiler)
    family = bundle["candidate_family"]
    target = bundle["target_contract"]
    source_id = next(iter(bundle["source_index"]))
    if family == "EXPLICIT_DEFINITION":
        fragment = _definition_fragment(target, source_id)
    elif family == "SCOPED_JUDGMENT":
        fragment = _scoped_judgment_fragment(target, source_id)
    elif family == "ELAPSED_DURATION":
        fragment = target["fragment"]
        _keys(fragment, {"mapping"}, "unsupported elapsed-duration fragment")
        try:
            fragment = {"family": family, "compiled": compile_elapsed_duration_family(fragment["mapping"]),
                        "external_effects": []}
        except SemanticFamilyCompilationError as exc:
            raise RawCandidateAdmissionError(str(exc)) from exc
    elif family == "EXPLICIT_OVERRIDE":
        fragment = target["fragment"]
        _keys(fragment, {"override"}, "unsupported explicit-override fragment")
        override = fragment["override"]
        _keys(override, {"id", "overrides", "scope", "consequence"},
              "unsupported explicit-override shape")
        _identifier(override["id"], "override id")
        _need(type(override["overrides"]) is list and bool(override["overrides"]) and
              all(type(item) is str and _IDENTIFIER.fullmatch(item) for item in override["overrides"]),
              "explicit override target required")
        _need(type(override["scope"]) is dict and bool(override["scope"]), "override scope required")
        _text(override["consequence"], "override consequence")
        fragment = {"family": family, "override": {**deepcopy(override), "source_ids": [source_id]},
                    "external_effects": []}
    elif family == "EXECUTABLE_COMPOSITION":
        fragment = target["fragment"]
        _keys(fragment, {"semantic_pack"}, "unsupported executable-composition fragment")
        try:
            pack = validate_semantic_pack(fragment["semantic_pack"])
            fragment = {"family": family, "semantic_pack": pack,
                        "operation_interfaces": operation_interfaces(pack),
                        "external_effects": []}
        except Exception as exc:
            raise RawCandidateAdmissionError(str(exc)) from exc
    else:
        raise RawCandidateAdmissionError(
            "qualified Work/Architecture families compile only as reviewed batch entries"
        )
    return {
        "schema": SCHEMA,
        "standing": STANDING,
        "candidate_family": family,
        "raw_candidate_id": bundle["raw_candidate_record"]["candidate_id"],
        "raw_rederivation_sha256": bundle["raw_rederivation_sha256"],
        "target_contract_sha256": bundle["target_contract_sha256"],
        "qualification_claim_sha256": qualification_digest(bundle["qualification"]["claim"]),
        "fragment": fragment,
        "authority_ceiling": AUTHORITY_CEILING,
        "effect_ceiling": EFFECT_CEILING,
        "external_effects": [],
    }


def compile_reviewed_batch_entry(
        bundle: dict[str, Any], compiler: RawSemanticCompiler) -> dict[str, Any]:
    """Bridge one reviewed Work/Architecture target into the sole batch builder."""
    bundle = validate_candidate_admission_bundle(bundle, compiler)
    family = bundle["candidate_family"]
    _need(family in _QUALIFIED_FAMILIES,
          "only qualified Work/Architecture families compile as batch entries")
    target = bundle["target_contract"]
    return {
        "stack": target["stack"],
        "parts": deepcopy(target["parts"]),
        "qualification": deepcopy(bundle["qualification"]),
        "source_index": deepcopy(bundle["source_index"]),
        "review_pins": deepcopy(bundle["review_pins"]),
    }


__all__ = [
    "AUTHORITY_CEILING", "EFFECT_CEILING", "RawCandidateAdmissionError", "SCHEMA",
    "STANDING", "SUPPORTED_FAMILIES", "TARGET_SCHEMA", "canonical",
    "compile_reviewed_batch_entry", "compile_reviewed_family_fragment", "digest", "qualify_candidate_family_mapping",
    "source_index_from_rederived_candidate", "validate_candidate_admission_bundle",
]
