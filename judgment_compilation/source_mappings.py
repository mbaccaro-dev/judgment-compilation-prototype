"""Links reviewed checks to exact source passages."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from typing import Any

from .semantic_contracts import canonical

SCHEMA = "jc/reviewed-source-mapping-index/1"
CEILING = (
    "EXACT_REVIEWED_SOURCE_TO_BOUNDED_PACK_INTERPRETATION_ONLY;"
    "NO_GENERAL_TEMPLATE_EXECUTION_OR_APPLICABILITY_OR_SATISFACTION_OR_"
    "COMPLIANCE_OR_RESPONSIBILITY_OR_EFFECT"
)

_SPECS = {
    "AC-2(l)": {
        "statement_id": "ac-2_smt.l",
        "template_sha256": "a42d3a21b20805049094d8acb3996b97dba1044abe28904eb4857f05e7ba8d69",
        "structural_oscal_locator": "oscal://sha256/a9e23b09116d5e651461d61777c2e7dc1f3454ab3f9e1e8fdf8af01c37dc01be/group/ac/control/ac-2/part/ac-2_smt/part/ac-2_smt.l",
        "execution_scope": "REVIEW_SELECTION_ONLY",
    },
    "AC-6 Control": {
        "statement_id": "ac-6_smt",
        "template_sha256": "6aa81b8960e14201d282fd570fe3c45398e4193ccce26adcb20ae417bbea1a7a",
        "structural_oscal_locator": "oscal://sha256/a9e23b09116d5e651461d61777c2e7dc1f3454ab3f9e1e8fdf8af01c37dc01be/group/ac/control/ac-6/part/ac-6_smt",
        "execution_scope": "REVIEW_SELECTION_ONLY",
    },
    "PS-4(a)": {
        "statement_id": "ps-4_smt.a",
        "template_sha256": "aabea98d1dd7487ff69a65b9683663ede0ff542500eef6cbdc247b520923bf9c",
        "structural_oscal_locator": "oscal://sha256/a9e23b09116d5e651461d61777c2e7dc1f3454ab3f9e1e8fdf8af01c37dc01be/group/ps/control/ps-4/part/ps-4_smt/part/ps-4_smt.a",
        "execution_scope": "REVIEW_SELECTION_AND_CALLER_SCOPED_INTEGER_COMPARISON",
    },
    "PS-4(b)": {
        "statement_id": "ps-4_smt.b",
        "template_sha256": "0c49c8378e450b9b82cb0dd3ab43c660b0006254ff2579b4079c9216dbce5db8",
        "structural_oscal_locator": "oscal://sha256/a9e23b09116d5e651461d61777c2e7dc1f3454ab3f9e1e8fdf8af01c37dc01be/group/ps/control/ps-4/part/ps-4_smt/part/ps-4_smt.b",
        "execution_scope": "REVIEW_SELECTION_ONLY",
    },
    "SI-2(c)": {
        "statement_id": "si-2_smt.c",
        "template_sha256": "8cefcbf5ca3c22076dfbedd92017d6a4cf34c844f32dc5e7680462cb03fc5a3a",
        "structural_oscal_locator": "oscal://sha256/a9e23b09116d5e651461d61777c2e7dc1f3454ab3f9e1e8fdf8af01c37dc01be/group/si/control/si-2/part/si-2_smt/part/si-2_smt.c",
        "execution_scope": "REVIEW_SELECTION_AND_CALLER_SCOPED_INTEGER_COMPARISON",
    },
}


class SourceMappingError(ValueError):
    """Raised when a source link is missing or invalid."""


def _digest(value: Any) -> str:
    return sha256(canonical(value)).hexdigest()


def _need(condition: bool, reason: str) -> None:
    if not condition:
        raise SourceMappingError(reason)


class SourceMappingRegistry:
    def __init__(self, *, requirements, pack, pack_sha256, interpretation_admission):
        self.requirements = requirements
        self.pack = deepcopy(pack)
        self.pack_sha256 = pack_sha256
        self.interpretation_admission = deepcopy(interpretation_admission)

    def build(self) -> dict[str, Any]:
        _need(_digest(self.pack) == self.pack_sha256, "active pack digest mismatch")
        _need(self.interpretation_admission.get("pack_sha256") == self.pack_sha256,
              "interpretation admission does not bind the active pack")
        _need(self.interpretation_admission.get("standing") == "SOURCE_REVIEWED",
              "reviewed interpretation standing required")

        disposition = self.requirements.validate_disposition_index(
            self.requirements.disposition_index()
        )
        templates = {row["statement_id"]: row for row in disposition["rows"]}
        semantic = self.pack["semantic_pack"]
        semantic_sources = {row["id"]: row["sha256"] for row in semantic["sources"]}
        judgments = {row["id"]: row for row in semantic["judgments"]}
        work = {row["id"]: row for row in semantic["work"]}

        rows = []
        for source_id, spec in sorted(_SPECS.items()):
            source = self.pack["sources"].get(source_id)
            template = templates.get(spec["statement_id"])
            _need(source is not None and template is not None,
                  "reviewed source or exact OSCAL template missing")
            _need(template["template_sha256"] == spec["template_sha256"],
                  "reviewed OSCAL template digest drift")
            _need(template["grammar_status"] == "SUPPORTED",
                  "reviewed OSCAL template is not structurally supported")
            _need(template["source"]["source_sha256"] ==
                  source["oscal_source_file"]["sha256"],
                  "OSCAL source digest mismatch")
            _need(template["source"]["xml_id"] == spec["statement_id"],
                  "OSCAL statement identity mismatch")
            _need(source["structural_oscal_locator"] == spec["structural_oscal_locator"],
                  "structural OSCAL locator drift")
            _need(semantic_sources.get(source_id) == _digest(source),
                  "semantic source digest binding mismatch")

            interpretation_ids = sorted(
                key for key, value in self.pack["interpretations"].items()
                if source_id in value.get("source_selection_reason", {})
            )
            work_interpretation_ids = sorted(
                key for key, value in self.pack["work_interpretations"].items()
                if source_id in value.get("source_selection_reason", {})
            )
            judgment_ids = sorted(
                key for key, value in judgments.items() if source_id in value["source_ids"]
            )
            work_ids = sorted(
                key for key, value in work.items()
                if (value["operation"] == "APPLY_JUDGMENT" and
                    value["judgment"] in judgment_ids) or
                   key in work_interpretation_ids
            )
            architecture_ids = sorted(
                architecture["id"] for architecture in semantic["architectures"]
                if any(step["work"] in work_ids for step in architecture["steps"])
            )
            _need(interpretation_ids and judgment_ids and work_ids and architecture_ids,
                  "source has no complete reviewed source-to-execution connector")
            if spec["execution_scope"].endswith("INTEGER_COMPARISON"):
                _need(work_interpretation_ids,
                      "comparison source has no reviewed work interpretation")
            else:
                _need(not work_interpretation_ids,
                      "review-only source unexpectedly binds comparison work")

            row = {
                "source_id": source_id,
                "statement_id": template["statement_id"],
                "control_id": template["control_id"],
                "status": "ADMITTED_TO_EXACT_REVIEWED_BOUNDED_PACK",
                "source_binding": {
                    "source_sha256": template["source"]["source_sha256"],
                    "template_sha256": template["template_sha256"],
                    "xml_id": template["source"]["xml_id"],
                    "xml_locator": template["source"]["xml_locator"],
                    "structural_oscal_locator": source["structural_oscal_locator"],
                    "oscal_rendered_quote": source["oscal_rendered_quote"],
                    "pdf_source_sha256": source["source_file"]["sha256"],
                    "physical_pdf_page_one_based": source["physical_pdf_page_one_based"],
                    "printed_page_label": source["printed_page_label"],
                    "character_span": deepcopy(source["character_span"]),
                    "quote_sha256": source["quote_sha256"],
                    "normalized_quote_sha256": source["normalized_quote_sha256"],
                },
                "interpretation_binding": {
                    "interpretation_ids": interpretation_ids,
                    "work_interpretation_ids": work_interpretation_ids,
                    "selection_reasons": {
                        key: self.pack["interpretations"][key]["source_selection_reason"][source_id]
                        for key in interpretation_ids
                    },
                    "work_selection_reasons": {
                        key: self.pack["work_interpretations"][key]["source_selection_reason"][source_id]
                        for key in work_interpretation_ids
                    },
                },
                "execution_binding": {
                    "judgment_ids": judgment_ids,
                    "work_ids": work_ids,
                    "architecture_ids": architecture_ids,
                    "scope": spec["execution_scope"],
                    "generic_requirement_runtime_executable": False,
                    "bounded_reviewed_pack_executable": True,
                },
                "admission_binding": {
                    key: self.interpretation_admission[key]
                    for key in ("standing", "claim_id", "claim_sha256", "review_id",
                                "review_sha256", "pack_sha256",
                                "interpretation_subject_sha256", "claim_ceiling")
                },
                "coverage_ceiling": CEILING,
            }
            row["mapping_sha256"] = _digest(row)
            rows.append(row)

        body = {
            "schema": SCHEMA,
            "source_sha256": disposition["source_sha256"],
            "pack_sha256": self.pack_sha256,
            "admission_sha256": _digest(self.interpretation_admission),
            "counts": {
                "generic_requirement_templates": disposition["counts"]["total_templates"],
                "generic_requirement_policy_semantic_mappings":
                    disposition["counts"]["admitted_policy_semantic_mappings"],
                "exact_reviewed_source_mappings": len(rows),
                "bounded_reviewed_pack_executable_mappings": len(rows),
            },
            "rows": rows,
            "full_library_semantic_compilation": "INCOMPLETE",
            "residuals": [
                {"reason": "FULL_LIBRARY_EXECUTABLE_SEMANTIC_COMPILATION_INCOMPLETE"},
                {"reason": "EXTERNAL_EFFECTS_DISABLED"},
            ],
            "explicit_selection_confirmed": False,
            "compliance_verdict": None,
            "responsibility_determination": None,
            "external_effects": [],
            "coverage_ceiling": CEILING,
        }
        body["index_sha256"] = _digest(body)
        return body

    def validate(self, value: Any) -> dict[str, Any]:
        expected = self.build()
        _need(type(value) is dict and value == expected, "source mapping index mismatch")
        return deepcopy(expected)
