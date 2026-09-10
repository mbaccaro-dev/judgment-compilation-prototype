"""Reports the included NIST source files and counts."""
from __future__ import annotations

from copy import deepcopy
from collections import Counter
from hashlib import sha256
from typing import Any

from .semantic_contracts import canonical
from .nist_profiles import PROFILE_FILES

SCHEMA = "jc/nist-source-accounting-manifest/1"
CEILING = (
    "SOURCE_ACCOUNTING_ONLY;NO_IMPLIED_INTERPRETATION_ADMISSION_OR_EXECUTABLE_"
    "POLICY_COVERAGE_OR_COMPLIANCE_OR_RESPONSIBILITY_OR_EFFECT"
)


class SourceAccountingError(ValueError):
    """A reconciled inventory or supplied accounting manifest is invalid."""


def _digest(value: Any) -> str:
    return sha256(canonical(value)).hexdigest()


def _need(condition: bool, reason: str) -> None:
    if not condition:
        raise SourceAccountingError(reason)


class SourceAccounting:
    """Build an on-demand manifest from existing verified adapters."""

    def __init__(self, *, integrity, library, catalog, requirements, profiles,
                 assessments, pack, pack_sha256, interpretation_admission,
                 source_mappings):
        self.integrity = deepcopy(integrity)
        self.library = library
        self.catalog = catalog
        self.requirements = requirements
        self.profiles = profiles
        self.assessments = assessments
        self.pack = deepcopy(pack)
        self.pack_sha256 = pack_sha256
        self.interpretation_admission = deepcopy(interpretation_admission)
        self.source_mappings = source_mappings

    def build(self) -> dict[str, Any]:
        library = self.library.summary()
        document_dispositions = Counter(
            document.get("interpretation_status", "UNDECLARED")
            for document in self.library.documents.values()
        )
        library.update(
            file_count=len(self.library.files),
            document_interpretation_dispositions=dict(sorted(document_dispositions.items())),
        )

        catalog = self.catalog.summary()
        catalog["source"] = self.catalog.source

        disposition_index = self.requirements.validate_disposition_index(
            self.requirements.disposition_index()
        )
        requirement_summary = self.requirements.summary()
        _need(requirement_summary["statement_templates"] ==
              disposition_index["counts"]["total_templates"],
              "requirement summary and disposition cardinality disagree")
        requirements = {
            "source_sha256": requirement_summary["source_sha256"],
            "source_metadata": requirement_summary["source_metadata"],
            "disposition_index_sha256": disposition_index["index_sha256"],
            **deepcopy(disposition_index["counts"]),
            "rows_embedded": False,
            "row_inventory_surface": "Requirements.disposition_index()",
            "coverage_ceiling": disposition_index["coverage_ceiling"],
        }

        profiles = self.profiles.accounting()
        assessments = self.assessments.summary()
        mapping_index = self.source_mappings.validate(self.source_mappings.build())

        semantic = self.pack["semantic_pack"]
        executable_counts = {
            name: len(semantic[name])
            for name in ("domain", "judgments", "work", "architectures")
        }
        executable_counts["architecture_steps"] = sum(
            len(record["steps"]) for record in semantic["architectures"]
        )
        source_excerpt_count = len(self.pack["sources"])

        admission = {
            **deepcopy(self.interpretation_admission),
            "admission_projection_sha256": _digest(self.interpretation_admission),
            "scope": "EXACT_REVIEWED_SEMANTIC_PACK_ONLY",
            "does_not_admit_requirement_templates": True,
        }
        _need(admission["pack_sha256"] == self.pack_sha256,
              "interpretation admission does not bind the active pack")
        _need(disposition_index["counts"]["admitted_policy_semantic_mappings"] == 0 and
              disposition_index["counts"]["executable_policy_templates"] == 0,
              "template execution requires a separate exact reviewed admission")

        body = {
            "schema": SCHEMA,
            "package_inputs": deepcopy(self.integrity),
            "source_accounting": {
                "status": "COMPLETE_FOR_RETAINED_PACKAGE_INPUTS",
                "library": library,
                "catalog": catalog,
                "profiles": profiles,
                "assessments": assessments,
                "requirements": requirements,
            },
            "interpretation_admission": admission,
            "executable_coverage": {
                "status": "BOUNDED_REVIEWED_PACK_ONLY",
                "pack_id": self.pack["id"],
                "pack_version": self.pack["version"],
                "pack_sha256": self.pack_sha256,
                "stacks": executable_counts,
                "exact_source_excerpts": source_excerpt_count,
                "admitted_policy_semantic_template_mappings": 0,
                "executable_policy_templates": 0,
                "exact_reviewed_source_mappings": mapping_index["counts"]["exact_reviewed_source_mappings"],
                "bounded_reviewed_pack_executable_mappings": mapping_index["counts"]["bounded_reviewed_pack_executable_mappings"],
                "source_mapping_index_sha256": mapping_index["index_sha256"],
                "full_library_semantic_compilation": "INCOMPLETE",
                "residual": "FULL_LIBRARY_EXECUTABLE_SEMANTIC_COMPILATION_INCOMPLETE",
                "coverage_ceiling": self.pack["coverage_ceiling"],
            },
            "separation_invariant": (
                "Complete source accounting, interpretation admission, and executable "
                "coverage are distinct claims and cannot substitute for one another."
            ),
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
        body["manifest_sha256"] = _digest(body)
        return body

    def validate(self, manifest: Any) -> dict[str, Any]:
        expected = self.build()
        _need(type(manifest) is dict and manifest == expected,
              "source accounting manifest mismatch")
        return deepcopy(expected)
