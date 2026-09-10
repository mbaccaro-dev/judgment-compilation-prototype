"""Tests package behavior."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import unittest

from judgment_compilation import nist_reviewed_raw_mappings as mappings


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = PROJECT_ROOT / "judgment_compilation"
LIBRARY_ROOT = PACKAGE_ROOT / "data" / "library"


class NistReviewedRawMappingsStagedTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = mappings
        cls.kwargs = {
            "root": LIBRARY_ROOT,
            "source_root": PACKAGE_ROOT,
        }
        cls.inventory = cls.module.build_nist_reviewed_raw_mappings(**cls.kwargs)

    def test_schema_and_all_reviewed_rows(self):
        self.assertEqual(self.inventory["schema"], "jc/nist-reviewed-raw-mappings/1")
        self.assertEqual(self.inventory["reviewed_source_count"], 7)
        self.assertEqual(
            [row["source_id"] for row in self.inventory["rows"]],
            ["AC-2(l)", "AC-6 Control", "PS-4(a)", "SI-2(c)",
             "PS-4(b)", "sc-7.25_smt", "sc-7.27_smt"],
        )
        self.assertEqual(
            self.inventory["source_pdf_sha256"],
            "fc63bcd61715d0181dd8e85998b1e6201ae3515fc6626102101cab1841e11ec6",
        )

    def test_exact_source_page_and_span_integrity(self):
        expected = {
            "AC-2(l)": (46, (2103, 2188)),
            "AC-6 Control": (63, (2179, 2370)),
            "PS-4(a)": (251, (2296, 2372)),
            "SI-2(c)": (360, (673, 818)),
            "PS-4(b)": (251, (2377, 2463)),
        }
        rows = {row["source_id"]: row for row in self.inventory["rows"]}
        for source_id, (page, (start, end)) in expected.items():
            span = rows[source_id]["reviewed_source_span"]
            self.assertEqual(span["pdf_page_number"], page)
            self.assertEqual((span["character_span"]["start"], span["character_span"]["end"]),
                             (start, end))
            self.assertEqual(span["source_file"]["sha256"], self.inventory["source_pdf_sha256"])

        sc725 = rows["sc-7.25_smt"]["reviewed_source_span"]
        self.assertEqual(sc725["xml_id"], "sc-7.25_smt")
        self.assertEqual(sc725["template_sha256"],
                         "a49d3576cdb23dc03bb87398eb6558f52d82e6bfdc4febba3993ddd9c2298986")
        support = sc725["pdf_projection_support"]
        self.assertEqual(support["pdf_page_number"], 330)
        self.assertEqual((support["character_span"]["start"], support["character_span"]["end"]),
                         (2450, 2663))
        sc727 = rows["sc-7.27_smt"]["reviewed_source_span"]
        self.assertEqual(sc727["xml_id"], "sc-7.27_smt")
        self.assertIsNone(sc727["pdf_projection_support"])

    def test_zero_exact_matches_and_unresolved_nearby_context(self):
        rows = self.inventory["rows"]
        self.assertTrue(all(not any(row["raw_candidate_matches"].values()) for row in rows))
        self.assertEqual(self.inventory["raw_candidate_policy"]["admission"], "NOT_ADMITTED")
        self.assertEqual(self.inventory["raw_candidate_policy"]["nearby_lexical_signals"],
                         "RETAINED_AS_UNRESOLVED_CONTEXT_ONLY")
        counts = {row["source_id"]: row["raw_candidate_counts_on_reviewed_page"] for row in rows}
        self.assertGreater(sum(counts["AC-2(l)"].values()), 0)
        self.assertGreater(sum(counts["AC-6 Control"].values()), 0)
        self.assertGreater(sum(counts["PS-4(a)"].values()), 0)
        self.assertGreater(sum(counts["SI-2(c)"].values()), 0)
        self.assertEqual(counts["sc-7.27_smt"],
                         {"DOMAIN": 0, "JUDGMENT": 0, "WORK": 0, "ARCHITECTURE": 0})

    def test_missing_producers_and_no_automatic_effect(self):
        self.assertEqual(
            self.inventory["missing_interfaces"],
            ["INTERPRETATION_QUALIFICATION", "DOMAIN_PRODUCER", "JUDGMENT_PRODUCER",
             "WORK_PRODUCER", "ARCHITECTURE_PRODUCER"],
        )
        self.assertFalse(self.inventory["explicit_selection_confirmed"])
        self.assertEqual(self.inventory["external_effects"], [])
        self.assertEqual(self.inventory["raw_candidate_policy"]["semantic_coordinates"], 0)
        for row in self.inventory["rows"]:
            self.assertIn("RAW_MATCHES_REMAIN_UNADMITTED", row["admission"])
            for stack in row["stack_surfaces"].values():
                self.assertEqual(stack["raw_candidate_qualification"], "MISSING")

    def test_deterministic_rebuild_and_tamper_rejection(self):
        rebuilt = self.module.build_nist_reviewed_raw_mappings(**self.kwargs)
        self.assertEqual(rebuilt, self.inventory)
        tampered = deepcopy(self.inventory)
        tampered["rows"][0]["source_id"] = "TAMPERED"
        with self.assertRaises(self.module.NistReviewedRawMappingsError):
            self.module.validate_nist_reviewed_raw_mappings(tampered, **self.kwargs)


if __name__ == "__main__":
    unittest.main()
