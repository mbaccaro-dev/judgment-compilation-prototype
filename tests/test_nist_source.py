"""Tests package behavior."""
import hashlib
from pathlib import Path
import tempfile
import unittest
import pymupdf
from judgment_compilation.nist_source import (
    ROOT, TARGETS, XML_HASH, frozen_inputs, provenance_inventory, normalized,
)
from judgment_compilation.kernel import Rejected


class SourceProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = frozen_inputs()
        cls.inventory = provenance_inventory(cls.manifest)

    def test_exact_source_spans_and_hashes(self):
        for label, control, parts, expected, page in TARGETS:
            row = self.inventory[label]
            self.assertEqual(row['physical_pdf_page_one_based'], page)
            self.assertIn('/control/' + control, row['structural_oscal_locator'])
            self.assertIn(XML_HASH, row['structural_oscal_locator'])
            self.assertEqual(row['occurrence_count'], len(row['all_exact_normalized_occurrences']))
            self.assertGreater(row['occurrence_count'], 0)
            for occurrence in row['all_exact_normalized_occurrences']:
                source = occurrence['source_file']
                raw = (ROOT / source['path']).read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), source['sha256'])
                with pymupdf.open(stream=raw, filetype='pdf') as document:
                    text = document[occurrence['physical_pdf_page_index_zero_based']].get_text('text', sort=False)
                span = occurrence['character_span']
                quote = text[span['start']:span['end']]
                self.assertEqual(quote, occurrence['quote'])
                self.assertEqual(normalized(quote), normalized(expected))
                self.assertEqual(hashlib.sha256(quote.encode()).hexdigest(), occurrence['quote_sha256'])
                self.assertEqual(hashlib.sha256(normalized(quote).encode()).hexdigest(), occurrence['normalized_quote_sha256'])
                self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), occurrence['extracted_page_text_sha256'])

    def test_source_mutation_rejected_before_extraction(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / 'data/corpus/source/source_manifest.json'
            manifest.parent.mkdir(parents=True)
            manifest.write_bytes((ROOT / 'data/corpus/source/source_manifest.json').read_bytes())
            first = root / self.manifest['frozen_sources'][0]['path']
            first.write_bytes(b'modified publication bytes')
            with self.assertRaisesRegex(Rejected, 'frozen source drift'):
                frozen_inputs(root)

    def test_manifest_mutation_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / 'data/corpus/source/source_manifest.json'
            manifest.parent.mkdir(parents=True)
            manifest.write_text('{}')
            with self.assertRaisesRegex(Rejected, 'source manifest drift'):
                frozen_inputs(root)

    def test_provenance_has_no_legacy_semantic_dependency(self):
        source = (ROOT / 'nist_source.py').read_text()
        for forbidden in ['data/semantic', 'population_records', 'domain_semantic_capital', 'sp800_53_compiled_ir']:
            self.assertNotIn(forbidden, source)
        for row in self.inventory.values():
            self.assertNotIn('coordinate', row)
            self.assertIn('No OCR', row['occurrence_scope']['coverage_ceiling'])


if __name__ == '__main__':
    unittest.main()
