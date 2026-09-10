"""Tests package behavior."""
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from judgment_compilation import nist_requirements as source
from judgment_compilation.bulk_semantic_contracts import (
    SP80053BulkContracts, BulkContractError, canonical, digest,
)


ROOT = Path(__file__).resolve().parents[1]


class BulkContractsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler = SP80053BulkContracts(ROOT)
        cls.compiled = cls.compiler.compile()
        cls.judgments = {j['statement_id']: j for j in cls.compiled['judgments']}

    def test_full_oscal_inventory_identity_without_full_library_claim(self):
        tree = ET.fromstring((ROOT / source.SOURCE_RELATIVE_PATH).read_bytes())
        ns = source.NS
        expected = set()
        def visit(node, in_statement=False):
            in_statement = in_statement or (node.tag == ns + 'part' and node.get('name') == 'statement')
            if in_statement and node.tag == ns + 'part' and node.get('name') in {'statement', 'item'} and node.get('id'):
                expected.add(node.get('id'))
            for child in node:
                visit(child, in_statement)
        visit(tree)
        self.assertEqual(set(self.judgments), expected)
        self.assertEqual(len(expected), 2138)
        c = self.compiled
        self.assertEqual(c['counts']['consumer_parameter_bindings'], 1271)
        self.assertEqual(c['counts']['source_choice_templates'], 342)
        self.assertEqual(c['counts']['work_interfaces'], 2)
        self.assertEqual(c['counts']['admitted_policy_interpretations'], 0)
        self.assertEqual(c['counts']['organizational_values'], 0)
        self.assertIn('NOT_FULL_PDF_LIBRARY_SEMANTICS', c['coverage'])
        self.assertIsNone(c['raw_document_connector']['document'])
        self.assertFalse(c['raw_document_connector']['whole_library_semantic_coverage'])
        self.assertEqual(c['disposition']['raw_document_semantics'], 'RAW_DOCUMENT_SEMANTICS_UNRESOLVED')
        by_xml_id = {n.get('id'): n for n in tree.iter() if n.get('id')}
        parameter_ids = {p['id'] for p in c['domain']['parameters']}
        for j in c['judgments']:
            self.assertEqual(j['source_template']['source']['serialized_xml'],
                             ET.tostring(by_xml_id[j['statement_id']], encoding='unicode'))
            self.assertTrue(set(j['domain_parameter_ids']) <= parameter_ids)
            self.assertEqual(j['disposition']['policy_interpretation'], 'UNRESOLVED_NOT_ADMITTED')
            self.assertTrue(all(j['disposition'][key] is None for key in
                                ['applicability', 'precedence', 'satisfaction', 'compliance', 'responsibility']))
        for p in c['domain']['parameters']:
            self.assertTrue(set(p['dependency_domain_ids']) <= parameter_ids)
            self.assertIsNone(p['value_contract']['value'])

    def test_determinism_and_returned_data_detachment(self):
        again = self.compiler.compile()
        self.assertEqual(canonical(again), canonical(self.compiled))
        again['judgments'][0]['source_template']['blocks'].clear()
        self.assertNotEqual(again, self.compiled)
        self.assertTrue(self.compiled['judgments'][0]['source_template']['blocks'])

    def test_rehashed_contract_tampering_and_inventory_omission_rejected(self):
        changed = deepcopy(self.compiled)
        changed['judgments'].pop()
        changed['compilation_sha256'] = digest({k: v for k, v in changed.items() if k != 'compilation_sha256'})
        with self.assertRaisesRegex(BulkContractError, 'derivation mismatch'):
            self.compiler.validate(changed)
        judgment = deepcopy(self.judgments['ac-2.3_smt'])
        judgment['disposition']['applicability'] = True
        with self.assertRaisesRegex(BulkContractError, 'derivation mismatch'):
            self.compiler.execute(judgment, self.inspect_request(judgment))

    @staticmethod
    def inspect_request(judgment):
        return {'schema': source.REQUEST_SCHEMA, 'operation': 'inspect',
                'statement_id': judgment['statement_id']}

    def instance_request(self, judgment):
        template = judgment['source_template']
        scope = {'organization_id': 'synthetic-org', 'system_id': 'synthetic-system'}
        return {'schema': source.REQUEST_SCHEMA, 'operation': 'instantiate',
                'statement_id': judgment['statement_id'], 'source_sha256': source.SOURCE_SHA256,
                'template_sha256': template['template_sha256'], 'scope': scope,
                'parameters': [
                    {'parameter_id': p['parameter_id'], 'control_id': template['control_id'],
                     'source_sha256': source.SOURCE_SHA256, 'scope': deepcopy(scope),
                     'values': ([{'choice_sha256': p['choice_templates'][0]['choice_sha256']}]
                                if p['kind'] == 'SELECTION' else ['caller opaque value']),
                     'evidence_refs': ['caller-unverified:fixture']}
                    for p in template['parameters']]}

    def test_exact_warrant_work_execution_and_missing_value_residual(self):
        judgment = self.judgments['ac-2.3_smt']
        inspected = self.compiler.execute(judgment, self.inspect_request(judgment))
        self.assertEqual(inspected['result']['status'], 'INSPECTED')
        request = self.instance_request(judgment)
        result = self.compiler.execute(judgment, request)
        self.assertEqual(result['result']['status'], 'INSTANTIATED')
        self.assertEqual(result['warrant']['preparation_sha256'], result['preparation_sha256'])
        self.assertEqual(result['result']['instance']['scope'], request['scope'])
        self.assertIsNone(result['result']['compliance_verdict'])
        self.assertEqual(result['disposition']['external_effects'], [])
        request['parameters'] = []
        held = self.compiler.execute(judgment, request)
        self.assertEqual(held['result']['status'], 'UNRESOLVED')
        self.assertIsNone(held['result']['instance'])
        self.assertTrue(any(r['reason'] == 'MISSING_PARAMETER' for r in held['result']['residuals']))
        request['statement_id'] = 'ac-2.2_smt'
        with self.assertRaisesRegex(BulkContractError, 'identity mismatch'):
            self.compiler.execute(judgment, request)

    def test_cross_control_declaration_is_not_consumer_identity(self):
        j = self.judgments['sc-42.2_smt']
        p = next(p for p in self.compiled['domain']['parameters']
                 if p['id'] in j['domain_parameter_ids'] and p['parameter_id'] == 'sc-42.01_odp')
        self.assertEqual(p['consumer_control_id'], 'sc-42.2')
        self.assertEqual(p['source_definition']['declaration_control_id'], 'sc-42.1')
        request = self.instance_request(j)
        next(p for p in request['parameters'] if p['parameter_id'] == 'sc-42.01_odp')['control_id'] = 'sc-42.1'
        with self.assertRaisesRegex(source.RequirementError, 'foreign control binding'):
            self.compiler.execute(j, request)

    def test_retained_pdf_connector_verifies_identity_but_not_interpretation(self):
        connector = self.compiler.retained_pdf_connector(True)
        self.assertEqual(connector['document']['publication_id'], 'NIST SP 800-53r5-upd1')
        self.assertEqual(connector['document']['source_file']['sha256'],
                         'fc63bcd61715d0181dd8e85998b1e6201ae3515fc6626102101cab1841e11ec6')
        self.assertEqual(connector['clause_correspondence'], 'UNRESOLVED')
        self.assertEqual(connector['raw_document_semantics'], 'RAW_DOCUMENT_SEMANTICS_UNRESOLVED')
        self.assertFalse(connector['whole_library_semantic_coverage'])
        with self.assertRaises(BulkContractError):
            self.compiler.retained_pdf_connector('true')

    def test_unsupported_grammar_stays_held_and_source_drift_rejected(self):
        raw = (b'<catalog xmlns="http://csrc.nist.gov/ns/oscal/1.0"><metadata>'
               b'<version>synthetic</version><oscal-version>1.2.2</oscal-version></metadata>'
               b'<control id="fixture"><title>Fixture</title><part id="fixture_smt" name="statement">'
               b'<p><unsupported>Do not infer this policy.</unsupported></p></part></control></catalog>')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / source.SOURCE_RELATIVE_PATH
            target.parent.mkdir(parents=True)
            target.write_bytes(raw)
            with patch.object(source, 'SOURCE_SHA256', sha256(raw).hexdigest()):
                compiler = SP80053BulkContracts(root)
                compiled = compiler.compile()
                self.assertEqual(compiled['counts']['unsupported_source_templates'], 1)
                j = compiled['judgments'][0]
                self.assertFalse(j['instantiation_supported'])
                result = compiler.execute(j, self.instance_request(j))
                self.assertEqual(result['result']['status'], 'UNRESOLVED')
                self.assertIsNone(result['result']['instance'])
                target.write_bytes(raw + b'\n')
                with self.assertRaisesRegex(source.RequirementError, 'checksum mismatch'):
                    compiler.compile()


if __name__ == '__main__':
    unittest.main()
