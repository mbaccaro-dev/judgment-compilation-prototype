"""Tests package behavior."""
from copy import deepcopy
import unittest
from judgment_compilation.semantic_contracts import (
    SCHEMA, COORDINATE_MODEL, SemanticContractError, canonical, coordinate,
    path_from_coordinate, semantic_coordinate,
    identity, validate_semantic_pack, resolve_domain, evaluate_judgment,
    execute_architecture,
)


def fixture():
    """A tiny document adapter fixture, not a population or compliance model."""
    roles = {'subject': 'system'}
    def clause(predicate, output=False):
        row = {'predicate': predicate, 'arguments': {'subject': 'target'}, 'value': True}
        if output:
            row['semantic_kind'] = 'SCENARIO_DERIVATION'
        return row
    def node(stack, path, label):
        return {'coordinate': semantic_coordinate(stack, path), 'label': label, 'aliases': []}
    semantic_capital = {
        'coordinate_model': COORDINATE_MODEL,
        'judgment': [node('judgment', [0], 'Scenario warrant'),
                     node('judgment', [0, 0], 'Scope-to-review warrant'),
                     node('judgment', [0, 1], 'Review-to-schedule warrant')],
        'work': [node('work', [0], 'Contract execution'),
                 node('work', [0, 0], 'Apply judgment')],
        'architecture': [node('architecture', [0], 'Dependency flow'),
                         node('architecture', [0, 0], 'Review flow')],
    }
    return {
        'schema': SCHEMA, 'id': 'fixture', 'root_id': 'NIST-SP800-local',
        'domain': [
            {'path': [], 'label': 'NIST SP 800', 'aliases': []},
            {'path': [1], 'label': 'Access control', 'aliases': ['access']},
            {'path': [1, 1], 'label': 'Account management', 'aliases': ['accounts']},
            {'path': [1, 2], 'label': 'Account review', 'aliases': ['accounts']},
        ],
        'semantic_capital': semantic_capital, 'entity_kinds': ['system'],
        'predicates': [
            {'id': 'in_scope', 'roles': roles, 'origin': 'INPUT'},
            {'id': 'review_required', 'roles': roles, 'origin': 'DERIVED'},
            {'id': 'review_scheduled', 'roles': roles, 'origin': 'DERIVED'},
        ],
        'sources': [{'id': 'document:section', 'sha256': 'a' * 64}],
        'judgments': [
            {'id': 'scope-to-review', 'semantic_coordinate': semantic_coordinate('judgment', [0, 0]),
             'bindings': {'target': 'system'},
             'premises': [clause('in_scope')], 'output': clause('review_required', True),
             'source_ids': ['document:section'], 'residual': 'Supply scope evidence.'},
            {'id': 'review-to-schedule', 'semantic_coordinate': semantic_coordinate('judgment', [0, 1]),
             'bindings': {'target': 'system'},
             'premises': [clause('review_required')], 'output': clause('review_scheduled', True),
             'source_ids': ['document:section'], 'residual': 'Review applicability remains open.'},
        ],
        'work': [
            {'id': 'review', 'semantic_coordinate': semantic_coordinate('work', [0, 0]),
             'operation': 'APPLY_JUDGMENT', 'judgment': 'scope-to-review', 'domain_path': [1, 1]},
            {'id': 'schedule', 'semantic_coordinate': semantic_coordinate('work', [0, 0]),
             'operation': 'APPLY_JUDGMENT', 'judgment': 'review-to-schedule', 'domain_path': [1, 2]},
        ],
        'architectures': [{'id': 'review-flow', 'semantic_coordinate': semantic_coordinate('architecture', [0, 0]), 'steps': [
            {'id': 'first', 'work': 'review', 'depends_on': []},
            {'id': 'second', 'work': 'schedule', 'depends_on': ['first']},
        ]}],
    }


def request():
    return {'entities': {'a': 'system', 'b': 'system'},
            'facts': [{'id': 'f1', 'predicate': 'in_scope', 'arguments': {'subject': 'a'}, 'value': True}],
            'bindings': {'target': ['a']}, 'unknowns': []}


class SemanticContractsTests(unittest.TestCase):
    def test_domain_root_multilevel_coordinate_and_occurrence_roundtrip(self):
        p = validate_semantic_pack(fixture())
        for n in p['domain']:
            c = coordinate(n['path'], 7)
            self.assertEqual(path_from_coordinate(c), n['path'])
            self.assertEqual(c['L'], n['path'][-1] if n['path'] else 0)
            self.assertEqual(c['Gs'], [0, *n['path'][:-1]] if n['path'] else [])
        self.assertEqual(coordinate([]), {'Gs': [], 'L': 0, 'I': 0})
        self.assertNotEqual(identity(p['root_id'], [1], 0), identity(p['root_id'], [1], 1))
        self.assertNotEqual(identity('other', [1]), identity(p['root_id'], [1]))
        self.assertEqual(canonical(p), canonical(validate_semantic_pack(p)))

    def test_alias_requires_context(self):
        self.assertEqual(resolve_domain(fixture(), 'accounts')['status'], 'AMBIGUOUS')
        self.assertEqual(resolve_domain(fixture(), 'accounts', [1, 1])['status'], 'RESOLVED')
        self.assertEqual(resolve_domain(fixture(), 'absent')['status'], 'NOT_FOUND')

    def test_reusable_warrant_distinct_entities_and_source_support(self):
        p, r = fixture(), request()
        first = evaluate_judgment(p, 'scope-to-review', r)
        self.assertEqual(first['status'], 'APPLIED')
        self.assertEqual(first['output']['support'], ['f1'])
        self.assertEqual(first['output']['source_ids'], ['document:section'])
        r['bindings'] = {'target': ['b']}
        r['facts'][0]['arguments']['subject'] = 'b'
        second = evaluate_judgment(p, 'scope-to-review', r)
        self.assertEqual(second['status'], 'APPLIED')
        self.assertNotEqual(first['output']['id'], second['output']['id'])
        self.assertIsNone(second['compliance_verdict'])
        self.assertEqual(second['external_effects'], [])

    def test_missing_ambiguous_unknown_conflicting_and_false_stay_distinct(self):
        for variant, reason in [('missing_binding', 'MISSING_BINDING'), ('ambiguity', 'AMBIGUOUS_BINDING'),
                                ('missing_fact', 'MISSING_FACT'), ('unknown', 'UNKNOWN_EVIDENCE'),
                                ('conflict', 'CONFLICTING_FACTS')]:
            with self.subTest(variant=variant):
                r = request()
                if variant == 'missing_binding': r['bindings'] = {}
                if variant == 'ambiguity': r['bindings']['target'] = ['a', 'b']
                if variant == 'missing_fact': r['facts'] = []
                if variant == 'unknown': r['facts'][0]['value'] = None
                if variant == 'conflict': r['facts'].append({**r['facts'][0], 'id': 'f2', 'value': False})
                result = evaluate_judgment(fixture(), 'scope-to-review', r)
                self.assertEqual(result['status'], 'UNRESOLVED')
                self.assertIn(reason, [x['reason'] for x in result['residuals']])
                self.assertIsNone(result['output'])
        r = request(); r['facts'][0]['value'] = False
        self.assertEqual(evaluate_judgment(fixture(), 'scope-to-review', r)['status'], 'NOT_APPLICABLE')

    def test_architecture_dependency_propagation_and_residual_preservation(self):
        r = request(); r['bindings'] = {'first': {'target': ['a']}, 'second': {'target': ['a']}}
        result = execute_architecture(fixture(), 'review-flow', r)
        self.assertEqual(result['status'], 'COMPLETE')
        self.assertEqual(result['outputs'][1]['support'], [result['outputs'][0]['id']])
        self.assertEqual(canonical(result), canonical(execute_architecture(fixture(), 'review-flow', r)))
        r['facts'] = []
        result = execute_architecture(fixture(), 'review-flow', r)
        self.assertEqual([s['status'] for s in result['steps']], ['UNRESOLVED', 'BLOCKED'])
        self.assertEqual(result['outputs'], [])

    def test_blocked_steps_still_reject_malformed_bindings(self):
        malformed = [None, [], 1.5, {'foreign': ['a']}, {'target': 'a'},
                     {'target': ['a', 'a']}, {'target': ['absent']},
                     {'target': [None]}, {'target': [1]}]
        for bindings in malformed:
            with self.subTest(bindings=bindings):
                r = request()
                r['facts'] = []
                r['bindings'] = {'first': {'target': ['a']}, 'second': bindings}
                with self.assertRaises(SemanticContractError):
                    execute_architecture(fixture(), 'review-flow', r)
        p = fixture()
        p['entity_kinds'].append('person')
        r = request()
        r['facts'] = []
        r['entities']['outsider'] = 'person'
        r['bindings'] = {'first': {'target': ['a']}, 'second': {'target': ['outsider']}}
        with self.assertRaises(SemanticContractError):
            execute_architecture(p, 'review-flow', r)

    def test_sibling_output_is_not_an_undeclared_dependency(self):
        p = fixture(); p['architectures'][0]['steps'][1]['depends_on'] = []
        r = request(); r['bindings'] = {'first': {'target': ['a']}, 'second': {'target': ['a']}}
        result = execute_architecture(p, 'review-flow', r)
        self.assertEqual(result['steps'][1]['status'], 'UNRESOLVED')

    def test_domain_dependency_coordinate_and_support_falsifiers(self):
        mutations = [
            lambda p: p['domain'][2].update(path=[9, 1]),
            lambda p: p['domain'][2].update(path=[1]),
            lambda p: p['domain'][1].update(coordinate={'Gs': [1], 'L': 8, 'I': 0}),
            lambda p: p['judgments'][0].update(source_ids=['absent']),
            lambda p: p['judgments'][0]['output'].update(semantic_kind='COMPLIANCE_VERDICT'),
            lambda p: p['judgments'][0]['premises'][0]['arguments'].update(subject='unbound'),
            lambda p: p['work'][0].update(operation='EXECUTE_SHELL'),
            lambda p: p['work'][0].update(judgment='missing'),
            lambda p: p['work'][0].update(semantic_coordinate=semantic_coordinate('work', [9])),
            lambda p: p['judgments'][0].update(semantic_coordinate=semantic_coordinate('judgment', [9])),
            lambda p: p['architectures'][0].update(semantic_coordinate=semantic_coordinate('architecture', [9])),
            lambda p: p['semantic_capital']['judgment'][1].update(coordinate=semantic_coordinate('judgment', [9, 0])),
            lambda p: p['architectures'][0]['steps'][0].update(depends_on=['absent']),
            lambda p: p['architectures'][0]['steps'][0].update(depends_on=['second']),
        ]
        for mutation_index, mutate in enumerate(mutations):
            with self.subTest(mutation_index=mutation_index):
                p = fixture(); mutate(p)
                with self.assertRaises(SemanticContractError): validate_semantic_pack(p)
        for c in [{'Gs': [1], 'L': 2, 'I': 0}, {'Gs': [True], 'L': 1, 'I': 0}, {'Gs': [], 'L': False, 'I': 0}]:
            with self.assertRaises(SemanticContractError): path_from_coordinate(c)

    def test_parameter_and_evidence_residuals_are_explicit_and_claim_types_fixed(self):
        p, r = fixture(), request()
        for kind, reason in [('PARAMETER_BINDING', 'MISSING_PARAMETER'), ('EVIDENCE', 'MISSING_EVIDENCE')]:
            p['predicates'][0]['input_kind'] = kind
            r['facts'] = []
            result = evaluate_judgment(p, 'scope-to-review', r)
            self.assertEqual(result['residuals'][0]['reason'], reason)
            self.assertEqual(result['residuals'][0]['type'], 'UNRESOLVED')
        r = request()
        result = evaluate_judgment(p, 'scope-to-review', r)
        self.assertEqual(result['output']['type'], 'DETERMINISTIC_DERIVATION')
        self.assertEqual(result['source_requirements'][0]['type'], 'SOURCE_BOUND')
        r['facts'][0]['id'] = 'derived:forged'
        with self.assertRaises(SemanticContractError): evaluate_judgment(p, 'scope-to-review', r)
    def test_forged_derived_or_support_input_is_rejected(self):
        for change in [{'predicate': 'review_required'}, {'support': ['absent']}, {'arguments': {'subject': 'absent'}}]:
            r = request(); r['facts'][0].update(change)
            with self.assertRaises(SemanticContractError): evaluate_judgment(fixture(), 'scope-to-review', r)


if __name__ == '__main__':
    unittest.main()

