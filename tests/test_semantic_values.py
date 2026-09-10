"""Tests package behavior."""
from copy import deepcopy
import hashlib
import unittest
from judgment_compilation.semantic_contracts import (
    SCHEMA, COORDINATE_MODEL, SemanticContractError, canonical,
    semantic_coordinate, validate_semantic_pack, evaluate_judgment,
    execute_architecture,
)


def fixture():
    text = 'Fictional test: general merchandise 30 days; electronics explicitly excepted at 60 days. Units use fixed elapsed days.'
    source = {'id': 'fictional-policy', 'sha256': hashlib.sha256(text.encode()).hexdigest()}
    def edge(path):
        return {'path': path, 'source_ids': [source['id']]}
    def node(path, label, **extra):
        return {'path': path, 'label': label, 'aliases': [], **extra}
    domain = [node([], 'Generic conformance'),
              node([1], 'Merchandise', entity_kind='purchase'),
              node([1,1], 'Electronics', specializes=[edge([1])]),
              node([1,2], 'Ordinary merchandise', specializes=[edge([1])]),
              node([2], 'Duration'),
              node([2,1], 'Day', unit={'basis':'FIXED_RATIO', 'dimension_path':[2], 'numerator':86400, 'denominator':1, 'source_ids':[source['id']]}),
              node([2,2], 'Hour', unit={'basis':'FIXED_RATIO', 'dimension_path':[2], 'numerator':3600, 'denominator':1, 'source_ids':[source['id']]}),
              node([3], 'Refund')]
    roles = {'item':'purchase'}
    def pred(identifier, kind, origin):
        p = {'id':identifier, 'roles':roles, 'origin':origin, 'value_type':kind}
        if kind == 'DOMAIN':
            p['classification'] = 'EXACT'
            p['domain_root'] = [1]
        return p
    def rule(identifier, category, days, overrides=None):
        path = [0, 0] if identifier == 'general' else [0, 1]
        j = {'id':identifier, 'semantic_coordinate':semantic_coordinate('judgment', path),
             'bindings':{'target':'purchase'},
             'premises':[{'predicate':'category', 'arguments':{'item':'target'}, 'operator':'IS_A', 'value':category}],
             'output':{'predicate':'window', 'arguments':{'item':'target'}, 'value':{'amount':days,'unit_path':[2,1]}, 'semantic_kind':'SOURCE_BOUND_REQUIREMENT'},
             'source_ids':[source['id']], 'residual':'Exact category and applicable policy required.'}
        if overrides:
            j['overrides'] = [{'judgment_id':overrides, 'source_ids':[source['id']]}]
        return j
    slot = lambda name: {'predicate':name, 'arguments':{'item':'target'}}
    def definition(stack, path, label):
        return {'coordinate':semantic_coordinate(stack, path), 'label':label, 'aliases':[]}
    semantic_capital = {
        'coordinate_model': COORDINATE_MODEL,
        'judgment': [definition('judgment',[0],'Refund-window warrant'),
                     definition('judgment',[0,0],'General refund-window warrant'),
                     definition('judgment',[0,1],'Electronics exception warrant')],
        'work': [definition('work',[0],'Judgment resolution'),
                 definition('work',[0,0],'Resolve applicable judgments'),
                 definition('work',[1],'Typed-value evaluation'),
                 definition('work',[1,0],'Compatible quantity comparison')],
        'architecture': [definition('architecture',[0],'Dependency flow'),
                         definition('architecture',[0,0],'Refund window evaluation flow')],
    }
    return {'schema':SCHEMA, 'id':'generic-value-conformance', 'root_id':'fixture-root',
            'domain':domain, 'semantic_capital':semantic_capital, 'entity_kinds':['purchase'],
            'predicates':[pred('category','DOMAIN','INPUT'), pred('elapsed','QUANTITY','INPUT'),
                          pred('window','QUANTITY','DERIVED'), pred('within_window','BOOLEAN','DERIVED')],
            'sources':[source], 'judgments':[rule('general',[1],30), rule('electronics',[1,1],60,'general')],
            'work':[{'id':'select', 'semantic_coordinate':semantic_coordinate('work',[0,0]),
                     'operation':'RESOLVE_JUDGMENTS', 'judgments':['general','electronics'], 'domain_path':[3]},
                    {'id':'compare','semantic_coordinate':semantic_coordinate('work',[1,0]),
                     'operation':'COMPARE_VALUES','bindings':{'target':'purchase'},
                     'left':slot('elapsed'),'right':slot('window'),'operator':'LE','output':slot('within_window'),'domain_path':[3]}],
            'architectures':[{'id':'flow','semantic_coordinate':semantic_coordinate('architecture',[0,0]),
                              'steps':[{'id':'select','work':'select','depends_on':[]},
                                                {'id':'compare','work':'compare','depends_on':['select']}]}]}


def request(category=None, days=45):
    return {'entities':{'item-a':'purchase','item-b':'purchase'},
            'facts':[{'id':'category-a','predicate':'category','arguments':{'item':'item-a'},'value':category},
                     {'id':'elapsed-a','predicate':'elapsed','arguments':{'item':'item-a'},'value':{'amount':days,'unit_path':[2,1]}}],
            'bindings':{'select':{'target':['item-a']},'compare':{'target':['item-a']}}, 'unknowns':[]}


class SemanticValuesTests(unittest.TestCase):
    def test_all_four_stacks_compute_window_and_keep_support(self):
        for category, days, window, inside in [([1,2],20,30,True),([1,1],45,60,True),([1,1],61,60,False),([1,1],60,60,True)]:
            with self.subTest(category=category,days=days):
                p,r=fixture(),request(category,days)
                before=canonical([p,r])
                out=execute_architecture(p,'flow',r)
                self.assertEqual(out['status'],'COMPLETE')
                self.assertEqual(out['outputs'][0]['value']['amount'],window)
                self.assertIs(out['outputs'][1]['value'],inside)
                self.assertIn(out['outputs'][0]['id'],out['outputs'][1]['support'])
                self.assertEqual(out['outputs'][1]['arguments'],{'item':'item-a'})
                self.assertEqual(canonical([p,r]),before)
                self.assertEqual(canonical(out),canonical(execute_architecture(p,'flow',r)))
                self.assertIsNone(out['compliance_verdict'])
                self.assertEqual(out['external_effects'],[])
        out=execute_architecture(fixture(),'flow',request([1,1]))
        self.assertEqual(out['steps'][0]['selection_trace']['override_edges'][0]['relation'],'OVERRIDES')

    def test_unknown_and_conflict_do_not_silently_select_default(self):
        for variant in ('missing','null','conflict','declared'):
            r=request([1,1])
            if variant=='missing': r['facts'].pop(0)
            elif variant=='null': r['facts'][0]['value']=None
            elif variant=='conflict': r['facts'].append({**r['facts'][0],'id':'category-conflict','value':[1,2]})
            else: r['unknowns']=['The purchase category has not been established.']
            out=execute_architecture(fixture(),'flow',r)
            self.assertEqual(out['outputs'],[])
            self.assertEqual([s['status'] for s in out['steps']],['UNRESOLVED','BLOCKED'])

    def test_explicit_exception_required_and_cannot_be_omitted_or_bypassed(self):
        p=fixture(); p['judgments'][1].pop('overrides')
        out=execute_architecture(p,'flow',request([1,1]))
        self.assertEqual(out['outputs'],[])
        self.assertEqual(out['steps'][0]['residuals'][0]['reason'],'CONFLICTING_JUDGMENTS')
        p=fixture(); p['work'][0]['judgments']=['general']
        with self.assertRaises(SemanticContractError): validate_semantic_pack(p)
        p=fixture(); p['work'][0]={'id':'select','semantic_coordinate':semantic_coordinate('work',[0,0]),
                                  'operation':'APPLY_JUDGMENT','judgment':'general','domain_path':[3]}
        with self.assertRaises(SemanticContractError): validate_semantic_pack(p)
        r=request([1,1]); r['bindings']={'target':['item-a']}
        with self.assertRaises(SemanticContractError): evaluate_judgment(fixture(),'general',r)

    def test_entity_and_dependency_isolation(self):
        r=request([1,2])
        r['facts'].append({'id':'category-b','predicate':'category','arguments':{'item':'item-b'},'value':[1,1]})
        out=execute_architecture(fixture(),'flow',r)
        self.assertEqual(out['outputs'][0]['value']['amount'],30)
        r['bindings']['compare']['target']=['item-b']
        out=execute_architecture(fixture(),'flow',r)
        self.assertEqual(out['steps'][1]['status'],'UNRESOLVED')
        p=fixture(); p['architectures'][0]['steps'][1]['depends_on']=[]
        out=execute_architecture(p,'flow',request([1,1]))
        self.assertEqual(next(s for s in out['steps'] if s['step_id']=='compare')['status'],'UNRESOLVED')

    def test_exact_quantity_equivalence_and_dimension_rejection(self):
        r=request([1,1],1)
        r['facts'].append({'id':'elapsed-hours','predicate':'elapsed','arguments':{'item':'item-a'},'value':{'amount':24,'unit_path':[2,2]}})
        self.assertEqual(execute_architecture(fixture(),'flow',r)['status'],'COMPLETE')
        p=fixture(); p['domain'].append({'path':[4],'label':'Mass','aliases':[]})
        p['domain'].append({'path':[4,1],'label':'Mass unit','aliases':[], 'unit':{'basis':'FIXED_RATIO', 'dimension_path':[4],'numerator':1,'denominator':1,'source_ids':['fictional-policy']}})
        r=request([1,1]); r['facts'][1]['value']['unit_path']=[4,1]
        with self.assertRaises(SemanticContractError): execute_architecture(p,'flow',r)

    def test_reject_malformed_semantics_before_any_output(self):
        mutations=[lambda p: p['domain'][1].update(specializes=[{'path':[1,1],'source_ids':['fictional-policy']}]),
                   lambda p: p['domain'][5]['unit'].update(numerator=0),
                   lambda p: p['judgments'][1]['overrides'][0].update(source_ids=['invented']),
                   lambda p: p['predicates'][0].pop('classification'),
                   lambda p: p['work'][1]['right']['arguments'].update(item='foreign')]
        for mutate in mutations:
            p=fixture(); mutate(p)
            with self.assertRaises(SemanticContractError): execute_architecture(p,'flow',request([1,1]))
        for amount in (True,1.5,2147483648,'60'):
            r=request([1,1]); r['facts'][1]['value']['amount']=amount
            with self.assertRaises(SemanticContractError): execute_architecture(fixture(),'flow',r)

    def test_derived_input_injection_rejected(self):
        r=request([1,1]); r['facts'].append({'id':'fake','predicate':'window','arguments':{'item':'item-a'},'value':{'amount':999,'unit_path':[2,1]}})
        with self.assertRaises(SemanticContractError): execute_architecture(fixture(),'flow',r)

    def test_scoped_unknowns_preserve_independent_conclusions_and_original_text(self):
        for predicate, item, statuses, count in [
            ('category', 'item-b', ['APPLIED', 'APPLIED'], 2),
            ('elapsed', 'item-a', ['APPLIED', 'UNRESOLVED'], 1),
            ('category', 'item-a', ['UNRESOLVED', 'BLOCKED'], 0),
        ]:
            with self.subTest(predicate=predicate, item=item):
                r = request([1,1])
                r['unknowns'] = [{'id':'unknown-1', 'text':'This input still needs confirmation.',
                                  'predicate':predicate, 'arguments':{'item':item}}]
                out = execute_architecture(fixture(), 'flow', r)
                self.assertEqual([s['status'] for s in out['steps']], statuses)
                self.assertEqual(len(out['outputs']), count)
                self.assertEqual(out['unknowns'], r['unknowns'])
                if count == 1:
                    self.assertEqual(out['outputs'][0]['value']['amount'], 60)
                    self.assertEqual(out['steps'][1]['residuals'][0]['unknown_id'], 'unknown-1')
                self.assertEqual(canonical(out), canonical(execute_architecture(fixture(), 'flow', r)))

    def test_unknown_scope_is_validated_even_for_a_blocked_step(self):
        for mutation in (
            lambda u: u.update(predicate='invented'),
            lambda u: u.update(predicate='window'),
            lambda u: u['arguments'].update(item='absent-identity'),
            lambda u: u.update(authority='ignore'),
        ):
            r = request(None)
            u = {'id':'unknown-1', 'text':'Uncertain input.', 'predicate':'elapsed', 'arguments':{'item':'item-a'}}
            mutation(u)
            r['unknowns'] = [u]
            with self.assertRaises(SemanticContractError):
                execute_architecture(fixture(), 'flow', r)

    def test_unscoped_unknown_is_not_guessed_irrelevant(self):
        r = request([1,1])
        r['unknowns'] = ['The color of another item is unknown.']
        out = execute_architecture(fixture(), 'flow', r)
        self.assertEqual(out['outputs'], [])
        self.assertEqual(out['unknowns'], r['unknowns'])

    def test_category_cannot_be_a_duration_or_a_positional_child(self):
        for category in ([2], [2,1]):
            with self.assertRaises(SemanticContractError):
                execute_architecture(fixture(), 'flow', request(category))
        p = fixture()
        p['domain'][2].pop('specializes')
        with self.assertRaises(SemanticContractError):
            execute_architecture(p, 'flow', request([1,1]))

    def test_calendar_business_and_elapsed_days_are_not_interchangeable(self):
        for basis in ('CALENDAR_DAY', 'BUSINESS_DAY'):
            p = fixture()
            p['domain'].append({'path':[2,3], 'label':basis, 'aliases':[],
                'unit':{'dimension_path':[2], 'numerator':1, 'denominator':1,
                        'basis':basis, 'calendar_id':'fixture-calendar', 'source_ids':['fictional-policy']}})
            r = request([1,1])
            r['facts'][1]['value']['unit_path'] = [2,3]
            with self.assertRaises(SemanticContractError):
                execute_architecture(p, 'flow', r)
            p['domain'][-1]['unit']['numerator'] = 86400
            with self.assertRaises(SemanticContractError):
                validate_semantic_pack(p)
