"""Tests package behavior."""
from copy import deepcopy
import pytest
from judgment_compilation.kernel import SemanticRuntime, Rejected, canonical, digest
from judgment_compilation.operation_interfaces import operation_interfaces
from tests.test_semantic_values import fixture


def consumer_fixture():
    semantic = fixture()
    sources = {'fictional-policy': {'quote': 'Fictional test policy: merchandise 30 fixed elapsed days; electronics explicitly excepted at 60.'}}
    semantic['sources'][0]['sha256'] = digest(sources['fictional-policy'])
    interpretations = {j['id']: {'text': '{target}: selected fixed elapsed-day window = {value}.',
                       'source_selection_reason': {'fictional-policy': 'Exact fictional category rule and explicit exception.'}}
                       for j in semantic['judgments']}
    pack = {'id':'fictional-consumer-conformance','version':'1','semantic_pack':semantic,
            'entity_kinds':['purchase'], 'sources':sources, 'interpretations':interpretations,
            'work_interpretations':{'compare':{'text':'{target}: time-window condition = {value}; other conditions and permission to issue a refund remain unestablished.',
                'source_selection_reason':{'fictional-policy':'Compare supplied duration against the explicitly selected policy window.'}}},
            'fact_templates':[
                {'text':'{item} is electronics.','roles':{'item':'purchase'},'predicate':'category','value':[1,1]},
                {'text':'{item} has elapsed 45 fixed days.','roles':{'item':'purchase'},'predicate':'elapsed','value':{'amount':45,'unit_path':[2,1]}}],
            'unknown_scopes':[], 'questions':{'Compare window.':{'kind':'assess','architecture':'flow','roles':{'target':'purchase'}}},
            'required_residuals':[{'text':'Other refund conditions and action authority are unresolved.','reason':'SCOPE_LIMIT'}],
            'authority_ceiling':{k:False for k in ('compliance_determination','responsibility_assignment','external_effects','explicit_selection_confirmed','production_ready')}}
    request = {'request_id':'request-a','scenario_id':'scenario-a',
               'entities':[{'id':'item-a','alias':'Purchase A','kind':'purchase'}],
               'statements':['Purchase A is electronics.','Purchase A has elapsed 45 fixed days.'],
               'unknowns':[],'question':'Compare window.'}
    return pack, canonical(request).decode()


def test_interfaces_bind_actual_producers_ports_and_scopes():
    interfaces = operation_interfaces(fixture())
    assert interfaces['select']['judgment_ids'] == ['electronics','general']
    assert interfaces['select']['inputs'][0]['value_type'] == 'DOMAIN'
    assert interfaces['select']['output']['value_type'] == 'QUANTITY'
    assert interfaces['compare']['producer'].endswith('COMPARE_VALUES')
    assert {p['predicate'] for p in interfaces['compare']['inputs']} == {'elapsed','window'}
    assert interfaces['compare']['output']['predicate'] == 'within_window'
    assert interfaces['compare']['conclusion_scope'] == 'COMPARISON_CONDITION_ONLY'
    p=fixture(); p['judgments'].reverse(); p['work'].reverse()
    assert operation_interfaces(p) == interfaces


def test_consumer_runs_selection_then_comparison_and_binds_egress():
    pack, raw = consumer_fixture()
    runtime = SemanticRuntime(pack,digest(pack))
    result = runtime.execute(raw)
    execution = result['semantic_execution'][0]
    assert execution['result']['status'] == 'COMPLETE'
    assert execution['result']['outputs'][0]['value']['amount'] == 60
    assert execution['result']['outputs'][1]['value'] is True
    assert execution['operation_interfaces'] == operation_interfaces(pack['semantic_pack'])
    assert [t['judgment_id'] for t in result['interpretation_trace']] == ['electronics',None]
    proposal = runtime.egress_proposal(raw)
    assert 'time-window condition = true' in runtime.admit_egress(raw,proposal)['text']
    proposal['segments'] = [s for s in proposal['segments'] if s['type'] != 'UNRESOLVED']
    with pytest.raises(Rejected): runtime.admit_egress(raw,proposal)
    proposal=runtime.egress_proposal(raw)
    proposal['segments'][-1]['text']='Refund approved.'
    with pytest.raises(Rejected): runtime.admit_egress(raw,proposal)
    assert canonical(result) == canonical(runtime.execute(raw))


def test_missing_executable_interpretation_binding_fails_at_admission():
    pack, raw = consumer_fixture()
    pack['work_interpretations'].clear()
    with pytest.raises(Rejected,match='work interpretation'):
        SemanticRuntime(pack,digest(pack))
