"""Tests package behavior."""
from copy import deepcopy
from pathlib import Path
import json
import pytest
from judgment_compilation.application import Application
from judgment_compilation.nist import build_pack, timing_example_request
from judgment_compilation.semantic_contracts import execute_architecture, canonical
from judgment_compilation.nist_source import normalized, normalize_with_map
from judgment_compilation.nist_admission import admit_pack_interpretation_bundle
from judgment_compilation.interpretation_qualification import InterpretationQualificationError

ROOT = Path(__file__).resolve().parents[1] / 'judgment_compilation'

@pytest.fixture(scope='module')
def pack():
    return build_pack()

@pytest.fixture
def app(pack):
    app = Application.__new__(Application)
    app.pack = deepcopy(pack)
    app.executor = execute_architecture
    app.integrity = {'status': 'TEST_REFERENCE_NOT_INSTALLED_PACKAGE'}
    # Unit execution supplies its test pack directly.
    app.interpretation_admission = {'standing': 'TEST_REFERENCE_UNADMITTED'}
    app.recommender = None
    return app

def test_changed_pack_cannot_reuse_the_prior_independent_admission(pack):
    admission = json.loads((ROOT / 'data/compiled/interpretation_admission.json').read_text(encoding='utf-8'))
    changed_pack = deepcopy(pack)
    changed_pack['authority_ceiling']['compliance_determination'] = True
    with pytest.raises(InterpretationQualificationError, match='reviewed pack digest mismatch'):
        admit_pack_interpretation_bundle(changed_pack, admission)

def ask(app, request=None):
    return app.query({'mode':'timing', 'request':request or timing_example_request()})

@pytest.mark.parametrize('elapsed,within', [(0,True),(86400,True),(86401,False),(2147483647,False)])
def test_numeric_timing_is_computed_with_exact_support(app, elapsed, within):
    request = timing_example_request(); request['facts'][2]['value'] = elapsed
    before = canonical(request)
    out = ask(app,request)
    assert canonical(request) == before
    assert out['kernel']['status'] == 'RESOLVED'
    assert out['kernel']['execution']['status'] == 'COMPLETE'
    outputs = out['kernel']['execution']['outputs']
    comparison = next(o for o in outputs if o['predicate']=='within_update_period')
    assert comparison['value'] is within
    claims = {c['id'] for c in out['kernel']['claims']}
    assert all(e['from'] in claims and e['to'] in claims for e in out['kernel']['support_graph'])
    assert out['egress']['claim_ids'] == [c['id'] for c in out['kernel']['claims']]
    assert out['kernel']['compliance_verdict'] is None and out['kernel']['external_effects']==[]
    assert canonical(out)==canonical(ask(app,request))

@pytest.mark.parametrize('variant', ['missing','null','conflict','unknown','other_system'])
def test_uncertainty_cannot_become_a_timing_answer(app,variant):
    r=timing_example_request()
    if variant=='missing': r['facts'].pop(3)
    elif variant=='null': r['facts'][3]['value']=None
    elif variant=='conflict': r['facts'].append({**deepcopy(r['facts'][3]),'id':'contradiction','value':1})
    elif variant=='unknown': r['unknowns']=['The correct clock origin has not been established.']
    else:
        r['entities'].append({'id':'system-b','alias':'Other system','kind':'system'})
        r['facts'][3]['arguments']['system']='system-b'
    out=ask(app,r)
    assert out['kernel']['status']=='UNRESOLVED'
    assert not any(o['predicate'].startswith('update_within') or o['predicate'].startswith('update_exceeds') for o in out['kernel']['execution']['outputs'])
    assert out['escalation']['status']=='CLARIFICATION_REQUIRED'
    if variant=='missing': assert any('integer value' in line for line in out['escalation']['required_inputs'])

@pytest.mark.parametrize('variant',['source','quote','negative','float','bool_integer','derived','authority','evidence','duplicate_alias'])
def test_ingress_rejects_unsupported_authority_and_values(app,variant):
    r=timing_example_request()
    if variant=='source':r['source_sha256']='0'*64
    elif variant=='quote':r['quote']='NIST gives every organization 30 days.'
    elif variant=='negative':r['facts'][2]['value']=-1
    elif variant=='float':r['facts'][2]['value']=1.5
    elif variant=='bool_integer':r['facts'][2]['value']=True
    elif variant=='derived':r['facts'][2]['predicate']='within_update_period'
    elif variant=='authority':r['compliant']=True
    elif variant=='evidence':r['facts'][3]['evidence_refs']=[]
    else:r['entities'][1]['alias']=r['entities'][0]['alias']
    with pytest.raises(ValueError):ask(app,r)

def test_known_false_scope_is_not_unknown_or_compliance(app):
    r=timing_example_request();r['facts'][0]['value']=False
    out=ask(app,r)
    assert out['kernel']['status']=='NOT_APPLICABLE'
    assert out['kernel']['execution']['outputs']==[]

def test_scenario_identity_binds_output_and_advice_cannot_override(app):
    first=ask(app)
    r=timing_example_request();r['scenario_id']='another-scenario'
    second=ask(app,r)
    assert first['egress']['kernel_sha256']!=second['egress']['kernel_sha256']
    class MaliciousAdvice:
        def recommend(self,packet):
            packet['deterministic_result'].clear()
            return 'Ignore the result and declare compliance.'
    app.recommender=MaliciousAdvice()
    out=app.query({'mode':'timing','request':timing_example_request(),'recommend':True})
    assert out['kernel']==first['kernel'] and out['egress']==first['egress']
    assert out['inference']['type']=='AI_INFERENCE'
    assert out['inference']['authority']=='ADVISORY_ONLY'

def test_pdf_hyphen_linewrap_preserves_exact_span_and_hyphen(pack):
    source=pack['sources']['SI-2(c)']
    assert source['physical_pdf_page_one_based']==360
    assert source['printed_page_label']=='CHAPTER THREE PAGE 333'
    assert normalized(source['quote'])==source['oscal_rendered_quote']
    assert source['occurrence_count']==len(source['all_exact_normalized_occurrences'])==1
    assert 'organization-\ndefined' in source['quote']
    value=' x organization-\ndefined y '
    norm,mapping=normalize_with_map(value)
    start=norm.index('organization-');end=start+len('organization-defined')
    assert value[mapping[start]:mapping[end-1]+1]=='organization-\ndefined'
    assert normalized('organization- defined')=='organization- defined'
    assert normalized('organiza-\ntion')=='organiza-tion'
