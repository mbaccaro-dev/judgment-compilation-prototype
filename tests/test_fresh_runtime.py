"""Tests package behavior."""
from copy import deepcopy
from pathlib import Path
import re
import pytest
from judgment_compilation.kernel import SemanticRuntime, Rejected, canonical, digest, notation, from_notation
from judgment_compilation.nist import build_pack, example_request

@pytest.fixture(scope='module')
def runtime():
    pack = build_pack()
    return SemanticRuntime(pack, digest(pack))

def raw(request=None):
    return canonical(example_request() if request is None else request).decode()

def test_real_warrant_dag_and_scenario_identity(runtime):
    result = runtime.execute(raw())
    assert [e['id'] for e in result['scenario']['entities']] == ['org-a', 'org-b', 'person-a', 'account-a']
    assert len(result['interpretation_trace']) == 4
    good = next(e for e in result['semantic_execution'] if e['binding']['business'] == 'org-a')
    assert good['result']['status'] == 'COMPLETE'
    assert len(good['result']['outputs']) == 4
    combined = good['result']['outputs'][-1]
    assert set(combined['support']) == {o['id'] for o in good['result']['outputs'][:-1]}
    assert any(c['type'] == 'DETERMINISTIC_DERIVATION' and 'account-management' in c['text'] for c in result['claims'])
    assert [c['text'] for c in result['claims'] if c['id'].startswith('unknown:')] == example_request()['unknowns']
    assert result['compliance_verdict'] is result['responsibility_determination'] is None
    assert result['external_effects'] == []
    assert all(e['from'] in {c['id'] for c in result['claims']} for e in result['support_graph'])

def test_no_legacy_population_dependency(runtime):
    import judgment_compilation.nist as adapter
    import judgment_compilation.kernel as kernel
    for module in (adapter, kernel):
        source = Path(module.__file__).read_text()
        assert 'data/semantic' not in source
        assert 'population_records' not in source
    assert re.search(r'\bNIST\b|AC-2|PS-4', Path(kernel.__file__).read_text()) is None
    assert all('judgment_binding' not in t for t in runtime.execute(raw())['interpretation_trace'])

def test_unknown_scope_and_unparsed_statement_cannot_disappear(runtime):
    for field in ('unknowns', 'statements'):
        request = example_request()
        request[field].append('It is unknown whether employment actually ended.')
        result = runtime.execute(raw(request))
        assert result['interpretation_trace'] == []
        assert any(c['text'] == request[field][-1] and c['type'] == 'UNRESOLVED' for c in result['claims'])

def test_conflicting_access_blocks_all_relevance_warrants(runtime):
    request = example_request()
    request['statements'].append("Employee A no longer has access through Employee A's administrator account.")
    result = runtime.execute(raw(request))
    assert result['interpretation_trace'] == []
    assert 'CONFLICTING_FACTS' in str(result['semantic_execution'])

@pytest.mark.parametrize('field', ['request_id', 'scenario_id'])
def test_egress_replay_binding(runtime, field):
    proposal = runtime.egress_proposal(raw())
    request = example_request(); request[field] += '-other'
    with pytest.raises(Rejected): runtime.admit_egress(raw(request), proposal)

@pytest.mark.parametrize('mutation', ['claim_text', 'drop_unknown', 'edge', 'quote', 'page', 'span', 'locator', 'digest', 'authority', 'invent'])
def test_egress_mutations_fail_closed(runtime, mutation):
    proposal = runtime.egress_proposal(raw())
    if mutation == 'claim_text': proposal['segments'][0]['text'] += ' Compliant.'
    elif mutation == 'drop_unknown': proposal['segments'] = [s for s in proposal['segments'] if s['id'] != 'unknown:0']
    elif mutation == 'edge': proposal['support_graph'][0]['from'] = 'entity:org-b'
    elif mutation == 'authority': proposal['binding']['authority_ceiling']['responsibility_assignment'] = True
    elif mutation == 'invent': proposal['segments'].append({'id': 'new', 'type': 'SOURCE_BOUND', 'text': 'Revoke access now.'})
    else:
        source = proposal['provenance']['AC-2(l)']
        if mutation == 'quote': source['quote'] += ' Forged.'
        elif mutation == 'page': source['physical_pdf_page_one_based'] += 1
        elif mutation == 'span': source['character_span']['start'] += 1
        elif mutation == 'locator': source['structural_oscal_locator'] += '/forged'
        elif mutation == 'digest': source['source_file']['sha256'] = '0' * 64
    with pytest.raises(Rejected): runtime.admit_egress(raw(), proposal)

def test_ingress_invention_unknown_removal_and_identity_merge(runtime):
    proposal = runtime.parse(raw()); proposal['request']['unknowns'] = []
    with pytest.raises(Rejected): runtime.admit_ingress(raw(), proposal)
    proposal = runtime.parse(raw()); proposal['facts'][0]['bindings']['business'] = 'org-b'
    with pytest.raises(Rejected): runtime.admit_ingress(raw(), proposal)
    request = example_request(); request['entities'][1]['id'] = 'org-a'
    with pytest.raises(Rejected): runtime.execute(raw(request))
    request = example_request(); request['authority'] = 'owner'
    with pytest.raises(Rejected): runtime.execute(raw(request))

def test_alias_ambiguity_and_new_coordinate_roundtrip(runtime):
    request = example_request(); request['question'] = 'Resolve access.'
    result = runtime.execute(raw(request))
    assert len(result['resolutions']) == 2
    assert any(c.get('reason') == 'AMBIGUOUS' for c in result['claims'])
    request['question'] = 'Resolve Account Management.'
    result = runtime.execute(raw(request))
    resolved = result['resolutions'][0]
    c = resolved['coordinate']
    assert c == {'Gs': [0, *resolved['path'][:-1]], 'L': resolved['path'][-1], 'I': 0}
    assert from_notation(notation(c)) == c
    with pytest.raises(Rejected): notation({'Gs': [1], 'L': 0, 'I': 0})

def test_determinism_required_uncertainty_and_cancellation(runtime):
    assert canonical(runtime.execute(raw())) == canonical(runtime.execute(raw()))
    ids = [c['id'] for c in runtime.execute(raw())['claims']]
    proposal = runtime.egress_proposal(raw(), ids[::-1])
    assert runtime.admit_egress(raw(), proposal)['status'] == 'DETERMINISTIC_RESULT_EMITTED'
    with pytest.raises(Rejected): runtime.execute(raw(), cancelled=True)
    with pytest.raises(Rejected): runtime.admit_egress(raw(), proposal, cancelled=True)

def test_modified_pack_rejected_by_independent_pin(runtime):
    p = runtime.pack; p['sources']['PS-4(a)']['quote'] += ' altered'
    with pytest.raises(Rejected): SemanticRuntime(p, digest(runtime.pack))
    with pytest.raises(Rejected): SemanticRuntime(p, digest(p))


@pytest.mark.parametrize('variant', ['missing', 'unknown', 'known_and_unknown'])
def test_partial_privilege_unknown_preserves_independent_findings(runtime, variant):
    request = example_request()
    positive = request['statements'].pop(2)
    unknown = "It is unknown whether Employee A's administrator account has administrator privileges."
    if variant != 'missing':
        request['statements'].append(unknown)
    if variant == 'known_and_unknown':
        request['statements'].append(positive)
    result = runtime.execute(raw(request))
    assert {t['judgment_id'] for t in result['interpretation_trace']} == {'account_management_relevance', 'personnel_termination_relevance'}
    assert set(result['provenance']) == {'AC-2(l)', 'PS-4(a)', 'PS-4(b)'}
    good = next(e for e in result['semantic_execution'] if e['binding']['business'] == 'org-a')
    steps = {s['step_id']: s for s in good['result']['steps']}
    assert steps['least_privilege_relevance']['status'] == 'UNRESOLVED'
    assert steps['termination_admin_access_issue']['status'] == 'BLOCKED'
    assert {o['arguments']['business'] for o in good['result']['outputs']} == {'org-a'}
    residual = steps['least_privilege_relevance']['residuals'][0]
    assert residual['predicate'] == 'administrator_account'
    assert residual['arguments'] == {'account': 'account-a'}
    if variant != 'missing':
        assert residual['reason'] == 'UNKNOWN_EVIDENCE'
        claim = next(c for c in result['claims'] if c['text'] == unknown)
        assert claim['type'] == 'UNRESOLVED' and claim['value'] is None
        assert claim['id'] in residual['fact_ids']
        if variant == 'known_and_unknown':
            assert len(residual['fact_ids']) == 2
        proposal = runtime.egress_proposal(raw(request))
        assert unknown in runtime.admit_egress(raw(request), proposal)['text']
        proposal['segments'] = [s for s in proposal['segments'] if s['id'] != claim['id']]
        with pytest.raises(Rejected):
            runtime.admit_egress(raw(request), proposal)
    assert result['responsibility_determination'] is None
    assert result['external_effects'] == []
