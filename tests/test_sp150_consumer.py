from copy import deepcopy
import pytest
from judgment_compilation.document_programs import ReviewedDocumentPrograms
from judgment_compilation.nist import build_pack

PACKAGE = 'nist-sp-800-150-tlp-table-3-3'
AMBER = 'AMBER_RECIPIENT_OWN_ORGANIZATION_OR_NEED_TO_KNOW_CLIENTS_CUSTOMERS_TO_PROTECT_OR_PREVENT_FURTHER_HARM'

@pytest.fixture(scope='module')
def programs():
    return ReviewedDocumentPrograms(build_pack()['semantic_pack'])

def request(color='AMBER', limits='NOT_APPLICABLE'):
    return {'request_id': 'tlp-request', 'scenario_id': 'tlp-scenario',
            'entities': {'org-a': 'organization'},
            'bindings': {'classify-tlp': {'subject': ['org-a']}},
            'facts': [
                {'id': 'color', 'predicate': 'tlp_color', 'arguments': {'subject': 'org-a'}, 'value': color},
                {'id': 'limits', 'predicate': 'amber_additional_limits', 'arguments': {'subject': 'org-a'}, 'value': limits},
            ]}

def execution(programs, payload):
    return programs.execute(PACKAGE, payload)['execution']['execution']['execution']

def test_all_frozen_tlp_dispositions_and_complete_source_fragments(programs):
    expected = {'AMBER': AMBER, 'GREEN': 'GREEN_SECTOR_COMMUNITY',
                'RED': 'RED_RESTRICTED', 'WHITE': 'WHITE_NO_RESTRICTION_SUBJECT_TO_RULES'}
    for color, value in expected.items():
        result = execution(programs, request(color))
        assert result['status'] == 'COMPLETE'
        assert [output['value'] for output in result['outputs']] == [value]
        assert result['compliance_verdict'] is None
        assert result['responsibility_determination'] is None
        assert result['external_effects'] == []
    citations = programs.inspect(PACKAGE)['source_citations']
    assert len(citations) == 3
    assert all(item['semantic_quote_sha256'] == '7ddcfc5ffd0eb51797b87e524557de407deef2bb3ebd95e59b91ac26d90e1d0c' for item in citations)
    assert all(item['citation']['provenance']['physical_pdf_page_number'] == 23 for item in citations)
    assert all(item['citation']['total_occurrences'] == item['citation']['returned_occurrences'] for item in citations)

def test_extra_limits_missing_conflicting_and_foreign_subjects_stay_unresolved(programs):
    cases = [request(limits='SOURCE_LIMITS_SUPPLIED')]
    missing = request(); missing['facts'].pop(); cases.append(missing)
    unknown = request(); unknown['facts'][0]['value'] = None; cases.append(unknown)
    conflict = request(); conflict['facts'].append({**deepcopy(conflict['facts'][0]), 'id': 'other-color', 'value': 'RED'}); cases.append(conflict)
    foreign = request(); foreign['entities']['org-b'] = 'organization'; foreign['facts'][1]['arguments']['subject'] = 'org-b'; cases.append(foreign)
    for payload in cases:
        result = execution(programs, payload)
        assert result['status'] == 'UNRESOLVED'
        assert result['outputs'] == []
        assert result['external_effects'] == []
    residuals = execution(programs, cases[0])['steps'][0]['residuals']
    assert any(item.get('reason') == 'FINITE_ENUM_UNKNOWN_ENUM_VALUE' and item.get('value') == 'SOURCE_LIMITS_SUPPLIED' for item in residuals)
