from copy import deepcopy
from pathlib import Path
import shutil

import pytest

from judgment_compilation.nist_requirements import (
    CEILING, REQUEST_SCHEMA, Requirements, RequirementError,
)
from judgment_compilation.nist_catalog import SOURCE_RELATIVE_PATH, SOURCE_SHA256


@pytest.fixture(scope='module')
def requirements():
    return Requirements()


def inspect(requirements, statement_id='ps-4_smt.a'):
    return requirements.ask({'schema': REQUEST_SCHEMA, 'operation': 'inspect', 'statement_id': statement_id})


def request_for(requirements, statement_id='ps-4_smt.a'):
    template = inspect(requirements, statement_id)['template']
    scope = {'organization_id': 'org-a', 'system_id': 'system-a'}
    parameters = []
    for definition in template['parameters']:
        parameters.append({'parameter_id': definition['parameter_id'], 'control_id': template['control_id'],
                           'source_sha256': SOURCE_SHA256, 'scope': deepcopy(scope),
                           'values': [definition['choices'][0]] if definition['kind'] == 'SELECTION' else ['24 hours'],
                           'evidence_refs': ['caller-policy:termination:version-1']})
    return {'schema': REQUEST_SCHEMA, 'operation': 'instantiate', 'statement_id': statement_id,
            'source_sha256': SOURCE_SHA256, 'template_sha256': template['template_sha256'],
            'scope': scope, 'parameters': parameters}


def tokens(blocks):
    for block in blocks:
        yield from block.get('tokens', [])
        yield from tokens(block.get('blocks', []))


def test_ps4_preserves_parent_condition_and_distinguishes_caller_values(requirements):
    result = requirements.ask(request_for(requirements))
    assert result['status'] == 'INSTANTIATED'
    instance = result['instance']
    parent = instance['ancestor_context'][0]
    assert parent['source']['xml_id'] == 'ps-4_smt'
    assert parent['selected_child_position'] > parent['paragraphs'][0]['source_child_position']
    assert ''.join(t['text'] for t in parent['paragraphs'][0]['tokens']) == 'Upon termination of individual employment:'
    own = list(tokens(instance['blocks']))
    assert own[0] == {'kind': 'SOURCE_TEXT', 'text': 'Disable system access within '}
    insertion = next(t for t in own if t['kind'] == 'PARAMETER')
    assert insertion['parameter_id'] == 'ps-04_odp.01'
    assert insertion['binding']['type'] == 'CALLER_SUPPLIED_UNVERIFIED'
    assert insertion['binding']['values'] == ['24 hours']
    assert '24 hours' not in instance['blocks'][0]['source']['serialized_xml']
    assert result['applicability'] is result['satisfaction'] is result['compliance_verdict'] is None
    assert result['external_effects'] == []
    assert result['ceiling'] == CEILING
    assert instance['source_sha256'] == SOURCE_SHA256
    assert instance['request_sha256'] == result['request_sha256']


def test_source_identity_and_full_ps4_hierarchy_remain_bound(requirements):
    template = inspect(requirements, 'ps-4_smt')['template']
    assert template['source']['xml_locator'].startswith("/*[local-name()='catalog'][1]")
    assert template['source']['source_sha256'] == SOURCE_SHA256
    assert template['blocks'][0]['kind'] == 'PARAGRAPH'
    children = [b['source']['xml_id'] for b in template['blocks'] if b['kind'] == 'ITEM']
    assert children[:2] == ['ps-4_smt.a', 'ps-4_smt.b']
    assert template['pdf_provenance'] is None
    assert template['grammar_status'] == 'SUPPORTED'


def test_explicit_one_or_more_choice_instantiation(requirements):
    request = request_for(requirements, 'ac-1_smt.a')
    template = inspect(requirements, 'ac-1_smt.a')['template']
    selected = next(p for p in template['parameters'] if p['parameter_id'] == 'ac-01_odp.03')
    assert selected['cardinality'] == 'one-or-more'
    assert selected['source_cardinality'] == 'one-or-more'
    assert selected['cardinality_basis'] == {'kind': 'EXPLICIT_SOURCE_ATTRIBUTE'}
    assert selected['choices'] == ['organization-level', 'mission/business process-level', 'system-level']
    binding = next(p for p in request['parameters'] if p['parameter_id'] == selected['parameter_id'])
    binding['values'] = ['organization-level', 'system-level']
    assert requirements.ask(request)['status'] == 'INSTANTIATED'
    binding['values'] = ['enterprise-level']
    result = requirements.ask(request)
    assert result['status'] == 'UNRESOLVED'
    assert result['instance'] is None
    assert any(r['reason'] == 'INVALID_LITERAL_SELECTION' for r in result['residuals'])


def test_ac2_2_retains_choices_deadline_and_versioned_single_choice_default(requirements):
    request = request_for(requirements, 'ac-2.2_smt')
    result = requirements.ask(request)
    assert result['status'] == 'INSTANTIATED'
    definitions = {p['parameter_id']: p for p in result['template']['parameters']}
    assert definitions['ac-02.02_odp.01']['choices'] == ['remove', 'disable']
    selection = definitions['ac-02.02_odp.01']
    assert selection['cardinality'] == 'one'
    assert selection['source_cardinality'] is None
    assert selection['cardinality_basis']['kind'] == 'VERSIONED_SCHEMA_DEFAULT'
    assert selection['cardinality_basis']['oscal_version'] == '1.2.2'
    assert selection['cardinality_basis']['reference_url'].endswith('/v1.2.2/catalog/xml-reference/')
    assert result['template']['source_metadata']['catalog_version'] == '5.2.0'
    assert result['template']['source_metadata']['oscal_version'] == '1.2.2'
    assert definitions['ac-02.02_odp.02']['label'] == 'time period'
    assert result['residuals'] == []
    binding = next(p for p in request['parameters'] if p['parameter_id'] == 'ac-02.02_odp.01')
    binding['values'] = ['remove', 'disable']
    invalid = requirements.ask(request)
    assert invalid['instance'] is None
    assert any(r['reason'] == 'SELECTION_REQUIRES_EXACTLY_ONE_VALUE' for r in invalid['residuals'])
    text = ''.join(t.get('text', '') for t in tokens(result['template']['blocks']))
    assert text == 'Automatically  temporary and emergency accounts after .'


@pytest.mark.parametrize('mutation,reason', [
    ('missing', 'MISSING_PARAMETER'),
    ('empty', 'MISSING_PARAMETER'),
    ('conflict', 'CONFLICTING_OR_DUPLICATE_PARAMETER_BINDINGS'),
    ('multiple', 'OPAQUE_ASSIGNMENT_REQUIRES_ONE_EXPLICIT_VALUE'),
    ('evidence', 'MISSING_BINDING_EVIDENCE_REFERENCE'),
])
def test_incomplete_or_conflicting_bindings_never_create_instance(requirements, mutation, reason):
    request = request_for(requirements)
    if mutation == 'missing':
        request['parameters'] = []
    elif mutation == 'empty':
        request['parameters'][0]['values'] = []
    elif mutation == 'conflict':
        other = deepcopy(request['parameters'][0])
        other['values'] = ['48 hours']
        request['parameters'].append(other)
    elif mutation == 'multiple':
        request['parameters'][0]['values'] = ['24 hours', '48 hours']
    else:
        request['parameters'][0]['evidence_refs'] = []
    result = requirements.ask(request)
    assert result['status'] == 'UNRESOLVED' and result['instance'] is None
    assert any(r['reason'] == reason for r in result['residuals'])


@pytest.mark.parametrize('mutation', ['scope', 'control', 'parameter', 'binding_source', 'source', 'template', 'extra', 'scalar', 'duplicate_values'])
def test_foreign_tampered_or_malformed_bindings_rejected(requirements, mutation):
    request = request_for(requirements)
    row = request['parameters'][0]
    if mutation == 'scope':
        row['scope']['organization_id'] = 'org-b'
    elif mutation == 'control':
        row['control_id'] = 'ac-2.2'
    elif mutation == 'parameter':
        row['parameter_id'] = 'ac-02.02_odp.02'
    elif mutation == 'binding_source':
        row['source_sha256'] = '0' * 64
    elif mutation == 'source':
        request['source_sha256'] = '0' * 64
    elif mutation == 'template':
        request['template_sha256'] = '0' * 64
    elif mutation == 'extra':
        request['applicable'] = True
    elif mutation == 'scalar':
        row['values'] = [True]
    else:
        row['values'] = ['24 hours', '24 hours']
    with pytest.raises(RequirementError):
        requirements.ask(request)


def test_results_are_detached_and_request_scope_changes_instance_identity(requirements):
    request = request_for(requirements)
    first = requirements.ask(request)
    second = requirements.ask(deepcopy(request))
    assert first == second
    first['template']['ancestor_context'] = []
    first['instance']['blocks'].clear()
    assert requirements.ask(request) == second
    request['scope']['system_id'] = 'system-b'
    request['parameters'][0]['scope']['system_id'] = 'system-b'
    changed = requirements.ask(request)
    assert changed['instance']['instance_sha256'] != second['instance']['instance_sha256']
    assert changed['template']['template_sha256'] == second['template']['template_sha256']


def test_cached_source_is_rechecked_before_use(tmp_path):
    source = Path(__file__).resolve().parents[1] / SOURCE_RELATIVE_PATH
    target = tmp_path / SOURCE_RELATIVE_PATH
    target.parent.mkdir(parents=True)
    shutil.copyfile(source, target)
    reader = Requirements(tmp_path)
    assert inspect(reader)['status'] == 'INSPECTED'
    target.write_bytes(target.read_bytes() + b' ')
    with pytest.raises(RequirementError, match='checksum'):
        inspect(reader)


def test_lookup_never_grants_applicability_and_guidance_is_not_a_statement(requirements):
    assert inspect(requirements)['instance'] is None
    result = inspect(requirements, 'ps-4_gdn')
    assert result['status'] == 'NOT_FOUND' and result['instance'] is None
    assert result['applicability'] is None
    with pytest.raises(RequirementError):
        requirements.ask({'schema': REQUEST_SCHEMA, 'operation': 'inspect', 'statement_id': 'ps-4_smt', 'parameters': []})


def test_summary_accounts_for_unsupported_grammar_separately(requirements):
    summary = requirements.summary()
    assert summary['statement_templates'] == summary['supported_templates'] + summary['unsupported_templates']
    assert summary['supported_templates'] == 2138
    assert summary['unsupported_templates'] == 0
    assert summary['source_sha256'] == SOURCE_SHA256
    assert 'counts do not measure' in summary['coverage_ceiling']


def nested_request(requirements):
    template = inspect(requirements, 'ac-7_smt.b')['template']
    selection = next(p for p in template['parameters'] if p['parameter_id'] == 'ac-07_odp.03')
    choice = selection['choice_templates'][0]
    scope = {'organization_id': 'org-a', 'system_id': 'system-a'}
    def binding(pid, values):
        return {'parameter_id': pid, 'control_id': 'ac-7', 'source_sha256': SOURCE_SHA256,
                'scope': deepcopy(scope), 'values': values, 'evidence_refs': ['caller-policy:lockout:v1']}
    return {'schema': REQUEST_SCHEMA, 'operation': 'instantiate', 'statement_id': 'ac-7_smt.b',
            'source_sha256': SOURCE_SHA256, 'template_sha256': template['template_sha256'],
            'scope': scope, 'parameters': [binding('ac-07_odp.03', [{'choice_sha256': choice['choice_sha256']}]),
                                         binding('ac-07_odp.04', ['15 minutes'])]}


def test_nested_source_choice_keeps_graph_identity_scope_and_parent(requirements):
    request = nested_request(requirements)
    result = requirements.ask(request)
    assert result['status'] == 'INSTANTIATED'
    template, instance = result['template'], result['instance']
    assert template['root_parameter_ids'] == ['ac-07_odp.03']
    assert len(template['parameters']) == 4
    definition = next(p for p in template['parameters'] if p['parameter_id'] == 'ac-07_odp.03')
    assert definition['cardinality'] == 'one-or-more'
    assert definition['dependency_parameter_ids'] == ['ac-07_odp.04', 'ac-07_odp.05', 'ac-07_odp.06']
    assert instance['ancestor_context'][0]['source']['xml_id'] == 'ac-7_smt'
    parent_choice = next(t for t in tokens(instance['blocks']) if t['kind'] == 'PARAMETER')
    selected = parent_choice['binding']['selected_choices'][0]
    assert selected['parameter_id'] == 'ac-07_odp.03' and selected['control_id'] == 'ac-7'
    assert selected['source']['source_sha256'] == SOURCE_SHA256
    assert selected['source']['xml_locator'].endswith("/*[local-name()='choice'][1]")
    assert selected['tokens'][0] == {'kind': 'SOURCE_TEXT', 'text': 'lock the account or node for '}
    child = next(t for t in selected['tokens'] if t['kind'] == 'PARAMETER')
    assert child['parameter_id'] == 'ac-07_odp.04'
    assert child['binding']['values'] == ['15 minutes']
    assert child['binding']['scope'] == request['scope']
    assert '15 minutes' not in selected['source']['serialized_xml']
    assert {p['parameter_id'] for p in instance['parameter_bindings']} == {'ac-07_odp.03', 'ac-07_odp.04'}
    assert instance['selected_choices']['ac-07_odp.03'] == [selected]
    assert result['applicability'] is result['compliance_verdict'] is None


@pytest.mark.parametrize('mutation,reason', [
    ('forged', 'INVALID_SOURCE_CHOICE_REFERENCE'),
    ('foreign_definition', 'INVALID_SOURCE_CHOICE_REFERENCE'),
    ('rendered_string', 'INVALID_LITERAL_SELECTION'),
    ('missing_nested', 'MISSING_PARAMETER'),
    ('empty_nested', 'MISSING_PARAMETER'),
    ('duplicate_choice', 'DUPLICATE_SOURCE_CHOICE'),
])
def test_nested_selection_falsifiers(requirements, mutation, reason):
    request = nested_request(requirements)
    if mutation == 'forged':
        request['parameters'][0]['values'] = [{'choice_sha256': '0' * 64}]
    elif mutation == 'foreign_definition':
        foreign = inspect(requirements, 'ac-11_smt.a')['template']['parameters'][0]['choice_templates'][0]
        request['parameters'][0]['values'] = [{'choice_sha256': foreign['choice_sha256']}]
    elif mutation == 'rendered_string':
        request['parameters'][0]['values'] = ['lock the account or node for 15 minutes']
    elif mutation == 'missing_nested':
        request['parameters'].pop()
    elif mutation == 'empty_nested':
        request['parameters'][1]['values'] = []
    else:
        definition = inspect(requirements, 'ac-7_smt.b')['template']['parameters'][0]
        literal = definition['choices'][0]
        choice = next(c for c in definition['choice_templates']
                      if all(t['kind'] == 'SOURCE_TEXT' for t in c['tokens'])
                      and ''.join(t['text'] for t in c['tokens']) == literal)
        request['parameters'][0]['values'] = [literal, {'choice_sha256': choice['choice_sha256']}]
    result = requirements.ask(request)
    assert result['status'] == 'UNRESOLVED' and result['instance'] is None
    assert any(r['reason'] == reason for r in result['residuals'])


def test_nested_binding_wrong_scope_is_rejected(requirements):
    request = nested_request(requirements)
    request['parameters'][1]['scope']['system_id'] = 'foreign-system'
    with pytest.raises(RequirementError, match='foreign parameter scope'):
        requirements.ask(request)


def test_unselected_dependencies_not_required_and_literal_api_retained(requirements):
    request = nested_request(requirements)
    request['parameters'] = request['parameters'][:1]
    request['parameters'][0]['values'] = ['notify system administrator']
    result = requirements.ask(request)
    assert result['status'] == 'INSTANTIATED'
    assert len(result['instance']['parameter_bindings']) == 1
    assert result['instance']['selected_choices']['ac-07_odp.03'][0]['tokens'] == [
        {'kind': 'SOURCE_TEXT', 'text': 'notify system administrator'}]


def test_cyclic_source_parameter_reference_is_unsupported(tmp_path, monkeypatch):
    from hashlib import sha256
    import judgment_compilation.nist_requirements as module
    raw = (Path(__file__).resolve().parents[1] / SOURCE_RELATIVE_PATH).read_bytes()
    assert b'id-ref="ac-07_odp.04"' in raw
    raw = raw.replace(b'id-ref="ac-07_odp.04"', b'id-ref="ac-07_odp.03"')
    target = tmp_path / SOURCE_RELATIVE_PATH
    target.parent.mkdir(parents=True)
    target.write_bytes(raw)
    # Synthetic pinned-source fixture tests graph rejection, not authentic NIST provenance.
    monkeypatch.setattr(module, 'SOURCE_SHA256', sha256(raw).hexdigest())
    reader = Requirements(tmp_path)
    result = inspect(reader, 'ac-7_smt.b')
    assert result['template']['grammar_status'] == 'UNSUPPORTED'
    assert any(r['reason'] == 'CYCLIC_PARAMETER_REFERENCE' for r in result['residuals'])
    request = nested_request(reader)
    request['source_sha256'] = module.SOURCE_SHA256
    request['parameters'] = request['parameters'][:1]
    request['parameters'][0]['source_sha256'] = module.SOURCE_SHA256
    result = reader.ask(request)
    assert result['status'] == 'UNRESOLVED' and result['instance'] is None
    assert any(r['reason'] == 'CYCLIC_PARAMETER_REFERENCE' for r in result['residuals'])


def test_template_discovery_is_bounded_deterministic_and_exact_control(requirements):
    first = requirements.list_templates(limit=2)
    second = requirements.list_templates(offset=2, limit=2)
    assert first == requirements.list_templates(limit=2)
    assert first['total_templates'] == first['matched_templates'] == 2138
    assert len(first['templates']) == len(second['templates']) == 2
    assert {t['statement_id'] for t in first['templates']}.isdisjoint(t['statement_id'] for t in second['templates'])
    scoped = requirements.list_templates(control_id='ac-7')
    assert scoped['matched_templates'] > 0
    assert all(t['control_id'] == 'ac-7' for t in scoped['templates'])
    assert all('blocks' not in t and 'source' not in t for t in scoped['templates'])
    assert requirements.list_templates(control_id='nonexistent')['templates'] == []
    assert requirements.list_templates(offset=99999)['templates'] == []
    for kwargs in [{'limit': 0}, {'limit': 101}, {'limit': True}, {'offset': -1},
                   {'offset': False}, {'control_id': ''}, {'control_id': 1}]:
        with pytest.raises(RequirementError):
            requirements.list_templates(**kwargs)


@pytest.mark.parametrize('statement_id', [
    'ac-16_smt', 'ac-16_smt.c', 'au-12_smt', 'au-12_smt.a', 'au-12_smt.c',
    'ca-3.7_smt', 'ca-3.7_smt.a',
])
def test_internal_source_links_preserve_visible_text_and_exact_markup(requirements, statement_id):
    import xml.etree.ElementTree as ET
    template = inspect(requirements, statement_id)['template']
    assert template['grammar_status'] == 'SUPPORTED'
    def paragraphs(blocks):
        for block in blocks:
            if block['kind'] == 'PARAGRAPH':
                yield block
            yield from paragraphs(block.get('blocks', []))
    linked = [p for p in paragraphs(template['blocks']) if 'href=' in p['source']['serialized_xml']]
    assert linked
    for paragraph in linked:
        source = ET.fromstring(paragraph['source']['serialized_xml'])
        assert ''.join(t.get('text', '') for t in paragraph['tokens']) == ''.join(source.itertext())
        assert paragraph['source']['source_sha256'] == SOURCE_SHA256
    assert template['ceiling'] == CEILING


def test_linked_assignment_label_preserves_constraint_and_instantiates(requirements):
    result = requirements.ask(request_for(requirements, 'au-2_smt.c'))
    assert result['status'] == 'INSTANTIATED'
    definition = next(p for p in result['template']['parameters'] if p['parameter_id'] == 'au-2_prm_2')
    assert definition['label'] == ('organization-defined event types (subset of the event types defined in '
                                   'AU-2a.) along with the frequency of (or situation requiring) logging '
                                   'for each identified event type')
    assert 'href="#au-2_smt.a"' in definition['source']['serialized_xml']
    assert result['applicability'] is result['satisfaction'] is result['compliance_verdict'] is None


@pytest.mark.parametrize('markup,label', [
    ('<a href="#missing">visible</a>', False),
    ('<a href="https://example.invalid/">visible</a>', False),
    ('<a href="#test_smt" title="hidden condition">visible</a>', False),
    ('<a href="#test_smt"><unsupported>hidden condition</unsupported></a>', False),
    ('<a href="#test_smt" title="hidden condition">visible</a>', True),
    ('<insert type="param" id-ref="p"/>', True),
])
def test_unsupported_link_and_label_grammar_fails_closed(tmp_path, monkeypatch, markup, label):
    from hashlib import sha256
    import judgment_compilation.nist_requirements as module
    label_text = markup if label else 'value'
    paragraph = '<insert type="param" id-ref="p"/>' if label else markup
    raw = (f'<catalog xmlns="http://csrc.nist.gov/ns/oscal/1.0"><metadata>'
           f'<version>test</version><oscal-version>1.2.2</oscal-version></metadata>'
           f'<control id="test"><title>Test</title><param id="p"><label>{label_text}</label></param>'
           f'<part id="test_smt" name="statement"><p>{paragraph}</p></part></control></catalog>').encode()
    target = tmp_path / SOURCE_RELATIVE_PATH
    target.parent.mkdir(parents=True)
    target.write_bytes(raw)
    monkeypatch.setattr(module, 'SOURCE_SHA256', sha256(raw).hexdigest())
    reader = Requirements(tmp_path)
    template = inspect(reader, 'test_smt')['template']
    assert template['grammar_status'] == 'UNSUPPORTED'
    request = request_for(reader, 'test_smt')
    request['source_sha256'] = module.SOURCE_SHA256
    for binding in request['parameters']:
        binding['source_sha256'] = module.SOURCE_SHA256
    result = reader.ask(request)
    assert result['status'] == 'UNRESOLVED' and result['instance'] is None


@pytest.mark.parametrize('statement_id,parameter_id,declaration_control', [
    *[(sid, 'ia-13_odp.01', 'ia-13') for sid in
      ['ia-13.3_smt', *['ia-13.3_smt.' + suffix for suffix in 'abcdef']]],
    ('si-10.1_smt', 'si-10_odp', 'si-10'),
    ('si-10.1_smt.a', 'si-10_odp', 'si-10'),
    ('sc-42.2_smt', 'sc-42.01_odp', 'sc-42.1'),
])
def test_real_catalog_references_preserve_declaration_and_consumer(
        requirements, statement_id, parameter_id, declaration_control):
    result = requirements.ask(request_for(requirements, statement_id))
    assert result['status'] == 'INSTANTIATED'
    template = result['template']
    definition = next(p for p in template['parameters'] if p['parameter_id'] == parameter_id)
    assert definition['control_id'] == template['control_id']
    assert definition['declaration_control_id'] == declaration_control
    assert definition['control_id'] != declaration_control
    assert definition['declaration_container']['xml_id'] == declaration_control
    assert definition['source']['xml_id'] == parameter_id
    assert definition['source']['source_sha256'] == SOURCE_SHA256
    assert definition['source']['xml_locator'].startswith(definition['declaration_container']['xml_locator'])
    assert definition['resolution_basis']['kind'] == 'EXACT_CATALOG_PARAMETER_ID'
    assert definition['resolution_basis']['oscal_version'] == '1.2.2'
    assert '/v1.2.2/' in definition['resolution_basis']['reference_url']
    assert all(p['control_id'] == template['control_id'] for p in result['instance']['parameter_bindings'])
    assert result['applicability'] is result['satisfaction'] is result['compliance_verdict'] is None
    assert result['external_effects'] == []
    # Keep the declaration separate from the organization binding.
    request = request_for(requirements, statement_id)
    next(p for p in request['parameters'] if p['parameter_id'] == parameter_id)['control_id'] = declaration_control
    with pytest.raises(RequirementError, match='foreign control binding'):
        requirements.ask(request)


def catalog_fixture(tmp_path, monkeypatch, body, version='1.2.2'):
    from hashlib import sha256
    import judgment_compilation.nist_requirements as module
    raw = (f'<catalog xmlns="http://csrc.nist.gov/ns/oscal/1.0"><metadata>'
           f'<version>synthetic</version><oscal-version>{version}</oscal-version></metadata>'
           f'{body}</catalog>').encode()
    target = tmp_path / SOURCE_RELATIVE_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
    # Isolated synthetic source pin; never claims authentic NIST provenance.
    monkeypatch.setattr(module, 'SOURCE_SHA256', sha256(raw).hexdigest())
    return Requirements(tmp_path)


def fixture_request(reader, statement_id='consumer_smt'):
    import judgment_compilation.nist_requirements as module
    request = request_for(reader, statement_id)
    request['source_sha256'] = module.SOURCE_SHA256
    for binding in request['parameters']:
        binding['source_sha256'] = module.SOURCE_SHA256
    return request


def consumer_statement(reference='p'):
    return (f'<control id="consumer"><title>Consumer</title>'
            f'<part id="consumer_smt" name="statement"><p>Use '
            f'<insert type="param" id-ref="{reference}"/>.</p></part></control>')


@pytest.mark.parametrize('container', ['catalog', 'group', 'sibling', 'ancestor'])
def test_exact_catalog_resolution_in_all_declaration_containers(tmp_path, monkeypatch, container):
    declaration = '<param id="p"><label>value</label></param>'
    consumer = consumer_statement()
    body = {
        'catalog': declaration + consumer,
        'group': '<group id="g"><title>Group</title>' + declaration + consumer + '</group>',
        'sibling': '<control id="other"><title>Other</title>' + declaration + '</control>' + consumer,
        'ancestor': '<control id="other"><title>Other</title>' + declaration + consumer + '</control>',
    }[container]
    reader = catalog_fixture(tmp_path, monkeypatch, body)
    result = reader.ask(fixture_request(reader))
    assert result['status'] == 'INSTANTIATED'
    definition = result['template']['parameters'][0]
    assert definition['control_id'] == 'consumer'
    assert definition['declaration_control_id'] == ('other' if container in {'sibling', 'ancestor'} else None)
    assert definition['declaration_container']['kind'] == {'sibling': 'control', 'ancestor': 'control'}.get(container, container)
    assert definition['source']['xml_id'] == 'p'
    assert result['instance']['parameter_bindings'][0]['control_id'] == 'consumer'


@pytest.mark.parametrize('body,reference,version,reason', [
    ('', 'p', '1.2.2', 'MISSING_CATALOG_PARAMETER'),
    ('<param id="prefix-p"><label>p</label><prop name="alt-identifier" value="p"/></param>',
     'p', '1.2.2', 'MISSING_CATALOG_PARAMETER'),
    ('', 'consumer', '1.2.2', 'WRONG_TYPE_CATALOG_PARAMETER_REFERENCE'),
    ('<param id="p"><label>value</label></param>', 'p', '9.0.0', 'UNSUPPORTED_PARAMETER_RESOLUTION_VERSION'),
])
def test_catalog_resolution_rejects_missing_alias_wrong_type_and_unqualified_version(
        tmp_path, monkeypatch, body, reference, version, reason):
    reader = catalog_fixture(tmp_path, monkeypatch, body + consumer_statement(reference), version)
    template = inspect(reader, 'consumer_smt')['template']
    assert template['grammar_status'] == 'UNSUPPORTED'
    assert any(r['reason'] == reason for r in template['grammar_residuals'])
    result = reader.ask(fixture_request(reader))
    assert result['status'] == 'UNRESOLVED' and result['instance'] is None


def test_duplicate_catalog_identity_never_resolves_by_proximity(tmp_path, monkeypatch):
    declaration = '<param id="p"><label>value</label></param>'
    body = declaration + '<control id="other"><title>Other</title>' + declaration + '</control>'
    reader = catalog_fixture(tmp_path, monkeypatch, body + consumer_statement())
    with pytest.raises(RequirementError, match='duplicate source identity'):
        inspect(reader, 'consumer_smt')


def test_cross_control_nested_choices_resolve_exact_dependencies_and_reject_foreign_digest(tmp_path, monkeypatch):
    from hashlib import sha256
    import json
    body = ('<param id="root"><label>root value</label></param>'
            '<group id="g"><title>Group</title><param id="group"><label>group value</label></param>'
            '<control id="other"><title>Other</title>'
            '<param id="p"><select><choice>Use <insert type="param" id-ref="root"/> and '
            '<insert type="param" id-ref="group"/></choice><choice>literal</choice></select></param>'
            '<param id="foreign"><select><choice>literal</choice></select></param>'
            '<part id="other_smt" name="statement"><p><insert type="param" id-ref="foreign"/></p></part>'
            '</control>' + consumer_statement() + '</group>')
    reader = catalog_fixture(tmp_path, monkeypatch, body)
    template = inspect(reader, 'consumer_smt')['template']
    definition = next(p for p in template['parameters'] if p['parameter_id'] == 'p')
    assert definition['dependency_parameter_ids'] == ['group', 'root']
    assert {p['parameter_id'] for p in template['parameters']} == {'p', 'root', 'group'}
    choice = definition['choice_templates'][0]
    assert choice['control_id'] == 'consumer' and choice['declaration_control_id'] == 'other'
    request = fixture_request(reader)
    binding = next(p for p in request['parameters'] if p['parameter_id'] == 'p')
    binding['values'] = [{'choice_sha256': choice['choice_sha256']}]
    result = reader.ask(request)
    assert result['status'] == 'INSTANTIATED'
    selected = result['instance']['selected_choices']['p'][0]
    assert [t['binding']['control_id'] for t in selected['tokens'] if t['kind'] == 'PARAMETER'] == ['consumer', 'consumer']
    missing = deepcopy(request)
    missing['parameters'] = [p for p in missing['parameters'] if p['parameter_id'] != 'group']
    assert any(r['reason'] == 'MISSING_PARAMETER' for r in reader.ask(missing)['residuals'])
    foreign = inspect(reader, 'other_smt')['template']['parameters'][0]['choice_templates'][0]
    substituted = deepcopy(choice)
    substituted.pop('choice_sha256')
    substituted['declaration_control_id'] = 'consumer'
    forged_digest = sha256(json.dumps(substituted, ensure_ascii=False, sort_keys=True,
                                     separators=(',', ':'), allow_nan=False).encode()).hexdigest()
    for digest in [foreign['choice_sha256'], forged_digest]:
        binding['values'] = [{'choice_sha256': digest}]
        rejected = reader.ask(request)
        assert rejected['status'] == 'UNRESOLVED' and rejected['instance'] is None
        assert any(r['reason'] == 'INVALID_SOURCE_CHOICE_REFERENCE' for r in rejected['residuals'])
    binding['values'] = ['literal']
    request['parameters'] = [binding]
    assert reader.ask(request)['status'] == 'INSTANTIATED'
    binding['source_sha256'] = '0' * 64
    with pytest.raises(RequirementError, match='foreign parameter source'):
        reader.ask(request)


def test_substituted_declaration_bytes_rejected_after_cached_resolution(tmp_path, monkeypatch):
    body = '<param id="p"><label>original</label></param>' + consumer_statement()
    reader = catalog_fixture(tmp_path, monkeypatch, body)
    request = fixture_request(reader)
    assert reader.ask(request)['status'] == 'INSTANTIATED'
    target = tmp_path / SOURCE_RELATIVE_PATH
    target.write_bytes(target.read_bytes().replace(b'<label>original</label>', b'<label>substituted</label>'))
    with pytest.raises(RequirementError, match='checksum mismatch'):
        reader.ask(request)
