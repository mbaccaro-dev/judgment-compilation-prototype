from copy import deepcopy

import pytest

from judgment_compilation.application import Application
from judgment_compilation.kernel import CLAIM_TYPES, Rejected, digest


def _complete_requests():
    return {
        'nist-sp-800-100-page-39': {
            'entities': {'org-a': 'organization'},
            'facts': [
                {'id': 'needs-a', 'predicate': 'needs_assessment_conducted',
                 'arguments': {'organization': 'org-a'}, 'value': True},
                {'id': 'strategy', 'predicate': 'strategy_developed',
                 'arguments': {'organization': 'org-a'}, 'value': True},
            ],
            'bindings': {'evaluate_named_prerequisite_facts': {'organization': ['org-a']}},
            'unknowns': [],
        },
        'nist-sp-800-101-recovery-activity': {
            'entities': {'recovery-a': 'system', 'device-a': 'system'},
            'facts': [
                {'id': 'evidence', 'predicate': 'digital_evidence_recovered_from_mobile_device',
                 'arguments': {'recovery_activity': 'recovery-a', 'mobile_device': 'device-a'}, 'value': True},
                {'id': 'conditions', 'predicate': 'forensically_sound_conditions_used_for_recovery_activity',
                 'arguments': {'recovery_activity': 'recovery-a', 'mobile_device': 'device-a'}, 'value': True},
                {'id': 'methods', 'predicate': 'accepted_methods_used_for_recovery_activity',
                 'arguments': {'recovery_activity': 'recovery-a', 'mobile_device': 'device-a'}, 'value': True},
            ],
            'bindings': {'evaluate_same_activity_recovery_facts': {
                'recovery_activity': ['recovery-a'], 'mobile_device': ['device-a']}},
        },
        'nist-sp-800-108-counter-mode-capacity-guard': {
            'entities': {'invocation-a': 'system'},
            'facts': [
                {'id': 'mode', 'predicate': 'counter_mode_established',
                 'arguments': {'invocation': 'invocation-a'}, 'value': True},
                {'id': 'n', 'predicate': 'counter_mode_iteration_count',
                 'arguments': {'invocation': 'invocation-a'}, 'value': 2},
                {'id': 'r', 'predicate': 'counter_width_bits',
                 'arguments': {'invocation': 'invocation-a'}, 'value': 2},
            ],
            'bindings': {'strict-capacity-boundary': {'invocation': ['invocation-a']}},
        },
        'nist-sp-800-111-centralized-management': {
            'entities': {'deployment-a': 'system'},
            'facts': [
                {'id': 'storage', 'predicate': 'storage_encryption_deployment',
                 'arguments': {'deployment': 'deployment-a'}, 'value': True},
                {'id': 'standalone', 'predicate': 'standalone_deployment',
                 'arguments': {'deployment': 'deployment-a'}, 'value': False},
                {'id': 'small', 'predicate': 'very_small_scale_deployment',
                 'arguments': {'deployment': 'deployment-a'}, 'value': False},
            ],
            'bindings': {'evaluate_recommendation_applicability': {'deployment': ['deployment-a']}},
        },
        'nist-sp-800-150-tlp-table-3-3': {
            'entities': {'org-a': 'organization'},
            'facts': [
                {'id': 'color', 'predicate': 'tlp_color',
                 'arguments': {'subject': 'org-a'}, 'value': 'AMBER'},
                {'id': 'limits', 'predicate': 'amber_additional_limits',
                 'arguments': {'subject': 'org-a'}, 'value': 'NOT_APPLICABLE'},
            ],
            'bindings': {'classify-tlp': {'subject': ['org-a']}},
        },
        'nist-sp-800-37r2-p1-assignment-entry': {
            'entities': {'record-a': 'rmf_role_assignment_record', 'person-a': 'person', 'role-a': 'rmf_role'},
            'facts': [
                {'id': 'documented', 'predicate': 'reported_documented_rmf_role_assignment_record',
                 'arguments': {'record': 'record-a'}, 'value': True},
                {'id': 'assignment', 'predicate': 'reported_record_assigns_person_to_rmf_role',
                 'arguments': {'record': 'record-a', 'person': 'person-a', 'role': 'role-a'}, 'value': True},
            ],
            'bindings': {'evaluate_documented_assignment_entry': {
                'record': ['record-a'], 'person': ['person-a'], 'role': ['role-a']}},
        },
        'nist-sp-800-145-section-2-caller-reports': {'bindings': {'resolve_01': {'service': ['service-a']},
                      'resolve_02': {'service': ['service-a']},
                      'resolve_03': {'service': ['service-a']},
                      'resolve_04': {'service': ['service-a']},
                      'resolve_05': {'service': ['service-a']},
                      'resolve_06': {'service': ['service-a']},
                      'resolve_07': {'service': ['service-a']},
                      'resolve_08': {'service': ['service-a']},
                      'resolve_09': {'service': ['service-a']},
                      'resolve_10': {'service': ['service-a']},
                      'resolve_11': {'service': ['service-a']},
                      'resolve_12': {'service': ['service-a']},
                      'resolve_13': {'service': ['service-a']},
                      'resolve_14': {'service': ['service-a']},
                      'resolve_15': {'service': ['service-a']},
                      'resolve_16': {'service': ['service-a']},
                      'resolve_17': {'service': ['service-a']},
                      'resolve_18': {'service': ['service-a']},
                      'resolve_19': {'service': ['service-a']}},
         'entities': {'service-a': 'cloud_service'},
         'facts': [{'arguments': {'service': 'service-a'},
                    'id': 'report-1',
                    'predicate': 'sp800_145_caller_report_consumer_can_unilaterally_provision_computing_capabilities',
                    'value': True},
                   {'arguments': {'service': 'service-a'},
                    'id': 'report-2',
                    'predicate': 'sp800_145_caller_report_provisioning_occurs_as_needed_automatically',
                    'value': True},
                   {'arguments': {'service': 'service-a'},
                    'id': 'report-3',
                    'predicate': 'sp800_145_caller_report_provisioning_does_not_require_human_interaction_with_each_service_provider',
                    'value': True},
                   {'arguments': {'service': 'service-a'},
                    'id': 'report-4',
                    'predicate': 'sp800_145_caller_report_capabilities_are_available_over_the_network',
                    'value': True},
                   {'arguments': {'service': 'service-a'},
                    'id': 'report-5',
                    'predicate': 'sp800_145_caller_report_standard_access_mechanisms_promote_use_by_heterogeneous_thin_or_thick_client_platforms',
                    'value': True},
                   {'arguments': {'service': 'service-a'},
                    'id': 'report-6',
                    'predicate': 'sp800_145_caller_report_provider_computing_resources_are_pooled_to_serve_multiple_consumers',
                    'value': True},
                   {'arguments': {'service': 'service-a'},
                    'id': 'report-7',
                    'predicate': 'sp800_145_caller_report_multi_tenant_model_is_used',
                    'value': True},
                   {'arguments': {'service': 'service-a'},
                    'id': 'report-8',
                    'predicate': 'sp800_145_caller_report_physical_and_virtual_resources_are_dynamically_assigned_and_reassigned_according_to_consumer_demand',
                    'value': True},
                   {'arguments': {'service': 'service-a'},
                    'id': 'report-9',
                    'predicate': 'sp800_145_caller_report_customer_generally_has_no_control_or_knowledge_of_exact_resource_location',
                    'value': True},
                   {'arguments': {'service': 'service-a'},
                    'id': 'report-10',
                    'predicate': 'sp800_145_caller_report_customer_may_be_able_to_specify_resource_location_at_higher_level_of_abstraction',
                    'value': True},
                   {'arguments': {'service': 'service-a'},
                    'id': 'report-11',
                    'predicate': 'sp800_145_caller_report_capabilities_can_be_elastically_provisioned_and_released',
                    'value': True},
                   {'arguments': {'service': 'service-a'},
                    'id': 'report-12',
                    'predicate': 'sp800_145_caller_report_elastic_provisioning_and_release_can_in_some_cases_be_automatic',
                    'value': True},
                   {'arguments': {'service': 'service-a'},
                    'id': 'report-13',
                    'predicate': 'sp800_145_caller_report_capabilities_can_scale_rapidly_outward_and_inward_commensurate_with_demand',
                    'value': True},
                   {'arguments': {'service': 'service-a'},
                    'id': 'report-14',
                    'predicate': 'sp800_145_caller_report_resource_use_is_automatically_controlled_and_optimized_by_leveraging_metering_capability',
                    'value': True},
                   {'arguments': {'service': 'service-a'},
                    'id': 'report-15',
                    'predicate': 'sp800_145_caller_report_metering_capability_is_at_some_level_of_abstraction_appropriate_to_service_type',
                    'value': True},
                   {'arguments': {'service': 'service-a'},
                    'id': 'report-16',
                    'predicate': 'sp800_145_caller_report_resource_usage_can_be_monitored',
                    'value': True},
                   {'arguments': {'service': 'service-a'},
                    'id': 'report-17',
                    'predicate': 'sp800_145_caller_report_resource_usage_can_be_controlled',
                    'value': True},
                   {'arguments': {'service': 'service-a'},
                    'id': 'report-18',
                    'predicate': 'sp800_145_caller_report_resource_usage_can_be_reported',
                    'value': True},
                   {'arguments': {'service': 'service-a'},
                    'id': 'report-19',
                    'predicate': 'sp800_145_caller_report_usage_reporting_provides_transparency_for_provider_and_consumer_of_utilized_service',
                    'value': True}]},
        'nist-sp-800-30r1-table-g5': {
            'entities': {'subject-1': 'assessment_subject'},
            'facts': [
                {'id': 'initiation', 'predicate': 'likelihood_of_threat_event_initiation_or_occurrence',
                 'arguments': {'assessment_subject': 'subject-1'}, 'value': 'High'},
                {'id': 'impact', 'predicate': 'likelihood_threat_events_result_in_adverse_impacts',
                 'arguments': {'assessment_subject': 'subject-1'}, 'value': 'Moderate'},
            ],
            'bindings': {'lookup': {'assessment_subject': ['subject-1']}},
        },
    }


def _assert_binding(response):
    binding = response['egress']['binding']
    assert binding['text'] == response['answer']
    assert binding['type'] == response['egress']['type']
    assert binding['kernel_sha256'] == digest(response['kernel'])
    assert binding['claim_ids'] == [claim['id'] for claim in response['kernel']['claims']]
    assert all(claim['type'] in CLAIM_TYPES for claim in response['kernel']['claims'])
    assert Application.verify_consumer_egress(response) is response


def test_all_shipped_reviewed_packages_bind_complete_and_unresolved_query_egress():
    app = Application()
    complete = _complete_requests()
    package_ids = [row['id'] for row in app.query({'mode': 'reviewed_programs'})['kernel']['packages']]
    assert set(package_ids) == set(complete)
    for package_id in package_ids:
        inspected = app.query({'mode': 'reviewed_program',
                               'request': {'operation': 'inspect', 'package_id': package_id}})
        _assert_binding(inspected)
        resolved = app.query({'mode': 'reviewed_program', 'request': {
            'operation': 'execute', 'package_id': package_id,
            'execution_request': {**complete[package_id], 'request_id': 'request-' + package_id,
                                                   'scenario_id': 'scenario-' + package_id}}})
        _assert_binding(resolved)
        outputs = resolved['kernel']['execution']['execution']['execution']['outputs']
        source_ids = {source_id for output in outputs for source_id in output['source_ids']}
        assert source_ids == {citation['source_id'] for citation in resolved['provenance']}
        assert resolved['egress']['type'] == 'DETERMINISTIC_DERIVATION'
        assert resolved['egress']['request_id'] == 'request-' + package_id
        assert resolved['egress']['scenario_id'] == 'scenario-' + package_id
        assert resolved['egress']['request_sha256'] == resolved['kernel']['execution']['request_sha256']
        assert resolved['egress']['result_sha256'] == resolved['kernel']['execution']['result_sha256']
        unresolved = app.query({'mode': 'reviewed_program', 'request': {
            'operation': 'execute', 'package_id': package_id,
            'execution_request': {'request_id': 'unresolved-' + package_id,
                                  'scenario_id': 'scenario-' + package_id,
                                  'entities': {}, 'facts': [], 'bindings': {}, 'unknowns': []}}})
        _assert_binding(unresolved)
        assert unresolved['egress']['type'] == 'UNRESOLVED'
        assert unresolved['provenance'] == []


def test_catalog_and_plain_source_claims_are_exact_source_text_not_presentation_text():
    app = Application()
    catalog = app.query({'mode': 'catalog', 'question': 'ac-2'})
    source = next(claim for claim in catalog['kernel']['claims'] if claim['type'] == 'SOURCE_BOUND')
    rendered = catalog['kernel']['candidates'][0]['rendered_text']
    assert source['text'] == rendered
    assert 'Structured source text.' not in source['text']
    assert catalog['egress']['type'] == 'DETERMINISTIC_DERIVATION'
    plain = app.query({'mode': 'inquiry', 'question': 'What does AC-2 say about account management?'})
    plain_source = next(claim for claim in plain['kernel']['claims'] if claim['type'] == 'SOURCE_BOUND')
    assert plain_source['text'] == rendered
    _assert_binding(catalog)
    _assert_binding(plain)


def test_consumer_egress_binding_rejects_text_type_seal_and_replay_mutations():
    response = Application().query({'mode': 'catalog', 'question': 'ac-2'})
    Application.verify_consumer_egress(response)
    text_mutation = deepcopy(response)
    text_mutation['answer'] += ' altered'
    with pytest.raises(Rejected, match='text'):
        Application._consumer_egress_binding(text_mutation)
    with pytest.raises(Rejected, match='text'):
        Application.verify_consumer_egress(text_mutation)
    type_mutation = deepcopy(response)
    type_mutation['kernel']['claims'][0]['type'] = 'SOURCEISH'
    with pytest.raises(Rejected, match='claim type'):
        Application._consumer_egress_binding(type_mutation)
    seal_mutation = deepcopy(response)
    seal_mutation['egress']['binding']['text'] += ' altered'
    with pytest.raises(Rejected, match='seal mismatch'):
        Application.verify_consumer_egress(seal_mutation)
    replay = Application().query({'mode': 'catalog', 'question': 'ac-2'})
    replay['egress']['binding'] = deepcopy(Application().query({
        'mode': 'inquiry', 'question': 'What does AC-2 say about account management?'})['egress']['binding'])
    with pytest.raises(Rejected, match='replay mismatch'):
        Application.verify_consumer_egress(replay)


def test_assessment_count_summary_is_deterministic_derivation():
    response = Application().query({'mode': 'assessments', 'request': {
        'schema': 'jc-nist-assessment-selection-request/1', 'operation': 'INSPECT', 'control_id': 'ps-4'}})
    assert response['kernel']['status'] == 'INSPECTED_SOURCE_STRUCTURE'
    assert response['egress']['type'] == 'DETERMINISTIC_DERIVATION'


def test_reviewed_execution_uses_sealed_execution_identities_in_egress_binding():
    class ReviewedPrograms:
        @staticmethod
        def execute(package_id, request):
            sealed = {
                'request_id': request['request_id'],
                'scenario_id': request['scenario_id'],
                'request_sha256': 'sealed-request',
                'result_sha256': 'sealed-result',
                'execution': {'execution': {'outputs': [], 'steps': []}},
            }
            return {
                'execution': sealed, 'source_citations': [], 'claim_ceiling': 'SOURCE_ONLY',
                'request_id': request['request_id'], 'scenario_id': request['scenario_id'],
                'request_sha256': 'outer-request', 'result_sha256': 'outer-result',
                'package_id': package_id, 'package_sha256': 'package-hash',
                'program_sha256': 'program-hash', 'scope': 'fixture scope',
            }

    app = Application.__new__(Application)
    app.document_programs = ReviewedPrograms()
    response, unresolved = app._reviewed_document_program({
        'operation': 'execute', 'package_id': 'fixture-package',
        'execution_request': {'request_id': 'request-1', 'scenario_id': 'scenario-1'},
    })
    assert unresolved == []
    assert response['egress']['request_id'] == 'request-1'
    assert response['egress']['scenario_id'] == 'scenario-1'
    assert response['egress']['request_sha256'] == 'sealed-request'
    assert response['egress']['result_sha256'] == 'sealed-result'
    bound = Application._consumer_egress_binding(response)
    assert bound['egress']['binding']['identities']['request_sha256'] == 'sealed-request'
    assert bound['egress']['binding']['identities']['result_sha256'] == 'sealed-result'


def test_reviewed_output_without_a_matching_kernel_source_citation_fails_closed():
    with pytest.raises(Rejected, match='source citations incomplete'):
        Application._reviewed_claims(
            {'source_citations': []}, 'answer', 'execute',
            [{'source_ids': ['required-source']}])


def test_library_routes_type_exact_pages_and_citations_as_source_bound_only():
    class Library:
        @staticmethod
        def ask(request):
            operation = request['operation']
            if operation == 'documents':
                return {'total': 2, 'documents': [{}, {}], 'source_file': {}}
            if operation == 'page':
                return {'page': {'text': 'exact page source text'}, 'source_file': {}}
            if operation == 'cite':
                return {
                    'claim': {'id': 'cite-1', 'type': 'SOURCE_BOUND', 'text': 'exact quoted source text',
                              'support': [], 'provenance_ids': [], 'provenance_sha256': 'provenance'},
                    'provenance': {}, 'interpretation_trace': {}, 'request_sha256': 'request',
                    'occurrence_inventory_sha256': 'inventory',
                }
            return {'total_occurrences': 3, 'pages_searched': 2, 'returned_occurrences': 1, 'matches': []}

    app = Application.__new__(Application)
    app.library = Library()
    app.integrity = {}
    app.interpretation_admission = {}
    app.pack = {'fact_templates': []}
    cases = {
        'documents': 'DETERMINISTIC_DERIVATION', 'page': 'SOURCE_BOUND',
        'cite': 'SOURCE_BOUND', 'search': 'DETERMINISTIC_DERIVATION',
    }
    for operation, expected_type in cases.items():
        response = app.query({'mode': 'library', 'request': {'operation': operation}})
        assert response['egress']['type'] == expected_type
        _assert_binding(response)
    assert app.query({'mode': 'library', 'request': {'operation': 'page'}})['answer'] == 'exact page source text'
    assert app.query({'mode': 'library', 'request': {'operation': 'cite'}})['answer'] == 'exact quoted source text'
