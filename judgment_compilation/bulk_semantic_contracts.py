"""Builds structured records from the SP 800-53 catalog."""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
from hashlib import sha256
import json

from . import nist_requirements as source
from .documentary_projection import DocumentaryProjection

SCHEMA = 'jc/sp80053-oscal-bulk-source-contracts/1'
CEILING = ('SOURCE_STRUCTURAL_CONTRACT_EXECUTION_ONLY;'
           'NO_POLICY_INTERPRETATION_OR_APPLICABILITY_OR_PRECEDENCE_OR_SATISFACTION_'
           'OR_COMPLIANCE_OR_RESPONSIBILITY_OR_EXTERNAL_EFFECT')
NAMESPACE = 'jc-sp80053-oscal-source-structural-contracts'


class BulkContractError(ValueError):
    """A compiled contract differs from the exact pinned source derivation."""


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False,
                          separators=(',', ':'), allow_nan=False).encode('utf-8')
    except (ValueError, TypeError, RecursionError) as exc:
        raise BulkContractError('invalid canonical contract JSON') from exc


def digest(value):
    return sha256(canonical(value)).hexdigest()


def _need(condition, message):
    if not condition:
        raise BulkContractError(message)


def _id(stack, *identity):
    return NAMESPACE + ':' + stack + ':' + digest([source.SOURCE_SHA256, *identity])


def _disposition():
    return {'policy_interpretation': 'UNRESOLVED_NOT_ADMITTED',
            'raw_document_semantics': 'RAW_DOCUMENT_SEMANTICS_UNRESOLVED',
            'applicability': None, 'precedence': None, 'satisfaction': None,
            'compliance': None, 'responsibility': None, 'external_effects': []}


def _parameter_id(control_id, parameter_id):
    # A declaration may serve multiple controls; organizational bindings are
    # Keep bindings separate when only declaration IDs match.
    return _id('domain-parameter', control_id, parameter_id)


def _work():
    result = []
    for operation in ('inspect', 'instantiate'):
        result.append({
            'id': _id('work', operation), 'stack': 'Work',
            'operation': operation, 'request_schema': source.REQUEST_SCHEMA,
            'result_schema': source.RESULT_SCHEMA,
            'input': 'EXACT_STATEMENT_ID' if operation == 'inspect' else
                     'EXACT_SOURCE_TEMPLATE_ID_AND_SCOPED_CALLER_PARAMETER_BINDINGS',
            'producer_chain': ['Requirements.prepare', 'Requirements.operation_warrant',
                               'Requirements.execute_prepared'],
            'warrant_schema': source.WARRANT_SCHEMA,
            'failure': 'REJECT_INVALID_INPUT_OR_SOURCE_DRIFT;PRESERVE_UNRESOLVED',
            'cancellation': 'SYNCHRONOUS_NO_BACKGROUND_WORK',
            'recovery': 'REVALIDATE_SOURCE_AND_RECOMPUTE_WITHOUT_EXTERNAL_EFFECT',
            'ceiling': CEILING, 'external_effects': [],
        })
    return result


def _judgment(template):
    return {
        'id': _id('judgment', template['statement_id']), 'stack': 'Judgment',
        'kind': 'SOURCE_TEMPLATE_TRANSFORMATION_WARRANT_DEFINITION',
        'source_sha256': source.SOURCE_SHA256,
        'statement_id': template['statement_id'], 'control_id': template['control_id'],
        'template_sha256': template['template_sha256'],
        'source_template': deepcopy(template),
        'domain_parameter_ids': [_parameter_id(template['control_id'], p['parameter_id'])
                                 for p in template['parameters']],
        'root_domain_parameter_ids': [_parameter_id(template['control_id'], pid)
                                      for pid in template['root_parameter_ids']],
        'work_interface_ids': [row['id'] for row in _work()],
        'warrant_rule': 'PINNED_SOURCE_IDENTITY_AND_EXACT_REQUEST_GRAMMAR_ONLY',
        'instantiation_supported': template['grammar_status'] == 'SUPPORTED',
        'grammar_residuals': deepcopy(template['grammar_residuals']),
        'disposition': _disposition(), 'ceiling': CEILING,
    }


def _domain(parameter, control_id):
    pid = parameter['parameter_id']
    return {
        'id': _parameter_id(control_id, pid), 'stack': 'Domain',
        'kind': 'SOURCE_PARAMETER_BINDING_DEFINITION',
        'source_sha256': source.SOURCE_SHA256,
        'consumer_control_id': control_id, 'parameter_id': pid,
        'source_definition': deepcopy(parameter),
        'dependency_domain_ids': [_parameter_id(control_id, dep)
                                  for dep in parameter.get('dependency_parameter_ids', [])],
        'value_contract': {
            'kind': parameter['kind'],
            'scope_type': {'organization_id': 'NONEMPTY_STRING', 'system_id': 'NONEMPTY_STRING'},
            'assignment_type': 'OPAQUE_CALLER_STRING_NOT_VERIFIED_POLICY',
            'selection_type': 'EXACT_SOURCE_CHOICE_DIGEST_OR_EXACT_LITERAL_CHOICE',
            'cardinality': parameter.get('cardinality'),
            'cardinality_basis': deepcopy(parameter.get('cardinality_basis')),
            'choice_ids': [_id('domain-choice', c['choice_sha256'])
                           for c in parameter.get('choice_templates', [])],
            'value': None, 'value_status': 'NO_ORGANIZATIONAL_VALUE_SUPPLIED',
            'substantive_validity': 'NOT_INFERRED',
        },
        'disposition': _disposition(), 'ceiling': CEILING,
    }


class SP80053BulkContracts:
    """Read SP 800-53 OSCAL records and execute one selected contract."""

    def __init__(self, root=None):
        self.requirements = source.Requirements(root)

    def retained_pdf_connector(self, include_document=False):
        """Return the retained PDF identity for the catalog."""
        _need(type(include_document) is bool, 'invalid PDF connector selection')
        self.requirements._load()
        record = None
        if include_document:
            projection = DocumentaryProjection(
                self.requirements._root / 'judgment_compilation/data/library')
            document = projection.documents.get('NIST SP 800-53r5-upd1')
            _need(document is not None and document['pdf']['sha256'] ==
                  'fc63bcd61715d0181dd8e85998b1e6201ae3515fc6626102101cab1841e11ec6',
                  'retained SP 800-53 base PDF identity mismatch')
            record = projection._document_record(document)
        return {
            'schema': 'jc/oscal-retained-pdf-connector/1',
            'oscal_source_sha256': source.SOURCE_SHA256,
            'document': record,
            'connection': 'BASE_PUBLICATION_IDENTITY_ONLY' if record else 'NOT_ATTACHED',
            'clause_correspondence': 'UNRESOLVED',
            'release_reconciliation': 'UNRESOLVED',
            'raw_document_semantics': 'RAW_DOCUMENT_SEMANTICS_UNRESOLVED',
            'whole_library_semantic_coverage': False,
            'ceiling': CEILING,
        }

    def compile(self, include_retained_pdf=False):
        reader = self.requirements
        reader._load()
        judgments, parameters, choices = [], {}, {}
        grammar = Counter()
        for sid in sorted(reader._statements):
            template = reader._template(sid)
            judgments.append(_judgment(template))
            grammar[template['grammar_status']] += 1
            for parameter in template['parameters']:
                row = _domain(parameter, template['control_id'])
                previous = parameters.setdefault(row['id'], row)
                _need(previous == row, 'inconsistent source parameter definition')
                for choice in parameter.get('choice_templates', []):
                    cid = _id('domain-choice', choice['choice_sha256'])
                    choice_row = {'id': cid, 'stack': 'Domain',
                                  'kind': 'SOURCE_CHOICE_VALUE_TEMPLATE',
                                  'parameter_binding_id': row['id'],
                                  'source_choice': deepcopy(choice),
                                  'value_status': 'SOURCE_OPTION_NOT_SELECTED',
                                  'disposition': _disposition(), 'ceiling': CEILING}
                    prior = choices.setdefault(cid, choice_row)
                    _need(prior == choice_row, 'inconsistent source choice identity')
        parameter_ids = set(parameters)
        _need(all(set(p['dependency_domain_ids']) <= parameter_ids for p in parameters.values()),
              'dangling parameter dependency')
        work = _work()
        architecture = {
            'id': _id('architecture', 'source-template-transformation'),
            'stack': 'Architecture', 'kind': 'SOURCE_STRUCTURAL_COMPOSITION',
            'stages': ['Domain', 'Judgment', 'Work'],
            'judgment_ids': [j['id'] for j in judgments],
            'work_interface_ids': [w['id'] for w in work],
            'connection_laws': [
                'EXACT_SOURCE_TEMPLATE_SELECTS_ONE_JUDGMENT_DEFINITION',
                'PARAMETER_DECLARATION_AND_CONSUMER_IDENTITIES_REMAIN_DISTINCT',
                'JUDGMENT_WARRANT_BINDS_EXACT_PREPARATION_BEFORE_WORK',
                'SELECTED_CHOICE_DEPENDENCIES_REQUIRE_SCOPED_BINDINGS',
                'UNSUPPORTED_GRAMMAR_AND_MISSING_VALUES_REMAIN_UNRESOLVED',
                'SOURCE_TREE_CONTAINMENT_DOES_NOT_DECLARE_POLICY_PRECEDENCE',
            ],
            'policy_composition': 'UNRESOLVED_NOT_ADMITTED',
            'ceiling': CEILING, 'external_effects': [],
        }
        body = {
            'schema': SCHEMA, 'namespace': NAMESPACE,
            'status': 'SOURCE_BOUND_STRUCTURAL_COMPILER_OUTPUT',
            'source_sha256': source.SOURCE_SHA256,
            'source_metadata': deepcopy(reader._metadata),
            'raw_document_connector': self.retained_pdf_connector(include_retained_pdf),
            'domain': {'parameters': sorted(parameters.values(), key=lambda r: r['id']),
                       'choices': sorted(choices.values(), key=lambda r: r['id'])},
            'judgments': judgments, 'work': work, 'architecture': architecture,
            'counts': {'source_templates': len(judgments),
                       'supported_source_templates': grammar['SUPPORTED'],
                       'unsupported_source_templates': grammar['UNSUPPORTED'],
                       'consumer_parameter_bindings': len(parameters),
                       'source_choice_templates': len(choices),
                       'work_interfaces': len(work), 'architecture_compositions': 1,
                       'admitted_policy_interpretations': 0,
                       'organizational_values': 0},
            'coverage': 'ALL_PINNED_SP800_53_OSCAL_STATEMENT_ITEM_TEMPLATES;NOT_FULL_PDF_LIBRARY_SEMANTICS',
            'disposition': _disposition(), 'ceiling': CEILING,
        }
        reader._load()  # Reject source drift during the bulk operation.
        body['compilation_sha256'] = digest(body)
        return body

    def validate(self, compiled, include_retained_pdf=False):
        """Reject rehashed tampering, omission and unsupported claimed meaning."""
        expected = self.compile(include_retained_pdf)
        _need(canonical(compiled) == canonical(expected), 'bulk source contract derivation mismatch')
        return expected

    def execute(self, judgment, request):
        """Run one source transformation through its exact generated definition."""
        _need(type(judgment) is dict and type(request) is dict, 'invalid execution input')
        sid = judgment.get('statement_id')
        _need(type(sid) is str and request.get('statement_id') == sid,
              'request and source contract identity mismatch')
        self.requirements._load()
        template = self.requirements._template(sid)
        _need(template is not None, 'unknown source contract')
        _need(canonical(judgment) == canonical(_judgment(template)), 'source judgment derivation mismatch')
        preparation = self.requirements.prepare(request)
        warrant = self.requirements.operation_warrant(preparation)
        result = self.requirements.execute_prepared(preparation, warrant)
        body = {'schema': 'jc/bulk-source-contract-execution/1',
                'judgment_id': judgment['id'],
                'work_interface_id': _id('work', request['operation']),
                'architecture_id': _id('architecture', 'source-template-transformation'),
                'domain_parameter_ids': deepcopy(judgment['domain_parameter_ids']),
                'judgment_definition_sha256': digest(judgment),
                'request_sha256': result['request_sha256'],
                'preparation_sha256': preparation['preparation_sha256'],
                'warrant': warrant, 'result': result,
                'disposition': _disposition(), 'ceiling': CEILING}
        self.requirements._load()
        body['execution_sha256'] = digest(body)
        return body
