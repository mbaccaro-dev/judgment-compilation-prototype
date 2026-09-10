"""Describes inputs and outputs for compiled operations."""
from copy import deepcopy
from .semantic_contracts import validate_semantic_pack, SemanticContractError, canonical


def operation_interfaces(pack):
    pack = validate_semantic_pack(pack)
    judgments = {j['id']: j for j in pack['judgments']}
    predicates = {p['id']: p for p in pack['predicates']}
    result = {}
    def port(selector):
        p = predicates[selector['predicate']]
        return {'predicate':p['id'], 'arguments':deepcopy(selector['arguments']),
                'roles':deepcopy(p['roles']), 'value_type':p.get('value_type', 'BOOLEAN'),
                'origin':p['origin']}
    for work in pack['work']:
        operation = work['operation']
        if operation == 'APPLY_JUDGMENT':
            selected = [judgments[work['judgment']]]
            producer = 'semantic_contracts._evaluate'
        elif operation == 'RESOLVE_JUDGMENTS':
            selected = [judgments[i] for i in sorted(work['judgments'])]
            producer = 'semantic_contracts._execute_work:RESOLVE_JUDGMENTS'
        elif operation == 'COMPARE_VALUES':
            selected = []
            producer = 'semantic_contracts._execute_work:COMPARE_VALUES'
        elif operation == 'COMPARE_INTEGER_POWER_OF_TWO_MINUS_ONE':
            selected = [judgments[work['judgment']]]
            producer = 'semantic_contracts._execute_work:COMPARE_INTEGER_POWER_OF_TWO_MINUS_ONE'
        elif operation == 'FINITE_ENUM_TABLE_LOOKUP':
            selected = []
            producer = 'semantic_contracts._execute_work:FINITE_ENUM_TABLE_LOOKUP'
        else:
            raise SemanticContractError('operation has no executable interface')
        if operation == 'COMPARE_INTEGER_POWER_OF_TWO_MINUS_ONE':
            bindings = selected[0]['bindings']
            inputs = [port(c) for c in selected[0]['premises']] + [port(work['left']), port(work['exponent'])]
            output = port(work['output'])
            scope = 'JUDGMENT_GATED_INTEGER_EXPRESSION_CONDITION_ONLY'
        elif selected:
            bindings = selected[0]['bindings']
            inputs = [port(c) for j in selected for c in j['premises']]
            output = port(selected[0]['output'])
            scope = 'DECLARED_JUDGMENT_CONCLUSION_ONLY'
        elif operation == 'COMPARE_VALUES':
            bindings = work['bindings']
            inputs = [port(work['left']), port(work['right'])]
            output = port(work['output'])
            scope = 'COMPARISON_CONDITION_ONLY'
        else:
            bindings = work['bindings']
            inputs = [port(item['selector']) for item in work['input_ports']]
            output = port(work['output'])
            scope = 'FINITE_ENUM_TABLE_LOOKUP_ONLY'
        unique = {canonical(p):p for p in inputs}
        result[work['id']] = {
            'operation':operation, 'producer':producer, 'bindings':deepcopy(bindings),
            'inputs':[unique[k] for k in sorted(unique)], 'output':output,
            'judgment_ids':[j['id'] for j in selected], 'conclusion_scope':scope,
            'missing_or_conflicting_input':'UNRESOLVED', 'external_effects':[],
            **({'finite_enum_program': {
                key: deepcopy(work['program'][key])
                for key in ('program_id', 'program_sha256', 'relation_sha256', 'provenance_sha256', 'provenance', 'claim_ceiling')
            }, 'source_ids': sorted(work['source_ids'])}
               if operation == 'FINITE_ENUM_TABLE_LOOKUP' else {})}
    return result
