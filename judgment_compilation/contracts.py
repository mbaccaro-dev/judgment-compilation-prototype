"""Evaluates compiled information contracts."""
from copy import deepcopy
from .kernel import require, digest

OPERATIONS = {'BIND_PARAMETER', 'REVIEW_REQUIREMENT', 'ASSESSMENT_WORK', 'SOURCE_CONTEXT'}

def evaluate_contracts(contract_pack, request):
    require(type(request) is dict and set(request) <= {'bindings', 'evidence', 'unknowns'}, 'invalid contract inputs')
    bindings = request.get('bindings', {})
    evidence = request.get('evidence', {})
    unknowns = request.get('unknowns', [])
    require(type(bindings) is dict and all(type(k) is str for k in bindings), 'bindings must be keyed by exact parameter identity')
    require(type(evidence) is dict and all(type(k) is str for k in evidence), 'evidence must be keyed by exact work identity')
    require(type(unknowns) is list and all(type(x) is str and x.strip() for x in unknowns), 'unknowns must be nonempty text')
    contracts = contract_pack['contracts']
    ids = [c['id'] for c in contracts]
    require(len(ids) == len(set(ids)), 'duplicate contract identity')
    parameters = {c['parameter_id'] for c in contracts if c['operation'] == 'BIND_PARAMETER'}
    work = {c['id'] for c in contracts if c['operation'] == 'ASSESSMENT_WORK'}
    require(set(bindings) <= parameters, 'unknown or foreign parameter binding')
    require(set(evidence) <= work, 'unknown or foreign evidence binding')
    def supplied(value):
        return value is not None and value != '' and value != [] and value != {}
    resolved = {key for key, value in bindings.items() if supplied(value)}
    results, residual = [], []
    for c in contracts:
        op = c['operation']
        require(op in OPERATIONS, 'unsupported contract operation')
        missing = sorted(set(c.get('requires_parameters', [])) - resolved)
        row = {'contract_id': c['id'], 'operation': op, 'source_record_id': c['source_record_id'], 'missing_parameters': missing,
               'source_support': deepcopy(c['source_support']), 'judgment_coordinate': deepcopy(c.get('judgment_coordinate'))}
        if op == 'BIND_PARAMETER':
            present = c['parameter_id'] in resolved
            row.update(status='BOUND_CALLER_VALUE' if present else 'MISSING_PARAMETER', value=deepcopy(bindings.get(c['parameter_id'])), value_validity='NOT_SUBSTANTIVELY_VALIDATED')
        elif op == 'SOURCE_CONTEXT':
            row['status'] = 'CONTEXT_AVAILABLE'
        elif op == 'ASSESSMENT_WORK':
            provided = supplied(evidence.get(c['id']))
            row.update(status='EVIDENCE_DECLARED_REVIEW_REQUIRED' if provided else 'EVIDENCE_REQUIRED', evidence=deepcopy(evidence.get(c['id'])), execution='NOT_PERFORMED')
        else:
            row['status'] = 'MISSING_PARAMETER' if missing else 'SUBSTANTIVE_EVALUATION_REQUIRED'
            row['determination'] = None
        if row['status'] not in {'BOUND_CALLER_VALUE', 'CONTEXT_AVAILABLE'}:
            residual.append({'contract_id': c['id'], 'reason': row['status'], 'missing_parameters': missing})
        results.append(row)
    residual.extend({'reason': 'SCENARIO_UNKNOWN', 'text': text} for text in unknowns)
    return {'status': 'UNRESOLVED' if residual else 'INPUT_BINDINGS_COMPLETE', 'contracts': results, 'residual': residual,
            'request': deepcopy(request), 'contract_pack_sha256': digest(contract_pack), 'request_sha256': digest(request),
            'compliance_verdict': None, 'external_effects': [], 'evaluation_scope': 'PARAMETER_BINDING_AND_EVIDENCE_AVAILABILITY;NO_INFERRED_POLICY_SATISFACTION'}
