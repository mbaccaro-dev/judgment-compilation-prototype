"""Defines and executes the typed check records."""
from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from fractions import Fraction
from typing import Any

from .finite_enum_table_lookup import (
    FiniteEnumTableLookupError,
    evaluate_reviewed_program,
    validate_reviewed_program,
)

SCHEMA = 'jc-local-semantic-contracts/2'
CEILING = 'LOCAL_TYPED_WARRANT_EXECUTION_ONLY;NO_COMPLIANCE_OR_RESPONSIBILITY_VERDICT'
STACK_PREFIXES = {'judgment': 1, 'work': 2, 'architecture': 3}
COORDINATE_MODEL = 'CHILD_Gs_EQUALS_PARENT_Gs_APPEND_PARENT_L;L_EQUALS_SIBLING_ORDINAL'


class SemanticContractError(ValueError):
    """Malformed or unsupported semantic input; no partial output is released."""


def _need(ok, reason):
    if not ok:
        raise SemanticContractError(reason)


def _keys(row, required, optional=()):
    _need(type(row) is dict and set(required) <= set(row) <= set(required) | set(optional),
          'unexpected or missing fields')


def _text(value):
    return type(value) is str and 0 < len(value) <= 4096 and value.strip() == value and not any(ord(x) < 32 for x in value)


def _names(values):
    _need(type(values) is list and all(_text(v) for v in values) and len(set(values)) == len(values), 'invalid or duplicate names')


def canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
    except (ValueError, TypeError, RecursionError) as exc:
        raise SemanticContractError('not canonical JSON') from exc


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _path(path):
    _need(type(path) is list and len(path) <= 64 and all(type(i) is int and 1 <= i <= 2147483647 for i in path), 'invalid canonical domain path')
    return tuple(path)


def coordinate(path, occurrence=0):
    p = _path(path)
    _need(type(occurrence) is int and 0 <= occurrence <= 2147483647, 'invalid occurrence')
    if not p:
        return {'Gs': [], 'L': 0, 'I': occurrence}
    return {'Gs': [0, *p[:-1]], 'L': p[-1], 'I': occurrence}


def path_from_coordinate(value):
    _keys(value, {'Gs', 'L', 'I'})
    _need(type(value['Gs']) is list and type(value['L']) is int and type(value['I']) is int,
          'invalid coordinate')
    if value['Gs'] == [] and value['L'] == 0:
        path = []
    else:
        _need(bool(value['Gs']) and value['Gs'][0] == 0, 'coordinate has no domain root lineage')
        path = [*value['Gs'][1:], value['L']]
    _need(value == coordinate(path, value['I']), 'coordinate disagrees with canonical position')
    return path


def semantic_coordinate(stack, path):
    """Project a nonempty stack-local sibling path into canonical (Gs,L)."""
    _need(stack in STACK_PREFIXES, 'unknown semantic stack')
    _need(type(path) is list and 1 <= len(path) <= 64 and
          all(type(i) is int and 0 <= i <= 2147483647 for i in path),
          'invalid semantic definition path')
    return {'Gs': [STACK_PREFIXES[stack], *path[:-1]], 'L': path[-1]}


def _semantic_key(value, stack):
    _keys(value, {'Gs', 'L'})
    _need(type(value['Gs']) is list and 1 <= len(value['Gs']) <= 64 and
          value['Gs'][0] == STACK_PREFIXES[stack] and
          all(type(i) is int and 0 <= i <= 2147483647 for i in value['Gs'][1:]) and
          type(value['L']) is int and 0 <= value['L'] <= 2147483647,
          'invalid semantic coordinate')
    return (tuple(value['Gs']), value['L'])


def _validate_semantic_capital(value):
    _keys(value, {'coordinate_model', *STACK_PREFIXES})
    _need(value['coordinate_model'] == COORDINATE_MODEL, 'unsupported semantic coordinate model')
    indexes = {}
    for stack in STACK_PREFIXES:
        rows = value[stack]
        _need(type(rows) is list and bool(rows), 'semantic definition tree required')
        index = {}
        for row in rows:
            _keys(row, {'coordinate', 'label', 'aliases'})
            key = _semantic_key(row['coordinate'], stack)
            _need(key not in index and _text(row['label']), 'duplicate or invalid semantic definition')
            _names(row['aliases'])
            index[key] = row
        for gs, level in index:
            if len(gs) > 1:
                _need((gs[:-1], gs[-1]) in index, 'dangling semantic definition branch')
        indexes[stack] = index
    return indexes


def identity(root_id, path, occurrence=0):
    _need(_text(root_id), 'invalid root identity')
    return canonical([root_id, coordinate(path, occurrence)]).decode('utf-8')


def _index(rows, name):
    _need(type(rows) is list, name + ' must be a list')
    _need(all(type(r) is dict and _text(r.get('id')) for r in rows), 'invalid ' + name + ' identity')
    out = {r['id']: r for r in rows}
    _need(len(out) == len(rows), 'duplicate ' + name + ' identity')
    return out


def _order(steps):
    by_id = _index(steps, 'steps')
    for step in steps:
        _names(step['depends_on'])
        _need(set(step['depends_on']) <= set(by_id) and step['id'] not in step['depends_on'], 'dangling or self dependency')
    ordered, remaining = [], set(by_id)
    while remaining:
        ready = sorted(i for i in remaining if set(by_id[i]['depends_on']) <= set(ordered))
        _need(bool(ready), 'cyclic architecture dependencies')
        ordered.extend(ready)
        remaining.difference_update(ready)
    return ordered


def _validate_completion(completion, step_ids):
    _keys(completion, {'required_steps', 'exclusive_terminal_groups'})
    _names(completion['required_steps'])
    _need(bool(completion['required_steps']), 'completion required steps required')
    groups = completion['exclusive_terminal_groups']
    _need(type(groups) is list and bool(groups), 'completion terminal groups required')
    accounted = set(completion['required_steps'])
    for group in groups:
        _names(group)
        _need(len(group) >= 2, 'exclusive terminal group requires alternatives')
        _need(not accounted.intersection(group), 'completion step appears more than once')
        accounted.update(group)
    _need(accounted == set(step_ids), 'completion must account for every architecture step')


def _architecture_complete(architecture, results):
    completion = architecture.get('completion')
    if completion is None:
        return all(result['status'] == 'APPLIED' for result in results.values())
    if any(results[step]['status'] != 'APPLIED' for step in completion['required_steps']):
        return False
    for group in completion['exclusive_terminal_groups']:
        applied = [step for step in group if results[step]['status'] == 'APPLIED']
        if len(applied) != 1:
            return False
        for step in group:
            if step != applied[0] and (results[step]['status'] != 'NOT_APPLICABLE' or results[step].get('residuals')):
                return False
    return True


def validate_semantic_pack(pack):
    """Validate and copy a semantic pack."""
    _keys(pack, {'schema', 'id', 'root_id', 'domain', 'semantic_capital', 'entity_kinds', 'predicates', 'sources', 'judgments', 'work', 'architectures'})
    _need(pack['schema'] == SCHEMA and _text(pack['id']) and _text(pack['root_id']), 'unsupported schema or identity')
    _names(pack['entity_kinds'])
    _need(bool(pack['entity_kinds']), 'entity kinds required')
    _need(type(pack['domain']) is list and bool(pack['domain']), 'domain root required')
    paths = set()
    for node in pack['domain']:
        _keys(node, {'path', 'label', 'aliases'}, {'entity_kind', 'specializes', 'unit'})
        p = _path(node['path'])
        _need(p not in paths and _text(node['label']), 'duplicate domain position or invalid label')
        paths.add(p)
        _names(node['aliases'])
    _need(() in paths and all(not p or p[:-1] in paths for p in paths), 'dangling domain branch')
    semantic = _validate_semantic_capital(pack['semantic_capital'])
    predicates = _index(pack['predicates'], 'predicates')
    for p in predicates.values():
        _keys(p, {'id', 'roles', 'origin'}, {'input_kind', 'value_type', 'classification', 'domain_root', 'enum_values'})
        _need(p.get('value_type', 'BOOLEAN') in VALUE_TYPES, 'unsupported predicate value type')
        _need(('classification' not in p and p.get('value_type') != 'DOMAIN') or (p.get('value_type') == 'DOMAIN' and p.get('classification') == 'EXACT'), 'domain predicates require exact classification semantics')
        if p.get('value_type') == 'DOMAIN':
            _need('domain_root' in p and _path(p['domain_root']) in paths, 'domain classification requires a valid semantic root')
        else:
            _need('domain_root' not in p, 'domain root only applies to domain classification')
        if p.get('value_type') == 'ENUM':
            _need(type(p.get('enum_values')) is list and bool(p['enum_values']), 'enum predicate requires a vocabulary')
            _names(p['enum_values'])
        else:
            _need('enum_values' not in p, 'enum vocabulary only applies to enum predicates')
        _need(p.get('input_kind', 'SCENARIO_FACT') in {'SCENARIO_FACT', 'PARAMETER_BINDING', 'EVIDENCE'}, 'unsupported input kind')
        _need(p['origin'] in {'INPUT', 'DERIVED'}, 'invalid predicate origin')
        _need(type(p['roles']) is dict and bool(p['roles']) and all(_text(k) and v in pack['entity_kinds'] for k, v in p['roles'].items()), 'invalid predicate roles')
    sources = _index(pack['sources'], 'sources')
    for source in sources.values():
        _keys(source, {'id', 'sha256'})
        _need(type(source['sha256']) is str and len(source['sha256']) == 64 and all(c in '0123456789abcdef' for c in source['sha256']), 'invalid source hash')
    _domain_types(pack, sources)
    judgments = _index(pack['judgments'], 'judgments')
    for j in judgments.values():
        _keys(j, {'id', 'semantic_coordinate', 'bindings', 'premises', 'output', 'source_ids', 'residual'}, {'overrides'})
        _need(_semantic_key(j['semantic_coordinate'], 'judgment') in semantic['judgment'], 'unknown judgment semantic definition')
        _need(type(j['bindings']) is dict and bool(j['bindings']) and all(_text(k) and v in pack['entity_kinds'] for k, v in j['bindings'].items()), 'invalid required bindings')
        _need(type(j['premises']) is list and bool(j['premises']), 'warrant premises required')
        _need(_text(j['residual']), 'residual explanation required')
        _names(j['source_ids'])
        _need(bool(j['source_ids']) and set(j['source_ids']) <= set(sources), 'unsupported judgment source link')
        for clause in [*j['premises'], j['output']]:
            _keys(clause, {'predicate', 'arguments', 'value'}, {'semantic_kind'} if clause is j['output'] else {'operator'})
            _need(clause['predicate'] in predicates, 'unsupported predicate')
            p = predicates[clause['predicate']]
            _validate_value(pack, p, clause['value'])
            if clause is not j['output']:
                op = clause.get('operator', 'EQ')
                kind = p.get('value_type', 'BOOLEAN')
                _need(op == 'EQ' or (op == 'IS_A' and kind == 'DOMAIN') or (op in COMPARISONS and kind in {'INTEGER','UNSIGNED_64_INTEGER','QUANTITY'}), 'unsupported premise operator')
            _need(type(clause['arguments']) is dict and set(clause['arguments']) == set(p['roles']), 'predicate arguments mismatch')
            _need(all(v in j['bindings'] and j['bindings'][v] == p['roles'][k] for k, v in clause['arguments'].items()), 'unbound or mistyped warrant role')
        _need(predicates[j['output']['predicate']]['origin'] == 'DERIVED', 'output must use derived predicate')
        _need(j['output'].get('semantic_kind') in {'SOURCE_BOUND_REQUIREMENT', 'SCENARIO_DERIVATION'}, 'unsupported output authority/type')
        _need(all(c['predicate'] != j['output']['predicate'] for c in j['premises']), 'circular warrant')
    _validate_overrides(judgments, sources)
    work = _index(pack['work'], 'work')
    for w in work.values():
        _need(_text(w.get('operation')), 'missing work operation')
        _need(_semantic_key(w.get('semantic_coordinate'), 'work') in semantic['work'], 'unknown work semantic definition')
        if w['operation'] != 'APPLY_JUDGMENT':
            _validate_extended_work(pack, w, judgments, predicates, paths, sources)
            continue
        _keys(w, {'id', 'semantic_coordinate', 'operation', 'judgment', 'domain_path'})
        _need(w['operation'] == 'APPLY_JUDGMENT', 'unsupported work operation')
        _need(w['judgment'] in judgments and _path(w['domain_path']) in paths, 'unsupported work judgment/domain link')
        _need(not _exception_participant(judgments, w['judgment']), 'exception-linked judgment requires resolution work')
    architectures = _index(pack['architectures'], 'architectures')
    for a in architectures.values():
        _keys(a, {'id', 'semantic_coordinate', 'steps'}, {'completion'})
        _need(_semantic_key(a['semantic_coordinate'], 'architecture') in semantic['architecture'], 'unknown architecture semantic definition')
        _need(type(a['steps']) is list and bool(a['steps']), 'architecture steps required')
        for step in a['steps']:
            _keys(step, {'id', 'work', 'depends_on'})
            _need(step['work'] in work, 'unsupported architecture work link')
        _order(a['steps'])
        if 'completion' in a:
            _validate_completion(a['completion'], _index(a['steps'], 'steps'))
    # All externally supplied scalars must survive the common JSON boundary.
    return json.loads(canonical(pack))


def resolve_domain(pack, alias, within_path=None):
    p = validate_semantic_pack(pack)
    _need(_text(alias), 'invalid alias')
    scope = _path(within_path) if within_path is not None else ()
    _need(any(tuple(n['path']) == scope for n in p['domain']), 'unknown domain scope')
    matches = sorted((n for n in p['domain'] if tuple(n['path'][:len(scope)]) == scope and alias.casefold() in {x.casefold() for x in [n['label'], *n['aliases']]}), key=lambda n: n['path'])
    return {'status': 'RESOLVED' if len(matches) == 1 else 'AMBIGUOUS' if matches else 'NOT_FOUND',
            'candidates': [{'identity': identity(p['root_id'], n['path']), **n, 'coordinate': coordinate(n['path'])} for n in matches],
            'residuals': [] if len(matches) == 1 else ['MULTIPLE_MEANINGS_REQUIRE_CONTEXT' if matches else 'NO_SUPPORTED_MEANING'],
            'claim_ceiling': 'ALIAS_CANDIDATES_ONLY;NO_OCCURRENCE_OR_FACT_WARRANT'}


def _request(pack, request):
    _keys(request, {'entities', 'facts', 'bindings'}, {'unknowns'})
    _need(type(request['entities']) is dict and all(_text(k) and v in pack['entity_kinds'] for k, v in request['entities'].items()), 'invalid entity identities/kinds')
    _need(type(request['bindings']) is dict, 'invalid bindings')
    predicates = {p['id']: p for p in pack['predicates']}
    # A finite table lookup owns its own unknown-enum residual.  Preserve an
    # unknown input for that operation so it returns
    # UNRESOLVED rather than being rejected before the table evaluator runs.
    finite_enum_inputs = {
        port['selector']['predicate']
        for work in pack['work'] if work['operation'] == 'FINITE_ENUM_TABLE_LOOKUP'
        for port in work['input_ports']
    }
    facts = _index(request['facts'], 'facts')
    for f in facts.values():
        _keys(f, {'id', 'predicate', 'arguments', 'value'})
        _need(not f['id'].startswith('derived:') and f['predicate'] in predicates and predicates[f['predicate']]['origin'] == 'INPUT', 'unsupported or forged derived input fact')
        _validate_value(pack, predicates[f['predicate']], f['value'], nullable=True,
                        allow_unknown_enum=f['predicate'] in finite_enum_inputs)
        _arguments(f, predicates, request['entities'])
    unknowns = request.get('unknowns', [])
    _need(type(unknowns) is list, 'invalid declared unknowns')
    seen = set()
    for unknown in unknowns:
        if type(unknown) is str:
            _need(_text(unknown), 'invalid unscoped unknown')
            key = ('text', unknown)
        else:
            _keys(unknown, {'id', 'text', 'predicate', 'arguments'})
            _need(_text(unknown['id']) and _text(unknown['text']), 'invalid scoped unknown identity/text')
            _need(unknown['predicate'] in predicates and predicates[unknown['predicate']]['origin'] == 'INPUT', 'unknown scope must name a declared input predicate')
            _arguments(unknown, predicates, request['entities'])
            key = ('id', unknown['id'])
        _need(key not in seen, 'duplicate declared unknown')
        seen.add(key)
    return deepcopy(request)


def _arguments(fact, predicates, entities):
    roles = predicates[fact['predicate']]['roles']
    _need(type(fact['arguments']) is dict and set(fact['arguments']) == set(roles), 'fact arguments mismatch')
    _need(all(v in entities and entities[v] == roles[k] for k, v in fact['arguments'].items()), 'dangling or mistyped fact entity')


def _unknown_residuals(request, selectors, bound, include_unscoped=True):
    """Match declared unknowns to exact input slots, never infer scope from prose."""
    slots = [(slot['predicate'], {k: bound[v] for k, v in slot['arguments'].items()})
             for slot in selectors if all(v in bound for v in slot['arguments'].values())]
    result = []
    for unknown in request.get('unknowns', []):
        if type(unknown) is str:
            if include_unscoped:
                result.append({'reason': 'USER_DECLARED_UNKNOWN', 'text': unknown})
        elif (unknown['predicate'], unknown['arguments']) in slots:
            result.append({'reason': 'USER_DECLARED_UNKNOWN', 'unknown_id': unknown['id'],
                           'text': unknown['text'], 'predicate': unknown['predicate'],
                           'arguments': deepcopy(unknown['arguments'])})
    return result


def _evaluate(pack, judgment_id, request, facts):
    judgments = {j['id']: j for j in pack['judgments']}
    _need(judgment_id in judgments, 'unknown judgment')
    j = judgments[judgment_id]
    _need(set(request['bindings']) <= set(j['bindings']), 'foreign required binding')
    residuals, bound = [], {}
    for role, kind in sorted(j['bindings'].items()):
        candidates = request['bindings'].get(role, [])
        _names(candidates)
        _need(all(i in request['entities'] and request['entities'][i] == kind for i in candidates), 'invalid binding candidate')
        if len(candidates) != 1:
            residuals.append({'reason': 'MISSING_BINDING' if not candidates else 'AMBIGUOUS_BINDING', 'binding': role, 'candidates': sorted(candidates)})
        else:
            bound[role] = candidates[0]
    residuals.extend(_unknown_residuals(request, j['premises'], bound))
    support = []
    semantic_sources = set()
    opposed = False
    if len(bound) == len(j['bindings']):
        for index, clause in enumerate(j['premises']):
            args = {k: bound[v] for k, v in clause['arguments'].items()}
            matched = [f for f in facts if f['predicate'] == clause['predicate'] and f['arguments'] == args]
            predicate = next(p for p in pack['predicates'] if p['id'] == clause['predicate'])
            values = {_value_key(pack, predicate, f['value']) for f in matched if f['value'] is not None}
            if len(values) > 1:
                residuals.append({'reason': 'CONFLICTING_FACTS', 'premise': index, 'predicate': clause['predicate'], 'arguments': args, 'fact_ids': sorted(f['id'] for f in matched)})
            elif any(f['value'] is None for f in matched):
                residuals.append({'reason': 'UNKNOWN_EVIDENCE', 'premise': index, 'predicate': clause['predicate'], 'arguments': args, 'fact_ids': sorted(f['id'] for f in matched)})
            elif not values:
                input_kind = next(p for p in pack['predicates'] if p['id'] == clause['predicate']).get('input_kind', 'SCENARIO_FACT')
                reason = {'PARAMETER_BINDING': 'MISSING_PARAMETER', 'EVIDENCE': 'MISSING_EVIDENCE', 'SCENARIO_FACT': 'MISSING_FACT'}[input_kind]
                residuals.append({'reason': reason, 'premise': index, 'predicate': clause['predicate'], 'arguments': args})
            elif not _compare(pack, predicate, next(f['value'] for f in matched if f['value'] is not None), clause['value'], clause.get('operator', 'EQ')):
                opposed = True
            else:
                support.extend(f['id'] for f in matched)
                for f in matched:
                    semantic_sources.update(f.get('source_ids', []))
                    semantic_sources.update(_unit_sources(pack, f['value']))
                    if clause.get('operator') == 'IS_A':
                        semantic_sources.update(_specialization_sources(pack, f['value'], clause['value']))
                semantic_sources.update(_unit_sources(pack, clause['value']))
    status = 'UNRESOLVED' if residuals else 'NOT_APPLICABLE' if opposed else 'APPLIED'
    output = None
    if status == 'APPLIED':
        clause = j['output']
        output = {'id': 'derived:' + digest({'judgment': judgment_id, 'bindings': bound, 'support': sorted(set(support))}),
                  'predicate': clause['predicate'], 'arguments': {k: bound[v] for k, v in clause['arguments'].items()},
                  'value': clause['value'], 'type': 'DETERMINISTIC_DERIVATION', 'semantic_kind': clause['semantic_kind'], 'support': sorted(set(support)), 'source_ids': sorted(set(j['source_ids']) | semantic_sources | set(_unit_sources(pack, clause['value'])))}
    return {'judgment_id': judgment_id, 'judgment_coordinate': deepcopy(j['semantic_coordinate']),
            'status': status, 'bindings': bound, 'output': output,
            'residuals': [{'type': 'UNRESOLVED', **item} for item in residuals], 'residual_explanation': j['residual'] if residuals else None,
            'source_requirements': [{'type': 'SOURCE_BOUND', **s} for s in pack['sources'] if s['id'] in j['source_ids']],
            'claim_ceiling': CEILING, 'compliance_verdict': None, 'responsibility_determination': None, 'external_effects': []}


def evaluate_judgment(pack, judgment_id, request):
    """Evaluate one reusable warrant on typed facts; uncertainty never is false."""
    p = validate_semantic_pack(pack)
    r = _request(p, request)
    _need(not _exception_participant({j['id']:j for j in p['judgments']}, judgment_id), 'exception-linked judgment requires resolution work')
    return _evaluate(p, judgment_id, r, r['facts'])


def execute_architecture(pack, architecture_id, request):
    """Execute a finite Work graph in dependency order."""
    p = validate_semantic_pack(pack)
    r = _request(p, request)
    architectures = {a['id']: a for a in p['architectures']}
    _need(architecture_id in architectures, 'unknown architecture')
    a = architectures[architecture_id]
    steps = {s['id']: s for s in a['steps']}
    _need(set(r['bindings']) <= set(steps), 'foreign architecture step binding')
    work = {w['id']: w for w in p['work']}
    judgments = {j['id']: j for j in p['judgments']}
    # Validate all supplied bindings before execution, including blocked steps.
    # Dependency uncertainty never makes malformed input admissible.
    for sid, bindings in r['bindings'].items():
        required = _work_bindings(work[steps[sid]['work']], judgments)
        _need(type(bindings) is dict, 'invalid step bindings')
        _need(set(bindings) <= set(required), 'foreign required binding')
        for role, candidates in bindings.items():
            _names(candidates)
            _need(all(i in r['entities'] and r['entities'][i] == required[role] for i in candidates),
                  'invalid binding candidate')
    results, ancestors = {}, {}
    for sid in _order(a['steps']):
        step = steps[sid]
        ancestors[sid] = set(step['depends_on'])
        for parent in step['depends_on']:
            ancestors[sid].update(ancestors[parent])
        blocked = sorted(i for i in step['depends_on'] if results[i]['status'] != 'APPLIED')
        if blocked:
            result = {'status': 'BLOCKED', 'output': None, 'residuals': [{'type': 'UNRESOLVED', 'reason': 'DEPENDENCY_UNRESOLVED_OR_NOT_APPLICABLE', 'steps': blocked}]}
        else:
            facts = r['facts'] + [results[i]['output'] for i in sorted(ancestors[sid]) if results[i]['output'] is not None]
            local = {**r, 'bindings': r['bindings'].get(sid, {})}
            _need(type(local['bindings']) is dict, 'invalid step bindings')
            result = _execute_work(p, work[step['work']], local, facts)
        if result['output'] is not None:
            result['output']['id'] = 'derived:' + digest({'architecture': architecture_id, 'step': sid, 'output': result['output']})
        results[sid] = {'step_id': sid, 'work_id': step['work'],
                        'work_coordinate': deepcopy(work[step['work']]['semantic_coordinate']), **result}
    outputs = [results[i]['output'] for i in results if results[i]['output'] is not None]
    return {'architecture_id': architecture_id, 'architecture_coordinate': deepcopy(a['semantic_coordinate']),
            'status': 'COMPLETE' if _architecture_complete(a, results) else 'UNRESOLVED',
            'steps': list(results.values()), 'outputs': outputs,
            'unknowns': deepcopy(r.get('unknowns', [])),
            'support_graph': [{'from': support, 'to': o['id'], 'relation': 'SUPPORTS'} for o in outputs for support in o['support']],
            'pack_sha256': digest(p), 'request_sha256': digest(r), 'claim_ceiling': CEILING,
            'compliance_verdict': None, 'responsibility_determination': None, 'external_effects': []}



# Typed values belong to domain definitions and instances.
VALUE_TYPES = {'BOOLEAN', 'INTEGER', 'UNSIGNED_64_INTEGER', 'DOMAIN', 'QUANTITY', 'ENUM'}
COMPARISONS = {'EQ', 'LT', 'LE', 'GT', 'GE'}


def _bounded_integer(value, positive=False):
    return type(value) is int and (-2147483647 <= value <= 2147483647) and (not positive or value > 0)


def _bounded_unsigned_64_integer(value):
    """Accept one exact non-Boolean unsigned 64-bit integer value."""
    return type(value) is int and 0 <= value <= 18446744073709551615


def _source_links(ids, sources):
    _names(ids)
    _need(bool(ids) and set(ids) <= set(sources), 'unsupported semantic source link')


def _domain_types(pack, sources):
    nodes = {tuple(n['path']): n for n in pack['domain']}
    kinds = set()
    for path, node in nodes.items():
        if 'entity_kind' in node:
            kind = node['entity_kind']
            _need(kind in pack['entity_kinds'] and kind not in kinds, 'invalid or duplicate domain entity kind')
            kinds.add(kind)
        parents = node.get('specializes', [])
        _need(type(parents) is list, 'invalid specialization list')
        seen = set()
        for edge in parents:
            _keys(edge, {'path', 'source_ids'})
            parent = _path(edge['path'])
            _need(parent in nodes and parent != path and parent not in seen, 'invalid specialization edge')
            seen.add(parent)
            _source_links(edge['source_ids'], sources)
        if 'unit' in node:
            unit = node['unit']
            _keys(unit, {'dimension_path', 'numerator', 'denominator', 'source_ids', 'basis'}, {'calendar_id'})
            dimension = _path(unit['dimension_path'])
            _need(dimension in nodes and 'unit' not in nodes[dimension], 'invalid unit dimension')
            _need(_bounded_integer(unit['numerator'], True) and _bounded_integer(unit['denominator'], True), 'invalid exact unit scale')
            _need(unit['basis'] in {'FIXED_RATIO', 'CALENDAR_DAY', 'BUSINESS_DAY'}, 'unsupported unit basis')
            if unit['basis'] == 'FIXED_RATIO':
                _need('calendar_id' not in unit, 'fixed-ratio unit cannot assert a calendar')
            else:
                _need(_text(unit.get('calendar_id')) and unit['numerator'] == unit['denominator'] == 1, 'calendar units require an explicit calendar identity and no fixed-second conversion')
            _source_links(unit['source_ids'], sources)
    # Positional containment does not imply specialization; only these edges do.
    done, pending = set(), set(nodes)
    while pending:
        ready = {p for p in pending if all(tuple(e['path']) in done for e in nodes[p].get('specializes', []))}
        _need(bool(ready), 'cyclic domain specialization')
        done.update(ready)
        pending.difference_update(ready)


def _validate_value(pack, predicate, value, nullable=False, allow_unknown_enum=False):
    if value is None and nullable:
        return
    kind = predicate.get('value_type', 'BOOLEAN')
    if kind == 'BOOLEAN':
        _need(type(value) is bool, 'invalid Boolean value')
    elif kind == 'INTEGER':
        _need(_bounded_integer(value), 'invalid bounded integer value')
    elif kind == 'UNSIGNED_64_INTEGER':
        _need(_bounded_unsigned_64_integer(value), 'invalid unsigned 64-bit integer value')
    elif kind == 'DOMAIN':
        _need(_path(value) in {tuple(n['path']) for n in pack['domain']}, 'unknown domain value')
        _need(_compare(pack, predicate, value, predicate['domain_root'], 'IS_A'), 'domain value outside declared classification root')
    elif kind == 'QUANTITY':
        _keys(value, {'amount', 'unit_path'})
        _need(_bounded_integer(value['amount']), 'invalid quantity amount')
        path = _path(value['unit_path'])
        node = next((n for n in pack['domain'] if tuple(n['path']) == path), None)
        _need(node is not None and 'unit' in node, 'unknown quantity unit')
    elif kind == 'ENUM':
        _need(allow_unknown_enum or value in predicate['enum_values'], 'enum value is outside declared vocabulary')
    else:
        _need(False, 'unsupported value type')


def _quantity(pack, value):
    unit = next(n['unit'] for n in pack['domain'] if n['path'] == value['unit_path'])
    return ((tuple(unit['dimension_path']), unit['basis'], unit.get('calendar_id')), Fraction(value['amount'] * unit['numerator'], unit['denominator']))


def _value_key(pack, predicate, value):
    if predicate.get('value_type', 'BOOLEAN') == 'QUANTITY':
        dimension, amount = _quantity(pack, value)
        return canonical([list(dimension), amount.numerator, amount.denominator])
    return canonical(value)


def _compare(pack, predicate, left, right, operator):
    kind = predicate.get('value_type', 'BOOLEAN')
    if operator == 'IS_A':
        _need(kind == 'DOMAIN', 'specialization requires domain values')
        nodes = {tuple(n['path']): n for n in pack['domain']}
        todo, visited = [tuple(left)], set()
        while todo:
            path = todo.pop()
            if path == tuple(right):
                return True
            if path not in visited:
                visited.add(path)
                todo.extend(tuple(e['path']) for e in nodes[path].get('specializes', []))
        return False
    _need(operator in COMPARISONS, 'unsupported comparison')
    if kind == 'QUANTITY':
        ld, left = _quantity(pack, left)
        rd, right = _quantity(pack, right)
        _need(ld == rd, 'incompatible quantity dimensions or unit bases')
    elif kind in {'BOOLEAN', 'DOMAIN'}:
        _need(operator == 'EQ', 'unordered semantic value')
    return {'EQ': lambda: left == right, 'LT': lambda: left < right,
            'LE': lambda: left <= right, 'GT': lambda: left > right,
            'GE': lambda: left >= right}[operator]()


def _validate_selector(slot, predicates, bindings):
    _keys(slot, {'predicate', 'arguments'})
    _need(slot['predicate'] in predicates, 'unknown value selector predicate')
    roles = predicates[slot['predicate']]['roles']
    _need(type(slot['arguments']) is dict and set(slot['arguments']) == set(roles), 'value selector roles mismatch')
    _need(all(v in bindings and bindings[v] == roles[k] for k, v in slot['arguments'].items()), 'unbound value selector role')


def _work_bindings(work, judgments):
    if work['operation'] in {'COMPARE_VALUES', 'FINITE_ENUM_TABLE_LOOKUP'}:
        return work['bindings']
    if work['operation'] == 'COMPARE_INTEGER_POWER_OF_TWO_MINUS_ONE':
        return judgments[work['judgment']]['bindings']
    key = work['judgment'] if work['operation'] == 'APPLY_JUDGMENT' else work['judgments'][0]
    return judgments[key]['bindings']


def _validate_extended_work(pack, work, judgments, predicates, paths, sources):
    if work['operation'] == 'RESOLVE_JUDGMENTS':
        _keys(work, {'id', 'semantic_coordinate', 'operation', 'judgments', 'domain_path'})
        _names(work['judgments'])
        _need(bool(work['judgments']) and set(work['judgments']) <= set(judgments), 'unknown candidate judgments')
        chosen = [judgments[i] for i in work['judgments']]
        first = chosen[0]
        signature = lambda j: (j['bindings'], j['output']['predicate'], j['output']['arguments'])
        _need(all(signature(j) == signature(first) for j in chosen), 'incompatible decision keys')
        selected = set(work['judgments'])
        for j in judgments.values():
            targets = {e['judgment_id'] for e in j.get('overrides', [])}
            _need(not (targets & selected) or j['id'] in selected, 'candidate set omits a declared exception')
            if j['id'] in selected:
                _need(targets <= selected, 'candidate set omits an overridden rule')
    elif work['operation'] == 'COMPARE_VALUES':
        _keys(work, {'id', 'semantic_coordinate', 'operation', 'bindings', 'left', 'right', 'operator', 'output', 'domain_path'})
        bindings = work['bindings']
        _need(type(bindings) is dict and bool(bindings) and all(_text(k) and v in pack['entity_kinds'] for k, v in bindings.items()), 'invalid comparison bindings')
        for slot in (work['left'], work['right'], work['output']):
            _validate_selector(slot, predicates, bindings)
        left, right, output = [predicates[work[s]['predicate']] for s in ('left', 'right', 'output')]
        _need(left['roles'] == right['roles'] == output['roles'] and work['left']['arguments'] == work['right']['arguments'] == work['output']['arguments'], 'comparison subject identity mismatch')
        _need(left.get('value_type', 'BOOLEAN') == right.get('value_type', 'BOOLEAN'), 'comparison value type mismatch')
        _need(work['operator'] in COMPARISONS and (left.get('value_type', 'BOOLEAN') in {'INTEGER','UNSIGNED_64_INTEGER','QUANTITY'} or work['operator'] == 'EQ'), 'unsupported comparison operation')
        _need(output['origin'] == 'DERIVED' and output.get('value_type', 'BOOLEAN') == 'BOOLEAN', 'comparison output must be a derived Boolean')
        _need(work['output']['predicate'] not in {work['left']['predicate'],work['right']['predicate']}, 'circular comparison')
    elif work['operation'] == 'COMPARE_INTEGER_POWER_OF_TWO_MINUS_ONE':
        _keys(work, {'id', 'semantic_coordinate', 'operation', 'judgment', 'left', 'exponent', 'operator', 'output', 'domain_path'})
        _need(work['judgment'] in judgments, 'unknown integer-expression condition judgment')
        condition = judgments[work['judgment']]
        _need(condition['output'].get('value_type', 'BOOLEAN') == 'BOOLEAN', 'integer-expression condition must have a Boolean output')
        bindings = condition['bindings']
        for slot in (work['left'], work['exponent'], work['output']):
            _validate_selector(slot, predicates, bindings)
        left, exponent, output = [predicates[work[s]['predicate']] for s in ('left', 'exponent', 'output')]
        _need(left['roles'] == exponent['roles'] == output['roles'] and work['left']['arguments'] == work['exponent']['arguments'] == work['output']['arguments'], 'integer-expression subject identity mismatch')
        _need(left.get('value_type') == exponent.get('value_type') == 'UNSIGNED_64_INTEGER', 'integer-expression operands must be unsigned 64-bit integers')
        _need(work['operator'] == 'GT', 'unsupported integer-expression comparison')
        _need(output['origin'] == 'DERIVED' and output.get('value_type', 'BOOLEAN') == 'BOOLEAN', 'integer-expression output must be a derived Boolean')
        _need(work['output']['predicate'] not in {work['left']['predicate'], work['exponent']['predicate']}, 'circular integer-expression comparison')
    elif work['operation'] == 'FINITE_ENUM_TABLE_LOOKUP':
        _keys(work, {'id', 'semantic_coordinate', 'operation', 'judgment', 'bindings', 'input_ports', 'output', 'program', 'source_ids', 'domain_path'})
        bindings = work['bindings']
        _need(type(bindings) is dict and bool(bindings) and all(_text(k) and v in pack['entity_kinds'] for k, v in bindings.items()), 'invalid finite enum bindings')
        _need(work['judgment'] in judgments, 'finite enum source mapping judgment is unknown')
        _need(judgments[work['judgment']]['bindings'] == bindings, 'finite enum source mapping judgment binding drift')
        _need(set(judgments[work['judgment']]['source_ids']) <= set(work['source_ids']), 'finite enum source mapping judgment provenance drift')
        _need(type(work['input_ports']) is list and len(work['input_ports']) >= 2, 'finite enum input ports required')
        _source_links(work['source_ids'], sources)
        try:
            program = validate_reviewed_program(work['program'])
        except FiniteEnumTableLookupError as exc:
            raise SemanticContractError('invalid finite enum table program') from exc
        _need(program['operation_id'] == work['id'], 'finite enum program must bind its Work id')
        _need([port.get('id') for port in work['input_ports']] == [port['id'] for port in program['input_ports']], 'finite enum Work ports drift from program')
        selectors = []
        for port, program_port in zip(work['input_ports'], program['input_ports'], strict=True):
            _keys(port, {'id', 'selector'})
            _need(port['id'] == program_port['id'], 'finite enum Work port identity drift')
            _validate_selector(port['selector'], predicates, bindings)
            predicate = predicates[port['selector']['predicate']]
            _need(predicate['origin'] == 'INPUT' and predicate.get('value_type') == 'ENUM', 'finite enum inputs require input enum predicates')
            _need(predicate['enum_values'] == program_port['enum_schema']['values'], 'finite enum input vocabulary drift')
            selectors.append(port['selector'])
        _validate_selector(work['output'], predicates, bindings)
        output = predicates[work['output']['predicate']]
        _need(output['origin'] == 'DERIVED' and output.get('value_type') == 'ENUM', 'finite enum output requires a derived enum predicate')
        _need(output['enum_values'] == program['output_enum_schema']['values'], 'finite enum output vocabulary drift')
        _need(all(selector['arguments'] == work['output']['arguments'] for selector in selectors), 'finite enum subject identity mismatch')
        _need(work['output']['predicate'] not in {selector['predicate'] for selector in selectors}, 'circular finite enum lookup')
    else:
        _need(False, 'unsupported work operation')
    _need(_path(work['domain_path']) in paths, 'unsupported work domain link')


def _validate_overrides(judgments, sources):
    for j in judgments.values():
        edges = j.get('overrides', [])
        _need(type(edges) is list, 'invalid override edges')
        seen = set()
        for edge in edges:
            _keys(edge, {'judgment_id','source_ids'})
            target = edge['judgment_id']
            _need(_text(target) and target in judgments and target != j['id'] and target not in seen, 'invalid override target')
            seen.add(target)
            _source_links(edge['source_ids'], sources)
            other = judgments[target]
            _need(j['bindings'] == other['bindings'] and j['output']['predicate'] == other['output']['predicate'] and j['output']['arguments'] == other['output']['arguments'], 'override decision key mismatch')
    done, remaining = set(), set(judgments)
    while remaining:
        ready = {i for i in remaining if all(e['judgment_id'] in done for e in judgments[i].get('overrides', []))}
        _need(bool(ready), 'cyclic judgment overrides')
        done.update(ready)
        remaining.difference_update(ready)



def _work_result(work, bound, output=None, residuals=None, **extra):
    residuals = residuals or []
    return {'work_id': work['id'], 'status': 'UNRESOLVED' if residuals else 'APPLIED',
            'bindings': bound, 'output': output,
            'residuals': [{'type': 'UNRESOLVED', **r} for r in residuals],
            'claim_ceiling': CEILING, 'compliance_verdict': None,
            'responsibility_determination': None, 'external_effects': [], **extra}


def _work_bound(work, required, request):
    _need(set(request['bindings']) <= set(required), 'foreign required binding')
    bound, residuals = {}, []
    for role, kind in sorted(required.items()):
        candidates = request['bindings'].get(role, [])
        _names(candidates)
        _need(all(i in request['entities'] and request['entities'][i] == kind for i in candidates), 'invalid binding candidate')
        if len(candidates) == 1:
            bound[role] = candidates[0]
        else:
            residuals.append({'reason': 'AMBIGUOUS_BINDING' if candidates else 'MISSING_BINDING', 'binding': role, 'candidates': sorted(candidates)})
    residuals.extend({'reason': 'USER_DECLARED_UNKNOWN', 'text': x} for x in request.get('unknowns', []) if type(x) is str)
    return bound, residuals


def _unit_sources(pack, value):
    if type(value) is dict and 'unit_path' in value:
        return next(n['unit']['source_ids'] for n in pack['domain'] if n['path'] == value['unit_path'])
    return []


def _execute_work(pack, work, request, facts):
    if work['operation'] == 'APPLY_JUDGMENT':
        return _evaluate(pack, work['judgment'], request, facts)
    judgments = {j['id']: j for j in pack['judgments']}
    required = _work_bindings(work, judgments)
    bound, residuals = _work_bound(work, required, request)
    if work['operation'] == 'RESOLVE_JUDGMENTS':
        candidates = [_evaluate(pack, i, request, facts) for i in sorted(work['judgments'])]
        unresolved = [c for c in candidates if c['status'] == 'UNRESOLVED']
        if unresolved:
            residuals.extend({'reason': 'CANDIDATE_APPLICABILITY_UNRESOLVED', 'judgment_id': c['judgment_id'], 'details': c['residuals']} for c in unresolved)
        applied = {c['judgment_id']: c for c in candidates if c['status'] == 'APPLIED'}
        suppressed, edges = set(), []
        # An edge is effective only between applicable candidates in this exact
        # bound decision. A dormant intermediate exception cannot supply precedence.
        for candidate in sorted(applied):
            for edge in judgments[candidate].get('overrides', []):
                if edge['judgment_id'] in applied:
                    suppressed.add(edge['judgment_id'])
                    edges.append({'from_judgment': candidate, 'to_judgment': edge['judgment_id'],
                                  'relation': 'OVERRIDES', 'source_ids': sorted(edge['source_ids'])})
        winners = sorted(set(applied) - suppressed)
        if not residuals and len(winners) != 1:
            residuals.append({'reason': 'CONFLICTING_JUDGMENTS' if winners else 'NO_APPLICABLE_JUDGMENT', 'candidates': winners})
        trace = {'candidates': candidates, 'override_edges': edges, 'selected_judgment': None}
        if residuals:
            return _work_result(work, bound, residuals=residuals, selection_trace=trace)
        selected = winners[0]
        output = deepcopy(applied[selected]['output'])
        output['source_ids'] = sorted(set(output['source_ids']) | {sid for edge in edges for sid in edge['source_ids']})
        output['id'] = 'derived:' + digest({'work': work, 'bindings': bound, 'candidate_results': candidates, 'override_edges': edges})
        trace['selected_judgment'] = selected
        return _work_result(work, bound, output=output, selection_trace=trace)
    if residuals:
        return _work_result(work, bound, residuals=residuals)
    if work['operation'] == 'FINITE_ENUM_TABLE_LOOKUP':
        ports = work['input_ports']
        residuals.extend(_unknown_residuals(request, [port['selector'] for port in ports], bound, include_unscoped=False))
        if residuals:
            return _work_result(work, bound, residuals=residuals)
        observations, support, source_ids = {}, [], set(work['source_ids'])
        for port in ports:
            slot = port['selector']
            args = {key: bound[value] for key, value in slot['arguments'].items()}
            matched = sorted((fact for fact in facts if fact['predicate'] == slot['predicate'] and fact['arguments'] == args), key=lambda fact: fact['id'])
            observations[port['id']] = [fact['value'] for fact in matched]
            support.extend(fact['id'] for fact in matched)
            for fact in matched:
                source_ids.update(fact.get('source_ids', []))
        try:
            result = evaluate_reviewed_program(
                work['program'], observations,
                expected_program_sha256=work['program']['program_sha256'],
            )
        except FiniteEnumTableLookupError as exc:
            raise SemanticContractError('finite enum table program drifted after validation') from exc
        if result['status'] != 'COMPLETE':
            table_residuals = [
                {'reason': 'FINITE_ENUM_' + item['reason'], 'port': item.get('input'),
                 **({'candidates': item['candidates']} if 'candidates' in item else {}),
                 **({'value': item['value']} if 'value' in item else {})}
                for item in result['residuals']
            ]
            return _work_result(work, bound, residuals=table_residuals,
                                finite_enum_table_lookup=deepcopy(result))
        output = {
            'id': 'derived:' + digest({'work': work, 'bindings': bound, 'observations': observations, 'support': sorted(set(support))}),
            'predicate': work['output']['predicate'],
            'arguments': {key: bound[value] for key, value in work['output']['arguments'].items()},
            'value': result['output'], 'type': 'DETERMINISTIC_DERIVATION',
            'semantic_kind': 'SCENARIO_DERIVATION', 'support': sorted(set(support)),
            'source_ids': sorted(source_ids),
        }
        return _work_result(work, bound, output=output,
                            finite_enum_table_lookup=deepcopy(result))
    gate = None
    if work['operation'] == 'COMPARE_INTEGER_POWER_OF_TWO_MINUS_ONE':
        gate = _evaluate(pack, work['judgment'], request, facts)
        if gate['status'] == 'UNRESOLVED':
            residuals.append({'reason': 'CONDITION_APPLICABILITY_UNRESOLVED', 'judgment_id': work['judgment'], 'details': gate['residuals']})
        elif gate['status'] != 'APPLIED' or gate['output']['value'] is not True:
            result = _work_result(work, bound, condition=gate)
            result['status'] = 'NOT_APPLICABLE'
            return result
    operand_names = ('left', 'exponent') if work['operation'] == 'COMPARE_INTEGER_POWER_OF_TWO_MINUS_ONE' else ('left', 'right')
    residuals.extend(_unknown_residuals(request, [work[name] for name in operand_names], bound, include_unscoped=False))
    predicates = {p['id']: p for p in pack['predicates']}
    values, support, source_ids = {}, [], set()
    if gate is not None and gate['status'] == 'APPLIED':
        support.extend(gate['output']['support'])
        source_ids.update(gate['output']['source_ids'])
    for name in operand_names:
        slot = work[name]
        args = {k: bound[v] for k, v in slot['arguments'].items()}
        matched = sorted((f for f in facts if f['predicate'] == slot['predicate'] and f['arguments'] == args), key=lambda f: f['id'])
        predicate = predicates[slot['predicate']]
        keys = {_value_key(pack, predicate, f['value']) for f in matched if f['value'] is not None}
        reason = None
        if len(keys) > 1:
            reason = 'CONFLICTING_FACTS'
        elif any(f['value'] is None for f in matched):
            reason = 'UNKNOWN_EVIDENCE'
        elif not matched:
            reason = {'PARAMETER_BINDING': 'MISSING_PARAMETER', 'EVIDENCE': 'MISSING_EVIDENCE'}.get(predicate.get('input_kind'), 'MISSING_FACT')
        elif predicate['origin'] == 'DERIVED' and len(matched) != 1:
            reason = 'AMBIGUOUS_DERIVED_RESULT'
        if reason:
            residuals.append({'reason': reason, 'operand': name, 'predicate': slot['predicate'], 'arguments': args, 'fact_ids': [f['id'] for f in matched]})
        else:
            values[name] = matched[0]['value']
            support.extend(f['id'] for f in matched)
            for f in matched:
                source_ids.update(f.get('source_ids', []))
                source_ids.update(_unit_sources(pack, f['value']))
    if work['operation'] == 'COMPARE_INTEGER_POWER_OF_TWO_MINUS_ONE' and not residuals:
        if values['exponent'] > 62:
            residuals.append({'reason': 'EXPONENT_COST_LIMIT', 'operand': 'exponent', 'maximum': 62, 'value': values['exponent']})
    if residuals:
        return _work_result(work, bound, residuals=residuals, condition=gate) if gate is not None else _work_result(work, bound, residuals=residuals)
    if work['operation'] == 'COMPARE_INTEGER_POWER_OF_TWO_MINUS_ONE':
        power = 2 ** values['exponent']
        threshold = power - 1
        value = values['left'] > threshold
        expression = {'operator': work['operator'], 'left': values['left'], 'exponent': values['exponent'], 'base': 2, 'power': power, 'minus_one': 1, 'threshold': threshold, 'value': value}
    else:
        value = _compare(pack, predicates[work['left']['predicate']], values['left'], values['right'], work['operator'])
        expression = {'operator': work['operator'], **values, 'value': value}
    output = {'id': 'derived:' + digest({'work': work, 'bindings': bound, 'values': values, 'support': sorted(set(support))}),
              'predicate': work['output']['predicate'], 'arguments': {k: bound[v] for k, v in work['output']['arguments'].items()},
              'value': value, 'type': 'DETERMINISTIC_DERIVATION', 'semantic_kind': 'SCENARIO_DERIVATION',
              'support': sorted(set(support)), 'source_ids': sorted(source_ids)}
    return _work_result(work, bound, output=output, condition=gate, integer_expression=expression) if gate is not None else _work_result(work, bound, output=output, comparison=expression)



def _exception_participant(judgments, judgment_id):
    return any((j['id'] == judgment_id and j.get('overrides')) or
               any(e['judgment_id'] == judgment_id for e in j.get('overrides', []))
               for j in judgments.values())


def _specialization_sources(pack, actual, expected):
    nodes = {tuple(n['path']): n for n in pack['domain']}
    target = tuple(expected)
    # Compute reachable dependency edges once per node.
    memo = {target: (True, set())}
    def visit(path):
        if path not in memo:
            found, sources = False, set()
            for edge in nodes[path].get('specializes', []):
                reaches, inherited = visit(tuple(edge['path']))
                if reaches:
                    found = True
                    sources.update(inherited)
                    sources.update(edge['source_ids'])
            memo[path] = (found, sources)
        return memo[path]
    return visit(tuple(actual))[1]
