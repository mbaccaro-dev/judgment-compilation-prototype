"""Executes compiled checks."""
from __future__ import annotations
import hashlib
import itertools
import json
import re
from typing import Any
from .operation_interfaces import operation_interfaces
from .semantic_contracts import validate_semantic_pack, execute_architecture, resolve_domain, path_from_coordinate, SemanticContractError

CLAIM_TYPES = frozenset({'SOURCE_BOUND', 'SCENARIO_FACT', 'DETERMINISTIC_DERIVATION', 'AI_INFERENCE', 'UNRESOLVED'})

class Rejected(ValueError):
    """An untrusted boundary failed; no partial result is released."""

def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')

def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()

def require(condition: bool, reason: str) -> None:
    if not condition:
        raise Rejected(reason)

def exact_keys(value: Any, keys: set[str]) -> None:
    require(type(value) is dict and set(value) == keys, 'unexpected or missing fields')

def text(value: Any, limit: int = 4096) -> bool:
    return type(value) is str and 0 < len(value) <= limit and value.strip() == value and not any(ord(c) < 32 for c in value)

def strict_json(raw: str, *, max_chars: int = 100000) -> Any:
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    require(type(max_chars) is int and max_chars >= 0, 'invalid JSON size bound')
    require(type(raw) is str and len(raw) <= max_chars, 'request size')
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(Rejected('nonfinite JSON')))
    except (ValueError, TypeError, RecursionError) as exc:
        raise Rejected('invalid JSON') from exc

def notation(coordinate: dict) -> str:
    try:
        path_from_coordinate(coordinate)
    except SemanticContractError as exc:
        raise Rejected(str(exc)) from exc
    return 'Gs=' + '.'.join(map(str, coordinate['Gs'])) + ';L=' + str(coordinate['L']) + ';I=' + str(coordinate['I'])

def from_notation(value: str) -> dict:
    require(type(value) is str and len(value) < 1024, 'invalid notation')
    match = re.fullmatch(r'Gs=([0-9.]*)\;L=([0-9]+)\;I=([0-9]+)', value)
    require(match is not None, 'invalid notation')
    try:
        result = {'Gs': [int(x) for x in match[1].split('.')] if match[1] else [], 'L': int(match[2]), 'I': int(match[3])}
    except ValueError as exc:
        raise Rejected('invalid notation') from exc
    require(notation(result) == value, 'noncanonical notation')
    return result

def substitutions(roles: dict, entities: list[dict]):
    names = sorted(roles)
    pools = [[e for e in entities if e['kind'] == roles[name]] for name in names]
    for values in itertools.product(*pools):
        yield dict(zip(names, values))

class SemanticRuntime:
    """Run a validated semantic pack with its expected hash."""
    def __init__(self, pack: dict, expected_sha256: str, *, executor=execute_architecture):
        require(digest(pack) == expected_sha256, 'pack integrity')
        semantic = validate_semantic_pack(pack['semantic_pack'])
        require(semantic['entity_kinds'] == pack['entity_kinds'], 'entity kind binding')
        require({x['id']: x['sha256'] for x in semantic['sources']} == {k: digest(v) for k, v in pack['sources'].items()}, 'semantic provenance binding')
        require(set(pack['interpretations']) == {j['id'] for j in semantic['judgments']}, 'missing interpretation binding')
        for key in ('compliance_determination', 'responsibility_assignment', 'external_effects', 'explicit_selection_confirmed', 'production_ready'):
            require(pack['authority_ceiling'].get(key) is False, 'unsupported authority')
        interfaces = operation_interfaces(semantic)
        required_work = {wid for wid, interface in interfaces.items() if not interface['judgment_ids']}
        require(set(pack.get('work_interpretations', {})) == required_work, 'missing executable work interpretation binding')
        require(callable(executor), 'semantic executor required')
        self._executor = executor
        self._pack_bytes = canonical(pack)

    @property
    def pack(self) -> dict:
        return json.loads(self._pack_bytes)

    def parse(self, raw: str) -> dict:
        request = strict_json(raw)
        exact_keys(request, {'request_id', 'scenario_id', 'entities', 'statements', 'unknowns', 'question'})
        require(all(text(request[k], 200) for k in ('request_id', 'scenario_id')), 'request identity')
        require(text(request['question']), 'question')
        entities = request['entities']
        require(type(entities) is list and 1 <= len(entities) <= 12, 'entity cardinality')
        for entity in entities:
            exact_keys(entity, {'id', 'alias', 'kind'})
            require(all(text(entity[k], 120) for k in entity), 'entity fields')
            require(entity['kind'] in self.pack['entity_kinds'], 'unknown entity kind')
        require(len({e['id'] for e in entities}) == len(entities), 'duplicate entity id')
        require(len({e['alias'].casefold() for e in entities}) == len(entities), 'ambiguous entity identity')
        for key in ('statements', 'unknowns'):
            require(type(request[key]) is list and len(request[key]) <= 64 and all(text(x) for x in request[key]), 'statement list')
        facts, residual = [], []
        pack = self.pack
        for index, statement in enumerate(request['statements']):
            matches = []
            for pattern in pack['fact_templates']:
                for binding in substitutions(pattern['roles'], entities):
                    if pattern['text'].format(**{k: v['alias'] for k, v in binding.items()}) == statement:
                        matches.append({'predicate': pattern['predicate'], 'value': pattern['value'], 'bindings': {k: v['id'] for k, v in binding.items()}})
            item = {'id': f'statement:{index}', 'text': statement}
            if len(matches) == 1:
                facts.append({**item, **matches[0]})
            else:
                residual.append({**item, 'reason': 'AMBIGUOUS_STATEMENT' if matches else 'UNSUPPORTED_STATEMENT', 'candidates': matches})
        return {'request': request, 'facts': facts, 'unresolved_statements': residual, 'canonical_request_hash': digest(request)}

    def admit_ingress(self, raw: str, ai_proposal: dict) -> dict:
        expected = self.parse(raw)
        require(canonical(ai_proposal) == canonical(expected), 'ingress proposal changed identities, facts, unknowns or authority')
        return expected

    def execute(self, raw: str, ai_proposal: dict | None = None, *, cancelled: bool = False) -> dict:
        require(not cancelled, 'cancelled; no result released')
        ingress = self.parse(raw) if ai_proposal is None else self.admit_ingress(raw, ai_proposal)
        request, pack = ingress['request'], self.pack
        entities = request['entities']
        claims, edges, trace, resolutions, executions = [], [], [], [], []
        def add(cid, kind, wording, support=(), provenance=(), **extra):
            require(kind in CLAIM_TYPES, 'invalid claim type')
            require(cid not in {c['id'] for c in claims}, 'duplicate claim id')
            claims.append({'id': cid, 'type': kind, 'text': wording, 'support': list(support), 'provenance': list(provenance), **extra})
            edges.extend({'from': sid, 'to': cid, 'relation': 'SUPPORTS'} for sid in support)
        for entity in entities:
            add('entity:' + entity['id'], 'SCENARIO_FACT', entity['alias'] + ' is a ' + entity['kind'] + '.', entity_id=entity['id'])
        for fact in ingress['facts']:
            kind = 'UNRESOLVED' if fact['value'] is None else 'SCENARIO_FACT'
            extra = {'reason': 'UNKNOWN_EVIDENCE'} if fact['value'] is None else {}
            add(fact['id'], kind, fact['text'], bindings=fact['bindings'], predicate=fact['predicate'], value=fact['value'], **extra)
        for item in ingress['unresolved_statements']:
            add(item['id'], 'UNRESOLVED', item['text'], reason=item['reason'], candidates=item['candidates'])
        policies = {s['text']: s for s in pack['unknown_scopes']}
        unknown_bindings = []
        blocking = []
        for i, unknown in enumerate(request['unknowns']):
            policy = policies.get(unknown)
            disposition = {'claim_id': f'unknown:{i}', 'text': unknown, 'scope': policy['scope'] if policy else 'UNCLASSIFIED_BLOCKS_EXECUTION',
                'reason': policy['reason'] if policy else 'Unknown scope has no authorized binding; all warrants remain unresolved.'}
            unknown_bindings.append(disposition)
            add(f'unknown:{i}', 'UNRESOLVED', unknown, reason='USER_DECLARED_UNKNOWN', scope=disposition['scope'])
            if policy is None:
                blocking.append(unknown)
        blocking.extend(x['text'] for x in ingress['unresolved_statements'])
        operation = pack['questions'].get(request['question'])
        if operation is None:
            add('request:unsupported', 'UNRESOLVED', pack['messages']['unsupported'], reason='UNSUPPORTED_REQUEST', original_question=request['question'])
        elif operation['kind'] == 'resolve':
            resolution = resolve_domain(pack['semantic_pack'], operation['alias'])
            resolutions = resolution['candidates']
            if resolution['status'] != 'RESOLVED':
                add('resolution:unresolved', 'UNRESOLVED', pack['messages']['ambiguous'] if resolutions else pack['messages']['not_found'], reason=resolution['status'])
            else:
                node = resolutions[0]
                add('resolution:known', 'DETERMINISTIC_DERIVATION', node['label'], coordinate=node['coordinate'], notation=notation(node['coordinate']), identity=node['identity'], claim_ceiling=resolution['claim_ceiling'])
        elif operation['kind'] == 'assess':
            semantic = pack['semantic_pack']
            architecture = next(a for a in semantic['architectures'] if a['id'] == operation['architecture'])
            work = {w['id']: w for w in semantic['work']}
            interfaces = operation_interfaces(semantic)
            candidates = list(substitutions(operation['roles'], entities))
            # One empty candidate yields explicit missing-binding residuals.
            for binding in candidates or [{}]:
                bound = {k: v['id'] for k, v in binding.items()}
                unit_request = {'entities': {e['id']: e['kind'] for e in entities},
                    'facts': [{'id': f['id'], 'predicate': f['predicate'], 'arguments': f['bindings'], 'value': f['value']} for f in ingress['facts']],
                    'bindings': {step['id']: {role: [bound[role]] for role in interfaces[step['work']]['bindings'] if role in bound} for step in architecture['steps']},
                    'unknowns': list(dict.fromkeys(blocking))}
                execution = self._executor(semantic, operation['architecture'], unit_request)
                execution_id = digest(unit_request)
                executions.append({'binding': bound, 'request': unit_request, 'result': execution,
                    'operation_interfaces': {step['work']: interfaces[step['work']] for step in architecture['steps']}})
                for step in execution['steps']:
                    output = step['output']
                    if output is None:
                        if step.get('residuals'):
                            add('residual:' + execution_id + ':' + step['step_id'], 'UNRESOLVED',
                                step.get('residual_explanation') or 'A required dependency remains unresolved or is not applicable.',
                                reason=step['status'], step_id=step['step_id'], binding=bound, residuals=step['residuals'])
                        continue
                    source_claims = []
                    for source_id in output['source_ids']:
                        cid = 'source:' + source_id
                        if cid not in {c['id'] for c in claims}:
                            add(cid, 'SOURCE_BOUND', pack['sources'][source_id]['quote'], provenance=[source_id])
                        source_claims.append(cid)
                    judgment_id = step.get('judgment_id') or step.get('selection_trace', {}).get('selected_judgment')
                    interpretation = pack['interpretations'][judgment_id] if judgment_id else pack['work_interpretations'][step['work_id']]
                    aliases = {k: v['alias'] for k, v in binding.items()}
                    aliases['value'] = canonical(output['value']).decode('utf-8')
                    wording = interpretation['text'].format(**aliases)
                    add(output['id'], 'DETERMINISTIC_DERIVATION', wording,
                        sorted(set(output['support'] + source_claims)), output['source_ids'],
                        predicate=output['predicate'], arguments=output['arguments'], value=output['value'], semantic_kind=output['semantic_kind'])
                    trace.append({'claim_id': output['id'], 'judgment_id': judgment_id, 'work_id': step['work_id'], 'architecture_id': architecture['id'], 'step_id': step['step_id'],
                        'source_selection_reason': {sid: reason.format(**aliases) for sid, reason in interpretation['source_selection_reason'].items()},
                        'support': output['support'], 'source_ids': output['source_ids'], 'standing': 'PACK_AUTHORED_INTERPRETATION_NOT_SOURCE_TEXT'})
        else:
            raise Rejected('unsupported operation')
        for index, item in enumerate(pack['required_residuals']):
            add(f'required-residual:{index}', 'UNRESOLVED', item['text'], reason=item['reason'])
        result = {'schema_version': '2.0.0', 'request_id': request['request_id'], 'scenario_id': request['scenario_id'],
            'canonical_ingress_hash': digest(ingress), 'canonical_request_hash': ingress['canonical_request_hash'],
            'pack_binding': {'id': pack['id'], 'version': pack['version'], 'sha256': digest(pack)},
            'scenario': request, 'claims': claims, 'support_graph': edges,
            'provenance': {sid: pack['sources'][sid] for sid in sorted({p for c in claims for p in c['provenance']})},
            'interpretation_trace': trace, 'semantic_execution': executions, 'unknown_bindings': unknown_bindings, 'resolutions': resolutions,
            'authority_ceiling': pack['authority_ceiling'], 'compliance_verdict': None, 'responsibility_determination': None, 'external_effects': [], 'model_authority': 'NONE'}
        ids = {c['id'] for c in claims}
        require(all(e['from'] in ids and e['to'] in ids for e in edges), 'dangling support edge')
        result['canonical_kernel_result_hash'] = digest(result)
        return result

    def egress_proposal(self, raw: str, order: list[str] | None = None) -> dict:
        result = self.execute(raw)
        ids = order if order is not None else [c['id'] for c in result['claims']]
        by_id = {c['id']: c for c in result['claims']}
        require(len(ids) == len(by_id) and set(ids) == set(by_id), 'all authorized claims required exactly once')
        return {'binding': {k: result[k] for k in ('request_id', 'scenario_id', 'canonical_request_hash', 'canonical_ingress_hash', 'canonical_kernel_result_hash', 'pack_binding', 'authority_ceiling')}, 'support_graph': result['support_graph'], 'provenance': result['provenance'], 'segments': [by_id[i] for i in ids]}

    def admit_egress(self, raw: str, ai_proposal: dict, *, cancelled: bool = False) -> dict:
        require(not cancelled, 'cancelled; no result released')
        exact_keys(ai_proposal, {'binding', 'support_graph', 'provenance', 'segments'})
        require(type(ai_proposal['segments']) is list, 'invalid segments')
        require(all(type(s) is dict and type(s.get('id')) is str for s in ai_proposal['segments']), 'invalid segment id')
        expected = self.egress_proposal(raw, [s['id'] for s in ai_proposal['segments']])
        require(canonical(ai_proposal) == canonical(expected), 'egress changed authorized claims, bindings, support or provenance')
        return {'status': 'DETERMINISTIC_RESULT_EMITTED', **expected, 'text': '\n'.join('[' + s['type'] + '] ' + s['text'] for s in expected['segments']), 'external_effects': [], 'model_authority': 'NONE'}
