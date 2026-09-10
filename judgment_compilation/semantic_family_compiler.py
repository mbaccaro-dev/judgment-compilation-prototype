"""Builds an elapsed-duration check from reviewed records."""
from __future__ import annotations

from copy import deepcopy
import re


class SemanticFamilyCompilationError(ValueError):
    """The declared family mapping is incomplete or internally inconsistent."""


_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]*$")


def _need(condition, message):
    if not condition:
        raise SemanticFamilyCompilationError(message)


def _exact(value, required, label):
    _need(type(value) is dict and set(value) == set(required), f"unsupported {label} shape")


def _identifier(value, label):
    _need(type(value) is str and _IDENTIFIER.fullmatch(value) is not None, f"invalid {label}")
    return value


def _text(value, label):
    _need(type(value) is str and bool(value.strip()), f"invalid {label}")
    return value


def _coordinate(value, stack, label):
    # The owning stack is the containing schema field; the coordinate itself is
    # the established lossless (Gs,L) representation.
    _need(type(value) is dict and set(value) == {'Gs', 'L'}, f"invalid {label} coordinate")
    _need(type(value['Gs']) is list and value['Gs'], f"invalid {label} {stack} coordinate")
    _need(all(type(item) is int and item >= 0 for item in value['Gs']), f"invalid {label} Gs")
    _need(type(value['L']) is int and value['L'] >= 0, f"invalid {label} L")
    return deepcopy(value)


def compile_elapsed_duration_family(mapping):
    """Build an elapsed-duration check from reviewed source records."""
    required = {
        'id', 'source_id', 'roles', 'scope_inputs', 'elapsed_predicate',
        'limit_predicate', 'scope_predicate', 'comparison_predicate',
        'within_predicate', 'exceeds_predicate', 'judgment_coordinates',
        'apply_coordinate', 'compare_coordinate', 'domain_path',
        'comparison_domain_path', 'architecture_id', 'comparison_work_id',
        'architecture_coordinate',
        'residual', 'interpretation_texts', 'interpretation_reason',
        'comparison_text', 'comparison_reason',
    }
    _exact(mapping, required, 'elapsed-duration family mapping')
    family_id = _identifier(mapping['id'], 'family id')
    source_id = _text(mapping['source_id'], 'source id')
    architecture_id = _identifier(mapping['architecture_id'], 'architecture id')
    comparison_work_id = _identifier(mapping['comparison_work_id'], 'comparison work id')
    roles = mapping['roles']
    _need(type(roles) is dict and roles, 'typed roles required')
    for role, kind in roles.items():
        _identifier(role, 'role id')
        _identifier(kind, 'entity kind')
    arguments = {role: role for role in roles}
    scope_inputs = mapping['scope_inputs']
    _need(type(scope_inputs) is list and scope_inputs and len(scope_inputs) == len(set(scope_inputs)),
          'unique scope inputs required')
    for predicate in scope_inputs:
        _identifier(predicate, 'scope input predicate')
    names = [mapping[key] for key in (
        'elapsed_predicate', 'limit_predicate', 'scope_predicate',
        'comparison_predicate', 'within_predicate', 'exceeds_predicate')]
    for name in names:
        _identifier(name, 'family predicate')
    _need(len(set(scope_inputs + names)) == len(scope_inputs) + len(names),
          'family predicate identities must be distinct')
    coordinates = deepcopy(mapping['judgment_coordinates'])
    _exact(coordinates, {'scope', 'within', 'exceeds'}, 'judgment coordinate binding')
    for name in coordinates:
        coordinates[name] = _coordinate(coordinates[name], 'judgment', name)
    apply_coordinate = _coordinate(mapping['apply_coordinate'], 'work', 'apply Work')
    compare_coordinate = _coordinate(mapping['compare_coordinate'], 'work', 'compare Work')
    architecture_coordinate = _coordinate(mapping['architecture_coordinate'], 'architecture', 'Architecture')
    for key in ('domain_path', 'comparison_domain_path'):
        path = mapping[key]
        _need(type(path) is list and path and all(type(item) is int and item >= 0 for item in path),
              f"invalid {key}")
    texts = mapping['interpretation_texts']
    _exact(texts, {'scope', 'within', 'exceeds'}, 'interpretation text')
    for key in texts:
        _text(texts[key], f'{key} interpretation')
    reason = _text(mapping['interpretation_reason'], 'interpretation reason')
    comparison_text = _text(mapping['comparison_text'], 'comparison interpretation')
    comparison_reason = _text(mapping['comparison_reason'], 'comparison reason')
    residual = _text(mapping['residual'], 'residual')

    scope_predicate, comparison_predicate, within_predicate, exceeds_predicate = (
        mapping['scope_predicate'], mapping['comparison_predicate'],
        mapping['within_predicate'], mapping['exceeds_predicate'])
    predicate_rows = [
        *[{'id': name, 'roles': deepcopy(roles), 'origin': 'INPUT', 'value_type': 'BOOLEAN'}
          for name in scope_inputs],
        {'id': mapping['elapsed_predicate'], 'roles': deepcopy(roles), 'origin': 'INPUT', 'value_type': 'INTEGER'},
        {'id': mapping['limit_predicate'], 'roles': deepcopy(roles), 'origin': 'INPUT', 'value_type': 'INTEGER'},
        {'id': scope_predicate, 'roles': deepcopy(roles), 'origin': 'DERIVED', 'value_type': 'BOOLEAN'},
        {'id': comparison_predicate, 'roles': deepcopy(roles), 'origin': 'DERIVED', 'value_type': 'BOOLEAN'},
        {'id': within_predicate, 'roles': deepcopy(roles), 'origin': 'DERIVED', 'value_type': 'BOOLEAN'},
        {'id': exceeds_predicate, 'roles': deepcopy(roles), 'origin': 'DERIVED', 'value_type': 'BOOLEAN'},
    ]

    def premise(predicate, value=True):
        return {'predicate': predicate, 'arguments': deepcopy(arguments), 'value': value}

    declared = [
        ('scope', scope_predicate, [premise(name) for name in scope_inputs]),
        ('within', within_predicate, [premise(scope_predicate), premise(comparison_predicate)]),
        ('exceeds', exceeds_predicate, [premise(scope_predicate), premise(comparison_predicate, False)]),
    ]
    judgments, work, interpretations = [], [], {}
    for role, judgment_id, premises in declared:
        judgments.append({
            'id': judgment_id,
            'semantic_coordinate': deepcopy(coordinates[role]),
            'bindings': deepcopy(roles),
            'premises': premises,
            'output': {'predicate': judgment_id, 'arguments': deepcopy(arguments), 'value': True,
                       'semantic_kind': 'SCENARIO_DERIVATION'},
            'source_ids': [source_id],
            'residual': residual,
        })
        work.append({
            'id': 'apply:' + judgment_id,
            'semantic_coordinate': deepcopy(apply_coordinate),
            'operation': 'APPLY_JUDGMENT',
            'judgment': judgment_id,
            'domain_path': deepcopy(mapping['domain_path']),
        })
        interpretations[judgment_id] = {
            'text': texts[role],
            'source_selection_reason': {source_id: reason},
        }
    work.append({
        'id': comparison_work_id,
        'semantic_coordinate': deepcopy(compare_coordinate),
        'operation': 'COMPARE_VALUES',
        'bindings': deepcopy(roles),
        'left': {'predicate': mapping['elapsed_predicate'], 'arguments': deepcopy(arguments)},
        'right': {'predicate': mapping['limit_predicate'], 'arguments': deepcopy(arguments)},
        'operator': 'LE',
        'output': {'predicate': comparison_predicate, 'arguments': deepcopy(arguments)},
        'domain_path': deepcopy(mapping['comparison_domain_path']),
    })
    architecture = {
        'id': architecture_id,
        'semantic_coordinate': architecture_coordinate,
        'steps': [
            {'id': 'scope', 'work': 'apply:' + scope_predicate, 'depends_on': []},
            {'id': 'compare', 'work': comparison_work_id, 'depends_on': ['scope']},
            {'id': 'within', 'work': 'apply:' + within_predicate, 'depends_on': ['scope', 'compare']},
            {'id': 'exceeds', 'work': 'apply:' + exceeds_predicate, 'depends_on': ['scope', 'compare']},
        ],
        'completion': {
            'required_steps': ['scope', 'compare'],
            'exclusive_terminal_groups': [['within', 'exceeds']],
        },
    }
    return {
        'family_id': family_id,
        'predicates': predicate_rows,
        'judgments': judgments,
        'work': work,
        'architecture': architecture,
        'interpretations': interpretations,
        'work_interpretations': {
            comparison_work_id: {
                'text': comparison_text,
                'source_selection_reason': {source_id: comparison_reason},
            }
        },
    }
