"""Tests package behavior."""
from copy import deepcopy

import pytest

from judgment_compilation.kernel import canonical, digest
from judgment_compilation.nist import build_pack
from judgment_compilation.semantic_contracts import semantic_coordinate
from judgment_compilation.semantic_family_compiler import (
    SemanticFamilyCompilationError,
    compile_elapsed_duration_family,
)


def mapping():
    return {
        'id': 'fixture-elapsed-duration',
        'source_id': 'fixture-source',
        'roles': {'subject': 'system'},
        'scope_inputs': ['scope_supplied'],
        'elapsed_predicate': 'elapsed_seconds',
        'limit_predicate': 'limit_seconds',
        'scope_predicate': 'scope',
        'comparison_predicate': 'within_limit',
        'within_predicate': 'within_conclusion',
        'exceeds_predicate': 'exceeds_conclusion',
        'judgment_coordinates': {
            'scope': semantic_coordinate('judgment', [0, 0]),
            'within': semantic_coordinate('judgment', [0, 1]),
            'exceeds': semantic_coordinate('judgment', [0, 2]),
        },
        'apply_coordinate': semantic_coordinate('work', [0]),
        'compare_coordinate': semantic_coordinate('work', [1]),
        'domain_path': [3],
        'comparison_domain_path': [4],
        'architecture_id': 'fixture-flow',
        'architecture_coordinate': semantic_coordinate('architecture', [0]),
        'comparison_work_id': 'compare_fixture_period',
        'residual': 'Supply the exact scope and compatible values.',
        'interpretation_texts': {
            'scope': 'The caller supplied the bounded comparison scope.',
            'within': 'The supplied elapsed duration is within the supplied limit.',
            'exceeds': 'The supplied elapsed duration exceeds the supplied limit.',
        },
        'interpretation_reason': 'A separately reviewed fixture maps this exact source to the declared relationship.',
        'comparison_text': 'The exact supplied comparison result is {value}.',
        'comparison_reason': 'The operation compares two supplied integers and makes no broader claim.',
    }


def test_compiler_connects_declared_judgment_work_and_architecture_only():
    declared = mapping()
    before = canonical(declared)
    fragment = compile_elapsed_duration_family(declared)
    assert canonical(declared) == before
    assert [row['id'] for row in fragment['judgments']] == [
        'scope', 'within_conclusion', 'exceeds_conclusion']
    assert [row['operation'] for row in fragment['work']] == [
        'APPLY_JUDGMENT', 'APPLY_JUDGMENT', 'APPLY_JUDGMENT', 'COMPARE_VALUES']
    assert fragment['architecture']['steps'] == [
        {'id': 'scope', 'work': 'apply:scope', 'depends_on': []},
        {'id': 'compare', 'work': 'compare_fixture_period', 'depends_on': ['scope']},
        {'id': 'within', 'work': 'apply:within_conclusion', 'depends_on': ['scope', 'compare']},
        {'id': 'exceeds', 'work': 'apply:exceeds_conclusion', 'depends_on': ['scope', 'compare']},
    ]
    assert fragment['architecture']['completion'] == {
        'required_steps': ['scope', 'compare'],
        'exclusive_terminal_groups': [['within', 'exceeds']],
    }
    assert all(row['source_ids'] == ['fixture-source'] for row in fragment['judgments'])
    assert fragment['work'][-1]['left']['predicate'] == 'elapsed_seconds'
    assert fragment['work'][-1]['right']['predicate'] == 'limit_seconds'
    assert fragment['work'][-1]['operator'] == 'LE'
    assert canonical(fragment) == canonical(compile_elapsed_duration_family(declared))


@pytest.mark.parametrize('mutation', [
    lambda row: row.update(authority='invented'),
    lambda row: row.update(scope_inputs=[]),
    lambda row: row.update(limit_predicate='elapsed_seconds'),
    lambda row: row.update(roles={}),
    lambda row: row['judgment_coordinates'].update(scope={'Gs': [], 'L': 0}),
    lambda row: row.update(comparison_text=''),
])
def test_compiler_rejects_incomplete_or_ambiguous_mapping(mutation):
    candidate = deepcopy(mapping())
    mutation(candidate)
    with pytest.raises(SemanticFamilyCompilationError):
        compile_elapsed_duration_family(candidate)


def test_nist_family_refactor_preserves_the_reviewed_pack_bytes():
    pack = build_pack()
    assert digest(pack) == '40538e9121ccaffc511bb73b72c5b101a243f80c2f95e265cd5fe612c9f4495f'
    assert digest(pack['semantic_pack']) == 'b1257d76ad924b32859047f327b0fd25aafacb06af4fa521ffbc64d51044126b'
    assert [row['id'] for row in pack['semantic_pack']['architectures']] == [
        'termination-assessment', 'update-timing', 'ps4a-access-disable-timing']
