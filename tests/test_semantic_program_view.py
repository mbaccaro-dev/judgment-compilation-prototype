import pytest

from judgment_compilation.application import Application


def test_consumer_can_inspect_a_real_admitted_nist_program():
    result = Application().query({
        'mode': 'semantic_program',
        'request': {'architecture_id': 'termination-assessment'},
    })
    kernel = result['kernel']
    assert result['route'] == 'DETERMINISTIC_ADMITTED_SEMANTIC_PROGRAM_INSPECTION'
    assert kernel['status'] == 'ADMITTED_PROGRAM_INSPECTED'
    assert kernel['architecture']['id'] == 'termination-assessment'
    assert kernel['architecture']['ordered_steps']
    assert kernel['work']
    assert kernel['judgments']
    assert kernel['composed_program']['program_sha256']
    assert kernel['external_effects'] == []
    assert result['inference']['model_calls'] == 0


def test_semantic_program_rejects_unknown_or_extra_input():
    app = Application()
    with pytest.raises(ValueError):
        app.query({'mode': 'semantic_program', 'request': {'architecture_id': 'missing'}})
    with pytest.raises(ValueError):
        app.query({'mode': 'semantic_program',
                   'request': {'architecture_id': 'termination-assessment', 'change': True}})
