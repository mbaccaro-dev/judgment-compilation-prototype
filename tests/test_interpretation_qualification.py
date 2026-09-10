from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import json

import pytest

from judgment_compilation.interpretation_qualification import (
    InterpretationQualificationError, REVIEW_SCHEMA, SCHEMA, STANDING, digest,
    qualify_interpretation, validate_reviewed_interpretation,
)
from judgment_compilation.nist_admission import admit_pack_interpretation_bundle


ROOT = Path(__file__).resolve().parents[1]


def source_index():
    quote = 'Fictional refund policy: electronics have a sixty-day window.'
    return {'fictional:refund': {
        'source_sha256': sha256(b'fictional-source-v1').hexdigest(),
        'quote_sha256': sha256(quote.encode()).hexdigest(),
        'locator': 'fictional-policy#electronics',
    }}


def target_contract():
    return {'schema': 'fictional-semantic-contract/1', 'judgments': ['electronics-refund-window']}


def claim():
    source = source_index()['fictional:refund']
    return {
        'id': 'fictional-electronics-refund-window',
        'source_support': [{'source_id': 'fictional:refund', **source}],
        'interpretation': {
            'rationale': 'The fictional policy expressly fixes an electronics refund window.',
            'mapping': {'premise': 'purchase.category is electronics', 'output': 'refund.window is 60 days'},
            'scope': {'policy': 'fictional-policy', 'product_class': 'electronics'},
            'limits': ['Fictional fixture only.', 'Does not determine an actual refund entitlement.'],
            'negative_case': 'A general-merchandise purchase does not use this electronics interpretation.',
        },
        'derivation_binding': {
            'subject_kind': 'JUDGMENT',
            'subject_id': 'electronics-refund-window',
            'target_contract_sha256': digest(target_contract()),
        },
    }


def review(proposed=None):
    return {
        'schema': REVIEW_SCHEMA,
        'id': 'fictional-review-001',
        'decision': 'REVIEW_CONFIRMED',
        'reviewed_claim_sha256': digest(proposed or claim()),
        'reviewer_evidence': ['fictional-review-note#counterexample-checked'],
    }


def qualified():
    proposed, receipt = claim(), review()
    pins = {receipt['id']: digest(receipt)}
    return qualify_interpretation(proposed, receipt, source_index(), target_contract(), review_pins=pins), pins


def test_reviewed_source_interpretation_is_held_and_exactly_bound():
    record, pins = qualified()
    validated = validate_reviewed_interpretation(record, source_index(), target_contract(), review_pins=pins)
    assert validated == record
    assert record['schema'] == SCHEMA
    assert record['standing'] == STANDING
    assert record['claim']['derivation_binding']['target_contract_sha256'] == digest(target_contract())


@pytest.mark.parametrize('subject_kind', ['DOMAIN_DEFINITION', 'DOMAIN_INSTANCE', 'DOMAIN_TYPED_VALUE'])
def test_domain_subject_kinds_are_explicitly_supported(subject_kind):
    proposed = claim()
    proposed['derivation_binding']['subject_kind'] = subject_kind
    receipt = review(proposed)
    pins = {receipt['id']: digest(receipt)}
    record = qualify_interpretation(
        proposed, receipt, source_index(), target_contract(), review_pins=pins,
    )
    assert record['claim']['derivation_binding']['subject_kind'] == subject_kind


@pytest.mark.parametrize('mutation', [
    lambda r: r['claim']['interpretation']['mapping'].update(output='refund.authorized is true'),
    lambda r: r['claim']['interpretation']['mapping'].update(premise='purchase.category is general merchandise'),
    lambda r: r['claim']['interpretation'].update(rationale='Changed prose changes the claimed interpretation.'),
    lambda r: r['claim']['interpretation']['scope'].update(product_class='general-merchandise'),
    lambda r: r['claim']['interpretation'].update(negative_case=''),
    lambda r: r['claim']['source_support'][0].update(quote_sha256='0' * 64),
    lambda r: r['claim']['derivation_binding'].update(subject_kind='OVERRIDE', subject_id='electronics-overrides-general'),
])
def test_changed_claim_cannot_reuse_old_review(mutation):
    record, pins = qualified()
    mutation(record)
    with pytest.raises(InterpretationQualificationError):
        validate_reviewed_interpretation(record, source_index(), target_contract(), review_pins=pins)


def test_unreviewed_irrelevant_source_and_unpinned_review_are_rejected():
    proposed = claim()
    proposed['source_support'][0]['source_id'] = 'invented:irrelevant'
    receipt = review(proposed)
    with pytest.raises(InterpretationQualificationError):
        qualify_interpretation(proposed, receipt, source_index(), target_contract(), review_pins={receipt['id']: digest(receipt)})
    proposed, receipt = claim(), review()
    with pytest.raises(InterpretationQualificationError):
        qualify_interpretation(proposed, receipt, source_index(), target_contract(), review_pins={})


def test_target_contract_or_review_digest_drift_rejects_held_record():
    record, pins = qualified()
    with pytest.raises(InterpretationQualificationError):
        validate_reviewed_interpretation(record, source_index(), {'schema': 'changed'}, review_pins=pins)
    bad_pins = dict(pins)
    bad_pins['fictional-review-001'] = 'f' * 64
    with pytest.raises(InterpretationQualificationError):
        validate_reviewed_interpretation(record, source_index(), target_contract(), review_pins=bad_pins)


def real_pack_and_admission():
    package = ROOT / 'judgment_compilation/data/compiled'
    return tuple(json.loads((package / name).read_text(encoding='utf-8')) for name in (
        'domain_pack.json', 'interpretation_admission.json'))


def test_shipped_nist_pack_requires_exact_independently_reviewed_interpretation():
    pack, bundle = real_pack_and_admission()
    admitted = admit_pack_interpretation_bundle(pack, bundle, expected_pack_sha256=digest(pack))
    assert admitted['standing'] == STANDING
    assert admitted['interpretation_subject_sha256'] == bundle['interpretation_subject_sha256']
    assert admitted['review_sha256'] == next(iter(bundle['review_pins'].values()))


@pytest.mark.parametrize('mutation', [
    lambda pack, bundle: pack['interpretations']['account_management_relevance'].update(text='Stronger unsupported interpretation.'),
    lambda pack, bundle: pack['sources'][next(iter(pack['sources']))].update(quote_sha256='0' * 64),
    lambda pack, bundle: bundle.update(interpretation_subject_sha256='0' * 64),
    lambda pack, bundle: bundle['review_pins'].update({next(iter(bundle['review_pins'])): '0' * 64}),
])
def test_shipped_interpretation_review_cannot_be_replayed_after_drift(mutation):
    pack, bundle = real_pack_and_admission()
    mutation(pack, bundle)
    with pytest.raises(InterpretationQualificationError):
        admit_pack_interpretation_bundle(pack, bundle)
