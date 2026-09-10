"""Validates a reviewed source-to-check record."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json


SCHEMA = 'jc/source-interpretation-qualification/1'
REVIEW_SCHEMA = 'jc/source-interpretation-review/1'
STANDING = 'SOURCE_REVIEWED'
SUBJECT_KINDS = {
    'JUDGMENT', 'OVERRIDE', 'SEMANTIC_DEFINITION', 'WHOLE_SEMANTIC_PACK',
    'DOMAIN_DEFINITION', 'DOMAIN_INSTANCE', 'DOMAIN_TYPED_VALUE',
}


class InterpretationQualificationError(ValueError):
    """The proposed semantic interpretation lacks a pinned independent review."""


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def digest(value) -> str:
    return sha256(canonical(value)).hexdigest()


def _need(condition, message):
    if not condition:
        raise InterpretationQualificationError(message)


def _text(value):
    return type(value) is str and bool(value.strip())


def _sha(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def _keys(value, required):
    _need(type(value) is dict and set(value) == set(required), 'unsupported qualification shape')


def _source(source_index, source_id):
    _need(type(source_index) is dict and source_id in source_index, 'unknown qualified source')
    row = source_index[source_id]
    _need(type(row) is dict, 'invalid qualified source')
    return row


def _source_field(row, name):
    if name in row:
        return row[name]
    # Provenance inventories may preserve the owning source-file hash beneath
    # this field; accepting that representation keeps the contract domain-neutral.
    if name == 'source_sha256' and type(row.get('oscal_source_file')) is dict:
        return row['oscal_source_file'].get('sha256')
    return None


def _validate_claim(claim, source_index, target_contract):
    _keys(claim, {'id', 'source_support', 'interpretation', 'derivation_binding'})
    _need(_text(claim['id']), 'qualification id required')
    _need(type(claim['source_support']) is list and claim['source_support'], 'source support required')
    seen = set()
    for support in claim['source_support']:
        _keys(support, {'source_id', 'source_sha256', 'quote_sha256', 'locator'})
        source_id = support['source_id']
        _need(_text(source_id) and source_id not in seen, 'duplicate or invalid source support')
        seen.add(source_id)
        row = _source(source_index, source_id)
        _need(_sha(support['source_sha256']) and support['source_sha256'] == _source_field(row, 'source_sha256'), 'source hash mismatch')
        _need(_sha(support['quote_sha256']) and support['quote_sha256'] == _source_field(row, 'quote_sha256'), 'quote hash mismatch')
        _need(_text(support['locator']) and support['locator'] == _source_field(row, 'locator'), 'source locator mismatch')
    interpretation = claim['interpretation']
    _keys(interpretation, {'rationale', 'mapping', 'scope', 'limits', 'negative_case'})
    _need(_text(interpretation['rationale']) and type(interpretation['mapping']) is dict and interpretation['mapping'], 'interpretation rationale and mapping required')
    _need(type(interpretation['scope']) is dict and interpretation['scope'], 'interpretation scope required')
    _need(type(interpretation['limits']) is list and interpretation['limits'] and all(_text(x) for x in interpretation['limits']), 'interpretation limits required')
    _need(_text(interpretation['negative_case']), 'interpretation negative case required')
    binding = claim['derivation_binding']
    _keys(binding, {'subject_kind', 'subject_id', 'target_contract_sha256'})
    _need(binding['subject_kind'] in SUBJECT_KINDS, 'unsupported derivation subject')
    _need(_text(binding['subject_id']), 'derivation subject required')
    _need(_sha(binding['target_contract_sha256']) and binding['target_contract_sha256'] == digest(target_contract), 'target contract digest mismatch')


def _validate_review(review, expected_claim_sha256, review_pins):
    _keys(review, {'schema', 'id', 'decision', 'reviewed_claim_sha256', 'reviewer_evidence'})
    _need(review['schema'] == REVIEW_SCHEMA and _text(review['id']), 'unsupported review record')
    _need(review['decision'] == 'REVIEW_CONFIRMED', 'review is not a source-reviewed approval')
    _need(review['reviewed_claim_sha256'] == expected_claim_sha256, 'review does not bind proposed interpretation')
    _need(type(review['reviewer_evidence']) is list and review['reviewer_evidence'] and all(_text(x) for x in review['reviewer_evidence']), 'reviewer evidence required')
    _need(type(review_pins) is dict and review_pins.get(review['id']) == digest(review), 'independently pinned review digest required')


def qualify_interpretation(claim, review, source_index, target_contract, *, review_pins):
    """Verify a source interpretation against a supplied review hash."""
    _validate_claim(claim, source_index, target_contract)
    proposed = deepcopy(claim)
    claim_sha256 = digest(proposed)
    _validate_review(review, claim_sha256, review_pins)
    return {
        'schema': SCHEMA,
        'standing': STANDING,
        'claim': proposed,
        # Preserve the independently pinned review evidence rather than a
        # label for it, so a detached record remains review-auditable.
        'review_evidence': deepcopy(review),
        'claim_ceiling': 'SOURCE_REVIEWED_INTERPRETATION;NO_COMPLIANCE_OR_EFFECT_OR_SOURCE_ENTAILMENT_AUTOMATION',
    }


def validate_reviewed_interpretation(record, source_index, target_contract, *, review_pins):
    """Validate a detached qualification against current source and target bytes."""
    _keys(record, {'schema', 'standing', 'claim', 'review_evidence', 'claim_ceiling'})
    _need(record['schema'] == SCHEMA and record['standing'] == STANDING, 'unsupported qualification standing')
    _need(record['claim_ceiling'] == 'SOURCE_REVIEWED_INTERPRETATION;NO_COMPLIANCE_OR_EFFECT_OR_SOURCE_ENTAILMENT_AUTOMATION', 'unsupported qualification ceiling')
    _validate_claim(record['claim'], source_index, target_contract)
    _validate_review(record['review_evidence'], digest(record['claim']), review_pins)
    return json.loads(canonical(record))
