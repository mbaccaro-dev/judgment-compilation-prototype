"""Validates the included interpretation record."""
from .interpretation_qualification import (
    validate_reviewed_interpretation, InterpretationQualificationError, digest,
)

SUBJECT_FIELDS = ('semantic_pack', 'interpretations', 'work_interpretations',
                  'fact_templates', 'unknown_scopes', 'questions',
                  'required_residuals', 'authority_ceiling')


def interpretation_subject(pack):
    return {key:pack[key] for key in SUBJECT_FIELDS}


def interpretation_source_index(pack):
    return {sid:{'source_sha256':row['source_file']['sha256'],
                 'quote_sha256':row['quote_sha256'],
                 'locator':row['structural_oscal_locator']}
            for sid,row in pack['sources'].items()}


def admit_pack_interpretation(pack, record, *, review_pins):
    qualified = validate_reviewed_interpretation(record, interpretation_source_index(pack),
                    interpretation_subject(pack), review_pins=review_pins)
    claim = qualified['claim']
    if (claim['derivation_binding']['subject_kind'] != 'WHOLE_SEMANTIC_PACK'
            or claim['derivation_binding']['subject_id'] != pack['semantic_pack']['id']
            or {s['source_id'] for s in claim['source_support']} != set(pack['sources'])):
        raise InterpretationQualificationError('incomplete pack interpretation coverage')
    return qualified


def admit_pack_interpretation_bundle(pack, bundle, *, expected_pack_sha256=None):
    """Verify and load the reviewed interpretation bundle for an exact pack."""
    required = {'schema', 'pack_sha256', 'interpretation_subject_sha256',
                'qualification', 'review_pins'}
    if type(bundle) is not dict or set(bundle) != required:
        raise InterpretationQualificationError('unsupported interpretation admission bundle')
    if bundle['schema'] != 'jc/nist-pack-interpretation-admission/1':
        raise InterpretationQualificationError('unsupported interpretation admission schema')
    actual_pack_sha256 = digest(pack)
    if bundle['pack_sha256'] != actual_pack_sha256:
        raise InterpretationQualificationError('reviewed pack digest mismatch')
    if expected_pack_sha256 is not None and actual_pack_sha256 != expected_pack_sha256:
        raise InterpretationQualificationError('runtime pack pin mismatch')
    subject_sha256 = digest(interpretation_subject(pack))
    if bundle['interpretation_subject_sha256'] != subject_sha256:
        raise InterpretationQualificationError('reviewed interpretation subject mismatch')
    qualified = admit_pack_interpretation(
        pack, bundle['qualification'], review_pins=bundle['review_pins'])
    return {
        'standing': qualified['standing'],
        'claim_id': qualified['claim']['id'],
        'claim_sha256': digest(qualified['claim']),
        'review_id': qualified['review_evidence']['id'],
        'review_sha256': digest(qualified['review_evidence']),
        'pack_sha256': actual_pack_sha256,
        'interpretation_subject_sha256': subject_sha256,
        'claim_ceiling': qualified['claim_ceiling'],
    }
