"""Tests package behavior."""
from copy import deepcopy

import pytest

from judgment_compilation.documentary_projection import DocumentaryProjection, DocumentaryProjectionError
from judgment_compilation.qualified_source_builder import (
    QualifiedSourceBuilderError,
    compose_qualified_source,
    decompose_qualified_source,
    recompose_qualified_source,
)
from test_semantic_values import fixture


PUBLICATION_ID = "NIST SP 800-100-upd1"


def _document():
    return next(DocumentaryProjection().iter_documents(publication_id=PUBLICATION_ID))


def test_registers_exact_retained_document_and_losslessly_replays():
    context = fixture()
    before = deepcopy(context)
    document = _document()

    candidate = compose_qualified_source(document, context=context)
    successor = recompose_qualified_source(context, candidate)

    assert decompose_qualified_source(candidate) == document
    assert candidate["source_registration"] == {
        "id": PUBLICATION_ID,
        "sha256": document["source_file"]["sha256"],
    }
    assert successor["sources"][-1] == candidate["source_registration"]
    assert candidate["status"] == "SOURCE_BOUND_NOT_EXECUTED"
    assert candidate["external_effects"] == []
    assert context == before


@pytest.mark.parametrize("mutation", [
    lambda document: document["source_file"].update(sha256="0" * 64),
    lambda document: document.update(title="changed"),
    lambda document: document["publication_metadata"].update(release_date="changed"),
    lambda document: document["disposition"].update(compliance=True),
])
def test_rejects_documentary_record_or_authority_drift(mutation):
    document = _document()
    mutation(document)
    with pytest.raises(QualifiedSourceBuilderError):
        compose_qualified_source(document, context=fixture())


def test_rejects_duplicate_source_and_candidate_tampering():
    document = _document()
    candidate = compose_qualified_source(document, context=fixture())
    successor = recompose_qualified_source(fixture(), candidate)
    with pytest.raises(QualifiedSourceBuilderError):
        compose_qualified_source(document, context=successor)

    tampered = deepcopy(candidate)
    tampered["source_registration"]["sha256"] = "0" * 64
    with pytest.raises(QualifiedSourceBuilderError):
        decompose_qualified_source(tampered)


def test_filtered_document_projection_rejects_unknown_identity():
    with pytest.raises(DocumentaryProjectionError, match="unknown publication identity"):
        next(DocumentaryProjection().iter_documents(publication_id="absent"))
