"""Tests package behavior."""
import hashlib
import json
from pathlib import Path
import pytest
from judgment_compilation.library import DocumentLibrary, normalized_spans, _text_location_index, _text_location, TEXT_LOCATION_METHOD
from judgment_compilation.kernel import Rejected, canonical, digest


@pytest.fixture
def small_library(tmp_path):
    documents, files = [], []
    def save(path, raw):
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        descriptor = dict(path=path, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        files.append(descriptor)
        return descriptor
    for index, text in enumerate(['Straße account. Other context.', 'STRASSE\naccount. ' * 102], 1):
        pid = 'Publication ' + str(index)
        pdf = save(f'doc{index}.pdf', ('frozen source ' + str(index)).encode())
        page = dict(pub_id=pid, source_sha256=pdf['sha256'], pdf_page_index=0,
                    pdf_page_number=1, text=text, char_count=len(text), text_sha256=hashlib.sha256(text.encode()).hexdigest())
        extraction = {}
        for view in ['plain', 'layout', 'coverage']:
            extraction[view] = save(f'{index}/{view}.jsonl', canonical(dict(page, view=view)) + b'\n')
        documents.append(dict(publication_id=pid, title=pid, page_count=1, pdf=pdf,
                              extraction=extraction, publication_metadata={'revision':str(index)}))
    manifest = dict(documents=documents, files=files, document_count=2, physical_page_count=2,
                    corpus_id='fixture', corpus_release='frozen-1', coverage_ceiling='EXTRACTED_TEXT_ONLY')
    raw = canonical(manifest)
    (tmp_path/'manifest.json').write_bytes(raw)
    return DocumentLibrary(tmp_path, hashlib.sha256(raw).hexdigest())


def cite(library, **changes):
    request = dict(operation='cite', publication_id='Publication 1', page_number=1,
                   character_span=[0,14], exact_quote='Straße account')
    request.update(changes)
    return library.ask(request)


def test_citation_binds_exact_text_and_every_occurrence_beyond_search_window(small_library):
    result = cite(small_library)
    assert result['claim']['type'] == 'SOURCE_BOUND'
    assert result['claim']['text'] == 'Straße account'
    assert result['claim']['provenance_sha256'] == digest(result['provenance'])
    assert result['total_occurrences'] == result['returned_occurrences'] == 103
    assert result['documents_searched'] == result['pages_searched'] == 2
    assert not result['truncated']
    assert result['occurrence_inventory_sha256'] == digest(result['occurrences'])
    assert len(small_library.search('Straße account')['matches']) == 20
    assert result['provenance']['sentence_index'] == 1
    assert result['provenance']['sentence_index_method'] == TEXT_LOCATION_METHOD
    assert result['provenance']['text_location'] == result['occurrences'][0]['text_location']
    assert result['provenance']['structural_oscal_locator'] is None
    projection = result['provenance']['normalized_page_projection']
    assert projection['schema'] == 'jc/documentary-projection/1'
    assert projection['role'] == 'NORMALIZED_DOCUMENTARY_EVIDENCE_NOT_SOURCE_AUTHORITY'
    assert projection['jsonl_file'] == small_library.documents['Publication 1']['extraction']['plain']
    assert projection['jsonl_line_number'] == 1
    assert projection['record_identity'] == {
        'publication_id':'Publication 1', 'pdf_page_index':0,
        'pdf_page_number':1, 'view':'plain'}
    assert projection['canonical_record_sha256'] == digest(
        small_library.page('Publication 1', 1)['page'])
    assert projection['page_text_sha256'] == result['provenance']['page_text_sha256']
    assert projection['source_pdf_sha256'] == result['provenance']['source_file']['sha256']
    assert result['interpretation_trace']['status'] == 'NOT_INTERPRETED'
    assert [m['text_location']['sentence_index'] for m in result['occurrences'][1:]] == list(range(1,103))
    assert canonical(result) == canonical(cite(small_library))
    for match in result['occurrences']:
        page = small_library.page(match['publication_id'], match['physical_pdf_page_number'])
        start, end = match['character_span']
        assert page['page']['text'][start:end] == match['exact_quote']
        assert normalized_spans(match['exact_quote'])[0] == 'strasse account'


@pytest.mark.parametrize('changes', [
    {'character_span':[False,14]}, {'character_span':[0,15]}, {'character_span':[-1,14]},
    {'character_span':[0,999]}, {'character_span':'0:14'}, {'character_span':[0]},
    {'exact_quote':'STRASSE account'}, {'exact_quote':'compliant'}, {'exact_quote':''},
    {'publication_id':'foreign'}, {'page_number':True}, {'page_number':2},
    {'source_sha256':'invented'}, {'structural_oscal_locator':'invented'},
    {'sentence_index':999}, {'text_location':{'sentence_index':999}},
    {'compliance_verdict':True}, {'authority':'accepted'},
])
def test_citation_rejects_modified_identity_span_quote_or_authority(small_library, changes):
    with pytest.raises(Rejected):
        cite(small_library, **changes)


def test_citation_rejects_drift_in_other_publication(small_library):
    other = small_library.documents['Publication 2']['pdf']
    small_library._path(other).write_bytes(b'drift')
    with pytest.raises(Rejected, match='input drift'):
        cite(small_library)


def test_too_common_quote_rejects_instead_of_returning_partial_inventory(small_library, monkeypatch):
    monkeypatch.setattr(small_library, '_occurrences', lambda needle, docs: iter([{}] * 10001))
    with pytest.raises(Rejected, match='10000 occurrences'):
        cite(small_library)


def test_text_location_records_cross_sentence_and_paragraph_spans():
    text = 'First sentence. Second sentence;\ncontinued?\n\nLast paragraph.'
    start, end = text.index('Second'), text.index('Last') + 4
    location = _text_location(_text_location_index(text), start, end)
    assert location['sentence_index'] == 2 and location['end_sentence_index'] == 4
    assert location['paragraph_index'] == 1 and location['end_paragraph_index'] == 2
    assert [text[a:b] for a,b in location['sentence_character_spans']] == [
        'Second sentence;', 'continued?', 'Last paragraph.']
    assert [text[a:b] for a,b in location['paragraph_character_spans']] == [
        'First sentence. Second sentence;\ncontinued?', 'Last paragraph.']
    assert location['method'] == TEXT_LOCATION_METHOD
    assert 'NOT_LINGUISTIC_OR_NORMATIVE_STRUCTURE' in location['ceiling']


def test_text_location_uses_exact_codepoints_and_declared_abbreviation_rule():
    text = '  Dr. Stra\u00dfe?\r\n \r\n\U0001f600 tail without punctuation  '
    a, b = text.index('\U0001f600'), text.index('punctuation') + len('punctuation')
    location = _text_location(_text_location_index(text), a, b)
    assert location['sentence_index'] == location['end_sentence_index'] == 3
    assert location['paragraph_index'] == 2
    assert location['sentence_character_spans'] == [[a,b]]
    with pytest.raises(Rejected, match='outside text segments'):
        _text_location(_text_location_index(text), 0, 1)
