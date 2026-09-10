"""Tests package behavior."""
import hashlib, json, shutil
from pathlib import Path
import pytest
from judgment_compilation.library import DocumentLibrary, ROOT, normalized_spans
from judgment_compilation.kernel import Rejected, canonical

@pytest.fixture(scope='module')
def library(): return DocumentLibrary()

def test_full_portable_library_bytes_and_all_page_identities(library):
    receipt = library.verify()
    assert receipt['document_count'] == 195
    assert receipt['physical_page_count'] == 15478
    assert receipt['file_count'] == 780
    expected={d['pdf']['path'] for d in library.documents.values()}
    expected.update(x['path'] for d in library.documents.values() for x in d['extraction'].values())
    assert set(library.files) == expected
    assert all(d['publication_metadata']['download_url'].startswith('https://') for d in library.documents.values())
    counts = {view:0 for view in ('plain','layout','coverage')}
    for document in library.documents.values():
        for view in counts:
            counts[view] += sum(1 for _ in library._pages(document,view))
    assert counts == dict(plain=15478,layout=15478,coverage=15478)

def test_catalog_pagination_and_distinct_publications(library):
    first = library.list_documents(limit=100)
    second = library.list_documents(offset=first['next_offset'],limit=100)
    ids = [d['publication_id'] for d in first['documents']+second['documents']]
    assert len(ids) == len(set(ids)) == 195 and second['next_offset'] is None
    assert all(d['interpretation_status'] == 'DOCUMENTARY_SOURCE_ONLY_NOT_COMPILED_JUDGMENT' for d in first['documents'])

def test_page_and_search_lift_back_exactly(library):
    publication = 'NIST SP 800-100-upd1'
    page = library.page(publication,1)
    assert page['page']['pdf_page_index'] == 0 and page['printed_page_label'] is None
    result = library.search('INFORMATION SECURITY',publication,limit=3)
    assert result['total_occurrences'] >= 3 and result['truncated']
    for match in result['matches']:
        source = library.page(publication,match['physical_pdf_page_number'])
        a,b = match['character_span']; quote = source['page']['text'][a:b]
        assert quote == match['exact_quote']
        assert hashlib.sha256(quote.encode()).hexdigest() == match['exact_quote_sha256']
        assert normalized_spans(quote)[0] == result['normalized_phrase']
        assert match['coverage']['source_sha256'] == match['source_file']['sha256']
    assert canonical(result) == canonical(library.search('INFORMATION SECURITY',publication,limit=3))

@pytest.mark.parametrize('payload',[
 {'operation':'page','publication_id':'../secret','page_number':1},
 {'operation':'page','publication_id':'NIST SP 800-100-upd1','page_number':True},
 {'operation':'page','publication_id':'NIST SP 800-100-upd1','page_number':0},
 {'operation':'page','publication_id':'NIST SP 800-100-upd1','page_number':1,'view':'raw'},
 {'operation':'search','phrase':' '}, {'operation':'search','phrase':'x','limit':101},
 {'operation':'documents','authority':'compliant'}, {'operation':'delete'},
])
def test_reject_unsupported_inputs(library,payload):
    with pytest.raises(Rejected): library.ask(payload)

def test_manifest_and_post_initialization_source_tampering(tmp_path):
    raw=(ROOT/'manifest.json').read_bytes()
    (tmp_path/'manifest.json').write_bytes(raw+b' ')
    with pytest.raises(Rejected,match='manifest drift'): DocumentLibrary(tmp_path)
    (tmp_path/'manifest.json').write_bytes(raw)
    lib=DocumentLibrary(tmp_path)
    doc=lib.documents['NIST SP 800-100-upd1']
    destination=tmp_path/doc['pdf']['path']; destination.parent.mkdir(parents=True)
    destination.write_bytes(b'changed source')
    with pytest.raises(Rejected,match='input drift'): lib.page(doc['publication_id'],1)

def test_normalization_keeps_unicode_expansion_and_whitespace_spans():
    value='  Stra\u00dfe\n \tA  '
    normalized, spans=normalized_spans(value)
    assert normalized == 'strasse a'
    assert value[spans[4][0]:spans[5][1]] == '\u00df'
    assert value[spans[7][0]:spans[7][1]] == '\n \t'

def test_pinned_manifest_still_rejects_duplicate_keys(tmp_path):
    raw = b'{"documents":[],"documents":[]}'
    (tmp_path/'manifest.json').write_bytes(raw)
    with pytest.raises(Rejected, match='duplicate manifest key'):
        DocumentLibrary(tmp_path, hashlib.sha256(raw).hexdigest())


def test_search_does_not_match_half_of_casefold_character(library, monkeypatch):
    document = next(iter(library.documents.values()))
    monkeypatch.setattr(library, '_verified_path', lambda descriptor: None)
    def pages(doc, view):
        if view == 'coverage': return iter([{}])
        return iter([{
            'text': 'Straße',
            'pub_id': doc['publication_id'],
            'view': 'plain',
            'source_sha256': doc['pdf']['sha256'],
            'pdf_page_index': 0,
            'pdf_page_number': 1,
            'text_sha256': hashlib.sha256('Straße'.encode()).hexdigest(),
        }])
    monkeypatch.setattr(library, '_pages', pages)
    result = library.search('s', document['publication_id'])
    assert result['total_occurrences'] == 1
    assert result['matches'][0]['exact_quote'] == 'S'
    result = library.search('ss', document['publication_id'])
    assert result['total_occurrences'] == 1
    assert result['matches'][0]['exact_quote'] == 'ß'
