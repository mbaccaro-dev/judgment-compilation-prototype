"""Reads the included document library."""
from copy import deepcopy
from pathlib import Path
import hashlib, json, re
from bisect import bisect_right
from .kernel import require, exact_keys, strict_json, digest

ROOT = Path(__file__).resolve().parent / 'data/library'
MANIFEST_SHA256 = 'a11f0668efbde0ccfe7dcc6f12e6e7e4bf549193d68a409ebc06dc087599ce11'
NORMALIZATION = 'UNICODE_CASEFOLD_AND_WHITESPACE_COLLAPSE_V1'
PROJECTION_SCHEMA = 'jc/documentary-projection/1'


def file_hash(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def normalized_spans(text):
    chars, spans = [], []
    for index, char in enumerate(text):
        if char.isspace():
            if chars and chars[-1] == ' ':
                spans[-1] = (spans[-1][0], index + 1)
            elif chars:
                chars.append(' '); spans.append((index, index + 1))
        else:
            for folded in char.casefold():
                chars.append(folded); spans.append((index, index + 1))
    if chars and chars[-1] == ' ': chars.pop(); spans.pop()
    return ''.join(chars), spans


def normalized_text(text):
    """Return normalized text without source offsets."""
    return ' '.join(text.casefold().split())


TEXT_LOCATION_METHOD = 'PAGE_TEXT_TERMINATOR_AND_BLANK_LINE_SEGMENTS_V1'


def _segments(text, separator):
    """Nonempty, trimmed half-open spans; never infer structure across pages."""
    result, start = [], 0
    for match in re.finditer(separator, text):
        end = match.end()
        a, b = start, end
        while a < b and text[a].isspace(): a += 1
        while b > a and text[b-1].isspace(): b -= 1
        if a < b: result.append([a, b])
        start = end
    a, b = start, len(text)
    while a < b and text[a].isspace(): a += 1
    while b > a and text[b-1].isspace(): b -= 1
    if a < b: result.append([a, b])
    return result


def _text_location_index(text):
    # These are reproducible extraction segments, not linguistic sentence or
    # normative paragraph recognition. Abbreviations/headings are not guessed.
    sentences = _segments(text, r'[.!?;](?=\s|$)')
    paragraphs = _segments(text, r'\r?\n[^\S\r\n]*\r?\n')
    return {'sentences': sentences, 'paragraphs': paragraphs,
            'sentence_starts': [s[0] for s in sentences],
            'paragraph_starts': [s[0] for s in paragraphs]}


def _text_location(index, start, end):
    result = {'method': TEXT_LOCATION_METHOD,
              'index_base': 1, 'span_convention': 'UNICODE_CODE_POINTS_HALF_OPEN',
              'scope': 'ONE_FROZEN_EXTRACTED_PAGE',
              'ceiling': 'DETERMINISTIC_TEXT_SEGMENTS_NOT_LINGUISTIC_OR_NORMATIVE_STRUCTURE'}
    for singular, plural in [('sentence', 'sentences'), ('paragraph', 'paragraphs')]:
        spans, starts = index[plural], index[singular + '_starts']
        first, last = bisect_right(starts, start)-1, bisect_right(starts, end-1)-1
        require(first >= 0 and last >= first and start < spans[first][1] and
                end <= spans[last][1], 'citation outside text segments')
        result[singular + '_index'] = first + 1
        result['end_' + singular + '_index'] = last + 1
        result[singular + '_character_spans'] = spans[first:last+1]
    return result


class DocumentLibrary:
    def __init__(self, root=ROOT, manifest_sha256=MANIFEST_SHA256):
        self.root = Path(root).resolve()
        raw = (self.root/'manifest.json').read_bytes()
        require(hashlib.sha256(raw).hexdigest() == manifest_sha256, 'library manifest drift')
        # Input request limits do not apply to a separately hash-pinned file manifest.
        def unique_pairs(pairs):
            value = {}
            for key, item in pairs:
                require(key not in value, 'duplicate manifest key')
                value[key] = item
            return value
        def reject_constant(value):
            raise ValueError('nonfinite manifest constant: '+value)
        require(len(raw) <= 4_000_000, 'manifest size')
        self.manifest = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_pairs, parse_constant=reject_constant)
        self.manifest_sha256 = manifest_sha256
        self.documents = {d['publication_id']:d for d in self.manifest['documents']}
        require(len(self.documents) == self.manifest['document_count'], 'duplicate publication identity')
        self.files = {d['path']:d for d in self.manifest['files']}
        require(len(self.files) == len(self.manifest['files']), 'duplicate library path')
        self._verified_page_cache = {}
        # Page records are an in-process speed layer only.  Every cache hit
        # re-authenticates the bound files before returning a record.
        self._page_cache = {}
        require(sum(d['page_count'] for d in self.documents.values()) == self.manifest['physical_page_count'], 'library page cardinality')
        for d in self.documents.values():
            for descriptor in [d['pdf'], *d['extraction'].values()]:
                require(self.files.get(descriptor['path']) == descriptor, 'unbound document input')

    def _path(self, descriptor):
        relative = Path(descriptor['path'])
        path = (self.root/relative).resolve()
        require(not relative.is_absolute() and path.is_relative_to(self.root), 'library path escapes root')
        return path

    def _verified_path(self, descriptor):
        path = self._path(descriptor)
        require(path.stat().st_size == descriptor['bytes'] and file_hash(path) == descriptor['sha256'], 'library input drift: '+descriptor['path'])
        return path

    def _verify_manifest(self):
        """Re-read the pinned manifest before reusing verified data."""
        raw = (self.root/'manifest.json').read_bytes()
        require(hashlib.sha256(raw).hexdigest() == self.manifest_sha256,
                'library manifest drift')

    def _verify_document_files(self, doc):
        """Authenticate every file bound to one retained document."""
        self._verify_manifest()
        self._verified_path(doc['pdf'])
        for descriptor in doc['extraction'].values():
            self._verified_path(descriptor)

    def verify(self):
        self._verify_manifest()
        for descriptor in self.files.values(): self._verified_path(descriptor)
        return {'status':'VERIFIED','manifest_sha256':self.manifest_sha256,'file_count':len(self.files),
                'document_count':len(self.documents),'physical_page_count':self.manifest['physical_page_count']}

    def summary(self):
        return {'corpus_id':self.manifest['corpus_id'],'corpus_release':self.manifest['corpus_release'],
                'manifest_sha256':self.manifest_sha256,'document_count':len(self.documents),
                'physical_page_count':self.manifest['physical_page_count'],'coverage_ceiling':self.manifest['coverage_ceiling']}

    def _document(self, publication_id):
        require(type(publication_id) is str and publication_id in self.documents, 'unknown publication identity')
        return self.documents[publication_id]

    def _pages(self, doc, view):
        descriptor = doc['extraction'][view]
        path = self._verified_path(descriptor)
        count = 0
        with path.open(encoding='utf-8') as stream:
            for index, line in enumerate(stream):
                record = strict_json(line)
                require(record['pub_id'] == doc['publication_id'] and record['source_sha256'] == doc['pdf']['sha256'], 'page source identity drift')
                require(record['pdf_page_index'] == index and record['pdf_page_number'] == index+1, 'page ordering drift')
                if view != 'coverage':
                    require(record['view'] == view and len(record['text']) == record['char_count'], 'page text shape drift')
                    require(hashlib.sha256(record['text'].encode()).hexdigest() == record['text_sha256'], 'page text digest drift')
                count += 1
                yield record
        require(count == doc['page_count'], 'extracted page cardinality drift')

    def list_documents(self, offset=0, limit=25):
        require(type(offset) is int and offset >= 0 and type(limit) is int and 1 <= limit <= 200, 'invalid document window')
        documents = sorted(self.documents.values(),key=lambda d:d['publication_id'])
        return {'status':'DOCUMENTARY_CATALOG','total':len(documents),'offset':offset,'documents':documents[offset:offset+limit],
                'next_offset':offset+limit if offset+limit<len(documents) else None,**self.summary()}

    def page(self, publication_id, page_number, view='plain'):
        doc = self._document(publication_id)
        require(type(page_number) is int and 1 <= page_number <= doc['page_count'], 'invalid physical page number')
        require(view in ('plain','layout'), 'unsupported extraction view')
        cache_key = (publication_id, page_number, view)
        if cache_key in self._page_cache:
            # Do not trust an in-memory page after same-process source drift.
            self._verify_document_files(doc)
            return deepcopy(self._page_cache[cache_key])
        self._verified_path(doc['pdf'])
        pages = list(self._pages(doc, view))
        coverage = list(self._pages(doc, 'coverage'))
        record = pages[page_number-1]
        result = {'status':'EXTRACTED_PAGE_FOR_INSPECTION','publication_id':publication_id,'page':record,
                'coverage':coverage[page_number-1], 'source_file':doc['pdf'],'extracted_file':doc['extraction'][view],
                'printed_page_label':None,'printed_page_label_status':'NOT_QUALIFIED',
                'semantic_status':'NOT_AN_APPLICABILITY_OR_COMPLIANCE_DETERMINATION',**self.summary()}
        self._page_cache[cache_key] = deepcopy(result)
        return result

    @staticmethod
    def _normalized_page_projection(doc, page, view='plain'):
        descriptor = doc['extraction'][view]
        return {
            'schema': PROJECTION_SCHEMA,
            'role': 'NORMALIZED_DOCUMENTARY_EVIDENCE_NOT_SOURCE_AUTHORITY',
            'view': view,
            'jsonl_file': descriptor,
            'jsonl_line_number': page['pdf_page_index'] + 1,
            'record_identity': {
                'publication_id': page['pub_id'],
                'pdf_page_index': page['pdf_page_index'],
                'pdf_page_number': page['pdf_page_number'],
                'view': page['view'],
            },
            'canonical_record_sha256': digest(page),
            'page_text_sha256': page['text_sha256'],
            'source_pdf_sha256': page['source_sha256'],
        }

    def bind_provenance_chains(self, sources):
        """Link semantic sources to exact pages in the document library."""
        require(type(sources) is dict and len(sources) <= 256, 'source inventory required')
        by_pdf = {}
        for doc in self.documents.values():
            by_pdf.setdefault(doc['pdf']['sha256'], []).append(doc)
        page_cache = {}
        result = {}
        for source_id in sorted(sources):
            source = sources[source_id]
            require(type(source_id) is str and source_id and type(source) is dict, 'invalid source record')
            source_file = source.get('source_file')
            require(type(source_file) is dict and type(source_file.get('sha256')) is str and
                    type(source_file.get('bytes')) is int, 'source PDF descriptor required')
            matches = by_pdf.get(source_file['sha256'], [])
            require(len(matches) == 1, 'source PDF is absent or ambiguous in retained library')
            doc = matches[0]
            require(source_file['bytes'] == doc['pdf']['bytes'], 'source PDF byte length drift')
            page_number = source.get('physical_pdf_page_one_based')
            page_index = source.get('physical_pdf_page_index_zero_based')
            require(type(page_number) is int and type(page_index) is int and
                    page_number == page_index + 1 and 1 <= page_number <= doc['page_count'],
                    'source page identity drift')
            cache_key = doc['publication_id']
            if cache_key not in page_cache:
                self._verify_document_files(doc)
                if cache_key not in self._verified_page_cache:
                    self._verified_page_cache[cache_key] = (
                        tuple(self._pages(doc, 'plain')), tuple(self._pages(doc, 'coverage')))
                page_cache[cache_key] = self._verified_page_cache[cache_key]
            pages, coverage = page_cache[cache_key]
            page = pages[page_index]
            require(page['source_sha256'] == source_file['sha256'], 'projection source PDF drift')
            quote = source.get('quote')
            span = source.get('character_span')
            require(type(quote) is str and quote and hashlib.sha256(quote.encode()).hexdigest() == source.get('quote_sha256'),
                    'qualified source quote digest drift')
            require(type(span) is dict and span.get('interval') == 'HALF_OPEN' and
                    span.get('unit') == 'UNICODE_CODE_POINT' and type(span.get('start')) is int and
                    type(span.get('end')) is int and span['start'] < span['end'],
                    'qualified source span drift')
            needle, _ = normalized_spans(quote)
            normalized_page, positions = normalized_spans(page['text'])
            require(bool(needle), 'empty normalized source quote')
            found, cursor = [], 0
            while (position := normalized_page.find(needle, cursor)) >= 0:
                finish = position + len(needle)
                cursor = position + 1
                if ((position and positions[position] == positions[position-1]) or
                        (finish < len(positions) and positions[finish-1] == positions[finish])):
                    continue
                start, end = positions[position][0], positions[finish-1][1]
                found.append([start, end])
            require(len(found) == 1, 'qualified quote is absent or ambiguous on normalized source page')
            projection_span = found[0]
            projection_quote = page['text'][projection_span[0]:projection_span[1]]
            oscal_locator = source.get('structural_oscal_locator')
            oscal_file = source.get('oscal_source_file')
            if oscal_locator is not None:
                require(type(oscal_locator) is str and oscal_locator.startswith('oscal://sha256/') and
                        type(oscal_file) is dict and type(oscal_file.get('sha256')) is str,
                        'invalid qualified OSCAL binding')
                structural_source = {
                    'status': 'QUALIFIED_OSCAL_SOURCE_AVAILABLE',
                    'source_file': oscal_file,
                    'locator': oscal_locator,
                    'oscal_version': source.get('oscal_version'),
                    'content_version': source.get('oscal_content_version'),
                    'reason': ('OSCAL is shown because NIST publishes SP 800-53 in this machine-readable '
                               'structure. It gives the control or control-part a stable structural address; '
                               'the semantic execution trace separately determines what conclusion is warranted.'),
                }
            else:
                structural_source = {
                    'status': 'NO_QUALIFIED_OSCAL_SOURCE',
                    'reason': ('OSCAL is optional. This source remains bound through the frozen PDF and normalized '
                               'page projection; no OSCAL address was qualified for it.'),
                }
            result[source_id] = {
                'schema': 'jc/documentary-source-chain/1',
                'source_id': source_id,
                'publication_identity': source.get('publication_identity', doc['title']),
                'publication_revision': source.get('publication_revision'),
                'corpus_release': source.get('corpus_release', self.manifest['corpus_release']),
                'source_authority': {
                    'semantic_pack_pdf': source_file,
                    'retained_library_pdf': doc['pdf'],
                    'binding': 'SAME_SHA256_AND_BYTE_LENGTH',
                },
                'qualified_source_location': {
                    'physical_pdf_page_index': page_index,
                    'physical_pdf_page_number': page_number,
                    'printed_page_label': source.get('printed_page_label'),
                    'item_label': source.get('paragraph_or_control_item_label'),
                    'sentence_index': source.get('sentence_index_one_based'),
                    'character_span': span,
                    'exact_quote': quote,
                    'exact_quote_sha256': source['quote_sha256'],
                    'extracted_page_text_sha256': source.get('extracted_page_text_sha256'),
                },
                'normalized_page_projection': self._normalized_page_projection(doc, page),
                'projection_occurrence': {
                    'character_span': projection_span,
                    'exact_quote': projection_quote,
                    'exact_quote_sha256': hashlib.sha256(projection_quote.encode()).hexdigest(),
                    'match_relation': 'EXACT_NORMALIZED_TEXT_ON_SAME_FROZEN_PDF_PAGE',
                    'coverage': coverage[page_index],
                },
                'structural_source': structural_source,
                'meaning_boundary': ('The PDF and OSCAL records establish source text and structure. The separate '
                                     'interpretation and execution traces establish only the admitted semantic result.'),
            }
        return result

    def _occurrences(self, needle, docs):
        """Yield all exact-normalized matches; verify every page even after a UI limit."""
        for doc in docs:
            self._verified_path(doc['pdf'])
            coverage = list(self._pages(doc, 'coverage'))
            for page in self._pages(doc, 'plain'):
                fast_normalized = normalized_text(page['text'])
                if needle not in fast_normalized:
                    continue
                normalized, spans = normalized_spans(page['text'])
                require(normalized == fast_normalized, 'citation normalization prefilter drift')
                location_index = _text_location_index(page['text'])
                cursor = 0
                while (position := normalized.find(needle, cursor)) >= 0:
                    finish = position + len(needle)
                    cursor = position + 1
                    # Never match half of a Unicode casefold expansion.
                    if (position and spans[position] == spans[position-1]) or (finish < len(spans) and spans[finish-1] == spans[finish]):
                        continue
                    start, end = spans[position][0], spans[finish-1][1]
                    quote = page['text'][start:end]
                    yield {'publication_id': doc['publication_id'],
                           'physical_pdf_page_index': page['pdf_page_index'],
                           'physical_pdf_page_number': page['pdf_page_number'],
                           'character_span': [start, end], 'exact_quote': quote,
                           'text_location': _text_location(location_index, start, end),
                           'exact_quote_sha256': hashlib.sha256(quote.encode()).hexdigest(),
                           'normalized_quote_sha256': hashlib.sha256(normalized_spans(quote)[0].encode()).hexdigest(),
                           'source_file': doc['pdf'], 'extracted_file': doc['extraction']['plain'],
                           'normalized_page_projection': self._normalized_page_projection(doc, page),
                           'page_text_sha256': page['text_sha256'],
                           'coverage': coverage[page['pdf_page_index']],
                           'admission': 'EXTRACTED_OCCURRENCE_ONLY_REQUIRES_SOURCE_AND_INTERPRETATION_REVIEW'}

    def _occurrences_many(self, needles, docs):
        """Enumerate several exact-normalized passages in one verified corpus pass."""
        require(type(needles) is list and needles and len(needles) <= 256 and
                all(type(needle) is str and needle for needle in needles),
                'normalized citation needles required')
        unique = list(dict.fromkeys(needles))
        results = {needle: [] for needle in unique}
        for doc in docs:
            self._verified_path(doc['pdf'])
            coverage = list(self._pages(doc, 'coverage'))
            for page in self._pages(doc, 'plain'):
                fast_normalized = normalized_text(page['text'])
                candidate_needles = [needle for needle in unique if needle in fast_normalized]
                if not candidate_needles:
                    continue
                normalized, spans = normalized_spans(page['text'])
                require(normalized == fast_normalized, 'citation normalization prefilter drift')
                positions_by_needle = {}
                for needle in candidate_needles:
                    found, cursor = [], 0
                    while (position := normalized.find(needle, cursor)) >= 0:
                        finish = position + len(needle)
                        cursor = position + 1
                        if ((position and spans[position] == spans[position-1]) or
                                (finish < len(spans) and spans[finish-1] == spans[finish])):
                            continue
                        found.append((position, finish))
                    if found:
                        positions_by_needle[needle] = found
                if not positions_by_needle:
                    continue
                location_index = _text_location_index(page['text'])
                for needle, found in positions_by_needle.items():
                    for position, finish in found:
                        start, end = spans[position][0], spans[finish-1][1]
                        quote = page['text'][start:end]
                        matches = results[needle]
                        require(len(matches) < 10000,
                                'citation exceeds 10000 occurrences; choose a more specific passage')
                        matches.append({
                            'publication_id': doc['publication_id'],
                            'physical_pdf_page_index': page['pdf_page_index'],
                            'physical_pdf_page_number': page['pdf_page_number'],
                            'character_span': [start, end], 'exact_quote': quote,
                            'text_location': _text_location(location_index, start, end),
                            'exact_quote_sha256': hashlib.sha256(quote.encode()).hexdigest(),
                            'normalized_quote_sha256': hashlib.sha256(
                                normalized_spans(quote)[0].encode()).hexdigest(),
                            'source_file': doc['pdf'], 'extracted_file': doc['extraction']['plain'],
                            'normalized_page_projection': self._normalized_page_projection(doc, page),
                            'page_text_sha256': page['text_sha256'],
                            'coverage': coverage[page['pdf_page_index']],
                            'admission': 'EXTRACTED_OCCURRENCE_ONLY_REQUIRES_SOURCE_AND_INTERPRETATION_REVIEW',
                        })
        return results

    def cite_many(self, requests):
        """Bind several citations while scanning the frozen corpus exactly once."""
        require(type(requests) is list and 1 <= len(requests) <= 256 and
                all(type(item) is dict for item in requests),
                'citation request list required')
        prepared = []
        target_pages = {}
        for request in requests:
            require(set(request) == {'publication_id', 'page_number', 'character_span', 'exact_quote'},
                    'citation request fields')
            publication_id = request['publication_id']
            page_number = request['page_number']
            character_span = request['character_span']
            exact_quote = request['exact_quote']
            require(type(character_span) is list and len(character_span) == 2 and
                    all(type(x) is int for x in character_span),
                    'citation span must contain two integer offsets')
            require(type(exact_quote) is str and 1 <= len(exact_quote) <= 1000,
                    'citation quote required (maximum 1000 characters)')
            page_key = (publication_id, page_number)
            if page_key not in target_pages:
                target_pages[page_key] = self.page(publication_id, page_number)
            page = target_pages[page_key]
            start, end = character_span
            text = page['page']['text']
            require(0 <= start < end <= len(text) and text[start:end] == exact_quote,
                    'citation quote/span mismatch')
            needle, _ = normalized_spans(exact_quote)
            require(bool(needle) and not exact_quote[0].isspace() and
                    not exact_quote[-1].isspace(),
                    'citation quote must have non-whitespace boundaries')
            prepared.append((request, needle))
        docs = sorted(self.documents.values(), key=lambda d: d['publication_id'])
        inventories = self._occurrences_many([needle for _request, needle in prepared], docs)
        results = []
        for request, needle in prepared:
            publication_id = request['publication_id']
            page_number = request['page_number']
            character_span = request['character_span']
            exact_quote = request['exact_quote']
            occurrences = inventories[needle]
            selected = [m for m in occurrences if m['publication_id'] == publication_id and
                        m['physical_pdf_page_number'] == page_number and
                        m['character_span'] == character_span]
            require(len(selected) == 1 and selected[0]['exact_quote'] == exact_quote,
                    'selected citation absent from verified occurrence inventory')
            doc = self._document(publication_id)
            provenance = {
                **selected[0], 'publication_title': doc['title'],
                'publication_metadata': doc['publication_metadata'],
                'corpus_release': self.manifest['corpus_release'],
                'manifest_sha256': self.manifest_sha256,
                'structural_oscal_locator': None, 'printed_page_label': None,
                'paragraph_or_control_item_label': None,
                'sentence_index': selected[0]['text_location']['sentence_index'],
                'sentence_index_method': TEXT_LOCATION_METHOD,
                'unqualified_fields': ['structural_oscal_locator', 'printed_page_label',
                                       'paragraph_or_control_item_label'],
                'location_ceiling': ('EXACT_FROZEN_PLAIN_EXTRACTION_SPAN;'
                                     'STRUCTURAL_AND_PRINTED_LOCATORS_NOT_QUALIFIED'),
            }
            claim = {'type': 'SOURCE_BOUND', 'text': exact_quote,
                     'scope': 'EXACT_EXTRACTED_TEXT_ONLY',
                     'provenance_sha256': digest(provenance)}
            claim['id'] = 'source-quote:' + digest(claim)
            results.append({
                'status': 'BOUND_EXTRACTED_TEXT_CITATION',
                'request_sha256': digest(request), 'claim': claim,
                'provenance': provenance,
                'interpretation_trace': {
                    'status': 'NOT_INTERPRETED',
                    'selection': ('Caller-selected exact page span; source identity and text '
                                  'verified deterministically.'),
                },
                'occurrences': occurrences,
                'occurrence_inventory_sha256': digest(occurrences),
                'total_occurrences': len(occurrences),
                'returned_occurrences': len(occurrences), 'truncated': False,
                'documents_searched': len(docs),
                'pages_searched': sum(d['page_count'] for d in docs),
                'normalization': NORMALIZATION,
                'occurrence_scope': ('ALL_RETAINED_FROZEN_PLAIN_PAGE_EXTRACTIONS_ONLY_'
                                     'NO_CROSS_PAGE_MATCHES'),
                'authority_ceiling': {'semantic_interpretation': False,
                                      'compliance_verdict': None,
                                      'responsibility_assignment': None,
                                      'external_effects': []},
                **self.summary(),
            })
        return results

    def search(self, phrase, publication_id=None, limit=20):
        require(type(phrase) is str and 1 <= len(phrase) <= 1000, 'search phrase required')
        needle, _ = normalized_spans(phrase)
        require(bool(needle) and type(limit) is int and 1 <= limit <= 100, 'invalid search limit or phrase')
        docs = [self._document(publication_id)] if publication_id is not None else sorted(self.documents.values(), key=lambda d:d['publication_id'])
        matches, total = [], 0
        for match in self._occurrences(needle, docs):
            total += 1
            if len(matches) < limit:
                matches.append(match)
        return {'status':'EXTRACTED_TEXT_OCCURRENCES','original_phrase':phrase,'normalized_phrase':needle,'normalization':NORMALIZATION,
                'matches':matches,'total_occurrences':total,'returned_occurrences':len(matches),'truncated':total>len(matches),
                'pages_searched':sum(d['page_count'] for d in docs),'documents_searched':len(docs),'publication_filter':publication_id,
                'occurrence_scope':'FROZEN_PLAIN_PAGE_EXTRACTIONS_ONLY_NO_CROSS_PAGE_MATCHES',**self.summary()}

    def cite(self, publication_id, page_number, character_span, exact_quote):
        """List all extracted-text matches for an exact supplied span."""
        require(type(character_span) is list and len(character_span) == 2 and
                all(type(x) is int for x in character_span), 'citation span must contain two integer offsets')
        require(type(exact_quote) is str and 1 <= len(exact_quote) <= 1000, 'citation quote required (maximum 1000 characters)')
        page = self.page(publication_id, page_number)
        start, end = character_span
        text = page['page']['text']
        require(0 <= start < end <= len(text) and text[start:end] == exact_quote, 'citation quote/span mismatch')
        needle, _ = normalized_spans(exact_quote)
        require(bool(needle) and not exact_quote[0].isspace() and not exact_quote[-1].isspace(), 'citation quote must have non-whitespace boundaries')
        docs = sorted(self.documents.values(), key=lambda d:d['publication_id'])
        occurrences = []
        for match in self._occurrences(needle, docs):
            require(len(occurrences) < 10000, 'citation exceeds 10000 occurrences; choose a more specific passage')
            occurrences.append(match)
        selected = [m for m in occurrences if m['publication_id'] == publication_id and
                    m['physical_pdf_page_number'] == page_number and m['character_span'] == character_span]
        require(len(selected) == 1 and selected[0]['exact_quote'] == exact_quote, 'selected citation absent from verified occurrence inventory')
        doc = self._document(publication_id)
        request = {'publication_id': publication_id, 'page_number': page_number,
                   'character_span': character_span, 'exact_quote': exact_quote}
        provenance = {**selected[0], 'publication_title': doc['title'],
                      'publication_metadata': doc['publication_metadata'],
                      'corpus_release': self.manifest['corpus_release'],
                      'manifest_sha256': self.manifest_sha256,
                      'structural_oscal_locator': None, 'printed_page_label': None,
                      'paragraph_or_control_item_label': None,
                      'sentence_index': selected[0]['text_location']['sentence_index'],
                      'sentence_index_method': TEXT_LOCATION_METHOD,
                      'unqualified_fields': ['structural_oscal_locator', 'printed_page_label',
                                             'paragraph_or_control_item_label'],
                      'location_ceiling': 'EXACT_FROZEN_PLAIN_EXTRACTION_SPAN;STRUCTURAL_AND_PRINTED_LOCATORS_NOT_QUALIFIED'}
        claim = {'type': 'SOURCE_BOUND', 'text': exact_quote, 'scope': 'EXACT_EXTRACTED_TEXT_ONLY',
                 'provenance_sha256': digest(provenance)}
        claim['id'] = 'source-quote:' + digest(claim)
        return {'status': 'BOUND_EXTRACTED_TEXT_CITATION', 'request_sha256': digest(request),
                'claim': claim, 'provenance': provenance,
                'interpretation_trace': {'status': 'NOT_INTERPRETED',
                    'selection': 'Caller-selected exact page span; source identity and text verified deterministically.'},
                'occurrences': occurrences, 'occurrence_inventory_sha256': digest(occurrences),
                'total_occurrences': len(occurrences), 'returned_occurrences': len(occurrences),
                'truncated': False, 'documents_searched': len(docs),
                'pages_searched': sum(d['page_count'] for d in docs),
                'normalization': NORMALIZATION,
                'occurrence_scope': 'ALL_RETAINED_FROZEN_PLAIN_PAGE_EXTRACTIONS_ONLY_NO_CROSS_PAGE_MATCHES',
                'authority_ceiling': {'semantic_interpretation': False, 'compliance_verdict': None,
                                      'responsibility_assignment': None, 'external_effects': []},
                **self.summary()}

    def ask(self, request):
        require(type(request) is dict, 'library request object required')
        operation = request.get('operation')
        allowed = {'documents':{'operation','offset','limit'},'page':{'operation','publication_id','page_number','view'},
                   'search':{'operation','phrase','publication_id','limit'},
                   'cite':{'operation','publication_id','page_number','character_span','exact_quote'}}
        require(operation in allowed and set(request) <= allowed[operation], 'unsupported library operation or fields')
        if operation == 'documents': return self.list_documents(request.get('offset',0),request.get('limit',25))
        if operation == 'page': return self.page(request.get('publication_id'),request.get('page_number'),request.get('view','plain'))
        if operation == 'cite':
            return self.cite(request.get('publication_id'), request.get('page_number'), request.get('character_span'), request.get('exact_quote'))
        return self.search(request.get('phrase'),request.get('publication_id'),request.get('limit',20))
