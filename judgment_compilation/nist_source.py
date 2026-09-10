"""Verifies NIST source files and page locations."""
from __future__ import annotations
import argparse
import hashlib
import json
import re
from pathlib import Path
import xml.etree.ElementTree as ET
import pymupdf
from .kernel import require

ROOT = Path(__file__).resolve().parent
CORPUS = 'data/corpus'
SOURCE_MANIFEST_SHA256 = '4c78ee86ace95572c2c9a6489b3aede74d24d8fff9e9092cc462afaf571dbce3'
XML_HASH = 'a9e23b09116d5e651461d61777c2e7dc1f3454ab3f9e1e8fdf8af01c37dc01be'
RELEASE = 'NIST_SP_800_53_SUITE_RELEASE_5_2_0'
NS = {'o': 'http://csrc.nist.gov/ns/oscal/1.0'}
TARGETS = [
 ('AC-2(l)', 'ac-2', ['ac-2_smt', 'ac-2_smt.l'], 'Align account management processes with personnel termination and transfer processes.', 46),
 ('AC-6 Control', 'ac-6', ['ac-6_smt'], 'Employ the principle of least privilege, allowing only authorized accesses for users (or processes acting on behalf of users) that are necessary to accomplish assigned organizational tasks.', 63),
 ('PS-4(a)', 'ps-4', ['ps-4_smt', 'ps-4_smt.a'], 'Disable system access within [Assignment: organization-defined time period];', 251),
 ('SI-2(c)', 'si-2', ['si-2_smt', 'si-2_smt.c'], 'Install security-relevant software and firmware updates within [Assignment: organization-defined time period] of the release of the updates; and', 360),
 ('PS-4(b)', 'ps-4', ['ps-4_smt', 'ps-4_smt.b'], 'Terminate or revoke any authenticators and credentials associated with the individual;', 251),
]

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def read_json(path: str, root: Path = ROOT):
    return json.loads((root / path).read_text(encoding='utf-8-sig'))

def descriptor(path: str, root: Path = ROOT) -> dict:
    data = (root / path).read_bytes()
    return {'path': path, 'bytes': len(data), 'sha256': sha(data)}

def normalized(value: str) -> str:
    return normalize_with_map(value)[0]

def normalize_with_map(value: str):
    chars, offsets = [], []
    for token in re.finditer(r'\S+', value):
        gap = value[offsets[-1] + 1:token.start()] if offsets else ''
        # Keep the source hyphen, but join a PDF line break immediately after it.
        linewrapped_hyphen = bool(chars and chars[-1] == '-' and ('\n' in gap or '\r' in gap))
        if chars and not linewrapped_hyphen:
            chars.append(' ')
            offsets.append(token.start() - 1)
        chars.extend(token.group())
        offsets.extend(range(token.start(), token.end()))
    return ''.join(chars), offsets

def frozen_inputs(root: Path = ROOT):
    root = root.resolve()
    path = root / CORPUS / 'source/source_manifest.json'
    raw = path.read_bytes()
    require(sha(raw) == SOURCE_MANIFEST_SHA256, 'source manifest drift')
    manifest = json.loads(raw)
    for source in manifest['frozen_sources']:
        source_path = (root / source['path']).resolve()
        require(source_path.is_relative_to(root) and not Path(source['path']).is_absolute(), 'source path escape')
        data = source_path.read_bytes()
        require(len(data) == source['bytes'] and sha(data) == source['sha256'], 'frozen source drift')
    return manifest


def xml_support(tree, control_id, parts):
    control = tree.find('.//o:control[@id="' + control_id + '"]', NS)
    require(control is not None, 'missing OSCAL control')
    current = control
    for part in parts:
        current = current.find('o:part[@id="' + part + '"]', NS)
        require(current is not None, 'missing OSCAL part')
    paragraph = current.find('o:p', NS)
    require(paragraph is not None, 'missing OSCAL paragraph')
    def render(node):
        value = node.text or ''
        for child in node:
            if child.tag.endswith('}insert'):
                parameter = control.find('o:param[@id="' + child.attrib['id-ref'] + '"]', NS)
                require(parameter is not None, 'missing OSCAL parameter')
                label = parameter.find('o:label', NS)
                require(label is not None, 'unsupported parameter rendering')
                value += '[Assignment: organization-defined ' + normalized(''.join(label.itertext())) + ']'
            else:
                value += render(child)
            value += child.tail or ''
        return value
    return normalized(render(paragraph))

def provenance_inventory(manifest, root: Path = ROOT):
    xml = next(s for s in manifest['frozen_sources'] if s['sha256'] == XML_HASH)
    tree = ET.parse(root / xml['path'])
    pdfs = [s for s in manifest['frozen_sources'] if s['path'].lower().endswith('.pdf')]
    occurrences = {t[0]: [] for t in TARGETS}
    coverage = []
    for source in pdfs:
        with pymupdf.open(root / source['path']) as document:
            for page_index in range(len(document)):
                page = document[page_index]
                value = page.get_text('text', sort=False)
                norm, mapping = normalize_with_map(value)
                footer = re.findall(r'CHAPTER\s+[A-Z]+\s+PAGE\s+\d+', value)
                printed = normalized(footer[-1]) if footer else None
                for label, _, _, query, _ in TARGETS:
                    begin = 0
                    while (at := norm.find(normalized(query), begin)) != -1:
                        end = at + len(normalized(query))
                        left, right = mapping[at], mapping[end - 1] + 1
                        quote = value[left:right]
                        require(normalized(quote) == normalized(query), 'quote lift-back')
                        occurrences[label].append({
                            'source_file': {k: source[k] for k in ('path', 'bytes', 'sha256', 'role')},
                            'physical_pdf_page_index_zero_based': page_index,
                            'physical_pdf_page_one_based': page_index + 1,
                            'printed_page_label': printed,
                            'pdf_page_label_metadata': page.get_label(),
                            'sentence_index_one_based': 1 + len(re.findall(r'[.!?;](?=\s|$)', value[:left])),
                            'character_span': {'start': left, 'end': right, 'unit': 'UNICODE_CODE_POINT', 'interval': 'HALF_OPEN'},
                            'quote': quote, 'quote_sha256': sha(quote.encode()),
                            'normalized_quote_sha256': sha(normalized(quote).encode()),
                            'extracted_page_text_sha256': sha(value.encode()),
                        })
                        begin = at + 1
            coverage.append({**{k: source[k] for k in ('path', 'bytes', 'sha256', 'role')}, 'pages_scanned': len(document)})
    inventory = {}
    for label, control, parts, query, physical in TARGETS:
        require(xml_support(tree, control, parts) == normalized(query), 'OSCAL/PDF textual mismatch: ' + label)
        primary = [o for o in occurrences[label] if o['source_file']['role'] == 'SP800_53_NORMATIVE_BASE_PUBLICATION' and o['physical_pdf_page_one_based'] == physical]
        require(len(primary) == 1, 'ambiguous primary support: ' + label)
        locator = 'oscal://sha256/' + XML_HASH + '/group/' + control.split('-')[0] + '/control/' + control + ''.join('/part/' + p for p in parts)
        inventory[label] = {
            **primary[0], 'id': label, 'publication_identity': 'NIST SP 800-53', 'publication_revision': 'Revision 5, September 2020; updates as of December 10, 2020',
            'corpus_release': RELEASE, 'oscal_content_version': '5.2.0', 'oscal_version': '1.2.2', 'oscal_release_date': '2025-08-27',
            'structural_oscal_locator': locator, 'oscal_source_file': {k: xml[k] for k in ('path', 'bytes', 'sha256')},
            'oscal_rendered_quote': normalized(query), 'paragraph_or_control_item_label': label,
            'all_exact_normalized_occurrences': occurrences[label],
            'occurrence_count': len(occurrences[label]),
            'occurrence_scope': {'normalization': 'Unicode whitespace runs collapsed to ASCII space except line breaks immediately after a hyphen, which are joined while preserving the hyphen; case and all non-whitespace characters preserved', 'sources': coverage, 'coverage_ceiling': 'All in-page exact-normalized occurrences in text extracted from every PDF frozen by the manifest, including the release change summary. No OCR, cross-page joins, semantic matches, or claims of occurrences in unlisted sources. Other-page occurrences do not inherit the primary OSCAL or item locator.', 'sentence_index_convention': 'One-based extracted-page segment index; boundaries are . ! ? or ; followed by whitespace/end, including headings and abbreviations; not linguistic sentence segmentation.', 'extractor': 'PyMuPDF ' + pymupdf.VersionBind, 'extraction': "page.get_text('text', sort=False)", 'printed_label_ceiling': 'Printed chapter footer when present; null means not structurally classified, with PDF metadata recorded separately.'},
        }
    return inventory
