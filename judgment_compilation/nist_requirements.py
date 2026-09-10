"""Reads NIST requirement templates and fills supplied values."""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import xml.etree.ElementTree as ET

from .nist_catalog import SOURCE_RELATIVE_PATH, SOURCE_SHA256, OSCAL_NAMESPACE, _element_locators

REQUEST_SCHEMA = 'jc/requirement-request/1'
TEMPLATE_SCHEMA = 'jc/requirement-template/1'
RESULT_SCHEMA = 'jc/requirement-result/1'
WARRANT_SCHEMA = 'jc/requirement-operation-warrant/1'
CEILING = 'SOURCE_REQUIREMENT_INSTANTIATION_ONLY;NO_APPLICABILITY_OR_SATISFACTION_OR_COMPLIANCE'
DISPOSITION_SCHEMA = 'jc/requirement-template-disposition-index/1'
DISPOSITION_CEILING = (
    'SOURCE_REQUIREMENT_INSTANTIATION_ONLY;'
    'NO_POLICY_SEMANTIC_MAPPING_OR_APPLICABILITY_OR_SATISFACTION_OR_COMPLIANCE_OR_EFFECT'
)
NS = '{' + OSCAL_NAMESPACE + '}'
OSCAL_REFERENCE = 'https://pages.nist.gov/OSCAL-Reference/models/v1.2.2/catalog/xml-reference/'
PARAMETER_INDEX_REFERENCE = ('https://github.com/usnistgov/OSCAL/blob/v1.2.2/'
                             'src/metaschema/oscal_catalog_metaschema.xml#L71-L73')


class RequirementError(ValueError):
    """Invalid input or source integrity failure; no requirement is released."""


def _need(condition, message):
    if not condition:
        raise RequirementError(message)


def _keys(value, required):
    _need(type(value) is dict and set(value) == set(required), 'unexpected or missing fields')


def _text(value):
    return type(value) is str and 0 < len(value) <= 4096 and value.strip() == value and not any(ord(c) < 32 for c in value)


def _names(values, maximum=128):
    _need(type(values) is list and len(values) <= maximum and all(_text(v) for v in values), 'invalid names or values')
    _need(len(values) == len(set(values)), 'duplicate names or values')


def _canonical(value):
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    except (TypeError, ValueError, RecursionError) as exc:
        raise RequirementError('invalid canonical JSON') from exc


def _digest(value):
    return sha256(_canonical(value)).hexdigest()


def _scope(value):
    _keys(value, {'organization_id', 'system_id'})
    _need(all(_text(v) for v in value.values()), 'invalid organization/system scope')


def _local(element):
    return element.tag.removeprefix(NS)


class Requirements:
    """Read, inspect, and instantiate pinned OSCAL requirement templates."""

    def __init__(self, root=None):
        self._root = Path(root).resolve() if root is not None else Path(__file__).resolve().parents[1]
        self._tree = None

    def _load(self):
        path = (self._root / SOURCE_RELATIVE_PATH).resolve()
        _need(path.is_relative_to(self._root), 'source path escape')
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise RequirementError('fixed OSCAL source unavailable') from exc
        _need(sha256(raw).hexdigest() == SOURCE_SHA256, 'fixed OSCAL source checksum mismatch')
        if self._tree is not None:
            return
        tree = ET.fromstring(raw)
        _need(tree.tag == NS + 'catalog', 'unsupported OSCAL source namespace')
        metadata = tree.find(NS + 'metadata')
        _need(metadata is not None, 'missing source metadata')
        self._metadata = {'catalog_version': metadata.findtext(NS + 'version'),
                          'oscal_version': metadata.findtext(NS + 'oscal-version'),
                          'source_relative_path': SOURCE_RELATIVE_PATH.as_posix(),
                          'version_basis': 'PINNED_XML_METADATA;FILENAME_IS_LOCATOR_ONLY'}
        self._locators = _element_locators(tree)
        self._parents = {id(child): parent for parent in tree.iter() for child in parent}
        self._nodes = {}
        for node in tree.iter():
            identity = node.get('id')
            if identity:
                _need(identity not in self._nodes, 'duplicate source identity')
                self._nodes[identity] = node
        self._statements = {}
        for node in tree.iter(NS + 'part'):
            if node.get('name') not in {'statement', 'item'} or not node.get('id'):
                continue
            ancestors = self._ancestors(node)
            if node.get('name') == 'statement' or any(a.tag == NS + 'part' and a.get('name') == 'statement' for a in ancestors):
                self._statements[node.get('id')] = node
        self._tree = tree

    def _ancestors(self, node):
        result = []
        while id(node) in self._parents:
            node = self._parents[id(node)]
            if node.tag == NS + 'control':
                break
            result.append(node)
        return list(reversed(result))

    def _owner(self, node):
        while node.tag != NS + 'control' and id(node) in self._parents:
            node = self._parents[id(node)]
        _need(node.tag == NS + 'control', 'statement has no owning control')
        return node

    def _reference(self, node):
        return {'source_sha256': SOURCE_SHA256, 'xml_locator': self._locators[id(node)],
                'xml_id': node.get('id'), 'serialized_xml': ET.tostring(node, encoding='unicode')}

    def _paragraph(self, node, position, issues):
        tokens = []

        def visit(element):
            if element.text:
                tokens.append({'kind': 'SOURCE_TEXT', 'text': element.text})
            for child in element:
                if child.tag == NS + 'insert':
                    if set(child.attrib) != {'type', 'id-ref'} or child.get('type') != 'param' or list(child) or child.text:
                        issues.append({'reason': 'UNSUPPORTED_INSERT_GRAMMAR', 'xml_locator': self._locators[id(child)]})
                    tokens.append({'kind': 'PARAMETER', 'parameter_id': child.get('id-ref'), 'xml_locator': self._locators[id(child)]})
                elif child.tag in {NS + x for x in ('em', 'strong', 'b', 'i', 'code', 'sub', 'sup')} and not child.attrib:
                    visit(child)
                elif (child.tag == NS + 'a' and set(child.attrib) == {'href'}
                      and child.get('href', '').startswith('#')
                      and child.get('href')[1:] in self._nodes):
                    # Preserve visible cross-reference text; the exact href and markup
                    # remain in serialized source. Do not dereference or interpret it.
                    visit(child)
                else:
                    issues.append({'reason': 'UNSUPPORTED_INLINE_GRAMMAR', 'xml_locator': self._locators[id(child)]})
                    tokens.append({'kind': 'UNSUPPORTED_SOURCE', 'serialized_xml': ET.tostring(child, encoding='unicode')})
                if child.tail:
                    tokens.append({'kind': 'SOURCE_TEXT', 'text': child.tail})
        visit(node)
        return {'kind': 'PARAGRAPH', 'source_child_position': position,
                'source': self._reference(node), 'tokens': tokens}

    def _body(self, node, issues):
        blocks = []
        for position, child in enumerate(node, 1):
            if child.tag == NS + 'p':
                blocks.append(self._paragraph(child, position, issues))
            elif child.tag == NS + 'part' and child.get('name') == 'item':
                blocks.append({'kind': 'ITEM', 'source_child_position': position,
                               'source': self._reference(child), 'blocks': self._body(child, issues)})
            elif child.tag != NS + 'prop':
                issues.append({'reason': 'UNSUPPORTED_STATEMENT_GRAMMAR', 'xml_locator': self._locators[id(child)]})
        return blocks

    def _parameter(self, parameter_id, control, issues):
        choices, choice_templates = [], []
        # OSCAL 1.2.2 indexes catalog-params over //param, keyed by exact @id.
        # _load rejects duplicate IDs and pins the whole catalog before this lookup.
        node = self._nodes.get(parameter_id)
        reason = None
        if self._metadata['oscal_version'] != '1.2.2':
            reason = 'UNSUPPORTED_PARAMETER_RESOLUTION_VERSION'
        elif node is None:
            reason = 'MISSING_CATALOG_PARAMETER'
        elif node.tag != NS + 'param':
            reason = 'WRONG_TYPE_CATALOG_PARAMETER_REFERENCE'
        elif self._parents[id(node)].tag not in {NS + x for x in ('catalog', 'group', 'control')}:
            reason = 'UNSUPPORTED_PARAMETER_DECLARATION_LOCATION'
        if reason:
            issues.append({'reason': reason, 'parameter_id': parameter_id})
            return {'parameter_id': parameter_id, 'kind': 'UNSUPPORTED', 'choices': []}
        parent = self._parents[id(node)]
        declaration_control_id = parent.get('id') if parent.tag == NS + 'control' else None
        resolution_basis = {'kind': 'EXACT_CATALOG_PARAMETER_ID', 'oscal_version': '1.2.2',
                            'reference_url': PARAMETER_INDEX_REFERENCE,
                            'index': 'catalog-params', 'target': '//param', 'key': '@id'}
        local_issues = []
        allowed = {NS + x for x in ('prop', 'label', 'guideline', 'select')}
        if any(child.tag not in allowed for child in node):
            local_issues.append('UNSUPPORTED_PARAMETER_GRAMMAR')
        labels = node.findall(NS + 'label')
        selects = node.findall(NS + 'select')
        cardinality = source_cardinality = None
        cardinality_basis = None
        kind = 'ASSIGNMENT'
        if selects:
            kind = 'SELECTION'
            if len(selects) != 1 or labels:
                local_issues.append('UNSUPPORTED_PARAMETER_GRAMMAR')
            selected = selects[0]
            source_cardinality = selected.get('how-many')
            cardinality = source_cardinality
            cardinality_basis = {'kind': 'EXPLICIT_SOURCE_ATTRIBUTE'}
            if source_cardinality is None and self._metadata['oscal_version'] == '1.2.2':
                cardinality = 'one'
                cardinality_basis = {
                    'kind': 'VERSIONED_SCHEMA_DEFAULT', 'oscal_version': '1.2.2',
                    'reference_url': OSCAL_REFERENCE,
                    'rule': 'Without this setting, only one value should be assumed to be permitted.',
                }
            if set(selected.attrib) - {'how-many'} or cardinality not in {'one', 'one-or-more'}:
                local_issues.append('UNSUPPORTED_SELECTION_CARDINALITY')
            for position, choice in enumerate(selected, 1):
                if choice.tag != NS + 'choice' or choice.attrib:
                    local_issues.append('UNSUPPORTED_SELECTION_CHOICE')
                    continue
                choice_issues = []
                tokens = self._paragraph(choice, position, choice_issues)['tokens']
                if choice_issues or not tokens:
                    local_issues.append('UNSUPPORTED_SELECTION_CHOICE')
                descriptor = {'kind': 'SOURCE_SELECTION_CHOICE', 'parameter_id': parameter_id,
                              'control_id': control.get('id'),
                              'declaration_control_id': declaration_control_id,
                              'source_child_position': position,
                              'source': self._reference(choice), 'tokens': tokens}
                descriptor['choice_sha256'] = _digest(descriptor)
                choice_templates.append(descriptor)
                if all(token['kind'] == 'SOURCE_TEXT' for token in tokens):
                    literal = ''.join(token['text'] for token in tokens)
                    if not _text(literal):
                        local_issues.append('UNSUPPORTED_SELECTION_CHOICE')
                    choices.append(literal)
            if not choice_templates or len(choices) != len(set(choices)):
                local_issues.append('UNSUPPORTED_SELECTION_CHOICE')
        label = labels[0].text if labels else None
        if not selects:
            label_issues = []
            label_tokens = (self._paragraph(labels[0], 1, label_issues)['tokens']
                            if len(labels) == 1 and not labels[0].attrib else [])
            if (label_issues or not label_tokens
                    or any(token['kind'] != 'SOURCE_TEXT' for token in label_tokens)):
                local_issues.append('UNSUPPORTED_ASSIGNMENT_LABEL')
            else:
                label = ''.join(token['text'] for token in label_tokens)
                if not _text(label):
                    local_issues.append('UNSUPPORTED_ASSIGNMENT_LABEL')
        issues.extend({'reason': reason, 'parameter_id': parameter_id} for reason in sorted(set(local_issues)))
        return {'parameter_id': parameter_id, 'control_id': control.get('id'), 'kind': kind,
                'declaration_control_id': declaration_control_id,
                'declaration_container': {'kind': _local(parent), 'xml_id': parent.get('id'),
                                          'xml_locator': self._locators[id(parent)]},
                'resolution_basis': resolution_basis, 'label': label, 'choices': choices,
                'choice_templates': choice_templates,
                'cardinality': cardinality, 'source_cardinality': source_cardinality,
                'cardinality_basis': cardinality_basis, 'source': self._reference(node),
                'value_ceiling': 'CALLER_SUPPLIED_OPAQUE_VALUE_NOT_VERIFIED_POLICY' if kind == 'ASSIGNMENT' else 'EXACT_SOURCE_CHOICE_IDENTITY_AND_CARDINALITY_ONLY'}

    def _template(self, statement_id):
        node = self._statements.get(statement_id)
        if node is None:
            return None
        control = self._owner(node)
        issues, context = [], []
        ancestors = [a for a in self._ancestors(node) if a.tag == NS + 'part']
        route = [*ancestors, node]
        for index, ancestor in enumerate(ancestors):
            if ancestor.get('name') not in {'statement', 'item'}:
                issues.append({'reason': 'UNSUPPORTED_ANCESTOR_GRAMMAR', 'xml_locator': self._locators[id(ancestor)]})
            paragraphs = [self._paragraph(child, pos, issues) for pos, child in enumerate(ancestor, 1) if child.tag == NS + 'p']
            context.append({'source': self._reference(ancestor), 'name': ancestor.get('name'),
                            'selected_child_position': list(ancestor).index(route[index + 1]) + 1,
                            'paragraphs': paragraphs,
                            'sibling_item_ids': [c.get('id') for c in ancestor if c.tag == NS + 'part' and c is not route[index + 1]],
                            'sibling_ceiling': 'PRESERVED_IN_SERIALIZED_SOURCE_NOT_INSTANTIATED_OR_INTERPRETED'})
        blocks = self._body(node, issues)
        parameter_ids = set()

        def collect(value):
            if type(value) is dict:
                if value.get('kind') == 'PARAMETER':
                    parameter_ids.add(value['parameter_id'])
                for child in value.values():
                    collect(child)
            elif type(value) is list:
                for child in value:
                    collect(child)
        collect([context, blocks])
        root_parameter_ids = sorted(parameter_ids, key=str)
        definitions, active = {}, set()

        def expand(pid):
            if pid in active:
                issues.append({'reason': 'CYCLIC_PARAMETER_REFERENCE', 'parameter_id': pid})
                return
            if pid in definitions:
                return
            active.add(pid)
            definition = self._parameter(pid, control, issues)
            definitions[pid] = definition
            dependencies = sorted({token['parameter_id']
                                   for choice in definition.get('choice_templates', [])
                                   for token in choice['tokens'] if token['kind'] == 'PARAMETER'}, key=str)
            definition['dependency_parameter_ids'] = dependencies
            for dependency in dependencies:
                expand(dependency)
            active.remove(pid)
        for pid in root_parameter_ids:
            expand(pid)
        parameters = [definitions[pid] for pid in sorted(definitions, key=str)]
        template = {'schema': TEMPLATE_SCHEMA, 'statement_id': statement_id,
                    'control_id': control.get('id'), 'control_title': control.findtext(NS + 'title'),
                    'source': self._reference(node), 'source_metadata': deepcopy(self._metadata),
                    'ancestor_context': context,
                    'blocks': blocks, 'root_parameter_ids': root_parameter_ids, 'parameters': parameters,
                    'grammar_status': 'UNSUPPORTED' if issues else 'SUPPORTED', 'grammar_residuals': issues,
                    'ceiling': CEILING, 'pdf_provenance': None}
        template['template_sha256'] = _digest(template)
        return template

    def list_templates(self, control_id=None, offset=0, limit=25):
        """Discover exact statement IDs without returning full source templates."""
        _need(control_id is None or _text(control_id), 'invalid control filter')
        _need(type(offset) is int and offset >= 0, 'invalid template offset')
        _need(type(limit) is int and 1 <= limit <= 100, 'invalid template limit')
        self._load()
        identities = sorted(sid for sid, node in self._statements.items()
                            if control_id is None or self._owner(node).get('id') == control_id)
        page = []
        for sid in identities[offset:offset + limit]:
            template = self._template(sid)
            page.append({key: deepcopy(template[key]) for key in
                         ('statement_id', 'control_id', 'control_title', 'grammar_status', 'template_sha256')})
        return {'schema': 'jc/requirement-list/1', 'source_sha256': SOURCE_SHA256,
                'control_id': control_id, 'offset': offset, 'limit': limit,
                'total_templates': len(self._statements), 'matched_templates': len(identities),
                'templates': page, 'ceiling': CEILING}

    def summary(self):
        self._load()
        counts = Counter()
        for identity in self._statements:
            template = self._template(identity)
            counts[template['grammar_status']] += 1
        return {'schema': 'jc/requirement-summary/1', 'source_sha256': SOURCE_SHA256,
                'source_metadata': deepcopy(self._metadata),
                'statement_templates': len(self._statements), 'supported_templates': counts['SUPPORTED'],
                'unsupported_templates': counts['UNSUPPORTED'], 'ceiling': CEILING,
                'coverage_ceiling': 'Structured OSCAL statement/item templates only; counts do not measure semantic applicability or full-library execution.'}

    def disposition_index(self):
        """List each extracted template and its review status."""
        self._load()
        rows = []
        grammar_counts = Counter()
        for statement_id in sorted(self._statements):
            template = self._template(statement_id)
            grammar_counts[template['grammar_status']] += 1
            parameters = []
            for parameter in template['parameters']:
                source = parameter.get('source')
                parameters.append({
                    'parameter_id': parameter['parameter_id'],
                    'kind': parameter['kind'],
                    'declaration_control_id': parameter.get('declaration_control_id'),
                    'dependency_parameter_ids': deepcopy(parameter.get('dependency_parameter_ids', [])),
                    'source': ({key: source[key] for key in ('source_sha256', 'xml_id', 'xml_locator')}
                               if source else None),
                    'choice_references': [
                        {
                            'choice_sha256': choice['choice_sha256'],
                            'source': {key: choice['source'][key]
                                       for key in ('source_sha256', 'xml_id', 'xml_locator')},
                        }
                        for choice in parameter.get('choice_templates', [])
                    ],
                })
            documentary_status = ('SOURCE_TEMPLATE_ONLY' if template['grammar_status'] == 'SUPPORTED'
                                  else 'UNSUPPORTED_DOCUMENTARY_TEMPLATE')
            rows.append({
                'statement_id': template['statement_id'],
                'control_id': template['control_id'],
                'control_title': template['control_title'],
                'template_sha256': template['template_sha256'],
                'grammar_status': template['grammar_status'],
                'grammar_residuals': deepcopy(template['grammar_residuals']),
                'source': {key: template['source'][key]
                           for key in ('source_sha256', 'xml_id', 'xml_locator')},
                'root_parameter_ids': deepcopy(template['root_parameter_ids']),
                'parameters': parameters,
                'disposition': {
                    'documentary_status': documentary_status,
                    'policy_semantic_mapping': {
                        'status': 'NOT_ADMITTED',
                        'residual': 'REQUIREMENT_TO_POLICY_SEMANTICS_NOT_ADMITTED',
                    },
                    'executable_policy': False,
                    'ceiling': DISPOSITION_CEILING,
                },
            })
        body = {
            'schema': DISPOSITION_SCHEMA,
            'source_sha256': SOURCE_SHA256,
            'source_metadata': deepcopy(self._metadata),
            'counts': {
                'total_templates': len(rows),
                'supported_documentary_templates': grammar_counts['SUPPORTED'],
                'unsupported_documentary_templates': grammar_counts['UNSUPPORTED'],
                'admitted_policy_semantic_mappings': 0,
                'executable_policy_templates': 0,
            },
            'rows': rows,
            'coverage_ceiling': DISPOSITION_CEILING,
        }
        body['index_sha256'] = _digest(body)
        return body

    def validate_disposition_index(self, index):
        """Rebuild from current bytes and reject any omission or mutation."""
        expected = self.disposition_index()
        _need(type(index) is dict and index == expected,
              'requirement disposition index mismatch')
        return deepcopy(expected)

    def prepare(self, request):
        """Validate and bind a request without executing template instantiation."""
        def seal_preparation(canonical_request, result, resolved=None, selected_choices=None):
            preparation = {
                'schema': 'jc/requirement-preparation/1',
                'request': deepcopy(canonical_request),
                'result': deepcopy(result),
                'resolved': deepcopy(resolved or {}),
                'selected_choices': deepcopy(selected_choices or {}),
            }
            preparation['preparation_sha256'] = _digest(preparation)
            return preparation

        _need(type(request) is dict, 'request must be an object')
        operation = request.get('operation')
        fields = {'schema', 'operation', 'statement_id'}
        _need(operation in {'inspect', 'instantiate'}, 'unsupported requirement operation')
        if operation == 'instantiate':
            fields |= {'source_sha256', 'template_sha256', 'scope', 'parameters'}
        _keys(request, fields)
        _need(request['schema'] == REQUEST_SCHEMA and _text(request['statement_id']), 'unsupported request schema or statement')
        request = json.loads(_canonical(request))
        self._load()
        template = self._template(request['statement_id'])
        result = {'schema': RESULT_SCHEMA, 'operation': operation, 'request_sha256': _digest(request),
                  'source_sha256': SOURCE_SHA256, 'template': template, 'instance': None,
                  'residuals': [], 'ceiling': CEILING, 'applicability': None,
                  'satisfaction': None, 'compliance_verdict': None, 'external_effects': []}
        if template is None:
            result.update(status='NOT_FOUND', residuals=[{'reason': 'UNKNOWN_STATEMENT_ID'}])
            return seal_preparation(request, result)
        if operation == 'inspect':
            result.update(status='INSPECTED', residuals=deepcopy(template['grammar_residuals']))
            return seal_preparation(request, result)
        _need(request['source_sha256'] == SOURCE_SHA256, 'request source mismatch')
        _need(request['template_sha256'] == template['template_sha256'], 'request template mismatch')
        _scope(request['scope'])
        _need(type(request['parameters']) is list and len(request['parameters']) <= 256, 'invalid parameter bindings')
        definitions = {p['parameter_id']: p for p in template['parameters']}
        provided = {}
        conflicts = set()
        for binding in request['parameters']:
            _keys(binding, {'parameter_id', 'control_id', 'source_sha256', 'scope', 'values', 'evidence_refs'})
            _need(_text(binding['parameter_id']) and binding['parameter_id'] in definitions, 'foreign parameter')
            _need(binding['control_id'] == template['control_id'], 'foreign control binding')
            _need(binding['source_sha256'] == SOURCE_SHA256, 'foreign parameter source')
            _scope(binding['scope'])
            _need(binding['scope'] == request['scope'], 'foreign parameter scope')
            values = binding['values']
            _need(type(values) is list and len(values) <= 128, 'invalid parameter values')
            for value in values:
                if type(value) is dict:
                    _keys(value, {'choice_sha256'})
                    digest = value['choice_sha256']
                    _need(type(digest) is str and len(digest) == 64 and
                          all(c in '0123456789abcdef' for c in digest), 'invalid choice digest')
                else:
                    _need(_text(value), 'invalid parameter value')
            _need(len({_canonical(v) for v in values}) == len(values), 'duplicate names or values')
            _names(binding['evidence_refs'])
            pid = binding['parameter_id']
            if pid in provided:
                conflicts.add(pid)
            provided[pid] = binding
        residuals = deepcopy(template['grammar_residuals'])
        resolved, selected_choices, visiting, attempted = {}, {}, set(), set()

        def resolve(pid):
            if pid in visiting:
                residuals.append({'reason': 'CYCLIC_PARAMETER_REFERENCE', 'parameter_id': pid})
                return
            if pid in attempted:
                return
            attempted.add(pid)
            visiting.add(pid)
            definition = definitions[pid]
            binding = provided.get(pid)
            reason = None
            if pid in conflicts:
                reason = 'CONFLICTING_OR_DUPLICATE_PARAMETER_BINDINGS'
            elif binding is None or not binding['values']:
                reason = 'MISSING_PARAMETER'
            elif not binding['evidence_refs']:
                reason = 'MISSING_BINDING_EVIDENCE_REFERENCE'
            elif definition['kind'] == 'ASSIGNMENT' and (len(binding['values']) != 1 or
                                                         type(binding['values'][0]) is not str):
                reason = 'OPAQUE_ASSIGNMENT_REQUIRES_ONE_EXPLICIT_VALUE'
            elif definition['kind'] == 'SELECTION':
                choices = definition['choice_templates']
                selected = []
                for value in binding['values']:
                    if type(value) is dict:
                        matches = [c for c in choices if c['choice_sha256'] == value['choice_sha256']]
                    else:
                        matches = [c for c in choices if all(t['kind'] == 'SOURCE_TEXT' for t in c['tokens'])
                                   and ''.join(t['text'] for t in c['tokens']) == value]
                    if len(matches) != 1:
                        reason = 'INVALID_SOURCE_CHOICE_REFERENCE' if type(value) is dict else 'INVALID_LITERAL_SELECTION'
                        break
                    selected.append(matches[0])
                if reason is None and len({c['choice_sha256'] for c in selected}) != len(selected):
                    reason = 'DUPLICATE_SOURCE_CHOICE'
                if definition['cardinality'] == 'one' and len(binding['values']) != 1:
                    reason = 'SELECTION_REQUIRES_EXACTLY_ONE_VALUE'
                if reason is None:
                    selected_choices[pid] = selected
                    for choice in selected:
                        for token in choice['tokens']:
                            if token['kind'] == 'PARAMETER':
                                resolve(token['parameter_id'])
            elif definition['kind'] != 'ASSIGNMENT':
                reason = 'UNSUPPORTED_PARAMETER_GRAMMAR'
            if reason:
                residuals.append({'reason': reason, 'parameter_id': pid})
            else:
                resolved[pid] = binding
            visiting.remove(pid)

        for pid in sorted(set(template['root_parameter_ids']) | set(provided)):
            resolve(pid)
        if residuals:
            result.update(status='UNRESOLVED', residuals=residuals)
            return seal_preparation(request, result, resolved, selected_choices)

        result.update(status='READY_TO_INSTANTIATE')
        return seal_preparation(request, result, resolved, selected_choices)

    def operation_warrant(self, preparation):
        """Produce the exact Judgment receipt that may authorize Work."""
        _need(type(preparation) is dict, 'invalid operation warrant input')
        _keys(preparation, {'schema', 'request', 'result', 'resolved',
                            'selected_choices', 'preparation_sha256'})
        body = deepcopy(preparation)
        preparation_sha256 = body.pop('preparation_sha256')
        _need(body['schema'] == 'jc/requirement-preparation/1'
              and preparation_sha256 == _digest(body), 'requirement preparation drift')
        request = body['request']
        result = body['result']
        status = {
            'READY_TO_INSTANTIATE': 'WARRANTED_EXACT_SOURCE_TEMPLATE_INSTANTIATION',
            'INSPECTED': 'SOURCE_TEMPLATE_INSPECTED_NO_INSTANCE',
        }.get(result['status'], 'UNRESOLVED')
        support_ids = []
        template = result.get('template')
        if template is not None:
            support_ids.append('source-template:' + template['template_sha256'])
        if request.get('operation') == 'instantiate':
            scenario_value = {
                'scope': deepcopy(request['scope']),
                'parameters': deepcopy(sorted(request['parameters'], key=lambda row: row['parameter_id'])),
            }
            support_ids.append('scenario-bindings:' + _digest(scenario_value))
        claim_id = 'requirement-warrant:' + _digest({
            'preparation_sha256': preparation_sha256,
            'request_sha256': result['request_sha256'],
            'status': status,
            'residuals': result.get('residuals', []),
        })
        text = {
            'WARRANTED_EXACT_SOURCE_TEMPLATE_INSTANTIATION': (
                'The declared source, scope, parameters, cardinalities, choices, and evidence references '
                'warrant only an exact documentary template instantiation.'
            ),
            'SOURCE_TEMPLATE_INSPECTED_NO_INSTANCE': (
                'The request warrants source-template inspection only; no requirement instance was requested.'
            ),
            'UNRESOLVED': (
                'The supplied bindings do not warrant an exact documentary template instantiation.'
            ),
        }[status]
        claim = {
            'id': claim_id,
            'type': 'UNRESOLVED' if status == 'UNRESOLVED' else 'DETERMINISTIC_DERIVATION',
            'text': text,
            'value': {'status': status, 'operation_status': result['status'],
                      'residuals': deepcopy(result.get('residuals', []))},
            'support_ids': sorted(support_ids),
        }
        warrant = {'schema': WARRANT_SCHEMA,
                   'preparation_sha256': preparation_sha256,
                   'claim': claim}
        warrant['warrant_sha256'] = _digest(warrant)
        return warrant

    def execute_prepared(self, preparation, warrant):
        """Execute preparation only through a bound Judgment warrant."""
        _need(type(preparation) is dict, 'invalid requirement preparation')
        _keys(preparation, {'schema', 'request', 'result', 'resolved',
                            'selected_choices', 'preparation_sha256'})
        body = deepcopy(preparation)
        supplied_sha256 = body.pop('preparation_sha256')
        _need(body['schema'] == 'jc/requirement-preparation/1'
              and supplied_sha256 == _digest(body), 'requirement preparation drift')
        request = body['request']
        result = body['result']
        resolved = body['resolved']
        selected_choices = body['selected_choices']
        _need(result['request_sha256'] == _digest(request), 'prepared request identity drift')
        _need(type(warrant) is dict, 'missing requirement operation warrant')
        _keys(warrant, {'schema', 'preparation_sha256', 'claim', 'warrant_sha256'})
        warrant_body = deepcopy(warrant)
        warrant_sha256 = warrant_body.pop('warrant_sha256')
        _need(warrant_body['schema'] == WARRANT_SCHEMA
              and warrant_sha256 == _digest(warrant_body),
              'requirement operation warrant drift')
        _need(warrant_body['preparation_sha256'] == supplied_sha256,
              'requirement operation warrant preparation mismatch')
        _need(warrant == self.operation_warrant(preparation),
              'requirement operation warrant is not the produced Judgment receipt')
        if result['status'] != 'READY_TO_INSTANTIATE':
            return deepcopy(result)
        template = result['template']

        def instantiate(value):
            if type(value) is list:
                return [instantiate(item) for item in value]
            if type(value) is not dict:
                return value
            output = {key: instantiate(item) for key, item in value.items()}
            if value.get('kind') == 'PARAMETER':
                binding = resolved[value['parameter_id']]
                output['binding'] = {'type': 'CALLER_SUPPLIED_UNVERIFIED', **deepcopy(binding), 'binding_sha256': _digest(binding)}
                if value['parameter_id'] in selected_choices:
                    output['binding']['selected_choices'] = instantiate(selected_choices[value['parameter_id']])
            return output
        instance = {'type': 'PARAMETERIZED_SOURCE_REQUIREMENT', 'source_sha256': SOURCE_SHA256,
                    'template_sha256': template['template_sha256'], 'request_sha256': _digest(request),
                    'statement_id': template['statement_id'], 'control_id': template['control_id'],
                    'scope': deepcopy(request['scope']), 'ancestor_context': instantiate(template['ancestor_context']),
                    'blocks': instantiate(template['blocks']), 'parameter_bindings': [deepcopy(resolved[pid]) for pid in sorted(resolved)],
                    'selected_choices': {pid: instantiate(choices) for pid, choices in sorted(selected_choices.items())},
                    'ceiling': CEILING, 'applicability': None, 'satisfaction': None, 'compliance_verdict': None}
        instance['instance_sha256'] = _digest(instance)
        result.update(status='INSTANTIATED', instance=instance)
        return result

    def ask(self, request):
        preparation = self.prepare(request)
        return self.execute_prepared(preparation, self.operation_warrant(preparation))
