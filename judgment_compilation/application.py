"""Provides services for the command line and local web page."""
from copy import deepcopy
from pathlib import Path
import hashlib, json, re
from . import __version__
from .kernel import CLAIM_TYPES, SemanticRuntime, canonical, digest, strict_json, require, exact_keys, notation, text
from .integrity import verify_inputs
from ._pins import PACK_SHA256
from .nist_catalog import Catalog
from .semantic_contracts import execute_architecture
from .semantic_node_composition import (
    compose_architecture_program,
    decompose_architecture,
    decompose_judgment,
    decompose_work,
)
from ._native import load_native_executor
from .library import DocumentLibrary
from .nist_requirements import Requirements, REQUEST_SCHEMA
from .requirement_semantics import RequirementSemanticRuntime
from .nist_admission import admit_pack_interpretation_bundle
from .nist_profiles import Profiles
from .nist_assessments import Assessments
from .source_accounting import SourceAccounting
from .source_mappings import SourceMappingRegistry
from .inquiry_planner import InquiryPlanner
from .document_programs import ReviewedDocumentPrograms

ROOT = Path(__file__).resolve().parent

def clarification_inputs(unresolved, request, pack):
    """Render existing residuals; never infer values or amend the kernel result."""
    entities = request.get('entities', [])
    aliases = {e['id']: e['alias'] for e in entities} if type(entities) is list else {}
    templates = {t['predicate']: t for t in reversed(pack['fact_templates']) if t['value'] is True}
    lines = []

    def visit(item, step=None):
        if type(item) is str:
            lines.append(item)
            return
        step = item.get('step_id', step)
        if item.get('residuals'):
            for child in item['residuals']:
                visit(child, step)
            return
        reason = item.get('reason', 'UNRESOLVED')
        prefix = ('[' + step + '] ') if step else ''
        predicate = item.get('predicate')
        args = item.get('arguments', item.get('bindings', {}))
        if predicate and args:
            labels = {role: aliases.get(eid, eid) + ' [' + eid + ']' for role, eid in args.items()}
            template = templates.get(predicate)
            proposition = (template['text'].format(**labels) if template and set(template['roles']) == set(labels)
                           else predicate + '(' + ', '.join(k + '=' + v for k, v in sorted(labels.items())) + ')')
            definition = next((p for p in pack['semantic_pack']['predicates'] if p['id'] == predicate), {})
            value_type = definition.get('value_type', 'BOOLEAN')
            unknown_prompt = ('whether this statement is true or false' if value_type == 'BOOLEAN' else 'the ' + value_type.lower() + ' value')
            if reason == 'CONFLICTING_FACTS':
                action = 'Reconcile conflicting evidence for: '
            elif reason == 'UNKNOWN_EVIDENCE':
                action = 'Establish ' + unknown_prompt + '; its value is unknown: '
            else:
                action = 'Provide the missing evidence for ' + unknown_prompt + ': '
            refs = item.get('fact_ids', [item['id']] if 'id' in item else [])
            lines.append(prefix + action + proposition + (' Evidence IDs: ' + ', '.join(refs) + '.' if refs else ''))
        elif reason in ('MISSING_BINDING', 'AMBIGUOUS_BINDING'):
            lines.append(prefix + 'Identify the intended ' + item['binding'] + ' entity. Candidates: ' + json.dumps(item['candidates']) + '.')
        elif reason == 'DEPENDENCY_UNRESOLVED_OR_NOT_APPLICABLE':
            lines.append(prefix + 'This step cannot run until its required steps are applicable and resolved: ' + ', '.join(item['steps']) + '.')
        elif reason in ('UNSUPPORTED_STATEMENT', 'AMBIGUOUS_STATEMENT'):
            lines.append(prefix + 'Clarify this statement using the supported fact vocabulary; its meaning has not been admitted: ' + item['text'])
        elif reason == 'USER_DECLARED_UNKNOWN' and item.get('scope', 'UNCLASSIFIED_BLOCKS_EXECUTION') == 'UNCLASSIFIED_BLOCKS_EXECUTION':
            lines.append(prefix + 'Clarify the meaning and scope of this unknown before execution: ' + item['text'])
        elif 'text' in item:
            lines.append(prefix + item['text'])
        else:
            details = {k: v for k, v in item.items() if k not in ('reason', 'type', 'step_id')}
            lines.append(prefix + reason + (': ' + json.dumps(details, sort_keys=True) if details else ''))

    for item in unresolved:
        visit(item)
    return list(dict.fromkeys(lines))


class Application:
    def __init__(self, recommender=None, *, executor=None, raw_semantic_compiler=None):
        executor = load_native_executor() if executor is None else executor
        self.integrity = verify_inputs(ROOT)
        # These package documents have already passed exact byte verification.
        # The request parser's 100 KiB hostile-input ceiling does not apply to
        # the larger, trusted compiled pack.
        self.pack = json.loads((ROOT/'data/compiled/domain_pack.json').read_bytes())
        admission = json.loads((ROOT/'data/compiled/interpretation_admission.json').read_bytes())
        self.interpretation_admission = admit_pack_interpretation_bundle(
            self.pack, admission, expected_pack_sha256=PACK_SHA256)
        self.executor = executor
        self.runtime = SemanticRuntime(self.pack, PACK_SHA256, executor=executor)
        self.catalog = Catalog(json.loads((ROOT/'data/compiled/source_catalog.json').read_bytes()))
        self.profiles = Profiles(self.catalog)
        self.assessments = Assessments(self.catalog)
        self.library = DocumentLibrary()
        self.requirements = Requirements()
        self.requirement_semantics = RequirementSemanticRuntime(
            self.requirements, self.catalog, self.pack['semantic_pack'])
        self.source_mappings = SourceMappingRegistry(
            requirements=self.requirements, pack=self.pack, pack_sha256=PACK_SHA256,
            interpretation_admission=self.interpretation_admission)
        self.inquiry_planner = InquiryPlanner(
            self.pack, requirement_disposition_index_sha256=self.requirements.disposition_index()['index_sha256'])
        self.document_programs = ReviewedDocumentPrograms(self.pack['semantic_pack'], self.library)
        self.source_accounting = SourceAccounting(
            integrity=self.integrity, library=self.library, catalog=self.catalog,
            requirements=self.requirements, profiles=self.profiles,
            assessments=self.assessments, pack=self.pack, pack_sha256=PACK_SHA256,
            interpretation_admission=self.interpretation_admission,
            source_mappings=self.source_mappings)
        self.recommender = recommender
        # The full library scan runs only when requested.
        self._raw_semantic_compiler = raw_semantic_compiler

    @staticmethod
    def _consumer_egress_binding_payload(response):
        """Recompute the response binding without changing the response."""
        kernel = response['kernel']
        egress = response['egress']
        claims = kernel.get('claims')
        require(type(response.get('answer')) is str and egress.get('text') == response['answer'],
                'consumer egress text must equal displayed answer')
        require(type(egress.get('type')) is str and egress['type'] in CLAIM_TYPES,
                'consumer egress claim type invalid')
        require(type(claims) is list and claims, 'consumer response requires typed claims')
        claim_ids = []
        bound_claims = []
        for claim in claims:
            require(type(claim) is dict and type(claim.get('id')) is str and claim['id'] and
                    type(claim.get('type')) is str and claim['type'] in CLAIM_TYPES,
                    'consumer claim type invalid')
            require(claim['id'] not in claim_ids, 'duplicate consumer claim identity')
            claim_ids.append(claim['id'])
            bound_claims.append({
                'id': claim['id'],
                'type': claim['type'],
                'support': deepcopy(claim.get('support', claim.get('support_ids', []))),
                'provenance': deepcopy(claim.get('provenance_ids', [])),
            })
        ceiling = egress.get('authority', kernel.get('claim_ceiling', kernel.get('authority_ceiling')))
        require(ceiling is not None, 'consumer response ceiling required')
        identities = {}
        for name in ('package_id', 'package_sha256', 'program_sha256', 'source_sha256',
                     'request_id', 'scenario_id', 'request_sha256', 'result_sha256', 'control_id'):
            value = egress.get(name, kernel.get(name, response.get('request', {}).get(name)))
            if value is not None:
                identities[name] = deepcopy(value)
        if type(kernel.get('package')) is dict:
            for name in ('id', 'sha256'):
                if kernel['package'].get(name) is not None:
                    identities['package_' + name] = deepcopy(kernel['package'][name])
        return {
            'text': response['answer'],
            'type': egress['type'],
            'kernel_sha256': digest(kernel),
            'pack_sha256': PACK_SHA256,
            'claim_ids': claim_ids,
            'claims': bound_claims,
            'provenance': deepcopy(response.get('provenance', [])),
            'ceiling': deepcopy(ceiling),
            'identities': identities,
        }

    @staticmethod
    def _consumer_egress_binding(response):
        """Create a hash-bound record of response fields."""
        binding = Application._consumer_egress_binding_payload(response)
        response['egress']['binding'] = {**binding, 'binding_sha256': digest(binding)}
        return response

    @staticmethod
    def verify_consumer_egress(response):
        """Verify response fields against their stored hash."""
        binding = response.get('egress', {}).get('binding')
        require(type(binding) is dict, 'consumer egress binding required')
        actual = deepcopy(binding)
        binding_sha256 = actual.pop('binding_sha256', None)
        require(type(binding_sha256) is str and binding_sha256 == digest(actual),
                'consumer egress binding seal mismatch')
        expected = Application._consumer_egress_binding_payload(response)
        require(canonical(actual) == canonical(expected), 'consumer egress binding replay mismatch')
        return response
    @staticmethod
    def _reviewed_claims(kernel, answer, operation, outputs):
        citations = kernel['source_citations']
        if operation == 'execute':
            source_ids = {source_id for output in outputs for source_id in output.get('source_ids', [])}
            citations = [citation for citation in citations if citation['source_id'] in source_ids]
            require({citation['source_id'] for citation in citations} == source_ids,
                    'reviewed output source citations incomplete')
        source_claims = [{
            'id': 'reviewed:source:' + citation['citation']['claim']['id'],
            'type': 'SOURCE_BOUND',
            'text': citation['citation']['claim']['text'],
            'support': [],
            'provenance_ids': [citation['source_id']],
        } for citation in citations]
        if operation == 'execute' and not outputs:
            return [{'id': 'reviewed:unresolved', 'type': 'UNRESOLVED', 'text': answer,
                     'support': [], 'provenance_ids': []}], citations
        return [*source_claims, {
            'id': 'reviewed:presentation', 'type': 'DETERMINISTIC_DERIVATION', 'text': answer,
            'support': [claim['id'] for claim in source_claims],
            'provenance_ids': [citation['source_id'] for citation in citations],
        }], citations

    def _raw_semantic_progress_compiler(self):
        if self._raw_semantic_compiler is None:
            from .raw_semantic_compiler import RawSemanticCompiler
            self._raw_semantic_compiler = RawSemanticCompiler(
                reviewed_program_index=self.document_programs.index)
        return self._raw_semantic_compiler

    @staticmethod
    def _raw_count(block, name):
        value = block.get(name + '_count') if type(block) is dict else None
        return value if type(value) is int and value >= 0 else None

    def _semantic_progress(self):
        """Report one on-demand raw compilation scan without admitting it."""
        result = self._raw_semantic_progress_compiler().summary()
        require(type(result) is dict, 'raw semantic compiler summary required')
        coverage = result.get('documentary_coverage')
        proposed = result.get('proposed_candidates')
        admitted = result.get('admitted_semantics')
        require(type(coverage) is dict and type(proposed) is dict and type(admitted) is dict,
                'raw semantic compiler summary shape required')
        document_count = coverage.get('document_count')
        page_count = coverage.get('physical_page_count')
        require(type(document_count) is int and document_count >= 0 and
                type(page_count) is int and page_count >= 0,
                'raw semantic documentary coverage counts required')
        require(type(result.get('claim_ceiling')) is str,
                'raw semantic compiler claim ceiling required')
        require(result.get('external_effects') == [],
                'raw semantic compiler must declare no external effects')

        def display(block, name):
            value = self._raw_count(block, name)
            return str(value) if value is not None else 'not reported by this scan'

        answer = (
            f'Scanned {document_count} documents and {page_count} PDF pages.\n'
            'Potential source matches: '
            f'Domain {display(proposed, "domain")}; Judgment {display(proposed, "judgment")}; '
            f'Work {display(proposed, "work")}; Architecture {display(proposed, "architecture")}.\n'
            'Reviewed definitions: '
            f'Domain {display(admitted, "domain")}; Judgment {display(admitted, "judgment")}; '
            f'Work {display(admitted, "work")}; Architecture {display(admitted, "architecture")}.'
        )
        uncovered = result.get('uncovered_document_count')
        if type(uncovered) is int and uncovered >= 0:
            answer += f' Documents with no source match: {uncovered}.'
        publication_coverage = result.get('publication_coverage')
        if type(publication_coverage) is dict:
            publication_count = publication_coverage.get('publication_count')
            package_count = publication_coverage.get('registered_reviewed_package_count')
            require(type(publication_count) is int and publication_count == document_count and
                    type(package_count) is int and package_count >= 0 and
                    publication_coverage.get('status') ==
                    'FULL_RETAINED_LIBRARY_PUBLICATION_DISPOSITION_ACCOUNTED' and
                    publication_coverage.get('external_effects') == [],
                    'publication coverage report is incomplete or has effects')
            answer += (f' Fully reviewed documents: 0 of {publication_count}. '
                       f'Reviewed check packages: {package_count}.')
        request = {'operation': 'semantic_progress'}
        return {
            'answer': answer,
            'route': 'DETERMINISTIC_RAW_SEMANTIC_PROGRESS',
            'request': request,
            'ingress': {'request': deepcopy(request), 'request_sha256': digest(request)},
            'kernel': result,
            'egress': {
                'text': answer,
                'type': 'DETERMINISTIC_DERIVATION',
                'authority': result['claim_ceiling'],
                'model_authored': False,
                'request_sha256': digest(request),
                'result_sha256': digest(result),
                'external_effects': [],
            },
            'provenance': deepcopy(coverage),
            'interpretation_trace': {
                'route_basis': 'ON_DEMAND_RAW_CANDIDATE_SUMMARY',
                'raw_summary_sha256': digest(result),
                'model_calls': 0,
                'qualification_required': True,
            },
        }

    def _semantic_program(self, request):
        """Expose the admitted J/W/A program without executing or changing it."""
        request = deepcopy(request)
        require(type(request) is dict and set(request) == {'architecture_id'} and
                type(request['architecture_id']) is str and request['architecture_id'],
                'one architecture_id is required')
        semantic = self.pack['semantic_pack']
        architecture = decompose_architecture(semantic, request['architecture_id'])
        work_ids = sorted({step['work_id'] for step in architecture['ordered_steps']})
        works = [decompose_work(semantic, work_id) for work_id in work_ids]
        judgment_ids = sorted({judgment_id for work in works
                               for judgment_id in work['judgment_dependencies']})
        judgments = [decompose_judgment(semantic, judgment_id)
                     for judgment_id in judgment_ids]
        program = compose_architecture_program(semantic, request['architecture_id'])
        kernel = {
            'status': 'ADMITTED_PROGRAM_INSPECTED',
            'architecture': architecture,
            'work': works,
            'judgments': judgments,
            'composed_program': program,
            'program_executes_only_when_a_separate_typed_request_is_supplied': True,
            'external_effects': [],
        }
        answer = (
            f"{request['architecture_id']} is composed from {len(architecture['ordered_steps'])} "
            f"ordered step(s), {len(works)} Work node(s), and {len(judgments)} Judgment node(s). "
            "The technical view shows every typed part, dependency, source binding, unresolved rule, "
            "and the hash of the exact assembled program. Inspecting it causes no action."
        )
        return {
            'answer': answer,
            'route': 'DETERMINISTIC_ADMITTED_SEMANTIC_PROGRAM_INSPECTION',
            'request': request,
            'ingress': {'request': deepcopy(request), 'request_sha256': digest(request)},
            'kernel': kernel,
            'egress': {'text': answer, 'type': 'DETERMINISTIC_DERIVATION',
                       'model_authored': False, 'request_sha256': digest(request),
                       'result_sha256': digest(kernel), 'external_effects': []},
            'provenance': program['architecture'],
            'interpretation_trace': {'model_calls': 0,
                                     'basis': 'EXACT_ADMITTED_SEMANTIC_PACK'},
        }

    def status(self):
        catalog = self.catalog.summary()
        semantic = self.pack['semantic_pack']
        stacks = {name: len(semantic[name]) for name in ('domain', 'judgments', 'work', 'architectures')}
        stacks['architecture_steps'] = sum(len(a['steps']) for a in semantic['architectures'])
        reviewed_programs = self.document_programs.index()
        return {'name': 'Judgment Compilation', 'version': __version__, 'standing': 'SOURCE_BOUND_RUNTIME',
                'coverage': {'executable_pack_stacks': stacks, 'scenario_judgment_ids': [j['id'] for j in semantic['judgments']], 'full_library_semantic_compilation': 'INCOMPLETE', 'count_basis': 'Current loaded pack; catalog structure and retained pages are not executable judgments.', 'catalog_domain_nodes': catalog['structural_records'] + catalog['library_document_roots'] + 1, 'controls_and_enhancements': catalog['controls_and_enhancements'], 'scenario_rules': len(self.pack['semantic_pack']['judgments']), 'exact_pdf_excerpts': len(self.pack['sources']), 'ceiling': self.pack['coverage_ceiling']},
                'execution_engine': getattr(self.executor, 'execution_engine', {
                    'implementation': 'RUST_NATIVE' if hasattr(self.executor, 'expected_sha256') else 'EXPLICIT_REFERENCE_OR_TEST_EXECUTOR',
                    'binary_sha256': getattr(self.executor, 'expected_sha256', None),
                }),
                'profile_membership': self.profiles.summary(),
                'assessment_selection': self.assessments.summary(),
                'reviewed_document_programs': {
                    'count': len(reviewed_programs['packages']),
                    'status': reviewed_programs['status'],
                    'schema': reviewed_programs['source_format_policy']['common_package'],
                },
                'retained_library': self.library.summary(), 'source_accounting': {'status': 'AVAILABLE_ON_DEMAND', 'operation': 'manifest'}, 'reviewed_source_mappings': {'status': 'AVAILABLE_ON_DEMAND', 'operation': 'index'}, 'inference_configured': self.recommender is not None, 'integrity': self.integrity,
                'interpretation_admission': deepcopy(self.interpretation_admission),
                'pack_sha256': PACK_SHA256, 'explicit_selection_confirmed': False, 'external_effects_authorized': False}

    def query(self, payload):
        require(type(payload) is dict, 'query object required')
        mode = payload.get('mode')
        if mode in ('semantic_progress', 'reviewed_programs'):
            allowed = {'mode'}
        elif mode in ('scenario', 'readiness', 'library', 'requirements', 'profiles', 'assessments', 'accounting', 'mappings', 'timing', 'ps4a_timing', 'semantic_program', 'reviewed_program'):
            allowed = {'mode', 'request', 'recommend'}
        else:
            allowed = {'mode', 'question', 'recommend'}
        require(set(payload) <= allowed and type(payload.get('recommend', False)) is bool, 'unexpected query fields')
        if mode == 'semantic_progress':
            response = self._semantic_progress()
            unresolved = ['RAW_CANDIDATES_REQUIRE_INTERPRETATION_QUALIFICATION']
        elif mode == 'reviewed_programs':
            kernel = self.document_programs.index()
            request = {'operation': 'list'}
            program_count = len(kernel['packages'])
            program_word = "program" if program_count == 1 else "programs"
            verb = "is" if program_count == 1 else "are"
            answer = f"{program_count} reviewed document {program_word} {verb} available. Each check links to its source PDF."
            response = {
                'answer': answer, 'route': 'DETERMINISTIC_REVIEWED_DOCUMENT_PROGRAM_INDEX',
                'request': request, 'ingress': {'request': deepcopy(request),
                                                'request_sha256': digest(request)},
                'kernel': kernel,
                'egress': {'text': answer, 'type': 'DETERMINISTIC_DERIVATION',
                           'model_authored': False, 'request_sha256': digest(request),
                           'result_sha256': digest(kernel), 'external_effects': []},
                'provenance': [],
                'interpretation_trace': {'model_calls': 0,
                                         'basis': 'EXACT_REVIEWED_DOCUMENT_PACKAGE_INDEX'},
            }
            unresolved = []
        elif mode == 'reviewed_program':
            response, unresolved = self._reviewed_document_program(payload.get('request'))
        elif mode == 'semantic_program':
            response = self._semantic_program(payload.get('request'))
            unresolved = []
        elif mode == 'inquiry':
            response = self._plain_inquiry(payload.get('question'))
            unresolved = response['kernel'].get('residual', [])
        elif mode == 'scenario':
            raw = canonical(payload.get('request')).decode()
            ingress = self.runtime.parse(raw)
            kernel = self.runtime.execute(raw)
            egress = self.runtime.admit_egress(raw, self.runtime.egress_proposal(raw))
            response = {'answer': egress['text'], 'route': 'DETERMINISTIC_WARRANT_DAG', 'request': ingress['request'], 'ingress': ingress, 'kernel': kernel, 'egress': egress, 'provenance': kernel['provenance'], 'source_chains': self.library.bind_provenance_chains(kernel['provenance']), 'inquiry_plan': self.inquiry_planner.plan(kernel)}
            unresolved = [c for c in kernel['claims'] if c['type'] == 'UNRESOLVED']
        elif mode == 'catalog':
            response = self._catalog_query(payload.get('question'))
            unresolved = response['kernel'].get('residual', [])
        elif mode == 'library':
            request = deepcopy(payload.get('request'))
            result = self.library.ask(request)
            if request['operation'] == 'documents':
                answer = f"{result['total']} retained documents; displaying {len(result['documents'])}."
                claims = [{'id': 'library:documents', 'type': 'DETERMINISTIC_DERIVATION',
                           'text': answer, 'support': [], 'provenance_ids': []}]
                claim_type = 'DETERMINISTIC_DERIVATION'
            elif request['operation'] == 'cite':
                answer = result['claim']['text']
                claims = [deepcopy(result['claim'])]
                claim_type = 'SOURCE_BOUND'
            elif request['operation'] == 'page':
                answer = result['page']['text']
                claims = [{'id': 'library:page:' + digest(result['page']), 'type': 'SOURCE_BOUND',
                           'text': answer, 'support': [], 'provenance_ids': []}]
                claim_type = 'SOURCE_BOUND'
            else:
                answer = f"{result['total_occurrences']} text occurrences in {result['pages_searched']} extracted pages; displaying {result['returned_occurrences']}. These are source candidates for review."
                claims = [{'id': 'library:search', 'type': 'DETERMINISTIC_DERIVATION',
                           'text': answer, 'support': [], 'provenance_ids': []}]
                claim_type = 'DETERMINISTIC_DERIVATION'
            result['claims'] = claims
            response = {'answer':answer,'route':'DETERMINISTIC_DOCUMENTARY_LOOKUP','request':request,
                        'ingress':{'request':request},'kernel':result,
                        'egress':{'text':answer, 'type':claim_type, 'authority':'DOCUMENTARY_INSPECTION_ONLY',
                                  'model_authored':False, 'external_effects':[]},
                        'provenance':result.get('matches',[]) if request['operation']=='search' else result.get('source_file',{})}
            if request['operation'] == 'cite':
                response['provenance'] = result['provenance']
                response['interpretation_trace'] = result['interpretation_trace']
                response['egress'].update(claim_id=result['claim']['id'],
                    request_sha256=result['request_sha256'], result_sha256=digest(result),
                    provenance_sha256=result['claim']['provenance_sha256'],
                    occurrence_inventory_sha256=result['occurrence_inventory_sha256'])
            unresolved = ['DOCUMENTARY_LOOKUP_DOES_NOT_ESTABLISH_POLICY_APPLICABILITY']
        elif mode == 'timing':
            response = self._timing(payload.get('request'))
            unresolved = response['kernel']['residuals']
        elif mode == 'ps4a_timing':
            response = self._ps4a_timing(payload.get('request'))
            unresolved = response['kernel']['residuals']
        elif mode == 'requirements':
            response = self._requirements(payload.get('request'))
            unresolved = response['kernel']['residuals'] + [{'reason': 'APPLICABILITY_AND_SATISFACTION_NOT_DETERMINED'}]
        elif mode == 'accounting':
            response = self._source_accounting(payload.get('request'))
            unresolved = response['kernel']['residuals']
        elif mode == 'mappings':
            response = self._source_mappings(payload.get('request'))
            unresolved = response['kernel']['residuals']
        elif mode == 'profiles':
            response = self._profile_membership(payload.get('request'))
            unresolved = response['kernel']['residuals']
        elif mode == 'assessments':
            response = self._assessment_selection(payload.get('request'))
            unresolved = response['kernel']['residuals']
        elif mode == 'readiness':
            response = self._readiness(payload.get('request'))
            unresolved = response['kernel']['residual']
        else:
            raise ValueError('unsupported query mode')
        if mode in ('reviewed_program', 'inquiry', 'catalog', 'library'):
            response = self._consumer_egress_binding(response)
            self.verify_consumer_egress(response)
        response['integrity'] = {**self.integrity, 'pack_sha256': PACK_SHA256,
                                 'interpretation_admission': deepcopy(self.interpretation_admission),
                                 'result_sha256': digest(response['kernel'])}
        # Escalation is data, not an external action or an automatic policy decision.
        escalation = {'status': 'CLARIFICATION_REQUIRED' if unresolved else 'NO_KNOWN_AMBIGUITY', 'unresolved': unresolved,
                      'required_inputs': clarification_inputs(unresolved, response['request'], self.pack),
                      'request_sha256': digest(response['request']), 'result_sha256': response['integrity']['result_sha256'],
                      'authority': 'ADVISORY_ONLY', 'automatic_resolution': False}
        response['escalation'] = escalation
        inference = {'type': 'AI_INFERENCE', 'status': 'NOT_REQUESTED', 'authority': 'ADVISORY_ONLY', 'required_inputs': escalation['required_inputs'], 'model_calls': 0}
        if payload.get('recommend'):
            if self.recommender is None:
                inference['status'] = 'NOT_CONFIGURED'
            else:
                packet = {'request': response['request'], 'deterministic_result': response['kernel'], 'escalation': escalation,
                          'scope': 'Suggest clarification; never replace the deterministic result.'}
                try:
                    proposed = self.recommender.recommend(deepcopy(packet))
                    require(type(proposed) is str and 0 < len(proposed) <= 16000, 'invalid recommendation')
                    inference.update(status='RECOMMENDATION', text=proposed, binding=deepcopy(escalation), model=getattr(self.recommender, 'model', 'test-adapter'), model_calls=1,
                                     verification='UNVERIFIED_MODEL_INTERPRETATION_NOT_ADMITTED_AS_SOURCE_OR_DETERMINISTIC_CLAIM')
                except Exception as error:
                    inference.update(status='FAILED', reason=type(error).__name__, model_calls=1)
        response['inference'] = inference
        return response

    def _reviewed_document_program(self, request):
        request = deepcopy(request)
        require(type(request) is dict and request.get('operation') in ('inspect', 'execute'),
                'reviewed document program operation must be inspect or execute')
        operation = request['operation']
        expected = {'operation', 'package_id'} if operation == 'inspect' else {
            'operation', 'package_id', 'execution_request'}
        require(set(request) == expected and type(request.get('package_id')) is str,
                'invalid reviewed document program request')
        if operation == 'inspect':
            kernel = self.document_programs.inspect(request['package_id'])
            unresolved = []
            outputs = []
            answer = (
                f"{kernel['package']['title']} has passed independent interpretation review and "
                "replays as one connected Domain, Judgment, Work, and Architecture program. "
                f"Its scope is limited: {kernel['package']['scope']}"
            )
        else:
            kernel = self.document_programs.execute(
                request['package_id'], request['execution_request'])
            execution = kernel['execution']['execution']['execution']
            outputs = execution['outputs']
            unresolved = [item for step in execution['steps'] for item in step['residuals']]
            if outputs:
                output = outputs[0]
                predicate = str(output['predicate']).replace('_', ' ')
                bindings = ', '.join(
                    f"{role}={value}" for role, value in sorted(output['arguments'].items()))
                answer = (
                    f"The supplied facts establish only the reviewed result '{predicate}'"
                    f" with {bindings}. Its scope remains limited: {kernel['scope']}"
                )
            else:
                answer = (
                    "The reviewed program cannot establish its narrow result from the "
                    "supplied information. Missing, conflicting, false, ambiguous, or cross-entity "
                    "inputs remain unresolved."
                )
        claims, provenance = self._reviewed_claims(kernel, answer, operation, outputs)
        kernel['claims'] = claims
        execution_identity = kernel['execution'] if operation == 'execute' else kernel
        if operation == 'execute':
            require(all(type(execution_identity.get(name)) is str and execution_identity[name]
                        for name in ('request_id', 'scenario_id', 'request_sha256', 'result_sha256')),
                    'reviewed execution identity required')
        return ({
            'answer': answer, 'route': 'DETERMINISTIC_REVIEWED_DOCUMENT_PROGRAM',
            'request': request,
            'ingress': {'request': deepcopy(request),
                        'request_sha256': execution_identity.get('request_sha256', digest(request))},
            'kernel': kernel,
            'egress': {'text': answer,
                       'type': ('DETERMINISTIC_DERIVATION'
                                if operation == 'inspect' or outputs else 'UNRESOLVED'),
                       'authority': kernel['claim_ceiling'], 'model_authored': False,
                       'request_id': execution_identity.get('request_id'),
                       'scenario_id': execution_identity.get('scenario_id'),
                       'request_sha256': execution_identity.get('request_sha256', digest(request)),
                       'result_sha256': execution_identity.get('result_sha256', digest(kernel)),
                       'external_effects': []},
             'provenance': provenance,
            'interpretation_trace': {
                'model_calls': 0,
                'basis': 'INDEPENDENTLY_REVIEWED_JC_SEMANTIC_DOCUMENT_PACKAGE',
                'oscal_required': False,
            },
        }, unresolved)

    def _profile_membership(self, request):
        request = deepcopy(request)
        result = self.profiles.ask(request)
        if result['status'] == 'RESOLVED':
            answer = result['claim']['text']
        else:
            answer = 'The supplied control ID is not an exact control identity in the pinned catalog; literal profile membership remains unresolved.'
        return {'answer': answer, 'route': 'DETERMINISTIC_NIST_PROFILE_LITERAL_MEMBERSHIP',
                'request': request, 'ingress': {'request': deepcopy(request), 'request_sha256': digest(request)},
                'kernel': result,
                'egress': {'text': answer,
                           'type': 'DETERMINISTIC_DERIVATION' if result['status'] == 'RESOLVED' else 'UNRESOLVED',
                           'authority': result['authority_ceiling'], 'model_authored': False,
                           'request_sha256': digest(request), 'result_sha256': digest(result),
                           'external_effects': []},
                'provenance': result['profile']}

    def _assessment_selection(self, request):
        request = deepcopy(request)
        result = self.assessments.ask(request)
        if result['status'] == 'INSPECTED_SOURCE_STRUCTURE':
            answer = (f"{result['control']['control_id']} has {len(result['objectives'])} source assessment "
                      f"objective records and {len(result['methods'])} potential method records.")
            claim_type = 'DETERMINISTIC_DERIVATION'
        else:
            answer = result['claim']['text']
            claim_type = 'DETERMINISTIC_DERIVATION'
        return {'answer': answer, 'route': 'DETERMINISTIC_NIST_ASSESSMENT_SELECTION',
                'request': request, 'ingress': {'request': deepcopy(request), 'request_sha256': digest(request)},
                'kernel': result,
                'egress': {'text': answer, 'type': claim_type,
                           'authority': result['authority_ceiling'], 'model_authored': False,
                           'request_sha256': digest(request), 'result_sha256': digest(result),
                           'external_effects': []},
                'provenance': result['source']}

    def _timing(self, request):
        """Execute the pinned SI-2(c) interpretation over explicitly supplied facts."""
        request = deepcopy(request)
        exact_keys(request, {'request_id', 'scenario_id', 'source_sha256', 'statement_id',
                             'entities', 'scope', 'facts', 'unknowns'})
        require(text(request['request_id']) and text(request['scenario_id']), 'request and scenario identity required')
        require('SI-2(c)' in self.pack['sources'], 'This timing check is unavailable in the installed package')
        source = self.pack['sources']['SI-2(c)']
        require(request['statement_id'] == 'si-2_smt.c' and
                request['source_sha256'] == source['oscal_source_file']['sha256'], 'unsupported or foreign timing source')
        require(type(request['entities']) is list and 0 < len(request['entities']) <= 128, 'timing entities required')
        entities, aliases = {}, {}
        for entity in request['entities']:
            exact_keys(entity, {'id', 'alias', 'kind'})
            require(text(entity['id']) and text(entity['alias']) and entity['kind'] in ('organization', 'system', 'update'), 'invalid timing entity')
            require(entity['id'] not in entities and entity['alias'] not in aliases.values(), 'duplicate timing identity or alias')
            entities[entity['id']] = entity['kind']; aliases[entity['id']] = entity['alias']
        roles = {'organization': 'organization', 'system': 'system', 'update': 'update'}
        exact_keys(request['scope'], set(roles))
        require(all(type(eid) is str and entities.get(eid) == roles[role] for role, eid in request['scope'].items()), 'invalid timing scope')
        input_types = {'security_relevant_update': 'BOOLEAN', 'si2_period_applies': 'BOOLEAN',
                       'elapsed_release_to_installation_seconds': 'INTEGER', 'organization_period_seconds': 'INTEGER'}
        require(type(request['facts']) is list and len(request['facts']) <= 512, 'invalid timing facts')
        facts, evidence, fact_ids = [], {}, set()
        for fact in request['facts']:
            exact_keys(fact, {'id', 'predicate', 'arguments', 'value', 'evidence_refs'})
            require(text(fact['id']) and fact['id'] not in fact_ids, 'invalid or duplicate fact identity')
            fact_ids.add(fact['id'])
            require(type(fact['predicate']) is str and fact['predicate'] in input_types, 'unsupported timing predicate')
            value = fact['value']; kind = input_types[fact['predicate']]
            require(value is None or (type(value) is bool if kind == 'BOOLEAN' else type(value) is int and 0 <= value <= 2147483647), 'invalid timing value')
            refs = fact['evidence_refs']
            require(type(refs) is list and 0 < len(refs) <= 32 and all(text(r) for r in refs) and len(set(refs)) == len(refs), 'caller evidence references required')
            facts.append({k: deepcopy(v) for k, v in fact.items() if k != 'evidence_refs'})
            evidence[fact['id']] = refs
        semantic_request = {'entities': entities, 'facts': facts, 'unknowns': request['unknowns'],
                            'bindings': {step: {r: [eid] for r, eid in request['scope'].items()}
                                         for step in ('scope', 'compare', 'within', 'exceeds')}}
        execution = self.executor(self.pack['semantic_pack'], 'update-timing', semantic_request)
        decisions = [o for o in execution['outputs'] if o['predicate'] in ('update_within_supplied_period', 'update_exceeds_supplied_period')]
        require(len(decisions) <= 1, 'conflicting timing decision')
        residuals = [r for step in execution['steps'] for r in step.get('residuals', [])]
        # A scope known false is distinct from missing facts, and is not a compliance result.
        scope_step = next(step for step in execution['steps'] if step['step_id'] == 'scope')
        status = 'RESOLVED' if decisions else 'NOT_APPLICABLE' if scope_step['status'] == 'NOT_APPLICABLE' else 'UNRESOLVED'
        if decisions:
            relation = 'within' if decisions[0]['predicate'] == 'update_within_supplied_period' else 'longer than'
            answer = (aliases[request['scope']['update']] + ': the supplied release-to-installation duration is ' + relation +
                      ' the supplied organization-defined period for ' + aliases[request['scope']['organization']] +
                      ' / ' + aliases[request['scope']['system']] + '.')
        elif status == 'NOT_APPLICABLE':
            answer = 'The supplied scope facts do not establish applicability of this SI-2(c) timing interpretation.'
        else:
            answer = 'The SI-2(c) timing comparison is unresolved. Supply consistent scope, relevance, applicable period and elapsed-time evidence.'
        ceiling = {'standing': 'SOURCE_BOUND_NOT_EXECUTED', 'compliance_determination': False,
                   'responsibility_assignment': False, 'external_effects': False, 'explicit_selection_confirmed': False}
        limitation = 'This comparison uses the values you supply. Compliance review is outside this check.'
        answer += '\n' + limitation
        claims = [{'id': 'source:SI-2(c)', 'type': 'SOURCE_BOUND', 'text': source['quote'], 'provenance_ids': ['SI-2(c)']}]
        claims += [{'id': 'scenario:' + f['id'], 'type': 'SCENARIO_FACT', 'fact': deepcopy(f)} for f in request['facts']]
        claims += [{'id': o['id'], 'type': 'DETERMINISTIC_DERIVATION', 'result': deepcopy(o)} for o in execution['outputs']]
        if not decisions:
            claims.append({'id': 'timing:unresolved', 'type': 'UNRESOLVED', 'text': answer.split('\n')[0]})
        claims.append({'id': 'timing:evidence-limit', 'type': 'UNRESOLVED', 'text': limitation})
        residuals.append({'reason': 'CALLER_EVIDENCE_AND_OTHER_CONTROL_OBLIGATIONS_UNVERIFIED', 'text': limitation})
        result = {'status': status, 'request_sha256': digest(request), 'semantic_ingress_sha256': digest(semantic_request),
                  'execution': execution, 'claims': claims, 'support_graph': [{**edge, 'from': 'scenario:' + edge['from'] if edge['from'] in fact_ids else edge['from']} for edge in execution['support_graph']] +
                      [{'from': 'source:' + sid, 'to': o['id'], 'relation': 'SUPPORTS'} for o in execution['outputs'] for sid in o['source_ids']],
                  'scenario_evidence': evidence, 'residuals': residuals, 'provenance': {'SI-2(c)': deepcopy(source)},
                  'authority_ceiling': ceiling, 'compliance_verdict': None, 'external_effects': []}
        egress = {'text': answer, 'model_authored': False, 'request_id': request['request_id'], 'scenario_id': request['scenario_id'],
                  'request_sha256': digest(request), 'ingress_sha256': digest(semantic_request), 'kernel_sha256': digest(result),
                  'pack_id': self.pack['id'], 'pack_version': self.pack['version'], 'pack_sha256': PACK_SHA256,
                  'claim_ids': [c['id'] for c in claims], 'support_graph_sha256': digest(result['support_graph']),
                  'provenance_sha256': digest(result['provenance']), 'authority_ceiling': deepcopy(ceiling)}
        return {'answer': answer, 'route': 'DETERMINISTIC_NIST_UPDATE_TIMING', 'request': request,
                'ingress': {'request': deepcopy(request), 'semantic_request': semantic_request}, 'kernel': result,
                'egress': egress, 'provenance': result['provenance'],
                'interpretation_trace': {'selected_source': 'SI-2(c)',
                    'reason': 'The exact provision relates installation time to release time and an organization-defined period. The caller must assert applicability for the exact organization, system and update.',
                    'operation': 'elapsed_release_to_installation_seconds <= organization_period_seconds',
                    'time_basis': 'CALLER_SUPPLIED_NONNEGATIVE_ELAPSED_SECONDS;NO_TIMESTAMP_OR_CALENDAR_INFERENCE',
                 'source_interpretation_status': self.interpretation_admission['standing']}}

    def _ps4a_timing(self, request):
        """Execute proposed PS-4(a) timing semantics over caller-supplied integers."""
        request = deepcopy(request)
        exact_keys(request, {'request_id', 'scenario_id', 'source_sha256', 'statement_id',
                             'entities', 'scope', 'facts', 'unknowns'})
        require(text(request['request_id']) and text(request['scenario_id']), 'request and scenario identity required')
        require('PS-4(a)' in self.pack['sources'], 'PS-4(a) timing capability is absent from this pack')
        source = self.pack['sources']['PS-4(a)']
        require(request['statement_id'] == 'ps-4_smt.a' and
                request['source_sha256'] == source['oscal_source_file']['sha256'], 'unsupported or foreign PS-4(a) timing source')
        require(type(request['entities']) is list and 0 < len(request['entities']) <= 128, 'PS-4(a) timing entities required')
        entities, aliases = {}, {}
        for entity in request['entities']:
            exact_keys(entity, {'id', 'alias', 'kind'})
            require(text(entity['id']) and text(entity['alias']) and entity['kind'] in ('organization', 'system', 'person', 'account'), 'invalid PS-4(a) timing entity')
            require(entity['id'] not in entities and entity['alias'] not in aliases.values(), 'duplicate PS-4(a) timing identity or alias')
            entities[entity['id']] = entity['kind']; aliases[entity['id']] = entity['alias']
        roles = {'organization': 'organization', 'system': 'system', 'employee': 'person', 'account': 'account'}
        exact_keys(request['scope'], set(roles))
        require(all(type(eid) is str and entities.get(eid) == roles[role] for role, eid in request['scope'].items()), 'invalid PS-4(a) timing scope')
        input_types = {'ps4a_timing_scope_supplied': 'BOOLEAN',
                       'elapsed_termination_to_access_disable_seconds': 'INTEGER',
                       'organization_allowed_access_disable_period_seconds': 'INTEGER'}
        require(type(request['facts']) is list and len(request['facts']) <= 512, 'invalid PS-4(a) timing facts')
        facts, evidence, fact_ids = [], {}, set()
        for fact in request['facts']:
            exact_keys(fact, {'id', 'predicate', 'arguments', 'value', 'evidence_refs'})
            require(text(fact['id']) and fact['id'] not in fact_ids, 'invalid or duplicate fact identity')
            fact_ids.add(fact['id'])
            require(type(fact['predicate']) is str and fact['predicate'] in input_types, 'unsupported PS-4(a) timing predicate')
            value = fact['value']; kind = input_types[fact['predicate']]
            require(value is None or (type(value) is bool if kind == 'BOOLEAN' else type(value) is int and 0 <= value <= 2147483647), 'invalid PS-4(a) timing value')
            refs = fact['evidence_refs']
            require(type(refs) is list and 0 < len(refs) <= 32 and all(text(r) for r in refs) and len(set(refs)) == len(refs), 'caller evidence references required')
            facts.append({k: deepcopy(v) for k, v in fact.items() if k != 'evidence_refs'})
            evidence[fact['id']] = refs
        semantic_request = {'entities': entities, 'facts': facts, 'unknowns': request['unknowns'],
                            'bindings': {step: {r: [eid] for r, eid in request['scope'].items()}
                                         for step in ('scope', 'compare', 'within', 'exceeds')}}
        execution = self.executor(self.pack['semantic_pack'], 'ps4a-access-disable-timing', semantic_request)
        decisions = [o for o in execution['outputs'] if o['predicate'] in ('ps4a_within_supplied_period', 'ps4a_exceeds_supplied_period')]
        require(len(decisions) <= 1, 'conflicting PS-4(a) timing decision')
        residuals = [r for step in execution['steps'] for r in step.get('residuals', [])]
        scope_step = next(step for step in execution['steps'] if step['step_id'] == 'scope')
        status = 'RESOLVED' if decisions else 'NOT_APPLICABLE' if scope_step['status'] == 'NOT_APPLICABLE' else 'UNRESOLVED'
        names = request['scope']
        if decisions:
            relation = 'within' if decisions[0]['predicate'] == 'ps4a_within_supplied_period' else 'longer than'
            answer = (aliases[names['employee']] + ' / ' + aliases[names['account']] + ': the supplied access-disable elapsed duration is ' + relation +
                      ' the supplied allowed period for ' + aliases[names['organization']] + ' / ' + aliases[names['system']] + '.')
        elif status == 'NOT_APPLICABLE':
            answer = 'The caller supplied a false PS-4(a) timing-comparison scope; no numeric comparison was produced.'
        else:
            answer = 'The PS-4(a) supplied-duration comparison is unresolved. Supply consistent exact scope and nonnegative elapsed and allowed durations in seconds.'
        ceiling = {'standing': 'SOURCE_BOUND_NOT_EXECUTED', 'compliance_determination': False,
                   'control_satisfaction_determination': False, 'responsibility_assignment': False,
                   'event_evidence_verification': False, 'external_effects': False, 'explicit_selection_confirmed': False}
        limitation = 'This comparison uses the integer-second values you supply. Applicability and compliance review are outside this check.'
        answer += '\n' + limitation
        claims = [{'id': 'source:PS-4(a)', 'type': 'SOURCE_BOUND', 'text': source['quote'], 'provenance_ids': ['PS-4(a)']}]
        claims += [{'id': 'scenario:' + f['id'], 'type': 'SCENARIO_FACT', 'fact': deepcopy(f)} for f in request['facts']]
        claims += [{'id': o['id'], 'type': 'DETERMINISTIC_DERIVATION', 'result': deepcopy(o)} for o in execution['outputs']]
        if not decisions:
            claims.append({'id': 'ps4a-timing:unresolved', 'type': 'UNRESOLVED', 'text': answer.split('\n')[0]})
        claims.append({'id': 'ps4a-timing:evidence-limit', 'type': 'UNRESOLVED', 'text': limitation})
        residuals.append({'reason': 'CALLER_SCOPE_DURATION_AND_EVENT_EVIDENCE_UNVERIFIED', 'text': limitation})
        result = {'status': status, 'request_sha256': digest(request), 'semantic_ingress_sha256': digest(semantic_request),
                  'execution': execution, 'claims': claims,
                  'support_graph': [{**edge, 'from': 'scenario:' + edge['from'] if edge['from'] in fact_ids else edge['from']} for edge in execution['support_graph']] +
                      [{'from': 'source:' + sid, 'to': o['id'], 'relation': 'SUPPORTS'} for o in execution['outputs'] for sid in o['source_ids']],
                  'scenario_evidence': evidence, 'residuals': residuals, 'provenance': {'PS-4(a)': deepcopy(source)},
                  'authority_ceiling': ceiling, 'compliance_verdict': None, 'external_effects': []}
        egress = {'text': answer, 'model_authored': False, 'request_id': request['request_id'], 'scenario_id': request['scenario_id'],
                  'request_sha256': digest(request), 'ingress_sha256': digest(semantic_request), 'kernel_sha256': digest(result),
                  'pack_id': self.pack['id'], 'pack_version': self.pack['version'], 'pack_sha256': PACK_SHA256,
                  'claim_ids': [c['id'] for c in claims], 'support_graph_sha256': digest(result['support_graph']),
                  'provenance_sha256': digest(result['provenance']), 'authority_ceiling': deepcopy(ceiling)}
        return {'answer': answer, 'route': 'DETERMINISTIC_NIST_PS4A_ACCESS_DISABLE_TIMING', 'request': request,
                'ingress': {'request': deepcopy(request), 'semantic_request': semantic_request}, 'kernel': result,
                'egress': egress, 'provenance': result['provenance'],
                'interpretation_trace': {'selected_source': 'PS-4(a)',
                    'reason': 'The exact provision concerns disabling system access and assigns an organization-defined time period. The caller supplies the comparison scope, identities and integer durations.',
                    'operation': 'elapsed_termination_to_access_disable_seconds <= organization_allowed_access_disable_period_seconds',
                    'time_basis': 'CALLER_SUPPLIED_NONNEGATIVE_INTEGER_SECONDS;NO_TIMESTAMP_OR_ENGLISH_DURATION_OR_CALENDAR_INFERENCE',
                    'source_interpretation_status': self.interpretation_admission['standing']}}

    def _plain_inquiry(self, question):
        """Accept ordinary English and either bind it exactly or preserve it as unresolved."""
        require(type(question) is str and 0 < len(question.strip()) <= 4000, 'question required')
        original = question.strip()
        normalized = ' '.join(re.findall(r'[a-z0-9]+(?:-[a-z0-9]+)?', original.casefold()))
        literal_normalized = ' '.join(re.findall(r'[a-z0-9]+', original.casefold()))
        stop_words = {
            'a', 'about', 'an', 'and', 'are', 'can', 'could', 'did', 'do', 'does',
            'explain', 'for', 'from', 'how', 'i', 'in', 'is', 'it', 'me', 'my',
            'of', 'on', 'or', 'our', 'please', 'say', 'should', 'show', 'tell',
            'the', 'this', 'to', 'us', 'what', 'when', 'where', 'which', 'who',
            'why', 'with', 'would', 'you', 'your'
        }
        meaningful = sorted({t for t in re.findall(r'[a-z0-9]+', normalized)
                             if t not in stop_words and len(t) > 1})

        controls = self.catalog.controls
        aliases = {}
        known_terms = set()
        for control_id, record in controls.items():
            values = [record.get('title') or '', *record.get('aliases', [])]
            for value in values:
                phrase = ' '.join(re.findall(r'[a-z0-9]+', str(value).casefold()))
                if not phrase or re.fullmatch(r'[a-z]{2} \d+(?: \d+)?', phrase):
                    continue
                aliases.setdefault(phrase, set()).add(control_id)
                known_terms.update(t for t in phrase.split() if t not in stop_words and len(t) > 1)

        semantic_terms = set()
        qualified_single_terms = set()
        for node in self.pack['semantic_pack']['domain']:
            for value in [node.get('label') or '', *node.get('aliases', [])]:
                value_terms = [
                    t for t in re.findall(r'[a-z0-9]+', str(value).casefold())
                    if t not in stop_words and len(t) > 1
                ]
                semantic_terms.update(value_terms)
                if len(value_terms) == 1:
                    qualified_single_terms.add(value_terms[0])
        known_terms.update(semantic_terms)

        raw_control_ids = re.findall(r'(?i)\b[a-z]{2}-\d+(?:\(\d+\)|\.\d+)?\b', original)
        control_ids = []
        for raw in raw_control_ids:
            control_id = raw.casefold()
            if '(' in control_id:
                base, enhancement = control_id[:-1].split('(')
                control_id = base + '.' + str(int(enhancement))
            if control_id not in control_ids:
                control_ids.append(control_id)

        padded = ' ' + normalized.replace('-', ' ') + ' '
        phrase_matches = []
        for phrase, ids in aliases.items():
            if ' ' + phrase + ' ' in padded:
                phrase_matches.append((len(phrase.split()), len(phrase), phrase, sorted(ids)))
        phrase_matches.sort(reverse=True)
        best_phrase_matches = []
        if phrase_matches:
            best_size = phrase_matches[0][:2]
            best_phrase_matches = [m for m in phrase_matches if m[:2] == best_size]

        bound_control_ids = sorted({cid for cid in control_ids if cid in controls})
        unknown_control_ids = sorted({cid for cid in control_ids if cid not in controls})
        if not bound_control_ids and not unknown_control_ids and best_phrase_matches:
            phrase_ids = sorted({cid for match in best_phrase_matches for cid in match[3]})
            if len(phrase_ids) == 1:
                bound_control_ids = phrase_ids

        # Match single words only to reviewed labels or aliases.
        matched_terms = sorted(set(meaningful) & qualified_single_terms)
        unbound_terms = sorted(set(meaningful) - qualified_single_terms)
        base_kernel = {
            'schema': 'jc/plain-english-inquiry/1',
            'accepted_inquiry': True,
            'original_question': original,
            'normalized_question': normalized,
            'matched_terms': matched_terms,
            'unbound_terms': unbound_terms,
            'explicit_control_ids': control_ids,
            'semantic_bindings': [],
            'executable_warrant': None,
            'compliance_verdict': None,
            'responsibility_assignment': None,
            'external_effects': [],
            'authority_ceiling': 'COMPILED_NIST_SOURCE_OR_SEMANTIC_BINDINGS_ONLY;NO_GUESSING_OR_COMPLIANCE_OR_ACTION',
        }

        # Bind exact control names and retain unmatched terms.
        control_scope_terms = set()
        if len(bound_control_ids) == 1 and not unknown_control_ids:
            control_id = bound_control_ids[0]
            control_scope_terms.update(re.findall(r'[a-z0-9]+', control_id))
            record = controls[control_id]
            for value in [record.get('title') or '', *record.get('aliases', [])]:
                phrase = ' '.join(re.findall(r'[a-z0-9]+', str(value).casefold()))
                if phrase and ' ' + phrase + ' ' in padded:
                    control_scope_terms.update(
                        term for term in phrase.split()
                        if term not in stop_words and len(term) > 1
                    )
        unbound_scope_terms = sorted(set(meaningful) - control_scope_terms)

        # Match reviewed packages by exact ID or title.
        reviewed_matches = []
        for package in self.document_programs.index()['packages']:
            package_terms = ' '.join(re.findall(r'[a-z0-9]+', package['id'].casefold()))
            title_terms = ' '.join(re.findall(r'[a-z0-9]+', package['title'].casefold()))
            if literal_normalized in (package_terms, title_terms):
                reviewed_matches.append(package)
        if len(reviewed_matches) == 1:
            package = reviewed_matches[0]
            selection = {
                'package_id': package['id'],
                'title': package['title'],
                'scope': package['scope'],
                'status': 'SOURCE_BOUND_NOT_EXECUTED',
                'next_typed_input_step': {
                    'mode': 'reviewed_program',
                    'operation': 'inspect',
                    'package_id': package['id'],
                    'reason': 'Inspect the package to obtain its typed inputs before any explicit execution request.',
                },
            }
            answer = (package['title'] + ' is an available checked document example. ' +
                      package['scope'] + ' Inspect it to see the typed facts it needs; this selection did not run it or determine applicability.')
            kernel = {**base_kernel,
                'status': 'SOURCE_REVIEWED_PROGRAM_DISCOVERY',
                'reviewed_program_selection': selection,
                'residual': [],
                'claims': [{'id': 'inquiry:reviewed-program-selection:' + package['id'],
                            'type': 'DETERMINISTIC_DERIVATION', 'text': answer,
                            'scope': 'PROGRAM_DISCOVERY_ONLY', 'support': [package['id']]}],
            }
            return {'answer': answer, 'route': 'DETERMINISTIC_PLAIN_ENGLISH_INQUIRY',
                'request': {'question': original},
                'ingress': {'question': original, 'normalized_question': normalized,
                            'accepted_inquiry': True},
                'kernel': kernel,
                'egress': {'text': answer, 'type': 'DETERMINISTIC_DERIVATION',
                           'scope': 'PROGRAM_DISCOVERY_ONLY',
                           'model_authored': False, 'request_sha256': digest({'question': original}),
                           'external_effects': [],
                           'authority': 'REVIEWED_PROGRAM_SELECTION_ONLY;NO_INSPECTION_OR_EXECUTION_OR_APPLICABILITY_DETERMINATION'},
                'provenance': [],
                'interpretation_trace': {'route_basis': [{'kind': 'LITERAL_REVIEWED_PROGRAM_ID_OR_TITLE',
                                                          'package_id': package['id']}],
                    'matched_terms': matched_terms, 'unbound_terms': unbound_terms, 'model_calls': 0}}
        if len(reviewed_matches) > 1:
            reason = ('More than one reviewed document program has this exact literal identifier or title. '
                      'Use an exact package ID so no program is selected.')
            kernel = {**base_kernel, 'status': 'UNRESOLVED_AMBIGUOUS_REVIEWED_PROGRAM_SELECTION',
                      'residual': [{'reason': 'UNRESOLVED_AMBIGUOUS_REVIEWED_PROGRAM_SELECTION', 'text': reason}],
                      'claims': [{'id': 'inquiry:unresolved', 'type': 'UNRESOLVED', 'text': reason, 'support': []}]}
            return {'answer': '[UNRESOLVED] ' + reason, 'route': 'DETERMINISTIC_PLAIN_ENGLISH_INQUIRY',
                    'request': {'question': original},
                    'ingress': {'question': original, 'normalized_question': normalized, 'accepted_inquiry': True},
                    'kernel': kernel,
                    'egress': {'text': '[UNRESOLVED] ' + reason, 'type': 'UNRESOLVED', 'model_authored': False,
                               'request_sha256': digest({'question': original}), 'external_effects': [],
                               'authority': base_kernel['authority_ceiling']},
                    'provenance': [],
                    'interpretation_trace': {'route_basis': [], 'matched_terms': matched_terms,
                                             'unbound_terms': unbound_terms, 'model_calls': 0}}

        if len(bound_control_ids) == 1 and not unknown_control_ids:
            control_id = bound_control_ids[0]
            lookup = self._catalog_query(control_id)
            source_result = lookup['kernel']
            source_candidate = source_result['candidates'][0]
            source_text = source_candidate['rendered_text']
            semantic_bindings = [{'kind': 'NIST_CONTROL', 'control_id': control_id,
                                  'basis': 'EXPLICIT_CONTROL_ID' if control_id in control_ids else 'EXACT_CONTROL_TITLE'}]
            if unbound_scope_terms:
                reason = (
                    'The exact ' + control_id.upper() + ' source matches, but these additional terms are unresolved: '
                    'additional terms from that control alone: ' + ', '.join(unbound_scope_terms) +
                    '.'
                )
                status = 'PARTIALLY_RESOLVED_SOURCE_CONTROL_WITH_UNBOUND_SCOPE'
                residual = [{'reason': status, 'text': reason, 'bound_control_id': control_id,
                             'unbound_scope_terms': unbound_scope_terms}]
                answer = '[PARTIAL] ' + reason + '\n\n' + lookup['answer']
                kernel = {**base_kernel,
                    'status': status,
                    'semantic_bindings': semantic_bindings,
                    'source_result': source_result,
                    'unbound_scope_terms': unbound_scope_terms,
                    'residual': residual,
                    'claims': [
                        {'id': 'inquiry:source:' + control_id, 'type': 'SOURCE_BOUND',
                         'text': source_text, 'support': [], 'provenance_ids': [control_id]},
                        {'id': 'inquiry:unresolved-scope:' + control_id, 'type': 'UNRESOLVED',
                         'text': reason, 'support': [], 'provenance_ids': []},
                        {'id': 'inquiry:presentation:' + control_id, 'type': 'DETERMINISTIC_DERIVATION',
                         'text': answer,
                         'support': ['inquiry:source:' + control_id,
                                     'inquiry:unresolved-scope:' + control_id],
                         'provenance_ids': [control_id]},
                    ],
                }
                return {'answer': answer, 'route': 'DETERMINISTIC_PLAIN_ENGLISH_INQUIRY',
                    'request': {'question': original},
                    'ingress': {'question': original, 'normalized_question': normalized,
                                'accepted_inquiry': True},
                    'kernel': kernel,
                    'egress': {'text': answer, 'type': 'UNRESOLVED', 'model_authored': False,
                               'request_sha256': digest({'question': original}), 'external_effects': [],
                               'authority': 'EXACT_SOURCE_CONTROL_LOOKUP_WITH_UNBOUND_SCOPE;NO_CLAIM_ABOUT_UNBOUND_TERMS',
                               'result_scope': 'PARTIAL_SOURCE_CONTEXT_ONLY'},
                    'provenance': lookup['provenance'],
                    'interpretation_trace': {'route_basis': semantic_bindings,
                        'unbound_terms': unbound_terms, 'unbound_scope_terms': unbound_scope_terms,
                        'model_calls': 0}}
            kernel = {**base_kernel,
                'status': 'RESOLVED_TO_SOURCE_CONTROL',
                'semantic_bindings': semantic_bindings,
                'source_result': source_result,
                'residual': source_result['residual'],
                'claims': [
                    {'id': 'inquiry:source:' + control_id, 'type': 'SOURCE_BOUND',
                     'text': source_text, 'support': [], 'provenance_ids': [control_id]},
                    {'id': 'inquiry:presentation:' + control_id, 'type': 'DETERMINISTIC_DERIVATION',
                     'text': lookup['answer'], 'support': ['inquiry:source:' + control_id],
                     'provenance_ids': [control_id]},
                ],
            }
            return {'answer': lookup['answer'], 'route': 'DETERMINISTIC_PLAIN_ENGLISH_INQUIRY',
                'request': {'question': original},
                'ingress': {'question': original, 'normalized_question': normalized,
                            'accepted_inquiry': True},
                'kernel': kernel,
                'egress': {**lookup['egress'], 'type': 'SOURCE_BOUND',
                           'request_sha256': digest({'question': original}),
                           'result_scope': 'EXACT_SOURCE_CONTROL_LOOKUP_ONLY'},
                'provenance': lookup['provenance'],
                'interpretation_trace': {'route_basis': kernel['semantic_bindings'],
                    'unbound_terms': unbound_terms, 'model_calls': 0}}

        if len(bound_control_ids) > 1:
            reason = ('More than one NIST control matches the question: ' +
                      ', '.join(cid.upper() for cid in bound_control_ids) +
                      '. Ask about one control at a time.')
            status = 'UNRESOLVED_MULTIPLE_CONTROL_BINDINGS'
        elif unknown_control_ids:
            reason = ('These control IDs are not in the included NIST catalog: ' +
                      ', '.join(cid.upper() for cid in unknown_control_ids) + '.')
            status = 'UNRESOLVED_UNKNOWN_CONTROL_ID'
        elif matched_terms or 'nist' in meaningful or any(t.startswith('800') for t in meaningful):
            shown = ', '.join(matched_terms[:12]) if matched_terms else 'NIST'
            reason = ('Matching NIST terms: ' + shown +
                      '. The whole question does not match one exact control or reviewed check. '
                      'Name a control, add the missing facts, or search the retained documents.')
            status = 'UNRESOLVED_WITHIN_NIST_SCOPE'
        else:
            shown = ', '.join(unbound_terms[:12]) or 'no meaningful terms'
            reason = ('No compiled NIST check matches this question. '
                      'The meaningful terms with no qualified binding are: ' + shown +
                      '.')
            status = 'UNRESOLVED_OUTSIDE_COMPILED_SEMANTICS'

        residual = [{'reason': status, 'text': reason, 'unbound_terms': unbound_terms,
                     'matched_terms': matched_terms}]
        kernel = {**base_kernel, 'status': status, 'residual': residual,
                  'claims': [{'id': 'inquiry:unresolved', 'type': 'UNRESOLVED',
                              'text': reason, 'support': []}]}
        return {'answer': '[UNRESOLVED] ' + reason,
            'route': 'DETERMINISTIC_PLAIN_ENGLISH_INQUIRY',
            'request': {'question': original},
            'ingress': {'question': original, 'normalized_question': normalized,
                        'accepted_inquiry': True},
            'kernel': kernel,
            'egress': {'text': '[UNRESOLVED] ' + reason, 'type': 'UNRESOLVED', 'model_authored': False,
                       'request_sha256': digest({'question': original}),
                       'external_effects': [], 'authority': base_kernel['authority_ceiling']},
            'provenance': [],
            'interpretation_trace': {'route_basis': [], 'matched_terms': matched_terms,
                'unbound_terms': unbound_terms, 'model_calls': 0}}

    def _catalog_query(self, question):
        require(type(question) is str and 0 < len(question.strip()) <= 1000, 'question required')
        term = question.strip()
        match = re.fullmatch(r'(?i)(?:explain |show |what is )?([a-z]{2}-\d+(?:\(\d+\)|\.\d+)?)\??', term)
        if match:
            cid = match[1].lower()
            if '(' in cid:
                base, enhancement = cid[:-1].split('(')
                cid = base + '.' + str(int(enhancement))
            result = self.catalog.ask(control_id=cid)
        else:
            result = self.catalog.ask(title=term)
        result['residual'] = ['SOURCE_LOOKUP_DOES_NOT_ESTABLISH_SCENARIO_APPLICABILITY']
        if result['status'] == 'resolved':
            control = result['candidates'][0]
            answer = control['id'].upper() + ' - ' + (control['title'] or control['id']) + '\n\n' + control['rendered_text']
            answer += '\n\nThe JSON includes parameter fields and child records.'
            claims = [
                {'id': 'catalog:source:' + control['id'], 'type': 'SOURCE_BOUND',
                 'text': control['rendered_text'], 'support': [], 'provenance_ids': [control['id']]},
                {'id': 'catalog:presentation:' + control['id'], 'type': 'DETERMINISTIC_DERIVATION',
                 'text': answer, 'support': ['catalog:source:' + control['id']],
                 'provenance_ids': [control['id']]},
            ]
        elif result['status'] == 'ambiguous':
            answer = 'Several source records match this alias. Choose the intended control ID.'
            result['residual'].append('MULTIPLE_SOURCE_CANDIDATES')
            claims = [{'id': 'catalog:unresolved', 'type': 'UNRESOLVED', 'text': answer,
                       'support': [], 'provenance_ids': []}]
        else:
            answer = 'No exact source title or control ID matches this question. Inspect the document library or supply a more specific term.'
            result['residual'].append('NO_SUPPORTED_SOURCE_CANDIDATE')
            claims = [{'id': 'catalog:unresolved', 'type': 'UNRESOLVED', 'text': answer,
                       'support': [], 'provenance_ids': []}]
        result['claims'] = claims
        return {'answer': answer, 'route': 'DETERMINISTIC_CATALOG_LOOKUP', 'request': {'question': question},
            'ingress': {'original_question': question, 'normalized_lookup': term}, 'kernel': result,
            'egress': {'text': answer, 'type': 'DETERMINISTIC_DERIVATION' if result['status'] == 'resolved' else 'UNRESOLVED', 'scope': 'STRUCTURED_XML_EXTRACTION_ONLY', 'authority': 'STRUCTURED_XML_EXTRACTION_ONLY;NO_COMPLIANCE_OR_APPLICABILITY_DETERMINATION', 'compliance_verdict': None},
            'provenance': result['source']}


    def _source_mappings(self, request):
        request = deepcopy(request)
        exact_keys(request, {'operation'})
        require(request['operation'] == 'index', 'unsupported source mapping operation')
        result = self.source_mappings.build()
        count = result['counts']['exact_reviewed_source_mappings']
        answer = (
            f"Bound {count} exact reviewed NIST source statements to the bounded semantic pack. "
            "The generic 2,138-template requirement interface remains documentary-only, and "
            "full-library executable semantic compilation remains incomplete."
        )
        return {
            'answer': answer, 'route': 'DETERMINISTIC_REVIEWED_SOURCE_MAPPINGS',
            'request': request,
            'ingress': {'request': deepcopy(request), 'request_sha256': digest(request)},
            'kernel': result,
            'egress': {'text': answer, 'type': 'DETERMINISTIC_DERIVATION',
                'authority': result['coverage_ceiling'], 'model_authored': False,
                'request_sha256': digest(request), 'result_sha256': digest(result),
                'index_sha256': result['index_sha256'], 'external_effects': []},
            'provenance': {
                'source_sha256': result['source_sha256'],
                'pack_sha256': result['pack_sha256'],
                'admission_sha256': result['admission_sha256'],
            },
            'interpretation_trace': {
                'mapping_scope': 'EXACT_REVIEWED_BOUNDED_PACK_ONLY',
                'generic_requirement_runtime': 'DOCUMENTARY_ONLY',
            },
        }

    def _source_accounting(self, request):
        request = deepcopy(request)
        exact_keys(request, {'operation'})
        require(request['operation'] == 'manifest', 'unsupported source accounting operation')
        result = self.source_accounting.build()
        answer = (
            f"Accounted for {result['source_accounting']['library']['document_count']} retained documents, "
            f"{result['source_accounting']['library']['physical_page_count']} physical pages, and "
            f"{result['source_accounting']['requirements']['total_templates']} OSCAL statement/item templates. "
            "Source accounting is complete for retained package inputs; full-library executable semantic compilation remains incomplete."
        )
        return {
            'answer': answer, 'route': 'DETERMINISTIC_NIST_SOURCE_ACCOUNTING',
            'request': request,
            'ingress': {'request': deepcopy(request), 'request_sha256': digest(request)},
            'kernel': result,
            'egress': {'text': answer, 'type': 'DETERMINISTIC_DERIVATION',
                'authority': result['coverage_ceiling'], 'model_authored': False,
                'request_sha256': digest(request), 'result_sha256': digest(result),
                'manifest_sha256': result['manifest_sha256'], 'external_effects': []},
            'provenance': {
                'library_manifest_sha256': result['source_accounting']['library']['manifest_sha256'],
                'catalog_source_sha256': result['source_accounting']['catalog']['source']['source_sha256'],
                'requirement_disposition_index_sha256': result['source_accounting']['requirements']['disposition_index_sha256'],
            },
            'interpretation_trace': {
                'source_accounting': 'EXHAUSTIVE_COMPACT_RECONCILIATION',
                'interpretation_admission': 'EXACT_REVIEWED_PACK_ONLY',
                'executable_coverage': 'BOUNDED_REVIEWED_PACK_ONLY',
            },
        }

    def _requirements(self, request):
        request = deepcopy(request)
        if type(request) is dict and request.get('operation') == 'dispositions':
            require(set(request) == {'schema', 'operation'}, 'unexpected disposition fields')
            require(request.get('schema') == REQUEST_SCHEMA, 'unsupported requirement request schema')
            result = self.requirements.disposition_index()
            result.update(request_sha256=digest(request), residuals=[], external_effects=[])
            counts = result['counts']
            answer = (
                f"Accounted for {counts['total_templates']} exact statement/item templates: "
                f"{counts['supported_documentary_templates']} supported documentary templates, "
                f"{counts['unsupported_documentary_templates']} unsupported documentary templates, and "
                f"{counts['admitted_policy_semantic_mappings']} admitted policy-semantic mappings. "
                "Every unadmitted row remains non-executable and unresolved at the policy-semantic boundary."
            )
            return {'answer': answer, 'route': 'DETERMINISTIC_REQUIREMENT_DISPOSITION_INDEX',
                'request': request, 'ingress': {'request': request, 'request_sha256': digest(request)},
                'kernel': result,
                'egress': {'text': answer, 'type': 'DETERMINISTIC_DERIVATION',
                    'authority': result['coverage_ceiling'], 'request_sha256': digest(request),
                    'result_sha256': digest(result), 'source_sha256': result['source_sha256'],
                    'text_sha256': hashlib.sha256(answer.encode()).hexdigest(),
                    'model_authored': False, 'external_effects': []},
                'provenance': {'source_sha256': result['source_sha256'],
                    'scope': 'EXHAUSTIVE_PINNED_OSCAL_TEMPLATE_DISPOSITIONS'},
                'interpretation_trace': {'selection': 'ALL_SORTED_STATEMENT_ITEM_IDENTITIES',
                    'policy_semantic_mapping': 'NOT_ADMITTED_UNLESS_EXACTLY_REVIEWED'}}
        if type(request) is dict and request.get('operation') == 'list':
            require(set(request) <= {'schema', 'operation', 'control_id', 'offset', 'limit'}, 'unexpected requirement list fields')
            require(request.get('schema') == REQUEST_SCHEMA, 'unsupported requirement request schema')
            result = self.requirements.list_templates(request.get('control_id'), request.get('offset', 0), request.get('limit', 25))
            result.update(request_sha256=digest(request), residuals=[], external_effects=[])
            lines = [f"{result['matched_templates']} matching statement/item templates; showing {len(result['templates'])} from offset {result['offset']}."]
            lines.extend(row['statement_id'] + ' - ' + row['control_title'] + ' [' + row['grammar_status'] + ']' for row in result['templates'])
            lines.append('Choose a statement ID to inspect its conditions and parameter fields.')
            answer = '\n'.join(lines)
            return {'answer': answer, 'route': 'DETERMINISTIC_REQUIREMENT_DISCOVERY', 'request': request,
                'ingress': {'request': request, 'request_sha256': digest(request)}, 'kernel': result,
                'egress': {'text': answer, 'type': 'DETERMINISTIC_DERIVATION', 'authority': result['ceiling'],
                    'request_sha256': digest(request), 'result_sha256': digest(result),
                    'source_sha256': result['source_sha256'], 'text_sha256': hashlib.sha256(answer.encode()).hexdigest(),
                    'model_authored': False, 'external_effects': []},
                'provenance': {'source_sha256': result['source_sha256'], 'scope': 'PINNED_OSCAL_TEMPLATE_IDENTITIES_ONLY'},
                'interpretation_trace': {'selection': 'EXACT_CONTROL_FILTER_AND_SORTED_STATEMENT_IDS', 'offset': result['offset'], 'limit': result['limit']}}
        result = self.requirement_semantics.execute(request)
        template = result['template']
        lines = []
        if template:
            lines.append(template['control_id'].upper() + ' / ' + template['statement_id'])
            def paragraphs(blocks, depth=0):
                for block in blocks:
                    if block['kind'] == 'PARAGRAPH':
                        text = ''.join(token['text'] if token['kind'] == 'SOURCE_TEXT' else
                            '[PARAMETER: ' + str(token['parameter_id']) + ']' if token['kind'] == 'PARAMETER' else
                            '[UNSUPPORTED SOURCE: inspect JSON]' for token in block['tokens'])
                        lines.append('  ' * depth + text)
                    elif block['kind'] == 'ITEM':
                        paragraphs(block['blocks'], depth + 1)
            for context in template['ancestor_context']:
                paragraphs(context['paragraphs'])
            paragraphs(template['blocks'])
            if template['parameters']:
                lines.append('Parameter definitions (organization values must be supplied separately):')
            for parameter in template['parameters']:
                pid = parameter['parameter_id']
                needed = 'required by statement' if pid in template['root_parameter_ids'] else 'required only if a selected choice references it'
                lines.append(pid + ' [' + parameter['kind'] + '; ' + needed + ']')
                if parameter['kind'] == 'ASSIGNMENT':
                    lines.append('  Supply one value for: ' + str(parameter['label']))
                elif parameter['kind'] == 'SELECTION':
                    lines.append('  Allowed selection count: ' + str(parameter['cardinality']))
                    for choice in parameter['choice_templates']:
                        text = ''.join(t['text'] if t['kind'] == 'SOURCE_TEXT' else '[PARAMETER: ' + str(t.get('parameter_id')) + ']' for t in choice['tokens'])
                        lines.append('  Source choice: ' + text)
                        lines.append('  Select using: ' + json.dumps({'choice_sha256': choice['choice_sha256']}))
        lines.extend(['', 'Binding status: ' + result['status']])
        if result['instance']:
            lines.append('Organization values (caller supplied; evidence references are not verified):')
            for binding in result['instance']['parameter_bindings']:
                lines.append(binding['parameter_id'] + ' = ' + json.dumps(binding['values'], ensure_ascii=True))
        if result['residuals']:
            lines.extend(r['reason'] + (': ' + r['parameter_id'] if 'parameter_id' in r else '') for r in result['residuals'])
        lines.append('Requirement structure and parameter bindings only. Applicability, satisfaction and compliance remain undetermined.')
        answer = '\n'.join(lines)
        return {'answer': answer, 'route': 'DETERMINISTIC_REQUIREMENT_INSTANTIATION',
            'request': request, 'ingress': {'request': request, 'request_sha256': result['request_sha256']},
            'kernel': result, 'egress': {'text': answer, 'type': 'DETERMINISTIC_DERIVATION',
                'authority': result['ceiling'], 'request_sha256': result['request_sha256'],
                'result_sha256': digest(result), 'source_sha256': result['source_sha256'],
                'template_sha256': template['template_sha256'] if template else None,
                'instance_sha256': result['instance']['instance_sha256'] if result['instance'] else None,
                'text_sha256': hashlib.sha256(answer.encode('utf-8')).hexdigest(),
                'model_authored': False, 'external_effects': []},
            'provenance': {'source': template['source'] if template else None,
                'ancestor_sources': [c['source'] for c in template['ancestor_context']] if template else [],
                'scope': 'PINNED_OSCAL_STRUCTURE_AND_DECODED_TEXT_ONLY', 'pdf_provenance': None},
            'interpretation_trace': {'selection': 'EXACT_CALLER_SELECTED_STATEMENT_ID',
                'ancestor_context': 'Preserved in source order before the selected statement.',
                'parameter_resolution': 'Exact source/template/control/organization/system bindings; no inferred values.'}}

    def _readiness(self, request):
        exact_keys(request, {'architecture_id', 'entities', 'facts', 'bindings', 'unknowns'})
        result = self.executor(self.pack['semantic_pack'], request['architecture_id'], {k: v for k, v in request.items() if k != 'architecture_id'})
        result['residual'] = [{**r, 'step_id': step['step_id']} for step in result['steps'] for r in step['residuals']]
        result['input_status'] = 'CALLER_DECLARATIONS_NOT_VERIFIED_IMPLEMENTATION_EVIDENCE'
        lines = [result['status'], 'Supported findings:']
        for output in result['outputs']:
            lines.append(output['predicate'] + ' ' + json.dumps(output['arguments'], sort_keys=True) + ' = ' + json.dumps(output['value']))
        if not result['outputs']:
            lines.append('No supported finding was derived.')
        if result['residual']:
            lines.append('Unresolved steps:')
            lines.extend(clarification_inputs(result['residual'], request, self.pack))
        answer = '\n'.join(lines)
        return {'answer': answer, 'route': 'DETERMINISTIC_TYPED_CONTRACT_EXECUTION', 'request': deepcopy(request),
            'ingress': deepcopy(request), 'kernel': result, 'egress': {'text': answer, 'type': 'DETERMINISTIC_DERIVATION'},
            'provenance': self.pack['sources']}
