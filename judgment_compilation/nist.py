"""Builds NIST source records and compiled checks."""
from pathlib import Path
from functools import lru_cache
from hashlib import sha256
import json
from .kernel import SemanticRuntime, canonical, digest, require
from .semantic_contracts import (SCHEMA, COORDINATE_MODEL, semantic_coordinate,
                                 validate_semantic_pack)
from .nist_catalog import compile_catalog, verified_catalog_inputs
from .semantic_family_compiler import compile_elapsed_duration_family
from .nist_source import ROOT, CORPUS, frozen_inputs, provenance_inventory, descriptor, RELEASE
OUTPUT = 'data/compiled'


def build_pack(root: Path = ROOT) -> dict:
    """Build the NIST semantic pack from verified inputs."""
    root = root.resolve()
    manifest = frozen_inputs(root)
    source_bytes, library_manifest_bytes = verified_catalog_inputs(root.parent)
    identity = (digest(manifest), sha256(source_bytes).hexdigest(),
                sha256(library_manifest_bytes).hexdigest())
    return json.loads(_compiled_pack_bytes(root, identity))


@lru_cache(maxsize=4)
def _compiled_pack_bytes(root: Path, input_identity: tuple[str, str, str]) -> bytes:
    return canonical(_build_pack(root))


def _build_pack(root: Path) -> dict:
    sources = provenance_inventory(frozen_inputs(root), root)
    roles = {'employee': 'person', 'account': 'account', 'business': 'organization'}
    templates = [
        {'id': 'employment_terminated', 'text': '{employee} employment at {business} has ended.', 'roles': {'employee': 'person', 'business': 'organization'}, 'predicate': 'employment_terminated', 'value': True},
        {'id': 'account_of', 'text': '{account} is an account of {employee}.', 'roles': {'account': 'account', 'employee': 'person'}, 'predicate': 'account_of', 'value': True},
        {'id': 'administrator_account', 'text': '{account} has administrator privileges.', 'roles': {'account': 'account'}, 'predicate': 'administrator_account', 'value': True},
        {'id': 'access_continues', 'text': '{employee} retains access through {account}.', 'roles': {'employee': 'person', 'account': 'account'}, 'predicate': 'access_continues', 'value': True},
        {'id': 'access_revoked', 'text': '{employee} no longer has access through {account}.', 'roles': {'employee': 'person', 'account': 'account'}, 'predicate': 'access_continues', 'value': False},
    ]
    templates.append({'id': 'administrator_privileges_unknown', 'text': 'It is unknown whether {account} has administrator privileges.', 'roles': {'account': 'account'}, 'predicate': 'administrator_account', 'value': None})
    catalog = compile_catalog(root.parent)
    # This is a derived working subset of the one catalog topology, not a second placement.
    domain = [{'path': [], 'label': 'NIST SP 800', 'aliases': ['NIST Special Publication 800 series']}]
    for document in catalog['domain_paths']['library_documents']:
        alias = ' '.join((document['title'] or '').split())
        domain.append({'path': document['domain_path'], 'label': document['publication_id'], 'aliases': [alias] if alias and alias != document['publication_id'] else []})
    selected = set()
    for cid in ('ac-2', 'ac-6', 'ps-4', 'si-2'):
        record = catalog['records'][cid]
        while record:
            selected.add(record['id'])
            record = catalog['records'].get(record['parent_id'])
    for rid in sorted(selected, key=lambda i: catalog['records'][i]['domain_path']):
        record = catalog['records'][rid]
        aliases = list(dict.fromkeys([record['id'].upper(), *record['aliases']]))
        if rid in ('ac-2', 'ac-6'):
            aliases.append('access')
        domain.append({'path': record['domain_path'], 'label': record['title'] or record['id'], 'aliases': aliases})
    control_paths = {cid: catalog['records'][cid]['domain_path'] for cid in ('ac-2', 'ac-6', 'ps-4', 'si-2')}
    predicates = [{'id': t['predicate'], 'roles': t['roles'], 'origin': 'INPUT'} for t in templates[:4]]
    premises = [{'predicate': t['predicate'], 'arguments': {r: r for r in t['roles']}, 'value': True} for t in templates[:4]]
    specifications = [
        ('account_management_relevance', ['AC-2(l)'], control_paths['ac-2'], 'For {employee} and {account} at {business}, the supplied termination and continued-access facts select AC-2(l) for review of account-management alignment with termination. They do not establish a deficiency or responsibility.'),
        ('least_privilege_relevance', ['AC-6 Control'], control_paths['ac-6'], 'For {employee} and {account} at {business}, the supplied continued administrator-access facts select AC-6 for review of authorized and necessary access. Necessity and authorization remain unverified.'),
        ('personnel_termination_relevance', ['PS-4(a)', 'PS-4(b)'], control_paths['ps-4'], 'For {employee} and {account} at {business}, the supplied termination and continued-access facts select PS-4(a)-(b) for review of access disabling and credential revocation. The applicable time period and responsible organization remain unresolved.'),
    ]
    def definitions(stack, rows):
        return [{'coordinate': semantic_coordinate(stack, path), 'label': label, 'aliases': aliases}
                for path, label, aliases in rows]
    semantic_capital = {
        'coordinate_model': COORDINATE_MODEL,
        'judgment': definitions('judgment', [
            ([0], 'Judgment warrant', ['warrant']),
            ([0, 0], 'Source-grounded scenario warrant', ['source-grounded warrant']),
            ([0, 0, 0], 'NIST control relevance warrant', ['control relevance']),
            ([0, 0, 0, 0], 'Account-management relevance warrant', ['AC-2 relevance']),
            ([0, 0, 0, 1], 'Least-privilege relevance warrant', ['AC-6 relevance']),
            ([0, 0, 0, 2], 'Personnel-termination relevance warrant', ['PS-4 relevance']),
            ([0, 0, 1], 'Conjunctive supported finding warrant', ['conjunctive warrant']),
            ([0, 0, 1, 0], 'Termination administrator-access issue warrant', ['termination access issue']),
             ([0, 0, 2], 'Applicability-scope warrant', ['scope warrant']),
             ([0, 0, 2, 0], 'Update-timing scope warrant', ['SI-2 timing scope']),
             ([0, 0, 2, 1], 'Personnel access-disable timing scope warrant', ['PS-4(a) timing scope']),
             ([0, 0, 3], 'Comparison conclusion warrant', ['comparison warrant']),
             ([0, 0, 3, 0], 'Within supplied update period warrant', ['within period']),
             ([0, 0, 3, 1], 'Exceeds supplied update period warrant', ['exceeds period']),
             ([0, 0, 3, 2], 'Within supplied personnel access-disable period warrant', ['within PS-4(a) period']),
             ([0, 0, 3, 3], 'Exceeds supplied personnel access-disable period warrant', ['exceeds PS-4(a) period']),
        ]),
        'work': definitions('work', [
            ([0], 'Contract execution', ['execute contract']),
            ([0, 0], 'Apply one Judgment warrant', ['apply judgment']),
            ([1], 'Typed-value evaluation', ['evaluate typed values']),
            ([1, 0], 'Compare compatible typed values', ['compare values']),
            ([1, 0, 0], 'Less-than-or-equal comparison', ['less than or equal']),
        ]),
        'architecture': definitions('architecture', [
            ([0], 'Dependency and flow composition', ['dependency flow']),
            ([0, 0], 'Dependency-ordered semantic execution', ['ordered semantic execution']),
             ([0, 0, 0], 'Termination assessment flow', ['termination assessment']),
             ([0, 0, 1], 'Update timing flow', ['update timing']),
             ([0, 0, 2], 'Personnel access-disable timing flow', ['PS-4(a) timing']),
        ]),
    }
    judgment_coordinates = {
        'account_management_relevance': semantic_coordinate('judgment', [0, 0, 0, 0]),
        'least_privilege_relevance': semantic_coordinate('judgment', [0, 0, 0, 1]),
        'personnel_termination_relevance': semantic_coordinate('judgment', [0, 0, 0, 2]),
        'termination_admin_access_issue': semantic_coordinate('judgment', [0, 0, 1, 0]),
         'update_timing_scope': semantic_coordinate('judgment', [0, 0, 2, 0]),
         'ps4a_timing_scope': semantic_coordinate('judgment', [0, 0, 2, 1]),
         'update_within_supplied_period': semantic_coordinate('judgment', [0, 0, 3, 0]),
         'update_exceeds_supplied_period': semantic_coordinate('judgment', [0, 0, 3, 1]),
         'ps4a_within_supplied_period': semantic_coordinate('judgment', [0, 0, 3, 2]),
         'ps4a_exceeds_supplied_period': semantic_coordinate('judgment', [0, 0, 3, 3]),
    }
    apply_coordinate = semantic_coordinate('work', [0, 0])
    compare_coordinate = semantic_coordinate('work', [1, 0, 0])
    judgments, work, steps, interpretations = [], [], [], {}
    for jid, sids, path, wording in specifications:
        predicates.append({'id': jid, 'roles': roles, 'origin': 'DERIVED'})
        # Termination/account-management relevance does not require administrator status.
        # Least-privilege wording below does, so only that warrant requires the privilege fact.
        required = premises if jid == 'least_privilege_relevance' else [p for p in premises if p['predicate'] != 'administrator_account']
        judgments.append({'id': jid, 'semantic_coordinate': judgment_coordinates[jid],
            'bindings': roles, 'premises': required,
            'output': {'predicate': jid, 'arguments': {r: r for r in roles}, 'value': True, 'semantic_kind': 'SCENARIO_DERIVATION'},
            'source_ids': sids, 'residual': ('Supply consistent termination, account identity, privilege and continued-access facts for this exact entity binding.' if jid == 'least_privilege_relevance' else 'Supply consistent termination, account identity and continued-access facts for this exact entity binding.')})
        work.append({'id': 'apply:' + jid, 'semantic_coordinate': apply_coordinate,
            'operation': 'APPLY_JUDGMENT', 'judgment': jid, 'domain_path': path})
        steps.append({'id': jid, 'work': 'apply:' + jid, 'depends_on': []})
        interpretations[jid] = {'text': wording, 'source_selection_reason': {sid: wording for sid in sids}}
    jid = 'termination_admin_access_issue'
    predicates.append({'id': jid, 'roles': roles, 'origin': 'DERIVED'})
    judgments.append({'id': jid, 'semantic_coordinate': judgment_coordinates[jid], 'bindings': roles,
        'premises': [{'predicate': x[0], 'arguments': {r: r for r in roles}, 'value': True} for x in specifications],
        'output': {'predicate': jid, 'arguments': {r: r for r in roles}, 'value': True, 'semantic_kind': 'SCENARIO_DERIVATION'},
        'source_ids': [sid for sid in sources if sid != 'SI-2(c)'], 'residual': 'All three control-relevance warrants must be supported before producing the combined finding.'})
    work.append({'id': 'apply:' + jid, 'semantic_coordinate': apply_coordinate,
        'operation': 'APPLY_JUDGMENT', 'judgment': jid, 'domain_path': catalog['domain_paths']['selected_library_document']})
    steps.append({'id': jid, 'work': 'apply:' + jid, 'depends_on': [x[0] for x in specifications]})
    interpretations[jid] = {'text': "The supplied facts about {employee}'s continued administrator access through {account} after employment at {business} ended jointly select AC-2, AC-6, and PS-4 for account-management, least-privilege, and personnel-termination review. This is a source-supported review finding; it does not establish control applicability, a violation, compliance status, responsibility, or action authority.",
        'source_selection_reason': {sid: 'Combined finding requires all three separately supported control-relevance warrants.' for sid in sources if sid != 'SI-2(c)'}}
    # The reusable compiler executes only explicit, independently reviewed
    # source-to-family mappings. It never infers one from matching words.
    concept_path = [1 + max(d['domain_path'][0] for d in catalog['domain_paths']['library_documents'])]
    domain.extend([
        {'path': concept_path, 'label': 'Scenario concepts', 'aliases': []},
        {'path': concept_path + [1], 'label': 'System', 'aliases': [], 'entity_kind': 'system'},
        {'path': concept_path + [2], 'label': 'Software or firmware update', 'aliases': [], 'entity_kind': 'update'},
        {'path': concept_path + [3], 'label': 'Elapsed duration', 'aliases': []},
        {'path': concept_path + [3, 1], 'label': 'Elapsed seconds', 'aliases': []},
        {'path': concept_path + [4], 'label': 'Personnel access-disable duration', 'aliases': []},
        {'path': concept_path + [4, 1], 'label': 'Personnel access-disable elapsed seconds', 'aliases': []},
    ])
    duration_mappings = [
        {
            'id': 'si2c-update-installation-elapsed-duration',
            'source_id': 'SI-2(c)',
            'roles': {'organization': 'organization', 'system': 'system', 'update': 'update'},
            'scope_inputs': ['security_relevant_update', 'si2_period_applies'],
            'elapsed_predicate': 'elapsed_release_to_installation_seconds',
            'limit_predicate': 'organization_period_seconds',
            'scope_predicate': 'update_timing_scope',
            'comparison_predicate': 'within_update_period',
            'within_predicate': 'update_within_supplied_period',
            'exceeds_predicate': 'update_exceeds_supplied_period',
            'judgment_coordinates': {
                'scope': judgment_coordinates['update_timing_scope'],
                'within': judgment_coordinates['update_within_supplied_period'],
                'exceeds': judgment_coordinates['update_exceeds_supplied_period'],
            },
            'apply_coordinate': apply_coordinate,
            'compare_coordinate': compare_coordinate,
            'domain_path': control_paths['si-2'],
            'comparison_domain_path': concept_path + [3, 1],
            'architecture_id': 'update-timing',
            'architecture_coordinate': semantic_coordinate('architecture', [0, 0, 1]),
            'comparison_work_id': 'compare_update_period',
            'residual': 'Supply consistent update relevance, exact organization/system/update scope, applicable organization period and release-to-installation duration.',
            'interpretation_texts': {
                'scope': 'The caller supplied that {update} for {system} at {organization} is security-relevant and that the SI-2(c) timing comparison is in scope. This selects the comparison; applicability and policy are not independently verified.',
                'within': 'For {update} on {system} at {organization}, the supplied release-to-installation duration is within the supplied organization-defined period. This establishes only that numeric comparison.',
                'exceeds': 'For {update} on {system} at {organization}, the supplied release-to-installation duration exceeds the supplied organization-defined period. This establishes only that numeric comparison.',
            },
            'interpretation_reason': 'The source relates installation of security-relevant updates to release and an organization-defined period. Applicability and numeric elapsed seconds are supplied scenario facts.',
            'comparison_text': 'For {update} on {system} at {organization}, the supplied elapsed seconds are less than or equal to the supplied period: {value}. This comparison grants no compliance or action authority.',
            'comparison_reason': 'The upstream operation records caller-supplied scope for the reviewed SI-2(c) mapping. The comparison itself is exact integer arithmetic on supplied seconds; it does not verify policy or event evidence.',
        },
        {
            'id': 'ps4a-access-disable-elapsed-duration',
            'source_id': 'PS-4(a)',
            'roles': {'organization': 'organization', 'system': 'system', 'employee': 'person', 'account': 'account'},
            'scope_inputs': ['ps4a_timing_scope_supplied'],
            'elapsed_predicate': 'elapsed_termination_to_access_disable_seconds',
            'limit_predicate': 'organization_allowed_access_disable_period_seconds',
            'scope_predicate': 'ps4a_timing_scope',
            'comparison_predicate': 'within_ps4a_allowed_period',
            'within_predicate': 'ps4a_within_supplied_period',
            'exceeds_predicate': 'ps4a_exceeds_supplied_period',
            'judgment_coordinates': {
                'scope': judgment_coordinates['ps4a_timing_scope'],
                'within': judgment_coordinates['ps4a_within_supplied_period'],
                'exceeds': judgment_coordinates['ps4a_exceeds_supplied_period'],
            },
            'apply_coordinate': apply_coordinate,
            'compare_coordinate': compare_coordinate,
            'domain_path': control_paths['ps-4'],
            'comparison_domain_path': concept_path + [4, 1],
            'architecture_id': 'ps4a-access-disable-timing',
            'architecture_coordinate': semantic_coordinate('architecture', [0, 0, 2]),
            'comparison_work_id': 'compare_ps4a_access_disable_period',
            'residual': 'Supply one exact organization, system, employee and account scope with a caller-supplied scope selection and nonnegative elapsed and allowed durations in seconds.',
            'interpretation_texts': {
                'scope': 'The caller supplied a PS-4(a) timing-comparison scope for {employee} and {account} on {system} at {organization}. This selects a numeric comparison only; it does not establish applicability, a termination event, access state, responsibility, policy, or action.',
                'within': 'For {employee} and {account} on {system} at {organization}, the supplied access-disable elapsed duration is within the supplied allowed period. This establishes only that numeric comparison.',
                'exceeds': 'For {employee} and {account} on {system} at {organization}, the supplied access-disable elapsed duration exceeds the supplied allowed period. This establishes only that numeric comparison.',
            },
            'interpretation_reason': 'The source concerns disabling system access when employment terminates and uses an organization-defined time-period assignment. Scope and exact integer durations remain caller supplied.',
            'comparison_text': 'For {employee} and {account} on {system} at {organization}, the supplied elapsed seconds are less than or equal to the supplied allowed period: {value}. This comparison grants no compliance, responsibility, or action authority.',
            'comparison_reason': 'The upstream operation records caller-supplied PS-4(a) comparison scope. The operation is exact integer arithmetic on supplied seconds; it does not infer timestamps, parse English durations, verify policy, or verify event evidence.',
        },
    ]
    duration_architectures = []
    work_interpretations = {}
    for mapping in duration_mappings:
        fragment = compile_elapsed_duration_family(mapping)
        predicates.extend(fragment['predicates'])
        judgments.extend(fragment['judgments'])
        work.extend(fragment['work'])
        interpretations.update(fragment['interpretations'])
        work_interpretations.update(fragment['work_interpretations'])
        duration_architectures.append(fragment['architecture'])
    semantic = validate_semantic_pack({'schema': SCHEMA, 'id': 'nist-termination-warrants', 'root_id': 'JC:NIST-SP800',
        'domain': domain, 'semantic_capital': semantic_capital,
        'entity_kinds': ['organization', 'person', 'account', 'system', 'update'], 'predicates': predicates,
        'sources': [{'id': sid, 'sha256': digest(source)} for sid, source in sources.items()],
        'judgments': judgments, 'work': work, 'architectures': [
            {'id': 'termination-assessment', 'semantic_coordinate': semantic_coordinate('architecture', [0, 0, 0]), 'steps': steps},
            *duration_architectures]})
    questions = {'Assess continued administrator access after employment termination.': {'kind': 'assess', 'architecture': 'termination-assessment', 'roles': roles}}
    for node in domain:
        for alias in [node['label'], *node['aliases']]:
            questions['Resolve ' + alias + '.'] = {'kind': 'resolve', 'alias': alias}
    questions['Resolve unknown term.'] = {'kind': 'resolve', 'alias': 'unknown term'}
    return {'id': 'JC_NIST_EXECUTABLE_PACK', 'version': '0.5.0', 'standing': 'SOURCE_BOUND_NOT_EXECUTED',
        'source_manifest': descriptor(CORPUS + '/source/source_manifest.json', root),
        'domain_projection': {'catalog_sha256': catalog['catalog_sha256'], 'derivation': 'All library document roots and exact catalog ancestors of selected control warrants; coordinates derived only from source catalog paths.'},
        'entity_kinds': semantic['entity_kinds'], 'fact_templates': templates, 'semantic_pack': semantic,
        'questions': questions, 'sources': sources, 'interpretations': interpretations, 'work_interpretations': work_interpretations,
        'unknown_scopes': [
            {'text': 'Account ownership is unknown.', 'scope': 'RESPONSIBILITY', 'reason': 'Ownership is required for responsibility assignment, not for the explicitly supplied termination/access finding.'},
            {'text': 'Contractual revocation responsibility between Business A and Business B is unknown.', 'scope': 'RESPONSIBILITY', 'reason': 'Contract responsibility is not a premise of the bounded relevance warrants.'},
            {'text': 'The organization-defined termination procedure and time period are unknown.', 'scope': 'RESPONSIBILITY_AND_TIMELINESS', 'reason': 'Procedure and time period are required to decide implementation or timeliness; this pack makes neither decision.'}],
        'required_residuals': [
            {'text': 'The system cannot determine which scenario organization is responsible for revocation until account ownership, contractual responsibility, and the organization-defined termination procedure and time period are provided.', 'reason': 'RESPONSIBILITY_AND_TERMINATION_BINDINGS_UNRESOLVED'},
            {'text': 'Authorization, assigned organizational tasks, and evidence of implementation remain unverified. No compliance determination or external action is authorized.', 'reason': 'EVIDENCE_AND_AUTHORITY_CEILING'}],
        'messages': {'unsupported': 'This request is unsupported by the domain pack; no determination or action is authorized.', 'ambiguous': 'The English alias has multiple candidate bindings; supply more specific context.', 'not_found': 'No candidate is known for this English alias.'},
        'authority_ceiling': {'standing': 'SOURCE_BOUND_NOT_EXECUTED', 'source_scope': RELEASE, 'compliance_determination': False, 'responsibility_assignment': False, 'external_effects': False, 'explicit_selection_confirmed': False, 'production_ready': False},
        'coverage_ceiling': 'Five exact documentary excerpts support termination relevance, a scoped SI-2(c) timing comparison, and a separately scoped PS-4(a) access-disable comparison. Timing uses explicitly supplied nonnegative integer seconds and caller-declared scope, not verified event timestamps or parsed English durations. Controlled-English termination ingress and typed timing ingress only. Full-library documentary lookup is separate; no claim of complete executable coverage or verified policy interpretation.'}


def example_request():
    return {'request_id': 'cold-user-request-001', 'scenario_id': 'business-a-business-b-employee-a', 'entities': [
        {'id': 'org-a', 'alias': 'Business A', 'kind': 'organization'},
        {'id': 'org-b', 'alias': 'Business B', 'kind': 'organization'},
        {'id': 'person-a', 'alias': 'Employee A', 'kind': 'person'},
        {'id': 'account-a', 'alias': "Employee A's administrator account", 'kind': 'account'},
    ], 'statements': ['Employee A employment at Business A has ended.', "Employee A's administrator account is an account of Employee A.", "Employee A's administrator account has administrator privileges.", "Employee A retains access through Employee A's administrator account."],
    'unknowns': ['Account ownership is unknown.', 'Contractual revocation responsibility between Business A and Business B is unknown.', 'The organization-defined termination procedure and time period are unknown.'],
    'question': 'Assess continued administrator access after employment termination.'}

def trusted_runtime(candidate_pack: dict | None = None):
    expected = build_pack()
    if candidate_pack is not None:
        require(canonical(candidate_pack) == canonical(expected), 'adapter rejected modified pack or provenance')
    return SemanticRuntime(expected, digest(expected))

def write_json(path: str, value):
    destination = ROOT / path
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + '.tmp')
    temporary.write_bytes(canonical(value) + b'\n')
    temporary.replace(destination)

def materialize_examples():
    pack = build_pack()
    runtime = SemanticRuntime(pack, digest(pack))
    request = example_request()
    raw = canonical(request).decode()
    from .nist_admission import interpretation_source_index, interpretation_subject
    proposal_claim = {'id': 'nist-pack-v0.5.0-ps4a-timing-proposed-interpretation',
        'source_support': [dict(source_id='PS-4(a)', **interpretation_source_index(pack)['PS-4(a)'])],
        'interpretation': {'rationale': 'Proposed separate mapping of PS-4(a) to a caller-scoped integer comparison. It must receive an independent review before admission.',
            'mapping': {'judgment_ids': ['ps4a_timing_scope', 'ps4a_within_supplied_period', 'ps4a_exceeds_supplied_period'], 'work_ids': ['compare_ps4a_access_disable_period'], 'source_ids': ['PS-4(a)']},
            'scope': {'pack_version': pack['version'], 'semantic_pack_id': pack['semantic_pack']['id'], 'judgment_count': 3, 'work_interpretation_count': 1},
            'limits': ['Caller scope and durations are not independently verified.', 'The operation does not infer timestamps, parse English durations, establish applicability, compliance, responsibility, satisfaction, or action.', 'This is a proposed qualification and has no admission standing.'],
            'negative_case': 'A missing, conflicting, foreign, or altered input or interpretation remains unresolved or rejected and cannot reuse the prior reviewed pack admission.'},
        'derivation_binding': {'subject_kind': 'WHOLE_SEMANTIC_PACK', 'subject_id': pack['semantic_pack']['id'], 'target_contract_sha256': digest(interpretation_subject(pack))}}
    proposal = {'schema': 'jc/source-interpretation-proposal/1', 'standing': 'PROPOSED_UNREVIEWED_NOT_ADMITTED',
        'pack_sha256': digest(pack), 'interpretation_subject_sha256': digest(interpretation_subject(pack)), 'claim': proposal_claim,
        'required_independent_review': {'schema': 'jc/source-interpretation-review/1', 'decision_required': 'REVIEW_CONFIRMED', 'reviewer_evidence_required': ['Claim-by-claim PS-4(a) source-to-semantics review.', 'Recomputed current pack, subject, source and quote hashes.', 'Explicit confirmation that the limits reject applicability, satisfaction, compliance, responsibility, event-evidence and action claims.']}}
    artifacts = {'domain_pack.json': pack, 'example_request.json': request, 'example_ingress.json': runtime.parse(raw), 'kernel_result.json': runtime.execute(raw), 'egress_proposal.json': runtime.egress_proposal(raw), 'constrained_egress_result.json': runtime.admit_egress(raw, runtime.egress_proposal(raw)), 'exact_provenance_inventory.json': pack['sources'], 'ps4a_timing_interpretation_proposal.json': proposal}
    for name, value in artifacts.items():
        write_json(OUTPUT + '/' + name, value)
    return artifacts


def timing_example_request():
    """Fictional facts; the 86400-second period is not prescribed by NIST."""
    scope = {'organization': 'org-a', 'system': 'system-a', 'update': 'update-a'}
    return {'request_id': 'timing-example-001', 'scenario_id': 'fictional-update-scenario',
        'statement_id': 'si-2_smt.c', 'source_sha256': 'a9e23b09116d5e651461d61777c2e7dc1f3454ab3f9e1e8fdf8af01c37dc01be',
        'entities': [{'id': 'org-a', 'alias': 'Example organization', 'kind': 'organization'},
                     {'id': 'system-a', 'alias': 'Example system', 'kind': 'system'},
                     {'id': 'update-a', 'alias': 'Example security update', 'kind': 'update'}],
        'scope': scope,
        'facts': [{'id': name, 'predicate': name, 'arguments': dict(scope), 'value': value,
                   'evidence_refs': ['fictional-example-only:' + name]}
                  for name, value in [('security_relevant_update', True), ('si2_period_applies', True),
                                      ('elapsed_release_to_installation_seconds', 72000), ('organization_period_seconds', 86400)]],
         'unknowns': []}


def ps4a_timing_example_request():
    """Fictional caller declarations; 14400 seconds is not prescribed by NIST."""
    scope = {'organization': 'org-a', 'system': 'system-a', 'employee': 'employee-a', 'account': 'account-a'}
    return {'request_id': 'ps4a-timing-example-001', 'scenario_id': 'fictional-personnel-access-disable-scenario',
        'statement_id': 'ps-4_smt.a', 'source_sha256': 'a9e23b09116d5e651461d61777c2e7dc1f3454ab3f9e1e8fdf8af01c37dc01be',
        'entities': [{'id': 'org-a', 'alias': 'Example organization', 'kind': 'organization'},
                     {'id': 'system-a', 'alias': 'Example system', 'kind': 'system'},
                     {'id': 'employee-a', 'alias': 'Example employee', 'kind': 'person'},
                     {'id': 'account-a', 'alias': 'Example employee account', 'kind': 'account'}],
        'scope': scope,
        'facts': [{'id': name, 'predicate': name, 'arguments': dict(scope), 'value': value,
                   'evidence_refs': ['fictional-example-only:' + name]}
                  for name, value in [('ps4a_timing_scope_supplied', True),
                                      ('elapsed_termination_to_access_disable_seconds', 7200),
                                      ('organization_allowed_access_disable_period_seconds', 14400)]],
        'unknowns': []}
