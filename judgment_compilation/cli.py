"""Provides the Judgment Compilation command line."""
import argparse, json
from pathlib import Path
from .kernel import canonical, strict_json, Rejected

def main():
    parser = argparse.ArgumentParser(
        prog='jc',
        description='Browse included NIST sources and run reviewed checks.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Start here:
  jc status                    Show package, coverage, and engine status.
  jc demo                      Run the bundled termination example.
  jc query "QUESTION"          Ask a plain-English source question.
  jc reviewed-programs         List reviewed document checks.
  jc documents --limit 200     List the included document library.
  jc serve --port 0            Start the localhost page.

Commands print JSON to stdout. Invalid input exits with status 2 and writes the reason to stderr.
Optional local notes require --model and --recommend.""",
    )
    parser.add_argument('--model', help='Name of a model installed in local Ollama')
    parser.add_argument('--model-url', default='http://127.0.0.1:11434', help='Local Ollama address')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('status', help='Show package, source-file, and engine status')
    sub.add_parser('semantic-progress', help='Show document and review counts')
    semantic_program = sub.add_parser('semantic-program', help='Show the parts and steps of a compiled check')
    semantic_program.add_argument('architecture_id')
    sub.add_parser('reviewed-programs', help='List reviewed document checks')
    reviewed_program = sub.add_parser('reviewed-program', help='Inspect one reviewed document check')
    reviewed_program.add_argument('package_id')
    run_reviewed = sub.add_parser('run-reviewed-program', help='Run one reviewed check with supplied facts')
    run_reviewed.add_argument('package_id'); run_reviewed.add_argument('request', type=Path)
    sub.add_parser('example', help='Print the bundled termination request as JSON')
    sub.add_parser('timing-example', help='Print the included SI-2(c) timing example')
    timing = sub.add_parser('timing', help='Compare supplied times for SI-2(c)')
    timing.add_argument('request', type=Path); timing.add_argument('--recommend', action='store_true')
    sub.add_parser('ps4a-timing-example', help='Print the included PS-4(a) timing example')
    ps4a_timing = sub.add_parser('ps4a-timing', help='Compare supplied times for PS-4(a)')
    ps4a_timing.add_argument('request', type=Path); ps4a_timing.add_argument('--recommend', action='store_true')
    demo = sub.add_parser('demo', help='Run the bundled termination example'); demo.add_argument('--recommend', action='store_true', help='Include optional notes from the local model')
    query = sub.add_parser('query', help='Ask a plain-English question against the packaged sources'); query.add_argument('question', metavar='QUESTION'); query.add_argument('--recommend', action='store_true', help='Include optional notes from the local model')
    assess = sub.add_parser('assess', help='Run a scenario request from a JSON file'); assess.add_argument('request', type=Path, metavar='REQUEST'); assess.add_argument('--recommend', action='store_true', help='Include optional notes from the local model'); assess.add_argument('--ingress-proposal', type=Path, metavar='FILE'); assess.add_argument('--egress-proposal', type=Path, metavar='FILE')
    readiness = sub.add_parser('readiness', help='Check whether a JSON request has the required inputs'); readiness.add_argument('request', type=Path, metavar='REQUEST')
    sub.add_parser('requirement-dispositions', help='List how each source template is handled')
    sub.add_parser('source-accounting', help='Show included NIST source counts and hashes')
    sub.add_parser('source-mappings', help='Show links between source passages and checks')
    requirements = sub.add_parser('requirements', help='List source statement IDs and titles')
    requirements.add_argument('--control', dest='control_id')
    requirements.add_argument('--offset', type=int, default=0); requirements.add_argument('--limit', type=int, default=25)
    requirement = sub.add_parser('requirement', help='Inspect a source requirement and its parameter fields')
    requirement.add_argument('statement_id')
    profile = sub.add_parser('profile-membership', help='Check whether a control ID appears in a NIST baseline profile')
    profile.add_argument('profile', choices=['LOW','MODERATE','HIGH','PRIVACY'])
    profile.add_argument('control_id')
    assessment = sub.add_parser('assessment', help='Inspect SP 800-53A objectives, methods, and objects')
    assessment.add_argument('control_id')
    prepare_assessment = sub.add_parser('prepare-assessment', help='Validate selected NIST assessment fields')
    prepare_assessment.add_argument('request', type=Path); prepare_assessment.add_argument('--recommend', action='store_true')
    instantiate = sub.add_parser('instantiate', help='Fill a requirement template with supplied values')
    instantiate.add_argument('request', type=Path); instantiate.add_argument('--recommend', action='store_true')
    serve = sub.add_parser('serve', help='Start the local web page'); serve.add_argument('--port', type=int, default=8765, help='Local port; use 0 to choose an available port')
    documents = sub.add_parser('documents', help='List included documents')
    documents.add_argument('--offset',type=int,default=0); documents.add_argument('--limit',type=int,default=25)
    page = sub.add_parser('page', help='Show one extracted PDF page')
    page.add_argument('publication_id'); page.add_argument('page_number',type=int); page.add_argument('--view',choices=['plain','layout'],default='plain')
    search = sub.add_parser('search', help='Search included document text')
    search.add_argument('phrase'); search.add_argument('--publication',dest='publication_id'); search.add_argument('--limit',type=int,default=20)
    cite = sub.add_parser('cite', help='List every match for an exact text span')
    cite.add_argument('publication_id'); cite.add_argument('page_number',type=int)
    cite.add_argument('start',type=int); cite.add_argument('end',type=int); cite.add_argument('exact_quote')
    sub.add_parser('verify', help='Verify included files, hashes, and source links')
    args = parser.parse_args()
    try:
        from .nist import example_request, timing_example_request, ps4a_timing_example_request
        if args.command == 'timing-example':
            print(json.dumps(timing_example_request(), indent=2)); return 0
        if args.command == 'ps4a-timing-example':
            print(json.dumps(ps4a_timing_example_request(), indent=2)); return 0
        if args.command == 'example':
            print(json.dumps(example_request(), indent=2)); return 0
        from .application import Application
        recommender = None
        if args.model:
            from .inference import LocalRecommendation
            recommender = LocalRecommendation(args.model_url, args.model)
        app = Application(recommender)
        if args.command == 'serve':
            from .web import Server
            server = Server(('127.0.0.1', args.port), app)
            print(f'Judgment Compilation: http://127.0.0.1:{server.server_address[1]} (Ctrl+C to stop)', flush=True)
            try: server.serve_forever()
            except KeyboardInterrupt: pass
            finally: server.server_close()
            return 0
        if args.command == 'verify':
            from .nist import build_pack
            from .kernel import digest, require
            from ._pins import PACK_SHA256
            require(digest(build_pack()) == PACK_SHA256, 'recompiled pack drift')
            result = {'status': 'PASS', 'pack_sha256': PACK_SHA256, 'library': app.library.verify(), 'checks': 'all packaged inputs and recomputed bounded PDF/OSCAL provenance'}
        elif args.command == 'status': result = app.status()
        elif args.command == 'semantic-progress': result = app.query({'mode': 'semantic_progress'})
        elif args.command == 'semantic-program':
            result = app.query({'mode': 'semantic_program', 'request': {'architecture_id': args.architecture_id}})
        elif args.command == 'reviewed-programs':
            result = app.query({'mode': 'reviewed_programs'})
        elif args.command == 'reviewed-program':
            result = app.query({'mode': 'reviewed_program', 'request': {
                'operation': 'inspect', 'package_id': args.package_id}})
        elif args.command == 'run-reviewed-program':
            result = app.query({'mode': 'reviewed_program', 'request': {
                'operation': 'execute', 'package_id': args.package_id,
                'execution_request': strict_json(args.request.read_text(encoding='utf-8-sig'))}})
        elif args.command == 'timing':
            result = app.query({'mode': 'timing', 'request': strict_json(args.request.read_text(encoding='utf-8-sig')), 'recommend': args.recommend})
        elif args.command == 'ps4a-timing':
            result = app.query({'mode': 'ps4a_timing', 'request': strict_json(args.request.read_text(encoding='utf-8-sig')), 'recommend': args.recommend})
        elif args.command == 'requirement-dispositions':
            from .nist_requirements import REQUEST_SCHEMA
            result = app.query({'mode': 'requirements', 'request': {
                'schema': REQUEST_SCHEMA, 'operation': 'dispositions'}})
        elif args.command == 'source-accounting':
            result = app.query({'mode': 'accounting', 'request': {'operation': 'manifest'}})
        elif args.command == 'source-mappings':
            result = app.query({'mode': 'mappings', 'request': {'operation': 'index'}})
        elif args.command == 'requirements':
            from .nist_requirements import REQUEST_SCHEMA
            result = app.query({'mode': 'requirements', 'request': {'schema': REQUEST_SCHEMA,
                'operation': 'list', 'control_id': args.control_id, 'offset': args.offset, 'limit': args.limit}})
        elif args.command == 'profile-membership':
            from .nist_profiles import SCHEMA as PROFILE_SCHEMA
            result = app.query({'mode': 'profiles', 'request': {'schema': PROFILE_SCHEMA,
                'operation': 'LITERAL_MEMBERSHIP', 'profile': args.profile, 'control_id': args.control_id}})
        elif args.command in ('assessment', 'prepare-assessment'):
            from .nist_assessments import SCHEMA as ASSESSMENT_SCHEMA
            request = ({'schema': ASSESSMENT_SCHEMA, 'operation': 'INSPECT',
                        'control_id': args.control_id} if args.command == 'assessment'
                       else strict_json(args.request.read_text(encoding='utf-8-sig')))
            result = app.query({'mode': 'assessments', 'request': request,
                                'recommend': getattr(args, 'recommend', False)})
        elif args.command in ('requirement', 'instantiate'):
            from .nist_requirements import REQUEST_SCHEMA
            request = {'schema': REQUEST_SCHEMA, 'operation': 'inspect', 'statement_id': args.statement_id} if args.command == 'requirement' else strict_json(args.request.read_text(encoding='utf-8-sig'))
            result = app.query({'mode': 'requirements', 'request': request, 'recommend': getattr(args, 'recommend', False)})
        elif args.command in ('documents','page','search','cite'):
            if args.command == 'documents': request = dict(operation='documents',offset=args.offset,limit=args.limit)
            elif args.command == 'page': request = dict(operation='page',publication_id=args.publication_id,page_number=args.page_number,view=args.view)
            elif args.command == 'cite': request = dict(operation='cite',publication_id=args.publication_id,page_number=args.page_number,character_span=[args.start,args.end],exact_quote=args.exact_quote)
            else: request = dict(operation='search',phrase=args.phrase,publication_id=args.publication_id,limit=args.limit)
            result = app.query({'mode':'library','request':request})
        else:
            recommend = getattr(args, 'recommend', False)
            if args.command == 'demo': payload = {'mode': 'scenario', 'request': example_request(), 'recommend': recommend}
            elif args.command == 'query': payload = {'mode': 'inquiry', 'question': args.question, 'recommend': recommend}
            else: payload = {'mode': 'scenario' if args.command == 'assess' else 'readiness', 'request': strict_json(args.request.read_text(encoding='utf-8-sig')), 'recommend': recommend}
            if args.command == 'assess':
                raw = canonical(payload['request']).decode()
                if args.ingress_proposal: app.runtime.admit_ingress(raw, strict_json(args.ingress_proposal.read_text()))
                if args.egress_proposal: app.runtime.admit_egress(raw, strict_json(args.egress_proposal.read_text()))
            result = app.query(payload)
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2))
        return 0
    except (Rejected, ValueError, OSError, KeyError) as error:
        parser.exit(2, 'REJECTED: ' + str(error) + '\n')

if __name__ == '__main__':
    raise SystemExit(main())
