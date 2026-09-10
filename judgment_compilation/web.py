"""Serves the local web page and JSON API."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from .kernel import canonical, strict_json
from .nist import example_request, ps4a_timing_example_request

class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    def __init__(self, address, app):
        if address[0] != '127.0.0.1':
            raise ValueError('demo server must bind 127.0.0.1')
        self.app = app
        super().__init__(address, Handler)

class Handler(BaseHTTPRequestHandler):
    server_version = 'JudgmentCompilation'
    def log_message(self, format, *args):
        pass  # Scenario content is not logged.

    def _allowed(self):
        port = self.server.server_address[1]
        origins = {f'http://127.0.0.1:{port}', f'http://localhost:{port}'}
        return self.headers.get('Host') in {f'127.0.0.1:{port}', f'localhost:{port}'} and self.headers.get('Origin') in (None, *origins)

    def _send(self, status, data, content_type='application/json; charset=utf-8'):
        body = data if isinstance(data, bytes) else canonical(data)
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self._allowed():
            return self._send(403, {'error': 'local origin required'})
        if self.path == '/':
            return self._send(200, (Path(__file__).parent/'static/index.html').read_bytes(), 'text/html; charset=utf-8')
        if self.path == '/api/example':
            return self._send(200, example_request())
        if self.path == '/api/ps4a-timing-example':
            return self._send(200, ps4a_timing_example_request())
        if self.path == '/api/status':
            return self._send(200, self.server.app.status())
        return self._send(404, {'error': 'not found'})

    def do_POST(self):
        if not self._allowed():
            return self._send(403, {'error': 'local origin required'})
        if self.path != '/api/query':
            return self._send(404, {'error': 'not found'})
        if self.headers.get('Content-Type', '').split(';')[0] != 'application/json' or self.headers.get('Transfer-Encoding'):
            return self._send(415, {'error': 'JSON with content length required'})
        try:
            length = int(self.headers.get('Content-Length', '-1'))
            if not 0 < length <= 100000:
                return self._send(413, {'error': 'request size'})
            self.connection.settimeout(10)
            raw = self.rfile.read(length).decode('utf-8')
            result = self.server.app.query(strict_json(raw))
            return self._send(200, result)
        except (ValueError, TypeError, KeyError, OSError, RecursionError):
            return self._send(400, {'error': 'Request rejected. Check the schema, identities, and supported fields.'})
