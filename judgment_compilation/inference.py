"""Gets optional notes from a model running on the local computer."""
import json
from urllib.parse import urlsplit
from urllib.request import Request, urlopen, ProxyHandler, build_opener, HTTPRedirectHandler
from .kernel import canonical, require

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('model redirects are not allowed')

class LocalRecommendation:
    def __init__(self, url: str, model: str):
        parsed = urlsplit(url)
        require(parsed.scheme == 'http' and parsed.hostname in ('127.0.0.1', '::1') and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment and parsed.path in ('', '/'), 'model URL must be an explicit HTTP loopback origin')
        require(isinstance(model, str) and 0 < len(model) < 200, 'model name required')
        self.url, self.model = url.rstrip('/') + '/api/chat', model

    def recommend(self, packet: dict) -> str:
        context = canonical(packet).decode()
        require(len(context) <= 60000, 'recommendation context too large; narrow the question')
        prompt = ('Review the supplied record. List missing information and suggest follow-up questions or draft wording. '
                  'Use only the supplied facts and citations. Keep people and systems separate. '
                  'Leave compliance, responsibility, and action decisions to the user. State what remains uncertain. '
                  'Return plain text.')
        payload = {'model': self.model, 'stream': False, 'messages': [{'role': 'system', 'content': prompt}, {'role': 'user', 'content': context}], 'options': {'temperature': 0}}
        opener = build_opener(ProxyHandler({}), NoRedirect())
        request = Request(self.url, data=canonical(payload), headers={'Content-Type': 'application/json'}, method='POST')
        with opener.open(request, timeout=45) as response:
            raw = response.read(65537)
        require(len(raw) <= 65536, 'model response too large')
        result = json.loads(raw)
        answer = result.get('message', {}).get('content')
        require(type(answer) is str and 0 < len(answer.strip()) <= 16000, 'invalid model recommendation')
        return answer.strip()
