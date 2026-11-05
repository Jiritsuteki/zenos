#!/usr/bin/env python3
# ZENOS office local server (Docs, Sheets, Slides): serves the built app and relays AI calls to the
# user's own provider (OpenAI-compatible or Anthropic). Same-origin for the app,
# so no CORS issues; the API key stays on this machine and is never stored here.
import os, sys, json
import urllib.request
import urllib.error
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

# usage: zoffice_server.py <app directory> <port>   (the app's built files are in <app directory>/dist)
DIST = os.path.join(os.path.abspath(sys.argv[1]), 'dist')
HOST = '127.0.0.1'
PORT = int(sys.argv[2])
GUARD_SOCK = os.environ.get('ZENOS_AIGUARD_SOCK', '/run/zenos/aiguard.sock')
KEYD_SOCK = os.environ.get('ZENOS_KEYD_SOCK', '/run/zenos/keyd.sock')


def guard_check(url):
    """Ask zenos-aiguard whether this AI may be reached now (it also learns the address, so the packet filter covers
    it from then on). The packet filter is what enforces it; this is so the user gets a clear answer."""
    import socket
    if not os.path.exists(GUARD_SOCK):
        if os.path.exists(KEYD_SOCK):       # installed system: the guard must answer
            return False, 'The AI guard (zenos-aiguard) is not running, so no AI can be used.'
        return True, ''                     # development layout without the root services
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(15)
        s.connect(GUARD_SOCK)
        s.sendall((json.dumps({'op': 'check', 'url': url}) + '\n').encode())
        buf = b''
        while not buf.endswith(b'\n'):
            c = s.recv(65536)
            if not c:
                break
            buf += c
        s.close()
        a = json.loads(buf or b'{}')
    except Exception:
        return False, 'The AI guard did not answer, so no AI can be used right now.'
    return a.get('allow') is True, a.get('message') or ''


ANTHROPIC = 'https://api.anthropic.com'


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):            # an AI endpoint that sends us elsewhere is not followed
        return None


OPENER = urllib.request.build_opener(_NoRedirect)


def endpoint_ok(base):
    """an AI endpoint the relay will call: http(s) only (never file: or others), no user name, query or fragment,
    and plain http only for this machine (a model server running here); everything else over https"""
    from urllib.parse import urlsplit
    try:
        u = urlsplit(base)
        host = (u.hostname or '').lower()
        if u.scheme not in ('http', 'https') or not host or u.username or u.password or u.query or u.fragment:
            return False
        return u.scheme == 'https' or host in ('127.0.0.1', 'localhost', '::1')
    except ValueError:
        return False


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=DIST, **k)

    def log_message(self, *a):
        pass

    def _host_ok(self):
        # Only accept requests addressed to this machine (blocks DNS-rebinding
        # and any access that is not same-origin localhost).
        h = (self.headers.get('Host') or '').rsplit(':', 1)[0]
        return h in ('127.0.0.1', 'localhost', '::1', '[::1]', '')

    def _json(self, code, obj):
        b = json.dumps(obj).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if not self._host_ok():
            return self._json(403, {'error': 'forbidden'})
        return super().do_GET()

    def _origin_ok(self):
        # a page in a browser (another site) must not make this relay call anywhere: its Origin is not ours, and
        # without the JSON content type its request would skip the browser's preflight
        o = self.headers.get('Origin')
        if o and o not in ('http://127.0.0.1:%d' % PORT, 'http://localhost:%d' % PORT, 'null'):
            return False
        return (self.headers.get('Content-Type') or '').split(';')[0].strip().lower() == 'application/json'

    def do_POST(self):
        if not self._host_ok() or not self._origin_ok():
            return self._json(403, {'error': 'forbidden'})
        if self.path.rstrip('/') != '/ai/chat':
            return self._json(404, {'error': 'not found'})
        try:
            ln = int(self.headers.get('Content-Length', '0') or '0')
            body = json.loads(self.rfile.read(ln) or b'{}')
        except Exception as e:
            return self._json(400, {'error': 'bad request: %s' % e})

        provider = (body.get('provider') or 'openai').lower()
        base = (body.get('baseUrl') or '').rstrip('/')
        key = body.get('apiKey') or ''
        model = body.get('model') or ''
        messages = body.get('messages') or []
        if not key:
            return self._json(400, {'error': 'No AI is set up yet (register a key first).'})
        if provider != 'anthropic' and not base:
            return self._json(400, {'error': 'Enter an OpenAI-compatible endpoint (/v1).'})
        if base and not endpoint_ok(base):
            return self._json(400, {'error': 'The AI address must start with https:// (http:// only for this PC).'})
        ok, why = guard_check(base or ANTHROPIC if provider == 'anthropic' else base)
        if not ok:
            return self._json(403, {'error': why})

        try:
            if provider == 'anthropic':
                text = self._anthropic(base, key, model, messages, body)
            else:
                text = self._openai(base, key, model, messages, body)
            return self._json(200, {'text': text})
        except urllib.error.HTTPError as e:
            try:
                detail = e.read().decode('utf-8', 'replace')[:700]
            except Exception:
                detail = str(e)
            self._json(e.code, {'error': detail})
        except Exception as e:
            self._json(502, {'error': 'relay failed: %s' % e})

    def _openai(self, base, key, model, messages, body):
        if not base:
            raise ValueError('Enter an OpenAI-compatible endpoint (/v1).')
        payload = json.dumps({
            'model': model or 'gpt-4o-mini',
            'messages': messages,
            'temperature': body.get('temperature', 0.2),
        }).encode('utf-8')
        req = urllib.request.Request(
            base + '/chat/completions',
            data=payload,
            method='POST',
            headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + key},
        )
        with OPENER.open(req, timeout=120) as r:
            data = json.loads(r.read())
        return data['choices'][0]['message']['content']

    def _anthropic(self, base, key, model, messages, body):
        base = base or ANTHROPIC
        system = '\n'.join(m.get('content', '') for m in messages if m.get('role') == 'system')
        conv = [
            {'role': m.get('role'), 'content': m.get('content', '')}
            for m in messages if m.get('role') in ('user', 'assistant')
        ]
        pl = {
            'model': model or 'claude-sonnet-4-5',
            'max_tokens': int(body.get('max_tokens', 2048)),
            'messages': conv,
        }
        if system:
            pl['system'] = system
        req = urllib.request.Request(
            base + '/v1/messages',
            data=json.dumps(pl).encode('utf-8'),
            method='POST',
            headers={
                'content-type': 'application/json',
                'x-api-key': key,
                'anthropic-version': '2023-06-01',
            },
        )
        with OPENER.open(req, timeout=120) as r:
            data = json.loads(r.read())
        parts = data.get('content') or []
        return ''.join(p.get('text', '') for p in parts if p.get('type') == 'text')


if __name__ == '__main__':
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
