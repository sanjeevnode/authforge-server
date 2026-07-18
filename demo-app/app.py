"""Demo relying-party app: "Sign in with AuthForge".

A ~150-line, zero-dependency (stdlib only) web app that proves a THIRD-PARTY
service can authenticate its users through AuthForge via OAuth2 Authorization
Code + PKCE. This is the payoff of Phase 4: AuthForge is now an Identity
Provider other apps integrate against — exactly like "Sign in with Google".

Setup:
  1. In the AuthForge portal (as an org owner): Your Apps -> Register app
       Redirect URI: http://localhost:9999/callback
     Copy the client_id and client_secret it shows once.
  2. Set env vars and run:
       AUTHFORGE_CLIENT_ID=afc_... AUTHFORGE_CLIENT_SECRET=afs_... python app.py
  3. Open http://localhost:9999 and click "Sign in with AuthForge".

Flow (see routers/oauth.py for the server side):
  / -> click login -> browser goes to the AuthForge portal consent page with a
  PKCE challenge -> user approves -> portal redirects back to /callback?code=...
  -> we exchange the code (+ verifier + secret) at /oauth/token -> we call
  /oauth/userinfo -> we show who logged in.
"""

import base64
import hashlib
import http.server
import json
import os
import secrets
import urllib.parse
import urllib.request

CLIENT_ID = os.environ.get("AUTHFORGE_CLIENT_ID", "SET_ME")
CLIENT_SECRET = os.environ.get("AUTHFORGE_CLIENT_SECRET", "SET_ME")
# Where AuthForge lives. Portal serves the consent UI; API serves token/userinfo.
PORTAL = os.environ.get("AUTHFORGE_PORTAL", "http://localhost:5173")
API = os.environ.get("AUTHFORGE_API", "http://localhost:8000/api/v1")
REDIRECT_URI = "http://localhost:9999/callback"
PORT = 9999

# In-memory PKCE state, keyed by the `state` param. A real app would use a
# session cookie; this keeps the demo to one file.
_pending: dict[str, str] = {}


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


def _post_form(url: str, fields: dict) -> dict:
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read().decode())


def _get_json(url: str, token: str) -> dict:
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read().decode())


def _page(body: str) -> bytes:
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Demo App · Sign in with AuthForge</title>
<style>
  body{{font-family:system-ui;background:#14122b;color:#f5f3ff;display:grid;
       place-items:center;min-height:100vh;margin:0}}
  .card{{background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);
        padding:48px;border-radius:20px;text-align:center;max-width:420px}}
  a.btn,button{{background:linear-gradient(135deg,#aa7de4,#52f9ab);color:#14122b;
        border:0;padding:14px 28px;border-radius:12px;font-weight:700;
        text-decoration:none;display:inline-block;cursor:pointer;font-size:15px}}
  code{{background:rgba(255,255,255,.08);padding:2px 8px;border-radius:6px}}
  h1{{font-size:22px}} .dim{{color:#b3aed6}}
</style></head><body><div class="card">{body}</div></body></html>""".encode()


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):  # quiet
        pass

    def _send(self, code: int, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/":
            self._send(200, _page(
                "<h1>🔐 Demo App</h1>"
                "<p class='dim'>A third-party app that trusts AuthForge for login.</p>"
                "<p><a class='btn' href='/login'>Sign in with AuthForge</a></p>"
            ))
        elif parsed.path == "/login":
            self._start_login()
        elif parsed.path == "/callback":
            self._handle_callback(urllib.parse.parse_qs(parsed.query))
        else:
            self._send(404, _page("<h1>404</h1>"))

    def _start_login(self):
        verifier, challenge = _pkce_pair()
        state = secrets.token_urlsafe(16)
        _pending[state] = verifier
        params = urllib.parse.urlencode({
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid profile email",
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        })
        # Send the browser to the AuthForge portal's consent screen.
        self.send_response(302)
        self.send_header("Location", f"{PORTAL}/oauth/consent?{params}")
        self.end_headers()

    def _handle_callback(self, q: dict):
        if "error" in q:
            self._send(200, _page("<h1>Access denied</h1><p class='dim'>You cancelled the login.</p><a href='/'>Back</a>"))
            return
        code = q.get("code", [None])[0]
        state = q.get("state", [None])[0]
        verifier = _pending.pop(state, None)
        if not code or not verifier:
            self._send(400, _page("<h1>Invalid callback</h1>"))
            return
        try:
            tokens = _post_form(f"{API}/oauth/token", {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "code_verifier": verifier,
            })
            info = _get_json(f"{API}/oauth/userinfo", tokens["access_token"])
        except Exception as e:  # noqa: BLE001 — demo: surface any failure plainly
            self._send(500, _page(f"<h1>Token exchange failed</h1><p class='dim'>{e}</p>"))
            return
        self._send(200, _page(
            "<h1>✅ Signed in!</h1>"
            f"<p>Logged in as <code>{info.get('email') or info['sub']}</code></p>"
            "<p class='dim'>Authenticated entirely through AuthForge — this app "
            "never saw your password.</p><a href='/'>Home</a>"
        ))


if __name__ == "__main__":
    if CLIENT_ID == "SET_ME":
        print("Set AUTHFORGE_CLIENT_ID and AUTHFORGE_CLIENT_SECRET first (see the docstring).")
    print(f"Demo relying-party app on http://localhost:{PORT}")
    http.server.HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
