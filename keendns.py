#!/usr/bin/env python3
"""Local launcher for the Keenetic DNS routes manager.

Serves keendns.html on 127.0.0.1 and proxies RCI calls to the router. The proxy
exists because the router refuses cross-origin requests outright (403, "invalid
origin") and marks its session cookie SameSite=Strict, so a page served from
anywhere but the router itself cannot talk to /rci directly.

Usage: python3 keendns.py [--host 192.168.1.1] [--user admin] [--port 8765]
Password comes from $KEENETIC_PASSWORD or an interactive prompt.
"""

import argparse
import getpass
import hashlib
import http.server
import json
import os
import sys
import time
import urllib.error
import urllib.request
import webbrowser

HERE = os.path.dirname(os.path.abspath(__file__))
PAGE = os.path.join(HERE, "keendns.html")


class Router:
    """RCI client: challenge auth, session cookie in memory, re-login on 401.

    The session cookie expires after 5 minutes (Max-Age=300), so every call
    has to be ready to authenticate again.
    """

    def __init__(self, host, user, password):
        self.base = "http://" + host
        self.user = user
        self.password = password
        self.cookie = None

    def _request(self, path, data=None, timeout=30):
        req = urllib.request.Request(self.base + path, data=data)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if self.cookie:
            req.add_header("Cookie", self.cookie)
        # No Origin/Referer header: the router rejects requests carrying a
        # foreign one, and urllib sends neither.
        return urllib.request.urlopen(req, timeout=timeout)

    @staticmethod
    def _cookie_from(headers):
        raw = headers.get("Set-Cookie")
        return raw.split(";", 1)[0] if raw else None

    def login(self):
        """GET /auth for the challenge, then POST the response digest."""
        try:
            self._request("/auth").read()
            return  # already authorised, cookie still valid
        except urllib.error.HTTPError as err:
            if err.code != 401:
                raise
            headers = err.headers

        realm = headers.get("X-NDM-Realm")
        challenge = headers.get("X-NDM-Challenge")
        if not realm or not challenge:
            raise RuntimeError("router did not offer a challenge; is this a Keenetic?")
        self.cookie = self._cookie_from(headers) or self.cookie

        md5 = hashlib.md5("{}:{}:{}".format(self.user, realm, self.password).encode()).hexdigest()
        digest = hashlib.sha256((challenge + md5).encode()).hexdigest()
        body = json.dumps({"login": self.user, "password": digest}).encode()
        try:
            resp = self._request("/auth", body)
        except urllib.error.HTTPError as err:
            if err.code == 401:
                raise RuntimeError("login rejected: wrong username or password")
            raise
        self.cookie = self._cookie_from(resp.headers) or self.cookie
        resp.read()

    def rci(self, payload):
        """POST a command tree to /rci/, re-authenticating once if needed."""
        data = json.dumps(payload).encode()
        try:
            return self._request("/rci/", data).read()
        except urllib.error.HTTPError as err:
            if err.code != 401:
                raise
        self.login()
        return self._request("/rci/", data).read()


LOG_FILE = None


def log(text):
    """Every exchange with the router, so a surprise can be traced afterwards."""
    line = "{} {}".format(time.strftime("%H:%M:%S"), text)
    sys.stderr.write(line + "\n")
    sys.stderr.flush()
    if LOG_FILE:
        LOG_FILE.write(line + "\n")
        LOG_FILE.flush()


def describe_request(payload):
    """One line per command: CLI verbatim, settings trees compact, reads named."""
    out = []
    for item in payload if isinstance(payload, list) else [payload]:
        if not isinstance(item, dict):
            out.append(repr(item))
        elif "parse" in item:
            out.append(item["parse"])
        elif "show" in item:
            out.append("show " + "/".join(_paths(item["show"])))
        else:
            out.append(json.dumps(item, ensure_ascii=False, sort_keys=True))
    return out


def _paths(node, prefix=""):
    if not isinstance(node, dict) or not node:
        return [prefix] if prefix else []
    paths = []
    for key, value in node.items():
        paths.extend(_paths(value, prefix + ("/" if prefix else "") + key) or
                     [prefix + ("/" if prefix else "") + key])
    return paths


def describe_statuses(body):
    """Pull every status message out of a response, however deep it sits."""
    found = []

    def walk(node):
        if isinstance(node, list):
            for item in node:
                walk(item)
        elif isinstance(node, dict):
            statuses = node.get("status")
            if isinstance(statuses, list):
                for status in statuses:
                    if isinstance(status, dict):
                        found.append("[{}] {}".format(status.get("status"),
                                                      status.get("message") or status.get("code")))
            for key, value in node.items():
                if key != "status":
                    walk(value)

    try:
        walk(json.loads(body))
    except ValueError:
        return ["<unparsable response>"]
    return found


class Handler(http.server.BaseHTTPRequestHandler):
    router = None
    protocol_version = "HTTP/1.1"

    def _send(self, status, body, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.split("?")[0] not in ("/", "/keendns.html"):
            self.send_error(404)
            return
        try:
            with open(PAGE, "rb") as fh:
                page = fh.read()
        except OSError:
            self._send(500, b"keendns.html not found next to keendns.py", "text/plain; charset=utf-8")
            return
        self._send(200, page, "text/html; charset=utf-8")

    def do_POST(self):
        if self.path != "/api/rci":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length") or 0)
        try:
            payload = json.loads(self.rfile.read(length) or b"null")
        except ValueError as exc:
            self._send(400, json.dumps({"error": str(exc)}).encode(), "application/json")
            return
        commands = describe_request(payload)
        # Reads happen on every refresh and would bury everything else.
        writing = any(not c.startswith("show ") for c in commands)
        if writing:
            for command in commands:
                log("→ " + command)
        try:
            body = self.router.rci(payload)
        except Exception as exc:  # network hiccup, auth failure, router error
            log("!! " + str(exc))
            self._send(502, json.dumps({"error": str(exc)}).encode(), "application/json")
            return
        if writing:
            for status in describe_statuses(body):
                log("← " + status)
        self._send(200, body, "application/json")

    def log_message(self, fmt, *args):
        pass  # request lines add nothing next to the command log


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    # Keenetic ships on 192.168.1.1; $KEENETIC_HOST covers a moved one without
    # having to pass the flag every time.
    parser.add_argument("--host", default=os.environ.get("KEENETIC_HOST", "192.168.1.1"),
                        help="router address (default: %(default)s)")
    parser.add_argument("--user", default=os.environ.get("KEENETIC_USER", "admin"),
                        help="router login (default: %(default)s)")
    parser.add_argument("--port", type=int, default=8765, help="local port (default: %(default)s)")
    # Loopback by default: whoever reaches this port is already logged into the
    # router. In a container it has to be 0.0.0.0, so publish it to 127.0.0.1
    # on the host side.
    parser.add_argument("--bind", default=os.environ.get("KEENDNS_BIND", "127.0.0.1"),
                        help="local address to listen on (default: %(default)s)")
    parser.add_argument("--no-browser", action="store_true", help="do not open a browser window")
    parser.add_argument("--log", metavar="FILE", default=os.environ.get("KEENDNS_LOG"),
                        help="also append the command log to this file")
    args = parser.parse_args()

    if args.log:
        global LOG_FILE
        LOG_FILE = open(args.log, "a", encoding="utf-8")
        log("--- keendns manager started ---")

    host = args.host
    router = Router(host, args.user, "")
    env_password = os.environ.get("KEENETIC_PASSWORD")
    if not env_password and not sys.stdin.isatty():
        sys.exit("No terminal to ask for the password. Set KEENETIC_PASSWORD.")
    for attempt in range(3):
        router.password = env_password or getpass.getpass(
            "Password for {}@{}: ".format(args.user, host))
        try:
            router.login()
            break
        except RuntimeError as err:
            print(err)
            if env_password or attempt == 2:
                sys.exit("Could not log in.")
        except OSError as err:
            sys.exit("Cannot reach {}: {}".format(host, err))
    print("Authenticated on {}".format(host))

    Handler.router = router
    server = http.server.ThreadingHTTPServer((args.bind, args.port), Handler)
    url = "http://127.0.0.1:{}/".format(args.port)
    if args.bind in ("0.0.0.0", "::", ""):
        # Typically a container: the port the browser uses is the published one.
        print("Manager listening on {}:{} — open the address you published it to"
              .format(args.bind or "0.0.0.0", args.port))
    else:
        print("Manager at {} — Ctrl-C to stop".format(url))
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
