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
import datetime
import getpass
import hashlib
import http.server
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser

HERE = os.path.dirname(os.path.abspath(__file__))
PAGE = os.path.join(HERE, "keendns.html")


# Commands per /rci/ POST. 709 in one request is known to pass, 15000 (~1 MB)
# is rejected by the router's SCGI as "content oversize".
RCI_CHUNK = 500


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
        # The nightly sync writes from its own thread; commands from two plans
        # must never interleave on the router.
        self.lock = threading.Lock()

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
        """POST a command tree to /rci/, re-authenticating once if needed.

        A long command list goes in chunks of RCI_CHUNK under one lock: the
        router rejects an oversized body ("content oversize") and after a few
        of those bans the client IP for 15 minutes.
        """
        if not isinstance(payload, list) or len(payload) <= RCI_CHUNK:
            with self.lock:
                return self._post(payload)
        # ponytail: a chunk that fails leaves the earlier ones applied and the
        # config unsaved; the UI shows the error and a refresh shows the state.
        out = []
        with self.lock:
            for i in range(0, len(payload), RCI_CHUNK):
                out.extend(json.loads(self._post(payload[i:i + RCI_CHUNK])))
        return json.dumps(out).encode()

    def _post(self, payload):
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


def iter_statuses(body):
    """Every status dict in a response, however deep it sits."""
    found = []

    def walk(node):
        if isinstance(node, list):
            for item in node:
                walk(item)
        elif isinstance(node, dict):
            statuses = node.get("status")
            if isinstance(statuses, list):
                found.extend(s for s in statuses if isinstance(s, dict))
            for key, value in node.items():
                if key != "status":
                    walk(value)

    try:
        walk(json.loads(body))
    except ValueError:
        return [{"status": "error", "message": "<unparsable response>"}]
    return found


def describe_statuses(body):
    return ["[{}] {}".format(s.get("status"), s.get("message") or s.get("code"))
            for s in iter_statuses(body)]


# A settings tree always answers "no input" next to the real result — noise,
# not a failure (see keendns.html, NO_INPUT).
NO_INPUT = "7471107"


def status_errors(body):
    return [s.get("message") or str(s.get("code")) for s in iter_statuses(body)
            if s.get("status") == "error" and str(s.get("code")) != NO_INPUT]


# =========================================================== allow-domains
# Ready-made lists from https://github.com/itdoginfo/allow-domains. A service
# pulls its domains and its IPv4 subnets into one list; the catalog is static
# because the GitHub API allows 60 anonymous requests an hour.
ALLOW_DOMAINS = "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/"
LIMIT = 300  # entries per object-group, the same firmware constant as in keendns.html
SHARD_RE = re.compile(r"^(.*)_(\d+)$")

PRESETS = {
    "Сервисы": {
        "cloudflare":   ["Services/cloudflare.lst", "Subnets/IPv4/cloudflare.lst"],
        "cloudfront":   ["Subnets/IPv4/cloudfront.lst"],
        "digitalocean": ["Subnets/IPv4/digitalocean.lst"],
        "discord":      ["Services/discord.lst", "Subnets/IPv4/discord.lst"],
        "google_ai":    ["Services/google_ai.lst"],
        "google_meet":  ["Services/google_meet.lst", "Subnets/IPv4/google_meet.lst"],
        "google_play":  ["Services/google_play.lst"],
        "hdrezka":      ["Services/hdrezka.lst"],
        "hetzner":      ["Subnets/IPv4/hetzner.lst"],
        "meta":         ["Services/meta.lst", "Subnets/IPv4/meta.lst"],
        "ovh":          ["Subnets/IPv4/ovh.lst"],
        "roblox":       ["Services/roblox.lst", "Subnets/IPv4/roblox.lst"],
        "telegram":     ["Services/telegram.lst", "Subnets/IPv4/telegram.lst"],
        "tiktok":       ["Services/tiktok.lst"],
        "twitter":      ["Services/twitter.lst", "Subnets/IPv4/twitter.lst"],
        "youtube":      ["Services/youtube.lst"],
    },
    "Категории": {n: ["Categories/%s.lst" % n]
                  for n in ["anime", "block", "geoblock", "hodca", "news", "porn"]},
    "Страны": {
        "russia-inside":  ["Russia/inside-raw.lst"],
        "russia-outside": ["Russia/outside-raw.lst"],
        "ukraine-inside": ["Ukraine/inside-raw.lst"],
    },
}


def preset_catalog():
    """{group: {name: label}} for the dropdown; the label says what a preset holds."""
    out = {}
    for group, presets in PRESETS.items():
        out[group] = {}
        for name, paths in presets.items():
            kinds = [k for k, prefix in (("домены", "Services/"), ("подсети", "Subnets/"))
                     if any(p.startswith(prefix) for p in paths)]
            out[group][name] = name + (" (" + " + ".join(kinds) + ")" if kinds != ["домены"] else "")
    return out


def preset_paths(name):
    for presets in PRESETS.values():
        if name in presets:
            return presets[name]
    raise KeyError("no such preset: " + name)


def normalize(text):
    """Twin of parseEntries in keendns.html — both sides of a diff must agree."""
    seen, out = set(), []
    for line in text.splitlines():
        line = re.sub(r"#.*$", "", line).strip()
        line = re.sub(r"^\*\.", "", line).lstrip(".")
        if not line or re.search(r"\s", line) or line in seen:
            continue
        seen.add(line)
        out.append(line)
    return out


def fetch_preset(name):
    """All files of a preset, normalized. Any file failing fails the whole
    preset: a half-loaded list is worse than none."""
    texts = []
    for path in preset_paths(name):
        with urllib.request.urlopen(ALLOW_DOMAINS + path, timeout=30) as resp:
            texts.append(resp.read().decode("utf-8", "replace"))
    return normalize("\n".join(texts))


def quote(value):
    return json.dumps(value) if re.search(r'[\s"]', value) else value


def sync_commands(shards, upstream, limit):
    """Commands that turn the shards into a mirror of upstream, touching only
    the entries that differ. shards: [(group_id, entries)] in shard order.
    Returns (commands, overflow) — overflow counts entries that found no room.
    # ponytail: never allocates a shard; port reshard() from keendns.html if
    # russia-inside outgrows its last one.
    """
    want = set(upstream)
    current = set()
    cmds = []
    room = []
    for gid, entries in shards:
        for e in entries:
            if e not in want:
                cmds.append("no object-group fqdn {} include {}".format(quote(gid), quote(e)))
        current.update(entries)
        room.append([gid, sum(1 for e in entries if e in want)])
    overflow = 0
    for e in upstream:
        if e in current:
            continue
        for slot in room:
            if slot[1] < limit:
                cmds.append("object-group fqdn {} include {}".format(quote(slot[0]), quote(e)))
                slot[1] += 1
                break
        else:
            overflow += 1
    return cmds, overflow


def read_groups(router):
    """{base: [(group_id, entries)]} — shards folded under their list, in order,
    the same way loadState/groupLists do it in keendns.html."""
    body = json.loads(router.rci([{"show": {"rc": {"object-group": {}}}}]))
    fqdn = ((body[0].get("show") or {}).get("rc") or {}).get("object-group") or {}
    fqdn = fqdn.get("fqdn") or {}
    groups = {}
    for gid, g in fqdn.items():
        label = g.get("description") or gid
        include = g.get("include") or []
        include = include if isinstance(include, list) else [include]
        entries = [e if isinstance(e, str) else (e or {}).get("address") for e in include]
        m = SHARD_RE.match(label)
        base, index = (m.group(1), int(m.group(2))) if m else (label, 1)
        groups.setdefault(base, []).append((index, gid, [e for e in entries if e]))
    return {base: [(gid, entries) for _, gid, entries in sorted(shards)]
            for base, shards in groups.items()}


class Sync:
    """Lists mirrored from allow-domains: which list follows which preset, and
    how the last run went. Lives in a small JSON file so it survives restarts."""

    def __init__(self, router, path):
        self.router = router
        self.path = path

    def load(self):
        try:
            with open(self.path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return {}

    def save(self, data):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=1)
        os.replace(tmp, self.path)

    def set(self, base, preset, was=None):
        """preset=None forgets the list; `was` carries a renamed list over."""
        data = self.load()
        if was and was != base and was in data:
            data[base] = data.pop(was)
        if preset:
            preset_paths(preset)  # KeyError for a preset that does not exist
            entry = data.setdefault(base, {"last": None, "result": None})
            entry["preset"] = preset
        else:
            data.pop(base, None)
        self.save(data)
        log("sync: {} {}".format(base, "→ " + preset if preset else "forgotten"))
        return data

    def run(self, only=None):
        """Bring every mirrored list (or just `only`) up to date. Returns
        {base: result text}; the same text lands in the state file."""
        data = self.load()
        bases = [only] if only else list(data)
        results = {}
        groups = read_groups(self.router)
        for base in bases:
            entry = data.get(base)
            if not entry:
                results[base] = "не синхронизируется"
                continue
            shards = groups.get(base)
            if not shards:
                log("sync {}: list gone, forgotten".format(base))
                data.pop(base)
                continue
            try:
                upstream = fetch_preset(entry["preset"])
                cmds, overflow = sync_commands(shards, upstream, LIMIT)
                if cmds:
                    for command in cmds:
                        log("→ " + command)
                    payload = [{"parse": c} for c in cmds]
                    payload.append({"system": {"configuration": {"save": {}}}})
                    body = self.router.rci(payload)
                    for status in describe_statuses(body):
                        log("← " + status)
                    errors = status_errors(body)
                    if errors:
                        raise RuntimeError(" | ".join(errors[:3]))
                added = sum(1 for c in cmds if not c.startswith("no "))
                result = "+{} −{}".format(added, len(cmds) - added)
                if overflow:
                    result += ", не влезло {} — открой список и сохрани его заново".format(overflow)
            except Exception as exc:  # network, GitHub, router — all end up in the row's tooltip
                result = "ошибка: {}".format(exc)
            log("sync {}: {}".format(base, result))
            entry["last"] = time.strftime("%Y-%m-%d %H:%M")
            entry["result"] = result
            results[base] = result
        self.save(data)
        return results

    def schedule(self, hour):
        """Run every day at hour:00 local time, forever, from a daemon thread."""
        def loop():
            while True:
                now = datetime.datetime.now()
                at = now.replace(hour=hour, minute=0, second=0, microsecond=0)
                if at <= now:
                    at += datetime.timedelta(days=1)
                log("sync: next run at {}".format(at.strftime("%Y-%m-%d %H:%M")))
                time.sleep(max(1, (at - datetime.datetime.now()).total_seconds()))
                try:
                    if self.load():
                        self.run()
                except Exception as exc:
                    log("!! sync: {}".format(exc))
        threading.Thread(target=loop, daemon=True).start()


def selftest():
    assert normalize("wdfiles.com \n\n.ua\nyoutube.com\nyoutube.com\n*.x.com\n# note\na b\n") == \
        ["wdfiles.com", "ua", "youtube.com", "x.com"]
    assert quote("a b") == '"a b"' and quote("a.b") == "a.b"
    shards = [("d0", ["a", "b"]), ("d1", ["c"])]
    assert sync_commands(shards, ["a", "b", "c"], 2) == ([], 0)
    assert sync_commands(shards, ["a", "b", "c", "z"], 2) == (["object-group fqdn d1 include z"], 0)
    assert sync_commands(shards, ["a", "c"], 2) == (["no object-group fqdn d0 include b"], 0)
    # a removal frees its slot before additions are placed
    assert sync_commands(shards, ["a", "z", "c", "y"], 2) == (
        ["no object-group fqdn d0 include b", "object-group fqdn d0 include z",
         "object-group fqdn d1 include y"], 0)
    assert sync_commands([("d0", ["a", "b"])], ["a", "b", "c", "d"], 2) == ([], 2)
    assert preset_paths("telegram") == ["Services/telegram.lst", "Subnets/IPv4/telegram.lst"]
    assert preset_catalog()["Сервисы"]["telegram"] == "telegram (домены + подсети)"
    assert preset_catalog()["Сервисы"]["youtube"] == "youtube"
    assert preset_catalog()["Сервисы"]["hetzner"] == "hetzner (подсети)"
    # a long list is split into RCI_CHUNK-sized POSTs and the replies are joined back
    router, seen = Router("h", "u", "p"), []
    router._post = lambda p: (seen.append(len(p)), json.dumps([{"i": i} for i in p]))[1].encode()
    n = RCI_CHUNK * 2 + 1
    assert json.loads(router.rci(list(range(n)))) == [{"i": i} for i in range(n)]
    assert seen == [RCI_CHUNK, RCI_CHUNK, 1]
    assert json.loads(router.rci([1, 2])) == [{"i": 1}, {"i": 2}]
    print("selftest ok")


class Handler(http.server.BaseHTTPRequestHandler):
    router = None
    sync = None
    protocol_version = "HTTP/1.1"

    def _send(self, status, body, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status, obj):
        self._send(status, json.dumps(obj, ensure_ascii=False).encode(), "application/json")

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(length) or b"null")

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/api/presets":
            return self._json(200, preset_catalog())
        if path.startswith("/api/presets/"):
            name = urllib.parse.unquote(path[len("/api/presets/"):])
            try:
                return self._json(200, {"entries": fetch_preset(name)})
            except KeyError as exc:
                return self._json(404, {"error": exc.args[0]})
            except Exception as exc:  # GitHub unreachable, HTTP error
                return self._json(502, {"error": str(exc)})
        if path == "/api/sync":
            return self._json(200, self.sync.load())
        if path not in ("/", "/keendns.html"):
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
        if self.path not in ("/api/rci", "/api/sync", "/api/sync/run"):
            self.send_error(404)
            return
        try:
            payload = self._body()
        except ValueError as exc:
            return self._json(400, {"error": str(exc)})
        if self.path == "/api/sync":
            try:
                return self._json(200, self.sync.set(payload["base"], payload.get("preset"),
                                                     payload.get("was")))
            except (KeyError, TypeError) as exc:
                return self._json(400, {"error": exc.args[0] if exc.args else str(exc)})
        if self.path == "/api/sync/run":
            try:
                return self._json(200, self.sync.run((payload or {}).get("base")))
            except Exception as exc:  # router unreachable
                log("!! sync: {}".format(exc))
                return self._json(502, {"error": str(exc)})
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
    parser.add_argument("--state", metavar="FILE",
                        default=os.environ.get("KEENDNS_STATE", os.path.join(HERE, "keendns-sync.json")),
                        help="where lists mirrored from allow-domains are remembered (default: %(default)s)")
    parser.add_argument("--sync-hour", type=int, default=int(os.environ.get("KEENDNS_SYNC_HOUR", "4")),
                        help="local hour of the nightly allow-domains sync (default: %(default)s)")
    parser.add_argument("--selftest", action="store_true", help="run the built-in checks and exit")
    args = parser.parse_args()

    if args.selftest:
        selftest()
        return

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
            print("Authenticated on {}".format(host))
            break
        except RuntimeError as err:
            print(err)
            if env_password or attempt == 2:
                sys.exit("Could not log in.")
        except OSError as err:
            if env_password:
                # Typically a container. The router may be rebooting or may have
                # banned this host for 15 minutes; exiting would only turn that
                # into a restart loop. rci() logs in on demand anyway.
                print("Cannot reach {}: {} — serving anyway, will log in on the first request"
                      .format(host, err))
                break
            sys.exit("Cannot reach {}: {}".format(host, err))

    Handler.router = router
    Handler.sync = Sync(router, args.state)
    Handler.sync.schedule(args.sync_hour)
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
