#!/usr/bin/env python3
"""Remote reboot for Huawei HG8245H via its web API.

The script auto-detects the firmware generation:

Modern firmware (/api/ XML interface):
  1. GET  /api/webserver/SesTokenInfo  -> SesInfo cookie + TokInfo token
  2. POST /api/system/user_login       -> session login (password is
     base64-encoded; newer firmware additionally hashes it with the token)
  3. GET  /api/system/deviceinfo       -> confirms the session is valid
  4. POST reboot endpoint (several known variants are tried in turn)

Legacy firmware (classic CGI web UI — answers with an HTML page to /api/):
  1. GET  /asp/GetRandCount.asp                    -> random token
  2. POST /login.cgi  (UserName, PassWord=base64)  -> session cookie sid
  3. GET  /html/ssmp/reset/reset.asp               -> hwonttoken value
  4. POST /html/ssmp/reset/set.cgi?x=InternetGatewayDevice.X_HW_DEBUG.SMP.DM.ResetBoard
     as a single-write raw-socket request (the GoAhead web server hangs on
     multi-segment POSTs), then verifies the web UI actually goes down.

Every request/response is logged: steps and status codes to console,
full bodies and headers to console with -v and always to the log file
(reboot.log next to the script, disable with --no-log-file).
Passwords are masked in all output.

Usage:
  ./reboot_hg8245h.py [-v] [--log-file PATH | --no-log-file]
Credentials come from a .env file next to the script (see .env.example):
  HG8245H_HOST=192.168.100.1
  HG8245H_USER=root
  HG8245H_PASSWORD=secret
CLI flags --host/--user/--password and real environment variables override .env.
"""

import argparse
import base64
import hashlib
import logging
import os
import re
import socket
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import requests

TIMEOUT = 15
DEFAULT_LOG_FILE = Path(__file__).resolve().parent / "reboot.log"

log = logging.getLogger("hg8245h")


def load_env():
    """Load KEY=VALUE pairs from .env (script dir, then CWD).

    Does not override variables already set in the environment.
    """
    for path in (Path(__file__).resolve().parent / ".env", Path.cwd() / ".env"):
        if not path.is_file():
            continue
        for line in path.read_text().splitlines():
            line = line.strip()
            if line.startswith("export "):
                line = line[len("export "):].lstrip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            os.environ.setdefault(key.strip(), value)


def setup_logging(verbose, log_file):
    log.setLevel(logging.DEBUG)
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%H:%M:%S"))
    log.addHandler(console)
    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s"))
        log.addHandler(fh)


def mask(data):
    """Hide password values before logging request data."""
    if isinstance(data, dict):
        return {k: ("***" if "password" in k.lower() else v) for k, v in data.items()}
    return data


def looks_like_error(body):
    """True if the body is an error response or an HTML page (e.g. login redirect)."""
    low = (body or "")[:2000].lower()
    return "<error" in low or "errorcode" in low or "<html" in low or "<!doctype" in low


def page_title(text):
    m = re.search(r"<title>([^<]*)</title>", text or "", re.I)
    return m.group(1).strip() if m else ""


class Router:
    def __init__(self, host, user, password, try_all=False):
        self.base = f"http://{host}"
        self.user = user
        self.password = password
        self.try_all = try_all
        self.s = requests.Session()
        self.s.headers["User-Agent"] = "Mozilla/5.0"
        self.token = None

    # -- plumbing ---------------------------------------------------------

    def get(self, path):
        url = path if path.startswith("http") else self.base + path
        log.info("GET %s", path)
        r = self.s.get(url, timeout=TIMEOUT)
        self._log(r)
        return r

    def post(self, path, data, content_type="application/x-www-form-urlencoded; charset=UTF-8"):
        log.info("POST %s data=%s", path, mask(data))
        r = self.s.post(
            self.base + path,
            data=data,
            headers={"Content-Type": content_type, "Referer": f"{self.base}/html/index.html"},
            timeout=TIMEOUT,
        )
        self._log(r)
        return r

    @staticmethod
    def _log(r):
        log.info("  <- HTTP %s (%d bytes, Content-Type=%s)",
                 r.status_code, len(r.content), r.headers.get("Content-Type"))
        body = (r.text or "").strip()
        log.debug("  <- body: %s", body[:2000] or "(empty)")
        log.debug("  <- headers: %s", dict(r.headers))

    def apply_token(self, r=None):
        """Keep __RequestVerificationToken current.

        Takes the token from the response header or body when present,
        otherwise re-fetches SesTokenInfo.
        """
        source = None
        if r is not None:
            tok = r.headers.get("__RequestVerificationToken")
            if not tok:
                m = re.search(r"<TokInfo>([^<]+)</TokInfo>", r.text or "")
                if m:
                    tok = m.group(1)
            if tok:
                self.token, source = tok, "previous response"
        if not self.token:
            self.fetch_ses_token()
            source = "SesTokenInfo"
        if source:
            log.debug("token from %s: %s...", source, str(self.token)[:16])
        if self.token:
            self.s.headers["__RequestVerificationToken"] = self.token

    def fetch_ses_token(self):
        """Detect the /api/ interface. Returns True when it is available."""
        r = self.get("/api/webserver/SesTokenInfo")
        text = (r.text or "").strip()
        if not text or looks_like_error(text):
            log.warning("/api/ interface not available (%s) — legacy CGI firmware, "
                        "switching to the legacy flow", "HTML page returned" if text else "empty response")
            self.token = None
            return False
        ses, tok = "", ""
        try:
            data = r.json()
            ses, tok = data.get("SesInfo", ""), data.get("TokInfo", "")
        except ValueError:
            try:
                root = ET.fromstring(text)
                ses = root.findtext(".//SesInfo") or ""
                tok = root.findtext(".//TokInfo") or ""
            except ET.ParseError:
                log.warning("cannot parse SesTokenInfo (%r) — treating as legacy firmware", text[:100])
                self.token = None
                return False
        if ses:
            self.s.headers["Cookie"] = ses
        self.token = tok or None
        if not self.token:
            log.warning("SesTokenInfo carried no token — treating as legacy firmware")
        return bool(self.token)

    # -- API steps --------------------------------------------------------

    def login(self):
        self.apply_token()

        pwd_b64 = base64.b64encode(self.password.encode()).decode()
        # Newer firmware: sha256 over base64(password)+token, then base64 again.
        pwd_hash = base64.b64encode(
            hashlib.sha256((pwd_b64 + self.token).encode()).hexdigest().encode()
        ).decode()

        last_response = "(none)"
        for variant, pwd in (("hashed", pwd_hash), ("base64", pwd_b64)):
            r = self.post(
                "/api/system/user_login",
                {"username": self.user, "password": pwd, "x.X_HW_Token": self.token},
            )
            if r.status_code == 200 and not looks_like_error(r.text):
                # Confirm the session really works: deviceinfo must return
                # data, not a login page.
                info = self.get("/api/system/deviceinfo")
                if info.status_code == 200 and (info.text or "").strip() and not looks_like_error(info.text):
                    log.info("login OK (%s password variant)", variant)
                    self.apply_token(info)
                    return
                log.warning("login with %s variant accepted, but deviceinfo check failed — treating as failed login", variant)
                last_response = (info.text or "")[:300]
            else:
                last_response = (r.text or "")[:300]
            # Fresh token for the next attempt.
            self.apply_token()

        raise RuntimeError(f"login failed (wrong credentials or unsupported firmware); last response: {last_response!r}")

    def reboot(self):
        candidates = [
            ("/api/system/reboot", '<?xml version="1.0" encoding="UTF-8"?><request><Reboot>1</Reboot></request>', "text/xml"),
            ("/api/system/deviceinfo", '<?xml version="1.0" encoding="UTF-8"?><request><Restart/></request>', "text/xml"),
        ]
        results = []
        for i, (path, data, content_type) in enumerate(candidates):
            r = self.post(path, data, content_type)
            if r.status_code in (200, 204) and not looks_like_error(r.text):
                log.info("reboot command accepted (endpoint %s)", path)
                return
            results.append(f"{path}: HTTP {r.status_code} {(r.text or '')[:200]!r}")
            if i < len(candidates) - 1:
                # The failed attempt consumed the token; get a fresh one.
                self.apply_token()
        raise RuntimeError("no reboot endpoint accepted the command — details: " + " | ".join(results))

    def discover_login(self):
        """Find the login page, parse its form and dump its auth scripts.

        Returns (page_path, action_url_or_None, [(field, type, value), ...]);
        (None, None, None) when nothing was recognised. A form without an
        action attribute (submitted by JS) yields action=None.
        """
        for path in ("/", "/index.html", "/html/index.html"):
            r = self.get(path)
            text = r.text or ""
            if "password" in text.lower():
                self.dump_page_scripts(path, text)
            fields = None
            action = None
            for chunk in re.split(r"</form>", text, flags=re.I):
                if "password" not in chunk.lower():
                    continue
                mform = re.search(r"<form[^>]*>", chunk, re.I)
                if not mform:
                    continue
                maction = re.search(r"\baction=[\"']([^\"']+)[\"']", mform.group(0), re.I)
                action = urljoin(self.base + path, maction.group(1)) if maction else None
                fields = []
                for tag in re.findall(r"<input[^>]*>", chunk, re.I):
                    name = re.search(r"name=[\"']([^\"']+)[\"']", tag, re.I)
                    if not name:
                        continue
                    type_ = re.search(r"type=[\"']([^\"']+)[\"']", tag, re.I)
                    value = re.search(r"value=[\"']([^\"']*)[\"']", tag, re.I)
                    fields.append((name.group(1),
                                   type_.group(1).lower() if type_ else "text",
                                   value.group(1) if value else ""))
                log.info("login form on %s (title=%r): action=%s, fields=%s",
                         path, page_title(text), action or "(set by JS)",
                         [(n, t) for n, t, _ in fields])
                break
            if fields is None:
                log.info("%s: no login form (title=%r, %d bytes)", path, page_title(text), len(r.content))
                continue
            return path, action, fields
        return None, None, None

    def dump_page_scripts(self, path, text):
        """Fetch the login page's auth-related scripts and log them.

        The exact password-hashing algorithm of the firmware lives in these
        files (safelogin.js / RndSecurityFormat.js / md5.js).
        """
        for src in re.findall(r"<script[^>]*src=[\"']([^\"']+)[\"']", text, re.I)[:6]:
            if "jquery" in src.lower():
                continue
            url = urljoin(self.base + path, src)
            try:
                r = self.get(url)
            except requests.RequestException as e:
                log.debug("script %s: %s", src, e)
                continue
            body = (r.text or "").strip()
            log.debug("script %s -> %d bytes:\n%s", src, len(r.content), body[:4000])

    def legacy_reboot(self):
        """Reboot via the classic CGI web UI (firmware without /api/)."""
        # 1. Random token. The body starts with a UTF-8 BOM; strip it on the
        # byte level — r.text may decode it as latin-1 and garble it.
        r = self.get("/asp/GetRandCount.asp")
        raw = r.content.strip()
        if raw.startswith(b"\xef\xbb\xbf"):
            raw = raw[3:]
        rand = raw.decode("utf-8", "replace").strip()
        if not rand or looks_like_error(r.text):
            raise RuntimeError(
                f"no random token from GetRandCount.asp: HTTP {r.status_code} {(r.text or '')[:120]!r}")
        log.debug("random token: %s", rand)

        # 2. Find the login page, then log in. The classic scheme posts
        # base64(password); some firmwares want a sha256 variant or plain.
        # Firmware quirk (verified on MGTS HG8245H): the web UI sets a cookie
        # NAMED "Cookie" with the value "body:Language:english:id=-1", so the
        # header must be "Cookie: Cookie=body:Language:english:id=-1".
        pwd = self.password
        pwd_b64 = base64.b64encode(pwd.encode()).decode()
        md5_pwd = hashlib.md5(pwd.encode()).hexdigest()
        variants = [
            ("base64", pwd_b64),
            ("md5(md5(pwd)+rand)", hashlib.md5((md5_pwd + rand).encode()).hexdigest()),
            ("md5(rand+md5(pwd))", hashlib.md5((rand + md5_pwd).encode()).hexdigest()),
            ("sha256", base64.b64encode(
                hashlib.sha256((pwd_b64 + rand).encode()).hexdigest().encode()).decode()),
            ("plain", pwd),
        ]
        if not self.try_all:
            variants = variants[:3]

        page, action, fields = self.discover_login()
        if action:
            pass
        elif fields:
            log.warning("login form has no action (JS-submitted) — posting to /login.cgi")
            action = self.base + "/login.cgi"
        else:
            log.warning("no login form found — falling back to POST /login.cgi with UserName/PassWord")
            action = self.base + "/login.cgi"
            fields = None
            page = page or "/"

        sid = None
        for variant, pwd in variants:
            if fields is not None:
                data = {}
                for fname, ftype, fvalue in fields:
                    low = fname.lower()
                    if ftype == "password" or "pass" in low:
                        data[fname] = pwd
                    elif "user" in low:
                        data[fname] = self.user
                    elif "token" in low:
                        data[fname] = fvalue or rand
                    else:
                        data[fname] = fvalue
            else:
                data = {"UserName": self.user, "PassWord": pwd, "x.X_HW_Token": rand}
            log.info("POST %s data=%s (password variant: %s)", action, mask(data), variant)
            r = self.s.post(
                action,
                data=data,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Referer": self.base + page,
                    # Cookie named "Cookie" (see comment above).
                    "Cookie": "Cookie=body:Language:english:id=-1",
                },
                timeout=TIMEOUT,
            )
            self._log(r)
            # The session cookie is set in quirky ways across firmwares:
            # either a cookie named "sid", or (MGTS) a cookie named "Cookie"
            # whose VALUE is "sid=<hash>:Language:english:id=1".
            sid = next((c.value for c in self.s.cookies
                        if "sid=" in (c.name + "=" + c.value).lower()), None)
            if sid:
                log.info("login OK (%s password variant)", variant)
                break
            log.warning("no sid cookie after the %s attempt — wrong password looks the same; "
                        "repeated failures can temporarily lock the account", variant)
        if not sid:
            raise RuntimeError(
                f"legacy login failed on {action}: no sid cookie after {len(variants)} password "
                "variants — wrong credentials, or an uncommon encoding (rerun with --try-all; "
                "note the web UI locks login for ~60 s after ~3 failures). "
                "The auth scripts were dumped to the log — send it for analysis")

        # 3. The reset page carries a per-session hwonttoken.
        r = self.get("/html/ssmp/reset/reset.asp")
        m = (re.search(r'hwonttoken[^>]*value="([^"]+)"', r.text or "", re.I)
             or re.search(r'value="([^"]+)"[^>]*hwonttoken', r.text or "", re.I))
        if not m:
            raise RuntimeError(
                f"no hwonttoken on reset page (session not accepted? title={page_title(r.text)!r}) — "
                f"response: {(r.text or '')[:200]!r}")
        log.debug("hw token: %s", m.group(1))

        # 4. Fire the reboot command over a raw socket, in a SINGLE write.
        # The ONT's GoAhead web server hangs on POSTs that arrive split
        # across TCP segments — and requests/urllib3 send headers and body
        # separately — so the browser-exact request is assembled manually
        # and written with one sendall(). On success the router resets
        # before answering, typically returning nothing at all.
        cookie_header = None
        for c in self.s.cookies:
            if "sid=" in (c.name + "=" + c.value).lower():
                cookie_header = f"{c.name}={c.value}"
                break
        if not cookie_header:
            raise RuntimeError("no session cookie found after login")

        u = urlsplit(self.base)
        hostname, port = u.hostname, u.port or 80
        path = ("/html/ssmp/reset/set.cgi?x=InternetGatewayDevice.X_HW_DEBUG.SMP.DM.ResetBoard"
                "&RequestFile=html/ssmp/reset/reset.asp")
        body = f"x.X_HW_Token={m.group(1)}"
        req = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {hostname}\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            f"Referer: {self.base}/html/ssmp/reset/reset.asp\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            f"Cookie: {cookie_header}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
            f"{body}"
        ).encode()
        log.info("POST %s (single-write raw socket)", path)
        try:
            sk = socket.create_connection((hostname, port), timeout=10)
        except OSError as e:
            raise RuntimeError(f"cannot connect to {hostname}:{port}: {e}")
        try:
            sk.sendall(req)
            sk.settimeout(5)
            try:
                resp = sk.recv(4096)
                log.info("  <- %r", resp[:120])
            except socket.timeout:
                log.info("  <- no response (router already resetting)")
        except OSError as e:
            log.warning("connection error after send (the command may still have been accepted): %s", e)
        finally:
            sk.close()

        # The response alone proves nothing on this firmware — the only
        # reliable success signal is the web UI actually going down.
        log.info("verifying: waiting up to 25 s for the web UI to go down...")
        deadline = time.time() + 25
        while time.time() < deadline:
            try:
                requests.get(self.base + "/asp/GetRandCount.asp", timeout=2)
            except requests.RequestException:
                log.info("SUCCESS — the router is rebooting (web UI went down)")
                return
            time.sleep(1)
        raise RuntimeError(
            "the reboot command did not take effect: the router still responds. "
            "The token may have expired or the firmware rejected the command — "
            "see the log (rerun with -v)")


def main():
    load_env()
    p = argparse.ArgumentParser(description="Reboot Huawei HG8245H router")
    p.add_argument("--host", default=os.environ.get("HG8245H_HOST", "192.168.100.1"))
    p.add_argument("--user", default=os.environ.get("HG8245H_USER", "root"))
    p.add_argument("--password", default=os.environ.get("HG8245H_PASSWORD", "admin"))
    p.add_argument("-v", "--verbose", action="store_true",
                   help="full debug output to console (bodies, headers)")
    p.add_argument("--try-all", action="store_true",
                   help="try every known password encoding (up to 5 login attempts "
                        "instead of 3; the web UI may lock login for ~60 s)")
    p.add_argument("--log-file", default=str(DEFAULT_LOG_FILE),
                   help=f"log file (default: {DEFAULT_LOG_FILE})")
    p.add_argument("--no-log-file", action="store_true", help="disable the log file")
    args = p.parse_args()

    setup_logging(args.verbose, None if args.no_log_file else args.log_file)
    log.info("target http://%s as user %r", args.host, args.user)

    router = Router(args.host, args.user, args.password, try_all=args.try_all)
    try:
        if router.fetch_ses_token():
            router.login()
            router.reboot()
        else:
            router.legacy_reboot()
    except (requests.RequestException, RuntimeError, ValueError) as e:
        log.error("FAILED: %s", e)
        return 1

    log.info("Reboot command sent to %s. Router will be back in ~1-2 minutes.", args.host)
    return 0


if __name__ == "__main__":
    sys.exit(main())
