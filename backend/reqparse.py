"""
reqparse.py — pull a JWT and a ready-to-replay target out of a raw HTTP request.

Paste a request straight from Burp / the browser devtools and this figures out
the method, URL, headers, body, and where the JWT lives (Authorization header,
a cookie, or the body) so the token can be swapped and the request replayed.
"""

from __future__ import annotations

import re
from typing import Optional

# eyJ... . ... . ...   (third segment may be empty for alg:none)
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def find_jwts(text: str) -> list[str]:
    seen, out = set(), []
    for m in JWT_RE.finditer(text or ""):
        t = m.group(0)
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def parse_raw_request(raw: str) -> dict:
    raw = raw.replace("\r\n", "\n").strip("\n")
    if not raw:
        raise ValueError("Empty request.")

    head, _, body = raw.partition("\n\n")
    lines = head.split("\n")

    request_line = lines[0].split()
    if len(request_line) < 2:
        raise ValueError("First line is not a valid request line (need 'METHOD path').")
    method = request_line[0].upper()
    path = request_line[1]

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()

    host = headers.get("Host", "")
    # scheme guess: :80 => http, otherwise https (the common pentest default)
    scheme = "http" if host.endswith(":80") else "https"
    if path.startswith("http://") or path.startswith("https://"):
        url = path
    else:
        url = f"{scheme}://{host}{path}"

    # where does the token live?
    token, location = None, None
    auth = headers.get("Authorization", "")
    for t in find_jwts(auth):
        token, location = t, "authorization"; break
    if not token:
        cookie = headers.get("Cookie", "")
        for t in find_jwts(cookie):
            token, location = t, "cookie"
            m = re.search(r"(\w+)=" + re.escape(t), cookie)
            location = f"cookie:{m.group(1)}" if m else "cookie"
            break
    if not token and body:
        for t in find_jwts(body):
            token, location = t, "body"; break

    return {
        "method": method,
        "url": url,
        "headers": headers,
        "body": body or "",
        "token": token,
        "token_location": location,
    }
