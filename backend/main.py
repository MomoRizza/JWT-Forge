"""
main.py — JWT Forge backend.

Design rule (per the brief): the browser holds all state and builds every
request; the backend only performs work the browser can't:
  - crypto signing / attack generation
  - relaying the final crafted HTTP request to the target (no browser CORS,
    no history kept server-side)
Nothing is persisted. Every response is computed and forgotten.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Optional

import requests
import urllib3
from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

import attacks
import jwt_core as jc
import reqparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

STATIC = Path(__file__).parent / "static"
app = FastAPI(title="JWT Forge", docs_url=None, redoc_url=None)


def _err(e: Exception, code: int = 400):
    return JSONResponse(status_code=code, content={"error": str(e)})


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class TokenIn(BaseModel):
    token: str


class SignIn(BaseModel):
    header: dict
    payload: Any
    signing: dict            # see jwt_core.encode_token


class AttacksIn(BaseModel):
    token: str
    claims: Optional[dict] = None
    public_key: Optional[str] = None
    attacker_url: Optional[str] = None


class CraftIn(BaseModel):
    token: str
    mode: str                     # jwk | x5c | jku | x5u
    url: Optional[str] = None
    claims: Optional[dict] = None
    private_key: Optional[str] = None
    alg: str = "RS256"


class CrackIn(BaseModel):
    token: str
    wordlist: list[str]


class VerifyIn(BaseModel):
    token: str
    public_key: Optional[str] = None
    secret: Optional[str] = None


class KeygenIn(BaseModel):
    type: str = "rsa"        # "rsa" | "ec"
    bits: int = 2048
    curve: str = "P-256"


class ParseIn(BaseModel):
    raw: str


class SendIn(BaseModel):
    method: str = "GET"
    url: str
    headers: dict[str, str] = {}
    body: str = ""
    insecure: bool = True         # labs & self-hosted targets often use bad certs
    follow_redirects: bool = False
    timeout: float = 20.0


# ---------------------------------------------------------------------------
# Crypto / attack endpoints
# ---------------------------------------------------------------------------

@app.post("/api/decode")
def decode(body: TokenIn):
    try:
        return jc.decode_token(body.token).to_dict()
    except Exception as e:
        return _err(e)


@app.post("/api/sign")
def sign(body: SignIn):
    try:
        return {"token": jc.encode_token(body.header, body.payload, body.signing)}
    except Exception as e:
        return _err(e)


@app.post("/api/attacks")
def gen_attacks(body: AttacksIn):
    try:
        return attacks.generate(body.token, claims=body.claims,
                                public_key=body.public_key,
                                attacker_url=body.attacker_url)
    except Exception as e:
        return _err(e)


@app.post("/api/craft")
def craft(body: CraftIn):
    try:
        return attacks.craft_key_injection(
            body.token, body.mode, url=body.url, claims=body.claims,
            private_key=body.private_key, alg=body.alg)
    except Exception as e:
        return _err(e)


@app.post("/api/crack")
def crack(body: CrackIn):
    try:
        return jc.crack_hmac(body.token, body.wordlist)
    except Exception as e:
        return _err(e)


@app.post("/api/verify")
def verify(body: VerifyIn):
    try:
        if body.public_key:
            return jc.verify_rsa_ec(body.token, body.public_key)
        if body.secret is not None:
            dec = jc.decode_token(body.token)
            alg = dec.header.get("alg", "")
            ok = jc.verify_hmac(dec.signing_input, dec.signature_b64,
                                body.secret.encode(), alg)
            return {"valid": ok, "alg": alg}
        raise ValueError("Provide either public_key or secret.")
    except Exception as e:
        return _err(e)


@app.post("/api/keygen")
def keygen(body: KeygenIn):
    try:
        if body.type == "ec":
            return jc.generate_ec(body.curve)
        return jc.generate_rsa(body.bits)
    except Exception as e:
        return _err(e)


@app.post("/api/parse")
def parse(body: ParseIn):
    try:
        return reqparse.parse_raw_request(body.raw)
    except Exception as e:
        return _err(e)


# ---------------------------------------------------------------------------
# The relay — actually performs the attack against the target
# ---------------------------------------------------------------------------

@app.post("/api/send")
def send(body: SendIn):
    try:
        t0 = time.perf_counter()
        resp = requests.request(
            method=body.method.upper(),
            url=body.url,
            headers=body.headers or None,
            data=body.body.encode("utf-8") if body.body else None,
            verify=not body.insecure,
            allow_redirects=body.follow_redirects,
            timeout=body.timeout,
        )
        elapsed = round((time.perf_counter() - t0) * 1000)
        text = resp.text
        truncated = False
        if len(text) > 200_000:            # keep the UI responsive
            text = text[:200_000]
            truncated = True
        return {
            "status": resp.status_code,
            "reason": resp.reason,
            "elapsed_ms": elapsed,
            "length": len(resp.content),
            "headers": dict(resp.headers),
            "body": text,
            "truncated": truncated,
            "final_url": resp.url,
        }
    except requests.exceptions.SSLError as e:
        return _err(f"TLS error (try enabling 'Ignore TLS'): {e}")
    except requests.exceptions.RequestException as e:
        return _err(f"Request failed: {e}")
    except Exception as e:
        return _err(e)


# ---------------------------------------------------------------------------
# Static UI
# ---------------------------------------------------------------------------

@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")
