"""
jwt_attacks — discover and attack JSON Web Tokens.

Finds JWTs in cookies, the Authorization header echo, and page/JS source, then checks the
classic weaknesses a red team exploits to forge a valid token:

  * **alg:none** — the token is unsigned (an attacker can rewrite any claim).        → CRITICAL
  * **weak HMAC secret** — the HS256/384/512 signing key is a common/guessable string
    (cracked offline against a wordlist); with it, an attacker mints admin tokens.    → CRITICAL
  * **sensitive claims / no expiry** — roles, emails, missing `exp`.                  → INFO/LOW

Signature cracking is done locally (HMAC compute, no extra requests). Tokens are redacted.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re

import httpx
from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine

MODULE = "jwt_attacks"

# header.payload.signature — signature may be empty (alg:none).
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{6,}\.eyJ[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{0,}")

# Common weak signing secrets to try (offline HMAC crack).
_SECRET_WORDLIST = [
    "secret", "password", "123456", "jwt", "changeme", "key", "admin", "test", "secretkey",
    "your-256-bit-secret", "your_jwt_secret", "jwtsecret", "supersecret", "s3cr3t", "private",
    "token", "mysecret", "qwerty", "letmein", "default", "passw0rd", "jwt_secret", "shhhh",
    "secret123", "0", "1234567890", "HS256", "JWTSecretKey",
]

_HASHES = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _redact(token: str) -> str:
    return f"{token[:12]}…{token[-6:]}" if len(token) > 24 else token


def _decode_part(seg: str) -> dict:
    try:
        return json.loads(_b64url_decode(seg))
    except Exception:  # noqa: BLE001
        return {}


# ---------------------------------------------------------------------------
# Token collection
# ---------------------------------------------------------------------------

def _collect_tokens(engine: ScanEngine) -> list[str]:
    blobs: list[str] = []
    try:
        resp = engine.get()
        blobs.append("; ".join(f"{k}={v}" for k, v in resp.cookies.items()))
        blobs.append(resp.text[:200_000])
    except httpx.HTTPError:
        pass
    if engine.cookies:
        blobs.append(engine.cookies)
    if engine.auth_token:
        blobs.append(engine.auth_token)
    try:
        blobs.extend(engine.get_crawl().pages.values())
    except Exception:  # noqa: BLE001
        pass

    tokens: list[str] = []
    seen: set[str] = set()
    for blob in blobs:
        for tok in _JWT_RE.findall(blob or ""):
            if tok not in seen:
                seen.add(tok)
                tokens.append(tok)
    return tokens


# ---------------------------------------------------------------------------
# Attacks
# ---------------------------------------------------------------------------

def _crack_hmac(token: str, alg: str) -> str | None:
    """Return the signing secret if it is in the wordlist, else None."""
    hashfn = _HASHES.get(alg.upper())
    if hashfn is None:
        return None
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError:
        return None
    signing_input = f"{header_b64}.{payload_b64}".encode()
    for secret in _SECRET_WORDLIST:
        digest = hmac.new(secret.encode(), signing_input, hashfn).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        if hmac.compare_digest(expected, sig_b64):
            return secret
    return None


def _analyse(token: str) -> list[Finding]:
    header = _decode_part(token.split(".")[0])
    payload = _decode_part(token.split(".")[1]) if token.count(".") >= 1 else {}
    alg = str(header.get("alg", "")).upper()
    findings: list[Finding] = []

    if alg == "NONE":
        findings.append(Finding(
            module=MODULE, title="JWT Accepts 'alg:none' — Unsigned Token",
            description=(
                f"A JWT using the 'none' algorithm was found ({_redact(token)}). Unsigned tokens "
                "let an attacker rewrite any claim (e.g. become admin) with no signature."
            ),
            severity=Severity.CRITICAL,
            recommendation="Reject the 'none' algorithm; pin the expected algorithm server-side.",
            raw={"token": _redact(token), "alg": "none", "claims": payload, "confidence": "high",
                 "attack": "T1606.001 Web Session Cookie / Forge Web Credentials",
                 "exploitation": [
                     {"step": 1, "description": "Forge an unsigned token to bypass signature checks.",
                      "command": "jwt_tool <token> -X a"},
                     {"step": 2, "description": "Tamper a claim (e.g. become admin) and re-issue it.",
                      "command": "jwt_tool <token> -X a -I -pc role -pv admin"}]},
        ))

    if alg in _HASHES:
        secret = _crack_hmac(token, alg)
        if secret is not None:
            findings.append(Finding(
                module=MODULE, title=f"JWT Signed with a Weak Secret ('{secret}')",
                description=(
                    f"The {alg} signing secret of a JWT is the guessable value '{secret}'. "
                    "An attacker who knows it can forge arbitrary valid tokens (full account "
                    "takeover / privilege escalation)."
                ),
                severity=Severity.CRITICAL,
                recommendation=("Use a long, random, high-entropy signing key stored as a secret; "
                                "rotate the current key immediately."),
                raw={"token": _redact(token), "alg": alg, "secret": secret, "claims": payload,
                     "confidence": "high", "attack": "T1552 Unsecured Credentials",
                     "exploitation": [
                         {"step": 1, "description": f"Mint an admin token signed with the cracked secret '{secret}'.",
                          "command": f'jwt_tool <token> -S {alg.lower()} -p "{secret}" -I -pc role -pv admin'},
                         {"step": 2, "description": "Or brute-force/confirm the secret with a wordlist.",
                          "command": "jwt_tool <token> -C -d rockyou.txt"}]},
            ))

    # Informational: claims & expiry posture.
    notes = []
    if any(k in payload for k in ("role", "roles", "admin", "is_admin", "scope", "permissions")):
        notes.append("carries authorization claims")
    if "exp" not in payload:
        notes.append("has no expiry (exp)")
    if notes and not findings:  # only if not already escalated
        findings.append(Finding(
            module=MODULE, title="JWT Claims Exposed (client-readable)",
            description=(
                f"A JWT readable from the client ({_redact(token)}) " + " and ".join(notes)
                + ". JWT payloads are not encrypted — never store secrets in them."
            ),
            severity=Severity.LOW,
            recommendation="Minimise claims, set a short `exp`, and never trust client-held tokens.",
            raw={"token": _redact(token), "alg": alg, "claims": payload, "confidence": "medium",
                 "attack": "T1552 Unsecured Credentials"},
        ))
    return findings


def run(engine: ScanEngine) -> list[Finding]:
    tokens = _collect_tokens(engine)
    if not tokens:
        return []
    findings: list[Finding] = []
    for tok in tokens[:20]:
        try:
            findings.extend(_analyse(tok))
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"jwt_attacks: token analysis failed: {exc}")
    _order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: _order.get(f.severity.value, 9))
    logger.info(f"jwt_attacks: {len(tokens)} token(s), {len(findings)} finding(s)")
    return findings
