"""
wellknown — audit a site's ``.well-known`` posture beyond security.txt (RFC 8615 registry).

``security_txt`` already covers RFC 9116. This sibling module probes three other standardised
``.well-known`` resources that tell a pentester something useful about a target — detection / recon
only, no exploitation:

* **change-password** (``/.well-known/change-password``) — a well-known URL that SHOULD redirect to
  the account password-change page so password managers can deep-link it. Its presence is a small
  maturity signal (INFO).
* **mta-sts.txt** (``/.well-known/mta-sts.txt``, RFC 8461) — the site's SMTP MTA-STS policy. A
  policy in ``mode: enforce`` requires TLS for inbound mail; ``testing`` / ``none`` (or a malformed
  policy) means TLS is not actually enforced, so mail can still be delivered in cleartext or via a
  downgrade — reported LOW.
* **openid-configuration** (``/.well-known/openid-configuration``) — the OpenID Connect discovery
  document. Surfaced as recon (issuer + endpoints, INFO); if it advertises the ``none`` signing
  algorithm for ID tokens the IdP may accept **unsigned** tokens, which is a real auth weakness
  (MEDIUM, verified from the published document).

Each resource emits a finding only when it is actually present, so a site without them is not
flooded with INFO noise. All fetches go through the engine, so scope / rate-limit / auth apply.
"""
from __future__ import annotations

import json
from typing import Any

import httpx
from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine

MODULE = "wellknown"

_CHANGE_PASSWORD_PATH = "/.well-known/change-password"
_MTA_STS_PATH = "/.well-known/mta-sts.txt"
_OIDC_PATH = "/.well-known/openid-configuration"


def _fetch(engine: ScanEngine, path: str) -> "httpx.Response | None":
    try:
        return engine.get(path)
    except httpx.HTTPError as exc:
        logger.debug(f"wellknown: {path} → {exc}")
        return None


def _looks_like_html(text: str) -> bool:
    head = text[:256].lstrip().lower()
    return head.startswith("<!doctype") or head.startswith("<html") or "<head" in head


# ---------------------------------------------------------------------------
# change-password
# ---------------------------------------------------------------------------

def _change_password(engine: ScanEngine) -> list[Finding]:
    resp = _fetch(engine, _CHANGE_PASSWORD_PATH)
    if resp is None:
        return []
    # A valid change-password URL answers with a redirect (3xx) to the real page, or a 200 page.
    # Engine redirects are followed, so treat a final 200/2xx or a 3xx as "published".
    if resp.status_code >= 400:
        return []
    return [Finding(
        MODULE, "Well-Known change-password URL Published",
        "The site serves /.well-known/change-password, the standard deep-link password managers "
        "use to send users straight to the password-change page. This is a small account-security "
        "maturity signal, not a vulnerability.",
        Severity.INFO, "",
        {"present": True, "path": _CHANGE_PASSWORD_PATH, "status": resp.status_code,
         "confidence": "high"},
    )]


# ---------------------------------------------------------------------------
# mta-sts.txt (RFC 8461)
# ---------------------------------------------------------------------------

def _parse_mta_sts(text: str) -> dict[str, str]:
    """Parse ``key: value`` lines of an MTA-STS policy (CRLF-separated per RFC 8461)."""
    fields: dict[str, str] = {}
    for raw in text.replace("\r\n", "\n").splitlines():
        line = raw.strip()
        if not line or ":" not in line:
            continue
        name, _, value = line.partition(":")
        name, value = name.strip().lower(), value.strip()
        if name and value:
            fields.setdefault(name, value)      # first value wins (mx may repeat; we only need mode)
    return fields


def _mta_sts(engine: ScanEngine) -> list[Finding]:
    resp = _fetch(engine, _MTA_STS_PATH)
    if resp is None or resp.status_code != 200:
        return []
    try:
        text = resp.text
    except Exception:  # noqa: BLE001
        return []
    if _looks_like_html(text) or "sts" not in text.lower():
        return []                                # a 200 HTML error page, not a policy
    fields = _parse_mta_sts(text)
    mode = fields.get("mode", "").lower()

    if mode == "enforce":
        return [Finding(
            MODULE, "MTA-STS Policy Enforced",
            "The domain publishes an MTA-STS policy in mode 'enforce', requiring TLS for inbound "
            "SMTP. This protects mail delivery against passive interception and active downgrade.",
            Severity.INFO, "",
            {"present": True, "mode": mode, "path": _MTA_STS_PATH, "confidence": "high"},
        )]

    # Present but not enforcing (testing / none / malformed) — TLS is not actually required.
    detail = (f"mode '{mode}'" if mode else "no valid 'mode' field")
    return [Finding(
        MODULE, "MTA-STS Policy Not Enforcing TLS",
        f"An MTA-STS policy is published but has {detail}. Only 'mode: enforce' makes a sending MTA "
        "require TLS; in 'testing' or 'none' (or a malformed policy) mail can still be delivered in "
        "cleartext or over a downgraded connection, so the policy gives no real transport protection.",
        Severity.LOW,
        "Once the policy has been validated, set 'mode: enforce' in the MTA-STS policy.",
        {"present": True, "mode": mode or None, "path": _MTA_STS_PATH, "confidence": "high"},
    )]


# ---------------------------------------------------------------------------
# openid-configuration (OIDC discovery)
# ---------------------------------------------------------------------------

def _load_json(resp: "httpx.Response") -> "dict[str, Any] | None":
    try:
        data = json.loads(resp.text)
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def _oidc(engine: ScanEngine) -> list[Finding]:
    resp = _fetch(engine, _OIDC_PATH)
    if resp is None or resp.status_code != 200:
        return []
    doc = _load_json(resp)
    if not doc or "issuer" not in doc:
        return []                                # not a real discovery document

    issuer = str(doc.get("issuer", ""))
    endpoints = {k: doc[k] for k in
                 ("authorization_endpoint", "token_endpoint", "userinfo_endpoint",
                  "jwks_uri", "registration_endpoint", "end_session_endpoint")
                 if k in doc}
    findings: list[Finding] = [Finding(
        MODULE, "OpenID Connect Discovery Document Exposed",
        f"An OIDC discovery document is published at {_OIDC_PATH} (issuer: {issuer or 'unknown'}). "
        "This is standard for an OIDC provider and is public by design, but it hands an attacker a "
        "ready map of the auth endpoints and supported parameters — useful recon for an auth review.",
        Severity.INFO, "",
        {"present": True, "issuer": issuer, "endpoints": endpoints, "path": _OIDC_PATH,
         "confidence": "high"},
    )]

    algs = doc.get("id_token_signing_alg_values_supported")
    if isinstance(algs, list) and any(str(a).lower() == "none" for a in algs):
        findings.append(Finding(
            MODULE, "OIDC Advertises 'none' ID-Token Signing Algorithm",
            "The OIDC discovery document lists 'none' in id_token_signing_alg_values_supported, "
            "meaning the provider advertises support for UNSIGNED ID tokens. An attacker who can "
            "get a relying party to accept an alg:none token can forge identities / claims. This is "
            "the OIDC form of the classic JWT 'alg:none' weakness.",
            Severity.MEDIUM,
            "Remove 'none' from id_token_signing_alg_values_supported and require an asymmetric "
            "signing algorithm (e.g. RS256 / ES256); ensure relying parties reject alg:none.",
            {"issuer": issuer, "algs": [str(a) for a in algs], "path": _OIDC_PATH,
             "confidence": "high"},
            cwe="CWE-347",
            verified=True,
            verification="'none' listed in the provider's published id_token signing algorithms",
        ))
    return findings


def run(engine: ScanEngine) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_change_password(engine))
    findings.extend(_mta_sts(engine))
    findings.extend(_oidc(engine))
    return findings
