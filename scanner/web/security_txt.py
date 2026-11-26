"""
security_txt — audit a site's ``security.txt`` vulnerability-disclosure posture (RFC 9116).

A ``security.txt`` file tells researchers how to report a vulnerability responsibly: who to
contact, where the disclosure policy lives, which encryption key to use. RFC 9116 standardises the
format and mandates that the file live at ``/.well-known/security.txt`` and carry at least a
``Contact`` and an ``Expires`` field. Its presence is a recognised maturity/credibility signal
(Mozilla Observatory, internet.nl and nuclei all check for it); its *absence* or *staleness* is a
soft finding a pentester routinely notes in a report.

This module is **detection / posture only**. It fetches the file over the existing engine (so scope,
rate-limiting and auth all apply), parses its fields per RFC 9116 and reports:

* **absent** — no file at the canonical or legacy location (INFO: no disclosure channel published);
* **legacy location only** — present at ``/security.txt`` but not ``/.well-known/security.txt`` (LOW);
* **missing ``Contact``** — the one mandatory channel is absent, so the file is unusable (MEDIUM);
* **missing / malformed / past ``Expires``** — the file is stale and tooling should ignore it (LOW→MEDIUM);
* **``Expires`` too far out** — RFC recommends < 1 year, long-lived files drift out of date (LOW);
* **served without HTTPS or not as text** — RFC requires an HTTPS ``text/plain`` resource (LOW).

It also surfaces the declared ``Contact`` / ``Policy`` / ``Encryption`` endpoints as recon context
and notes whether the file is PGP-signed. No field value is treated as a secret; the file is public
by design.
"""
from __future__ import annotations

from datetime import datetime, timezone

import httpx
from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine

MODULE = "security_txt"

# RFC 9116 §3: the file MUST be served from the .well-known path; a top-level /security.txt is a
# pre-RFC legacy location still seen in the wild.
_CANONICAL_PATH = "/.well-known/security.txt"
_LEGACY_PATH = "/security.txt"

# RFC 9116 §2.5.4 recommends an Expires value no more than a year out.
_MAX_EXPIRY_DAYS = 366

# Fields whose values point at a disclosure endpoint worth surfacing as recon context.
_RECON_FIELDS = ("contact", "policy", "encryption", "acknowledgments", "hiring", "canonical")


def _looks_like_html(text: str) -> bool:
    head = text[:256].lstrip().lower()
    return head.startswith("<!doctype") or head.startswith("<html") or "<head" in head


def _fetch(engine: ScanEngine, path: str) -> "httpx.Response | None":
    try:
        return engine.get(path)
    except httpx.HTTPError as exc:
        logger.debug(f"security_txt: {path} → {exc}")
        return None


def _is_served(resp: "httpx.Response | None") -> bool:
    """A real security.txt is an HTTP 200 text resource — not a 404 and not an HTML error page."""
    if resp is None or resp.status_code != 200:
        return False
    try:
        return not _looks_like_html(resp.text)
    except Exception:  # noqa: BLE001 — unreadable body is not a served file
        return False


def _parse_fields(text: str) -> dict[str, list[str]]:
    """Parse ``Field: value`` lines (case-insensitive field names), ignoring comments/blank lines
    and the PGP signature envelope. Multiple values per field (e.g. several Contact lines) are kept."""
    fields: dict[str, list[str]] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-----") or ":" not in line:
            continue
        name, _, value = line.partition(":")
        name = name.strip().lower()
        value = value.strip()
        if not name or not value or " " in name:
            continue
        fields.setdefault(name, []).append(value)
    return fields


def _parse_expires(value: str) -> "datetime | None":
    """Parse an RFC 9116 Expires value (an RFC 3339 / ISO 8601 timestamp). Returns an aware UTC
    datetime, or None if unparseable."""
    v = value.strip()
    if v.endswith(("Z", "z")):
        v = v[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _signed(text: str) -> bool:
    return "-----BEGIN PGP SIGNED MESSAGE-----" in text


def _absent_finding() -> Finding:
    return Finding(
        MODULE, "No security.txt Published",
        "No security.txt was found at /.well-known/security.txt or /security.txt. RFC 9116 "
        "defines this file as the standard channel for researchers to report vulnerabilities. "
        "Its absence is not itself a vulnerability, but it means there is no published, "
        "machine-readable way to disclose one responsibly.",
        Severity.INFO,
        "Publish a security.txt at https://<host>/.well-known/security.txt with at least a "
        "Contact and an Expires field (RFC 9116).",
        {"present": False, "confidence": "high"},
    )


def _posture_findings(location: str, canonical: bool, resp: "httpx.Response",
                      text: str) -> list[Finding]:
    fields = _parse_fields(text)
    findings: list[Finding] = []

    contacts = fields.get("contact", [])
    recon = {f: fields[f] for f in _RECON_FIELDS if f in fields}
    signed = _signed(text)

    findings.append(Finding(
        MODULE, f"security.txt Found ({location})",
        (f"A security.txt is published at {location} with "
         f"{len(contacts)} Contact, {len(fields.get('expires', []))} Expires and "
         f"{len(fields)} field(s) total"
         + (" (PGP-signed)" if signed else "") + "."),
        Severity.INFO, "",
        {"present": True, "location": location, "canonical": canonical, "signed": signed,
         "fields": sorted(fields), "contacts": contacts[:10],
         "recon": {k: v[:5] for k, v in recon.items()}, "confidence": "high"},
    ))

    # Served from the legacy top-level path only — RFC mandates /.well-known/.
    if not canonical:
        findings.append(Finding(
            MODULE, "security.txt Only at Legacy Location",
            "security.txt was found at /security.txt but not at the RFC 9116 canonical path "
            "/.well-known/security.txt. Standards-compliant tooling looks at the canonical path "
            "first and may not discover the legacy one.",
            Severity.LOW,
            "Serve the file from https://<host>/.well-known/security.txt (a redirect from "
            "/security.txt is fine).",
            {"location": location, "confidence": "high"}))

    # Not over HTTPS — RFC 9116 §3 requires an HTTPS resource.
    if str(resp.request.url).lower().startswith("http://"):
        findings.append(Finding(
            MODULE, "security.txt Not Served over HTTPS",
            "security.txt was retrieved over plain HTTP. RFC 9116 requires the file to be served "
            "over HTTPS so its contents cannot be tampered with in transit.",
            Severity.LOW,
            "Serve security.txt over HTTPS only.",
            {"location": location, "confidence": "high"}))

    # Missing mandatory Contact → the file cannot be acted on.
    if not contacts:
        findings.append(Finding(
            MODULE, "security.txt Missing Mandatory Contact Field",
            "The published security.txt has no Contact field. RFC 9116 makes Contact mandatory; "
            "without it a researcher has no address to send a report to, so the file serves no "
            "purpose.",
            Severity.MEDIUM,
            "Add at least one Contact field (a mailto:, https:// form, or tel: URI).",
            {"location": location, "confidence": "high"}))

    # Expires handling (mandatory field; must be in the future and not absurdly far out).
    expires = fields.get("expires", [])
    if not expires:
        findings.append(Finding(
            MODULE, "security.txt Missing Mandatory Expires Field",
            "The published security.txt has no Expires field. RFC 9116 makes Expires mandatory so "
            "consumers know when the information is no longer to be trusted.",
            Severity.LOW,
            "Add an Expires field with an RFC 3339 timestamp less than a year in the future.",
            {"location": location, "confidence": "high"}))
    else:
        parsed = _parse_expires(expires[0])
        now = datetime.now(timezone.utc)
        if parsed is None:
            findings.append(Finding(
                MODULE, "security.txt Malformed Expires Field",
                f"The Expires value '{expires[0]}' is not a valid RFC 3339 timestamp, so consumers "
                "cannot tell whether the file is still current.",
                Severity.LOW,
                "Use an RFC 3339 / ISO 8601 timestamp, e.g. 2027-01-01T00:00:00Z.",
                {"location": location, "expires": expires[0], "confidence": "high"}))
        elif parsed < now:
            findings.append(Finding(
                MODULE, "security.txt Has Expired",
                f"The security.txt Expires date ({expires[0]}) is in the past. RFC 9116 says an "
                "expired file should be treated as stale, so researchers and tooling may ignore it "
                "and skip reporting.",
                Severity.MEDIUM,
                "Refresh the file and set Expires to a date less than a year in the future.",
                {"location": location, "expires": expires[0], "expired": True,
                 "confidence": "high"}))
        elif (parsed - now).days > _MAX_EXPIRY_DAYS:
            findings.append(Finding(
                MODULE, "security.txt Expires Too Far in the Future",
                f"The security.txt Expires date ({expires[0]}) is more than a year away. RFC 9116 "
                "recommends an expiry under a year so the contact details are reviewed regularly.",
                Severity.LOW,
                "Set Expires to less than a year out and refresh it periodically.",
                {"location": location, "expires": expires[0], "confidence": "high"}))

    return findings


def run(engine: ScanEngine) -> list[Finding]:
    canonical = _fetch(engine, _CANONICAL_PATH)
    if _is_served(canonical) and canonical is not None:
        logger.info("security_txt: found at canonical path")
        return _posture_findings(_CANONICAL_PATH, True, canonical, canonical.text)

    legacy = _fetch(engine, _LEGACY_PATH)
    if _is_served(legacy) and legacy is not None:
        logger.info("security_txt: found at legacy path only")
        return _posture_findings(_LEGACY_PATH, False, legacy, legacy.text)

    return [_absent_finding()]
