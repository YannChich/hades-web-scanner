"""
cloud_buckets — public cloud storage discovery (S3 / GCS / Azure Blob).

A very common real-world breach: a misconfigured object-storage bucket left world-readable.
This module (1) extracts bucket URLs already referenced in the site's source, and (2) guesses
likely bucket names from the target domain, then probes each provider:

  * open listing (anonymous read of the file index) → CRITICAL
  * bucket exists but is access-controlled            → LOW (useful intel for a red team)

Read-only: it never writes/uploads. Bucket guessing uses only the target's own name.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import httpx
from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine

MODULE = "cloud_buckets"

_MAX_CANDIDATES = 36

# Bucket references already present in the site source.
_S3_HOST_RE = re.compile(r"https?://([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3[.\-][a-z0-9\-]*\.?amazonaws\.com", re.I)
_S3_PATH_RE = re.compile(r"https?://s3[.\-][a-z0-9\-]*\.?amazonaws\.com/([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])", re.I)
_GCS_HOST_RE = re.compile(r"https?://([a-z0-9][a-z0-9._\-]{1,61})\.storage\.googleapis\.com", re.I)
_GCS_PATH_RE = re.compile(r"https?://storage\.googleapis\.com/([a-z0-9][a-z0-9._\-]{1,61})", re.I)
_AZURE_RE = re.compile(r"https?://([a-z0-9]{3,24})\.blob\.core\.windows\.net", re.I)

# Name-mutation affixes used to guess bucket names from the domain label.
_SUFFIXES = ["", "-assets", "-static", "-media", "-uploads", "-upload", "-backup", "-backups",
             "-data", "-prod", "-production", "-dev", "-staging", "-cdn", "-public", "-private",
             "-files", "-images", "-img", "-logs", "-web", "-www", "-storage", "-s3"]
_PREFIXES = ["assets-", "static-", "cdn-", "backup-", "media-", "www-"]


def _domain_label(host: str) -> str:
    host = host.lower()
    if host.startswith("www."):     # strip the prefix, not the character set (lstrip('www.') was a bug)
        host = host[4:]
    parts = host.split(".")
    return parts[0] if parts else host


def _candidate_names(engine: ScanEngine) -> dict[str, str]:
    """Return {bucket_name: origin} where origin is 'referenced' (linked in the site source —
    certainly the target's) or 'guessed' (a name mutation that may belong to a namesake)."""
    host = urlparse(engine.url).hostname or ""
    label = _domain_label(host)
    names: dict[str, str] = {}
    if label:
        for suf in _SUFFIXES:
            names[label + suf] = "guessed"
        for pre in _PREFIXES:
            names[pre + label] = "guessed"
        names[host.replace(".", "-")] = "guessed"
        names[host.replace(".", "")] = "guessed"
    # Buckets referenced directly in the source are the target's for sure — they override guesses.
    try:
        blob = "\n".join(engine.get_crawl().pages.values())
        for rx in (_S3_HOST_RE, _S3_PATH_RE, _GCS_HOST_RE, _GCS_PATH_RE, _AZURE_RE):
            for m in rx.findall(blob):
                names[m.lower()] = "referenced"
    except Exception:  # noqa: BLE001
        pass
    return {n: o for n, o in names.items() if 3 <= len(n) <= 63}


# ---------------------------------------------------------------------------
# Provider probes
# ---------------------------------------------------------------------------

def _get(engine: ScanEngine, url: str) -> "httpx.Response | None":
    try:
        return engine.request("GET", url, timeout=8.0)
    except httpx.HTTPError:
        return None


def _probe_bucket(engine: ScanEngine, name: str, origin: str = "guessed") -> list[Finding]:
    findings: list[Finding] = []

    # --- Amazon S3 ---
    r = _get(engine, f"https://{name}.s3.amazonaws.com/")
    if r is not None:
        if r.status_code == 200 and ("<ListBucketResult" in r.text or "<Contents>" in r.text):
            findings.append(_open_finding("Amazon S3", name, f"https://{name}.s3.amazonaws.com/", r.text, origin))
        elif r.status_code == 403 and "AccessDenied" in r.text:
            findings.append(_private_finding("Amazon S3", name, f"https://{name}.s3.amazonaws.com/"))
        if findings:
            return findings

    # --- Google Cloud Storage ---
    r = _get(engine, f"https://storage.googleapis.com/{name}")
    if r is not None:
        if r.status_code == 200 and "<ListBucketResult" in r.text:
            findings.append(_open_finding("Google Cloud Storage", name,
                                          f"https://storage.googleapis.com/{name}", r.text, origin))
        elif r.status_code == 403 and ("AccessDenied" in r.text or "permission" in r.text.lower()):
            findings.append(_private_finding("Google Cloud Storage", name,
                                             f"https://storage.googleapis.com/{name}"))
        if findings:
            return findings

    # --- Azure Blob (storage-account names are alphanumeric, <=24 chars) ---
    if name.isalnum() and len(name) <= 24:
        url = f"https://{name}.blob.core.windows.net/?comp=list"
        r = _get(engine, url)
        if r is not None and r.status_code == 200 and "EnumerationResults" in r.text:
            findings.append(_open_finding("Azure Blob", name, url, r.text, origin))
    return findings


def _sample_keys(body: str) -> list[str]:
    return re.findall(r"<Key>([^<]+)</Key>", body)[:8] or re.findall(r"<Name>([^<]+)</Name>", body)[:8]


def _open_finding(provider: str, name: str, url: str, body: str, origin: str = "guessed") -> Finding:
    keys = _sample_keys(body)
    sample = (" Sample objects: " + ", ".join(keys[:6]) + ".") if keys else ""
    # A guessed name could belong to a namesake (object-storage names are a global namespace),
    # so flag ownership verification and lower the confidence; referenced buckets are the target's.
    referenced = origin == "referenced"
    caveat = ("" if referenced else
              " NOTE: this bucket name was guessed from the domain — confirm it belongs to the "
              "target (storage names are a global namespace) before reporting it as theirs.")
    return Finding(
        module=MODULE,
        title=f"Open {provider} Bucket — World-Readable: {name}",
        description=(
            f"The {provider} bucket '{name}' ({origin}) allows anonymous listing/reading at {url}. "
            f"Anyone can download its contents.{sample}{caveat}"
        ),
        severity=Severity.CRITICAL,
        recommendation=(
            "Block public access on the bucket, enforce least-privilege bucket policies, and "
            "review the exposed objects for sensitive data."
        ),
        raw={"provider": provider, "bucket": name, "url": url, "proof_url": url,
             "objects": keys, "origin": origin,
             "confidence": "high" if referenced else "medium",
             "attack": "T1530 Data from Cloud Storage",
             "exploit_cmd": f"aws s3 ls s3://{name} --no-sign-request"
             if provider == "Amazon S3" else f"curl '{url}'",
             "evidence": [f"GET {url} → 200 with a bucket listing body",
                          (f"{len(keys)} object key(s) readable anonymously: {', '.join(keys[:5])}"
                           if keys else "anonymous listing markup present (ListBucketResult)"),
                          f"bucket name origin: {origin}"],
             "exploitation": (
                 [{"step": 1, "description": "List the bucket contents anonymously.",
                   "command": f"aws s3 ls s3://{name} --no-sign-request"},
                  {"step": 2, "description": "Download the entire bucket for offline review.",
                   "command": f"aws s3 sync s3://{name} ./loot_{name} --no-sign-request"}]
                 if provider == "Amazon S3" else
                 [{"step": 1, "description": "Fetch the public object listing.",
                   "command": f'curl -sk "{url}"'},
                  {"step": 2, "description": "Download an exposed object by key.",
                   "command": f'curl -sk -O "{url}<object-key>"'}])},
    )


def _private_finding(provider: str, name: str, url: str) -> Finding:
    return Finding(
        module=MODULE,
        title=f"{provider} Bucket Exists (Access-Controlled): {name}",
        description=(
            f"The {provider} bucket '{name}' exists but denies anonymous access ({url}). "
            "Useful intel: the name is valid and may be brute-forced for objects or targeted "
            "with credential-based access."
        ),
        severity=Severity.LOW,
        recommendation="Confirm the bucket policy denies public access and audit IAM grants.",
        raw={"provider": provider, "bucket": name, "url": url, "confidence": "high",
             "attack": "T1580 Cloud Infrastructure Discovery",
             "evidence": [f"GET {url} → 403 AccessDenied — bucket name is valid but access-controlled"]},
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(engine: ScanEngine) -> list[Finding]:
    candidate_map = _candidate_names(engine)
    # Probe referenced buckets first (highest value), then guesses, capped.
    candidates = sorted(candidate_map, key=lambda n: (candidate_map[n] != "referenced", n))[:_MAX_CANDIDATES]
    if not candidates:
        return []
    findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=min(engine.threads, 12)) as pool:
        futures = {pool.submit(_probe_bucket, engine, n, candidate_map[n]): n for n in candidates}
        for fut in as_completed(futures):
            try:
                findings.extend(fut.result())
            except Exception as exc:  # noqa: BLE001
                logger.debug(f"cloud_buckets: probe {futures[fut]} failed: {exc}")
    _order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: _order.get(f.severity.value, 9))
    logger.info(f"cloud_buckets: tested {len(candidates)} candidate(s), {len(findings)} finding(s)")
    return findings
