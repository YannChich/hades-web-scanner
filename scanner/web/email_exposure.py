"""
email_exposure — reports e-mail addresses exposed across crawled pages.

E-mail addresses harvested by the shared crawl (mailto: links and addresses in page
text) are surfaced here. Exposed addresses are a phishing and scraping surface; on-domain
addresses (matching the target host) are graded LOW, third-party ones INFO.
"""
from __future__ import annotations

from urllib.parse import urlparse

from scanner.engine import Finding, Severity, ScanEngine

MODULE = "email_exposure"


def _domain_of(email: str) -> str:
    return email.rsplit("@", 1)[-1].lower() if "@" in email else ""


def run(engine: ScanEngine) -> list[Finding]:
    crawl = engine.get_crawl()
    emails = sorted(crawl.emails)

    if not emails:
        return [Finding(
            module=MODULE,
            title="Email Exposure: None Found",
            description="No e-mail addresses were found in the crawled pages.",
            severity=Severity.INFO,
            recommendation="",
            raw={"pages_crawled": len(crawl.pages)},
        )]

    # Match addresses whose domain is the target's registrable host (rough check:
    # the target netloc ends with the email domain or vice-versa).
    target_host = urlparse(engine.url).netloc.split(":")[0].lower()
    target_root = ".".join(target_host.split(".")[-2:]) if "." in target_host else target_host

    findings: list[Finding] = []
    for email in emails:
        domain = _domain_of(email)
        on_domain = bool(domain) and (domain == target_root or domain.endswith("." + target_root))
        findings.append(Finding(
            module=MODULE,
            title=f"Exposed Email{' (on-domain)' if on_domain else ''}: {email}",
            description=(
                f"The address {email} is publicly exposed in the site's pages. "
                + ("It belongs to the target domain and is a direct phishing/spear-phishing target."
                   if on_domain else
                   "Harvested addresses fuel spam and social-engineering campaigns.")
            ),
            severity=Severity.LOW if on_domain else Severity.INFO,
            recommendation=(
                "Obfuscate addresses (e.g. contact forms, JS encoding) or use role aliases "
                "instead of publishing personal mailboxes."
            ),
            raw={"email": email, "domain": domain, "on_domain": on_domain},
        ))

    return findings
