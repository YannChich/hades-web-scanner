"""Quick import-health check — run after any module edit to catch broken imports."""
import importlib
import sys
import traceback

MODULES = [
    "scanner.engine",
    "scanner.recon.basic_info",
    "scanner.recon.whois_lookup",
    "scanner.recon.dns_check",
    "scanner.recon.ssl_check",
    "scanner.recon.port_scan",
    "scanner.recon.waf_detect",
    "scanner.recon.tech_stack",
    "scanner.web.headers_check",
    "scanner.web.robots_txt",
    "scanner.web.sitemap",
    "scanner.web.cms_detect",
    "scanner.web.admin_panel",
    "scanner.web.dir_scan",
    "scanner.web.subdomain_scan",
    "scanner.web.broken_links",
    "scanner.web.http_methods",
    "scanner.web.backup_files",
    "scanner.web.sensitive_files",
    "scanner.web.cookie_analysis",
    "scanner.web.redirect_chain",
    "scanner.web.email_exposure",
    "scanner.web.favicon_hash",
    "scanner.web.cors_check",
    "scanner.web.clickjacking",
    "scanner.web.dir_listing",
    "scanner.web.blacklist_check",
    "scanner.web.screenshot",
    "scanner.vulns.sqli_detect",
    "scanner.vulns.xss_detect",
    "scanner.vulns.cve_mapping",
    "scanner.vulns.default_creds",
    "scanner.output.console",
    "scanner.output.scorer",
    "scanner.output.report_json",
    "scanner.output.report_html",
    "scanner.output.report_pdf",
]

errors: list[tuple[str, str]] = []
for mod in MODULES:
    try:
        importlib.import_module(mod)
        print(f"OK  {mod}")
    except Exception as exc:
        errors.append((mod, traceback.format_exc()))
        print(f"ERR {mod}: {exc}")

if errors:
    print(f"\n[HOOK] {len(errors)} import error(s) detected:")
    for mod, tb in errors:
        print(f"  --- {mod} ---\n{tb}")
    sys.exit(1)
else:
    print(f"\n[HOOK] All {len(MODULES)} modules OK")
