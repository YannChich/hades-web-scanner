"""
integrations — optional bridges to industry-standard external tools (Nmap, Gobuster, theHarvester,
Recon-ng). Each integration runs the real tool when it is installed and degrades gracefully to a single
INFO "install hint" when it is not — the same convention Hades already uses for sslyze / playwright /
sqlmap. Hades never reimplements these engines; it shells out to them and ingests their output as
Findings. Active integrations (Nmap, Gobuster) are skipped in safe mode.
"""
