"""
arsenal_data — the offensive-tools catalogue behind the RedTeam Arsenal page (menu option 666).

Each category groups tools by the *kind of attack/assessment* they serve. Every tool carries a
one-line explanation, its project link, and a ``star`` flag for the modern/essential picks.
GitHub/project links are sourced from the tools' own repos and the Z4nzu/hackingtool catalogue.
Every entry resolves to a real project page; where a generic capability (e.g. port scanning,
host-to-IP) is provided by Hades itself, it links to the Hades repository. ``url=None`` is still
honoured defensively (the page would show "no public repo" and never invent a link), but no entry
currently uses it. Reference-only: Hades does not run or bundle these tools.
"""
from __future__ import annotations

# (name, explanation, project_url_or_None, is_starred)
Tool = tuple[str, str, "str | None", bool]

CATEGORIES: list[dict] = [
    {"icon": "🛡", "name": "Anonymously Hiding", "attack": "Anonymity & traffic obfuscation", "tools": [
        ("Anonymous Surf", "Route all system traffic through Tor for anonymous browsing.", "https://github.com/Und3rf10w/kali-anonsurf", False),
        ("Multitor", "Run multiple Tor instances with load balancing for stronger anonymity.", "https://github.com/trimstray/multitor", False),
    ]},

    {"icon": "🔍", "name": "Information Gathering", "attack": "Reconnaissance, OSINT & attack-surface mapping", "tools": [
        ("Nmap", "The de-facto network/port scanner and service fingerprinter (NSE scripts).", "https://github.com/nmap/nmap", False),
        ("Dracnmap", "Wrapper that simplifies powerful Nmap scans into menu options.", "https://github.com/Screetsec/Dracnmap", False),
        ("Port scanning", "TCP port discovery to map a target's exposed services (Hades' port_scan module).", "https://github.com/YannChich/hades-web-scanner", True),
        ("Host to IP", "Resolve a hostname to its IP address(es) during recon (Hades' basic_info / dns_check).", "https://github.com/YannChich/hades-web-scanner", True),
        ("Xerosploit", "MITM toolkit for LAN attacks (sniffing, injection, DoS).", "https://github.com/LionSec/xerosploit", False),
        ("RED HAWK", "All-in-one web recon: WHOIS, headers, CMS, geo-IP, subdomains.", "https://github.com/Tuhinshubhra/RED_HAWK", False),
        ("ReconSpider", "Advanced OSINT crawler aggregating data from many sources.", "https://github.com/bhavsec/reconspider", False),
        ("Infoga", "Gather e-mail accounts and breach info from public sources.", "https://github.com/m4ll0k/Infoga", False),
        ("ReconDog", "Recon Swiss-army knife pulling from many recon APIs.", "https://github.com/s0md3v/ReconDog", False),
        ("Striker", "Offensive information-and-vulnerability recon scanner.", "https://github.com/s0md3v/Striker", False),
        ("SecretFinder", "Find API keys, tokens and secrets in JavaScript files.", "https://github.com/m4ll0k/SecretFinder", False),
        ("Shodanfy", "Query Shodan for ports, banners and vulns of an IP.", "https://github.com/m4ll0k/Shodanfy.py", False),
        ("rang3r", "Multithreaded IP-range / open-port scanner.", "https://github.com/floriankunushevci/rang3r", False),
        ("Breacher", "Brute-force hidden admin panels and login paths.", "https://github.com/s0md3v/Breacher", False),
        ("theHarvester", "Harvest emails, subdomains, hosts and names from public sources.", "https://github.com/laramies/theHarvester", True),
        ("Amass", "In-depth DNS/asset discovery and subdomain enumeration (OWASP).", "https://github.com/owasp-amass/amass", True),
        ("Masscan", "Internet-scale TCP port scanner (asynchronous, very fast).", "https://github.com/robertdavidgraham/masscan", True),
        ("RustScan", "Ultra-fast port scanner that pipes results straight into Nmap.", "https://github.com/RustScan/RustScan", True),
        ("Holehe", "Check whether an email is registered on 100+ sites.", "https://github.com/megadose/holehe", True),
        ("Maigret", "Hunt a username across thousands of sites (OSINT).", "https://github.com/soxoj/maigret", True),
        ("httpx", "Fast, multi-purpose HTTP probe/toolkit (ProjectDiscovery).", "https://github.com/projectdiscovery/httpx", True),
        ("SpiderFoot", "Automated OSINT engine with 200+ data-source modules.", "https://github.com/smicallef/spiderfoot", True),
        ("Subfinder", "Passive subdomain discovery from dozens of sources.", "https://github.com/projectdiscovery/subfinder", True),
        ("TruffleHog", "Find leaked credentials/secrets in git repos and more.", "https://github.com/trufflesecurity/trufflehog", True),
        ("Gitleaks", "Detect and prevent hardcoded secrets in git repositories.", "https://github.com/gitleaks/gitleaks", True),
    ]},

    {"icon": "📚", "name": "Wordlist Generator", "attack": "Password cracking & wordlist building", "tools": [
        ("Cupp", "Build targeted password wordlists from a victim's personal info.", "https://github.com/Mebus/cupp", False),
        ("WordlistCreator", "Generate custom wordlists from keywords and rules.", "https://github.com/Z4nzu/wlcreator", False),
        ("Goblin WordGenerator", "Random/custom wordlist generator for brute-forcing.", "https://github.com/UndeadSec/GoblinWordGenerator", False),
        ("Password list (1.4B)", "Massive collected credential/password wordlist (SMWYG).", "https://github.com/Viralmaniar/SMWYG-Show-Me-What-You-Got", False),
        ("Hashcat", "The world's fastest GPU password/hash cracker.", "https://github.com/hashcat/hashcat", True),
        ("John the Ripper", "Classic, extensible password cracker (Jumbo).", "https://github.com/openwall/john", True),
        ("haiti", "Identify a hash type from its format (hash-ID).", "https://github.com/noraj/haiti", True),
    ]},

    {"icon": "📶", "name": "Wireless Attack", "attack": "Wi-Fi / Bluetooth attacks", "tools": [
        ("WiFi-Pumpkin", "Rogue-AP framework for Wi-Fi MITM and phishing.", "https://github.com/P0cL4bs/wifipumpkin3", False),
        ("pixiewps", "Offline brute-force of the WPS PIN (Pixie-Dust attack).", "https://github.com/wiire-a/pixiewps", False),
        ("Bluetooth Honeypot (bluepot)", "Bluetooth honeypot to capture and analyse BT attacks.", "https://github.com/andrewmichaelsmith/bluepot", False),
        ("Fluxion", "Captive-portal social-engineering attack against WPA keys.", "https://github.com/FluxionNetwork/fluxion", False),
        ("Wifiphisher", "Rogue-AP phishing to harvest Wi-Fi creds and run MITM.", "https://github.com/wifiphisher/wifiphisher", False),
        ("Wifite", "Automated wireless auditing (WEP/WPA/WPS).", "https://github.com/derv82/wifite2", False),
        ("EvilTwin", "Create a malicious twin access point to capture clients (fakeap).", "https://github.com/Z4nzu/fakeap", False),
        ("Fastssh", "Mass-scan and brute-force exposed SSH services.", "https://github.com/Z4nzu/fastssh", False),
        ("Howmanypeople", "Count people nearby by sniffing Wi-Fi probe requests.", "https://github.com/schollz/howmanypeoplearearound", False),
        ("Airgeddon", "Multi-use Wi-Fi auditing framework (all-in-one).", "https://github.com/v1s1t0r1sh3r3/airgeddon", True),
        ("hcxdumptool", "Capture WPA/WPA2 handshakes/PMKIDs from Wi-Fi.", "https://github.com/ZerBea/hcxdumptool", True),
        ("hcxtools", "Convert captured Wi-Fi data into hashcat-crackable formats.", "https://github.com/ZerBea/hcxtools", True),
        ("Bettercap", "The Swiss-army knife for network/Wi-Fi/BLE MITM attacks.", "https://github.com/bettercap/bettercap", True),
    ]},

    {"icon": "🧩", "name": "SQL Injection", "attack": "SQL / NoSQL injection (database compromise)", "tools": [
        ("Sqlmap", "Automatic SQL-injection detection and full DB takeover.", "https://github.com/sqlmapproject/sqlmap", False),
        ("NoSqlMap", "Automated NoSQL (MongoDB…) injection and enumeration.", "https://github.com/codingo/NoSQLMap", False),
        ("DSSS", "Damn Small SQLi Scanner — a tiny SQLi detector.", "https://github.com/stamparm/DSSS", False),
        ("Explo", "Describe and reproduce web vulns (incl. SQLi) declaratively.", "https://github.com/dtag-dev-sec/explo", False),
        ("Blisqy", "Time-based blind SQLi in HTTP headers (MySQL/MariaDB).", "https://github.com/JohnTroony/Blisqy", False),
        ("Leviathan", "Mass-audit toolkit: discovery, brute-force and SQLi.", "https://github.com/leviathan-framework/leviathan", False),
        ("SQLScan", "Lightweight SQL-injection vulnerability scanner.", "https://github.com/Cvar1984/sqlscan", False),
    ]},

    {"icon": "🎣", "name": "Phishing Attack", "attack": "Phishing, social engineering & credential theft", "tools": [
        ("Autophisher", "Automated phishing-page hosting toolkit.", "https://github.com/CodingRanjith/autophisher", False),
        ("PyPhisher", "Easy phishing tool with 70+ ready-made site templates.", "https://github.com/KasRoudra/PyPhisher", False),
        ("AdvPhishing", "OTP-bypass phishing with real-time credential capture.", "https://github.com/Ignitetch/AdvPhishing", False),
        ("Setoolkit", "The Social-Engineer Toolkit — the SE attack framework.", "https://github.com/trustedsec/social-engineer-toolkit", False),
        ("SocialFish", "Phishing framework with an Android/education focus.", "https://github.com/UndeadSec/SocialFish", False),
        ("HiddenEye", "Modern phishing with keylogger and many templates.", "https://github.com/Morsmalleo/HiddenEye", False),
        ("Evilginx3", "Man-in-the-middle phishing that steals sessions/2FA tokens.", "https://github.com/kgretzky/evilginx2", False),
        ("I-See-You", "Grab a target's geolocation via a crafted link.", "https://github.com/Viralmaniar/I-See-You", False),
        ("SayCheese", "Snap a webcam photo of the victim via a link.", "https://github.com/hangetzzu/saycheese", False),
        ("QR Code Jacking", "Hijack QR-code-based logins to steal sessions (ohmyqr).", "https://github.com/cryptedwolf/ohmyqr", False),
        ("BlackEye", "Phishing toolkit with 30+ cloned site templates.", "https://github.com/An0nUD4Y/blackeye", False),
        ("ShellPhish", "Phishing for popular social networks with tunnelling.", "https://github.com/An0nUD4Y/shellphish", False),
        ("Thanos", "Multi-template phishing automation tool.", "https://github.com/TridevReddy/Thanos", False),
        ("QRLJacking", "Session hijacking by abusing QR-code login flows (OWASP).", "https://github.com/OWASP/QRLJacking", False),
        ("Maskphish", "Hide a phishing URL behind a trusted-looking domain.", "https://github.com/jaykali/maskphish", False),
        ("BlackPhish", "Lightweight, fast phishing framework.", "https://github.com/iinc0gnit0/BlackPhish", False),
        ("dnstwist", "Find typosquatting/lookalike domains used for phishing.", "https://github.com/elceef/dnstwist", False),
    ]},

    {"icon": "🌐", "name": "Web Attack", "attack": "Web application attacks & content discovery", "tools": [
        ("Web2Attack", "Web pentest framework (scan, exploit, payloads).", "https://github.com/santatic/web2attack", False),
        ("Skipfish", "Active web-app recon scanner producing a sitemap of issues.", "https://github.com/spinkham/skipfish", False),
        ("Sublist3r", "Fast subdomain enumeration for a target domain.", "https://github.com/aboul3la/Sublist3r", False),
        ("CheckURL", "Detect malicious / phishing URLs.", "https://github.com/UndeadSec/checkURL", False),
        ("Sub-Domain TakeOver", "Detect dangling DNS records vulnerable to takeover.", "https://github.com/edoardottt/takeover", False),
        ("Dirb", "Classic dictionary-based web content/dir brute-forcer.", "https://gitlab.com/kalilinux/packages/dirb", False),
        ("Nuclei", "Template-based vulnerability scanner (huge community templates).", "https://github.com/projectdiscovery/nuclei", True),
        ("ffuf", "Blazing-fast web fuzzer for paths, params and vhosts.", "https://github.com/ffuf/ffuf", True),
        ("Feroxbuster", "Fast, recursive content discovery (Rust).", "https://github.com/epi052/feroxbuster", True),
        ("Nikto", "Web-server scanner for known files, configs and vulns.", "https://github.com/sullo/nikto", True),
        ("wafw00f", "Fingerprint the WAF/firewall protecting a web app.", "https://github.com/EnableSecurity/wafw00f", True),
        ("Katana", "Next-gen crawling and spidering framework.", "https://github.com/projectdiscovery/katana", True),
        ("Gobuster", "Fast brute-forcer for dirs, DNS, vhosts and S3 buckets.", "https://github.com/OJ/gobuster", True),
        ("Dirsearch", "Advanced web path brute-forcer with rich filtering.", "https://github.com/maurosoria/dirsearch", True),
        ("OWASP ZAP", "Full-featured open-source web application proxy/scanner.", "https://github.com/zaproxy/zaproxy", True),
        ("testssl.sh", "Command-line TLS/SSL configuration and vuln tester.", "https://github.com/drwetter/testssl.sh", True),
        ("Arjun", "Discover hidden HTTP parameters via smart fuzzing.", "https://github.com/s0md3v/Arjun", True),
        ("Caido", "Modern web-security auditing proxy (Burp alternative).", "https://github.com/caido/caido", True),
        ("mitmproxy", "Interactive HTTPS intercepting proxy for traffic analysis.", "https://github.com/mitmproxy/mitmproxy", True),
    ]},

    {"icon": "🔧", "name": "Post Exploitation", "attack": "Post-exploitation, C2 & lateral movement", "tools": [
        ("Vegile", "Backdoor/stealth persistence helper for Linux.", "https://github.com/Screetsec/Vegile", False),
        ("Chrome Keylogger", "Hera Keylogger — capture keystrokes from the browser.", "https://github.com/UndeadSec/HeraKeylogger", False),
        ("pwncat-cs", "Post-exploitation reverse/bind shell handler with automation.", "https://github.com/calebstewart/pwncat", True),
        ("Sliver", "Cross-platform adversary-emulation / C2 framework (BishopFox).", "https://github.com/BishopFox/sliver", True),
        ("Havoc", "Modern, malleable C2 framework with a sleek UI.", "https://github.com/HavocFramework/Havoc", True),
        ("PEASS-ng (LinPEAS/WinPEAS)", "Local privilege-escalation enumeration scripts.", "https://github.com/peass-ng/PEASS-ng", True),
        ("Ligolo-ng", "Fast tunnel/pivot tool using a TUN interface.", "https://github.com/nicocha30/ligolo-ng", True),
        ("Chisel", "Fast TCP/UDP tunnel over HTTP for pivoting.", "https://github.com/jpillora/chisel", True),
        ("Evil-WinRM", "The ultimate WinRM shell for Windows post-exploitation.", "https://github.com/Hackplayers/evil-winrm", True),
        ("Mythic", "Collaborative, multi-agent red-team C2 platform.", "https://github.com/its-a-feature/Mythic", True),
    ]},

    {"icon": "🕵", "name": "Forensic", "attack": "Digital forensics & memory analysis", "tools": [
        ("Autopsy", "GUI digital-forensics platform over The Sleuth Kit.", "https://github.com/sleuthkit/autopsy", False),
        ("Wireshark", "The world's foremost network-protocol analyser.", "https://github.com/wireshark/wireshark", False),
        ("Bulk extractor", "Carve emails, URLs, card numbers etc. from disk images.", "https://github.com/simsong/bulk_extractor", False),
        ("Guymager", "Fast forensic disk-imaging (acquisition) tool.", "https://guymager.sourceforge.io/", False),
        ("Toolsley", "Online toolkit for file/hash/signature inspection.", "https://www.toolsley.com/", False),
        ("Volatility 3", "Advanced memory (RAM) forensics framework.", "https://github.com/volatilityfoundation/volatility3", True),
        ("Binwalk", "Analyse and extract embedded files from firmware/binaries.", "https://github.com/ReFirmLabs/binwalk", True),
        ("pspy", "Snoop on Linux processes/cron without root.", "https://github.com/DominicBreuker/pspy", True),
    ]},

    {"icon": "📦", "name": "Payload Creation", "attack": "Malware / payload generation", "tools": [
        ("The FatRat", "Generate undetectable backdoors and payloads.", "https://github.com/Screetsec/TheFatRat", False),
        ("Brutal", "Create malicious HID (Rubber-Ducky style) payloads.", "https://github.com/Screetsec/Brutal", False),
        ("Stitch", "Cross-platform Python remote-administration payload.", "https://github.com/nathanlopez/Stitch", False),
        ("MSFvenom Payload Creator", "Wrapper that simplifies msfvenom payload generation.", "https://github.com/g0tmi1k/msfpc", False),
        ("Venom", "Shellcode generator/handler that wraps msfvenom.", "https://github.com/r00t-3xp10it/venom", False),
        ("Spycam", "Payload to remotely access a victim's camera.", "https://github.com/indexnotfound404/spycam", False),
        ("Mob-Droid", "Generate Android (APK) Metasploit payloads.", "https://github.com/kinghacker0/Mob-Droid", False),
        ("Enigma", "Multiplatform payload dropper/obfuscator.", "https://github.com/UndeadSec/Enigma", False),
    ]},

    {"icon": "🧰", "name": "Exploit Framework", "attack": "Exploitation frameworks", "tools": [
        ("RouterSploit", "Exploitation framework for embedded devices/routers.", "https://github.com/threat9/routersploit", False),
        ("WebSploit", "MITM and web-exploitation framework.", "https://github.com/The404Hacking/websploit", False),
        ("Commix", "Automated OS command-injection detection and exploitation.", "https://github.com/commixproject/commix", False),
        ("Web2Attack", "Web pentest/exploitation framework.", "https://github.com/santatic/web2attack", False),
    ]},

    {"icon": "🔁", "name": "Reverse Engineering", "attack": "Reverse engineering & binary analysis", "tools": [
        ("Androguard", "Reverse-engineer and analyse Android APKs.", "https://github.com/androguard/androguard", False),
        ("Apk2Gold", "Decompile Android APKs back to Java/smali source.", "https://github.com/lxdvs/apk2gold", False),
        ("JadX", "Dex-to-Java decompiler with a handy GUI.", "https://github.com/skylot/jadx", False),
        ("Ghidra", "NSA's full software reverse-engineering suite.", "https://github.com/NationalSecurityAgency/ghidra", True),
        ("Radare2", "Portable command-line reverse-engineering framework.", "https://github.com/radareorg/radare2", True),
    ]},

    {"icon": "⚡", "name": "DDOS Attack", "attack": "Denial-of-service (stress testing)", "tools": [
        ("DDoS Script", "Simple script for flooding a target (stress test).", "https://github.com/the-deepnet/ddos", False),
        ("SlowLoris", "Low-bandwidth DoS that holds many connections open.", "https://github.com/gkbrk/slowloris", False),
        ("Asyncrone", "Multifunction SYN-flood DoS weapon.", "https://github.com/fatihsnsy/aSYNcrone", False),
        ("UFOnet", "Botnet-style DDoS via open-redirect abuse.", "https://github.com/epsylon/ufonet", False),
        ("GoldenEye", "HTTP/S layer-7 DoS testing tool.", "https://github.com/jseidl/GoldenEye", False),
    ]},

    {"icon": "🖥", "name": "Remote Administrator (RAT)", "attack": "Remote access / remote administration", "tools": [
        ("Pyshell", "Lightweight Python remote-shell / RAT.", "https://github.com/knassar702/pyshell", False),
    ]},

    {"icon": "💥", "name": "XSS Attack", "attack": "Cross-site scripting (XSS)", "tools": [
        ("DalFox", "Fast, powerful parameter-analysis XSS scanner.", "https://github.com/hahwul/dalfox", False),
        ("XSS Payload Generator", "Generate context-specific XSS payloads (XSS-LOADER).", "https://github.com/capture0x/XSS-LOADER", False),
        ("Extended XSS Searcher", "Search reflected parameters for XSS at scale.", "https://github.com/Damian89/extended-xss-search", False),
        ("XSS-Freak", "Crawls and tests a site for reflected XSS.", "https://github.com/PR0PH3CY33/XSS-Freak", False),
        ("XSpear", "Ruby-based XSS scanner and parameter analyser.", "https://github.com/hahwul/XSpear", False),
        ("XSSCon", "Simple, smart XSS scanner.", "https://github.com/menkrep1337/XSSCon", False),
        ("XanXSS", "Reflected-XSS finder that mutates payloads.", "https://github.com/Ekultek/XanXSS", False),
        ("XSStrike", "Advanced XSS detection with context-aware payloads.", "https://github.com/s0md3v/XSStrike", False),
        ("RVuln", "Multithreaded web-vulnerability (incl. XSS) scanner.", "https://github.com/iinc0gnit0/RVuln", False),
    ]},

    {"icon": "🖼", "name": "Steganography", "attack": "Steganography (hiding data)", "tools": [
        ("StegoCracker", "Hide data in files and brute-force stego passwords.", "https://github.com/W1LDN16H7/StegoCracker", False),
        ("Whitespace", "Encode hidden messages using whitespace characters (snow10).", "https://github.com/beardog108/snow10", False),
    ]},

    {"icon": "🏢", "name": "Active Directory", "attack": "Active Directory attacks", "tools": [
        ("BloodHound", "Map and abuse Active Directory attack paths via graphs.", "https://github.com/SpecterOps/BloodHound", True),
        ("NetExec (nxc)", "Swiss-army knife for AD/network protocol attacks (CME successor).", "https://github.com/Pennyw0rth/NetExec", True),
        ("Impacket", "Python classes for crafting/abusing network protocols (SMB, Kerberos…).", "https://github.com/fortra/impacket", True),
        ("Responder", "LLMNR/NBT-NS/MDNS poisoner that captures hashes.", "https://github.com/lgandx/Responder", True),
        ("Certipy", "Enumerate and abuse Active Directory Certificate Services.", "https://github.com/ly4k/Certipy", True),
        ("Kerbrute", "Fast Kerberos user-enumeration and password-spraying.", "https://github.com/ropnop/kerbrute", True),
    ]},

    {"icon": "☁", "name": "Cloud Security", "attack": "Cloud security assessment", "tools": [
        ("Prowler", "Multi-cloud security & compliance assessment (AWS/Azure/GCP).", "https://github.com/prowler-cloud/prowler", True),
        ("ScoutSuite", "Multi-cloud security-posture auditing tool.", "https://github.com/nccgroup/ScoutSuite", True),
        ("Pacu", "Offensive AWS exploitation framework.", "https://github.com/RhinoSecurityLabs/pacu", True),
        ("Trivy", "Scan containers/IaC/cloud for vulns and misconfigurations.", "https://github.com/aquasecurity/trivy", True),
    ]},

    {"icon": "📱", "name": "Mobile Security", "attack": "Mobile app security testing", "tools": [
        ("MobSF", "Automated static+dynamic analysis of Android/iOS apps.", "https://github.com/MobSF/Mobile-Security-Framework-MobSF", True),
        ("Frida", "Dynamic instrumentation toolkit for hooking apps at runtime.", "https://github.com/frida/frida", True),
        ("Objection", "Runtime mobile exploration built on Frida.", "https://github.com/sensepost/objection", True),
    ]},

    {"icon": "✨", "name": "Other Tools", "attack": "Misc. offensive utilities", "tools": [
        ("AllinOne SocialMedia Attack", "Combined social-media brute-force toolkit (Brute_Force).", "https://github.com/Matrix07ksa/Brute_Force", False),
        ("Facebook Attack", "Facebook account brute-force (Brute_Force).", "https://github.com/Matrix07ksa/Brute_Force", False),
        ("Application Checker", "Inspect installed apps for security issues (underhanded).", "https://github.com/jakuta-tech/underhanded", False),
        ("Keydroid", "Android keylogger payload builder.", "https://github.com/F4dl0/keydroid", False),
        ("MySMS", "Send/spoof SMS from the command line.", "https://github.com/papusingh2sms/mysms", False),
        ("Lockphish", "Phish the device lock-screen PIN/pattern via a link.", "https://github.com/JasonJerry/lockphish", False),
        ("DroidCam / WishFish", "Phish for camera access through a shared link.", "https://github.com/kinghacker0/WishFish", False),
        ("EvilApp", "Bind a session-stealer into a legitimate Android app.", "https://github.com/crypticterminal/EvilApp", False),
        ("IDN Homograph Attack (EvilURL)", "Generate lookalike Unicode domains for phishing.", "https://github.com/UndeadSec/EvilURL", False),
        ("Knockmail (Email Verify)", "Verify whether an email address exists.", "https://github.com/heywoodlh/KnockMail", False),
        ("Hash Buster (Hash Cracking)", "Crack hashes using online lookup services.", "https://github.com/s0md3v/Hash-Buster", False),
        ("WifiJammer-NG (Deauth)", "Continuously deauthenticate clients from Wi-Fi.", "https://github.com/MisterBianco/wifijammer-ng", False),
        ("KawaiiDeauther", "Mass Wi-Fi deauthentication / beacon flooding.", "https://github.com/aryanrtm/KawaiiDeauther", False),
        ("Sherlock (SocialMedia Finder)", "Hunt a username across 400+ social networks.", "https://github.com/sherlock-project/sherlock", False),
        ("SocialScan", "Check email/username availability on online platforms.", "https://github.com/iojw/socialscan", False),
        ("Find SocialMedia By Facial Recognition", "Locate social profiles from a face image (social_mapper).", "https://github.com/Greenwolf/social_mapper", False),
        ("Find SocialMedia By UserName", "Find accounts reusing a given username (finduser).", "https://github.com/xHak9x/finduser", False),
        ("Debinject (Payload Injector)", "Inject malicious payloads into .deb packages.", "https://github.com/UndeadSec/Debinject", False),
        ("Pixload", "Hide payloads inside valid image files (polyglots).", "https://github.com/chinarulezzz/pixload", False),
        ("Gospider (Web Crawling)", "Fast web spider written in Go for recon.", "https://github.com/jaeles-project/gospider", False),
    ]},
]
