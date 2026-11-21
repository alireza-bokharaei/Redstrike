"""Extended MCP tool catalog for the 2.3 tool-execution layer.

The original 2.1 catalog hard-coded a handful of tools and *permanently* banned
certain argv flags in code. 2.3 replaces that with the prompt's model: a wider
catalog (105+ registered tools) where each tool's argv surface is governed by a
declarative policy row (``config/policies.yaml``) plus the engagement posture.

Design rules that remain true regardless of policy:

* argv is always an argument **vector** built by this module — never a shell
  string, never operator-supplied interpolation into a flag position;
* a tool runs only if its policy row is enabled *and* its binary exists;
* a tool's output is byte-capped by the executor;
* the target is always passed after ``--`` where the tool supports it, and is
  always the scope-validated pin, not a re-resolved name;
* ``refused_flags`` in a policy row are refused **in code** for that tool. A
  config edit can move a flag between ``allowed`` and ``refused``, but the
  argv builder refuses anything not explicitly allowed, so the default is deny.

The catalog is grouped so the API can report an honest "N registered tools"
number instead of a marketing claim.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Tools that only read data the operator already has (no network, no target).
OFFLINE_TOOLS = frozenset({"checksec", "elf_info", "ropgadget", "one_gadget", "readelf"})

# Tool families, used for reporting and for mode defaults.
CATEGORIES: dict[str, tuple[str, ...]] = {
    "dns": ("dig", "host", "whois", "dnsrecon", "dnsenum", "fierce", "subfinder", "amass",
            "dnsx", "massdns", "shuffledns", "puredns", "knockpy", "dnsgen"),
    "network": ("nmap", "masscan", "zmap", "naabu", "unicornscan", "hping3", "arp-scan",
                "netdiscover", "tcpdump", "responder", "nbtscan", "enum4linux", "smbmap",
                "smbclient", "rpcclient", "snmpwalk", "onesixtyone", "ike-scan"),
    "web": ("nikto", "nuclei", "gobuster", "ffuf", "feroxbuster", "dirsearch", "wfuzz",
            "whatweb", "wafw00f", "wpscan", "joomscan", "droopescan", "dirb", "katana",
            "hakrawler", "gau", "waybackurls", "httpx", "aquatone", "gospider", "arjun",
            "paramspider", "x8", "kiterunner", "graphql-cop", "jwt_tool", "corsy",
            "dalfox", "xsstrike", "commix", "crlfuzz", "smuggler", "h2csmuggler",
            "nuclei-templates-check", "sanitizer", "retire", "npm-audit", "trufflehog",
            "gitleaks", "git-dumper", "subjack", "tko-subs", "cmsmap", "testssl.sh",
            "sslyze", "sslscan", "sshaudit"),
    "injection": ("sqlmap", "nosqlmap", "ssrfmap", "xxeinjector", "ldapdomaindump"),
    "tls": ("testssl.sh", "sslyze", "sslscan", "tlssled", "ssldump"),
    "cloud": ("prowler", "scoutsuite", "cloud_enum", "s3scanner", "gcpbucketbrute",
              "azurehound", "trivy", "kube-bench", "kube-hunter", "pacuke"),
    "ad": ("bloodhound-python", "impacket-secretsdump", "impacket-GetNPUsers",
           "impacket-GetUserSPNs", "impacket-psexec", "impacket-wmiexec", "crackmapexec",
           "netexec", "ldapsearch", "kerbrute", "rubeus", "certipy"),
    "password": ("hydra", "medusa", "john", "hashcat", "patator", "crowbar", "ncrack"),
    "osint": ("theHarvester", "recon-ng", "sherlock", "holehe", "mosint", "spiderfoot",
              "metagoofil", "exiftool", "shodan", "censys", "fofa", "waybackpy"),
    "binary": ("checksec", "elf_info", "ropgadget", "one_gadget", "readelf", "objdump",
               "strings", "nm", "gdb", "ltrace", "strace", "patchelf", "pwntools"),
    "web_search": ("searchsploit", "exploitdb-sync", "cve-search", "nvd-lookup"),
    "reporting": ("pandoc", "markdown-link-check", "sarif-validate"),
    # 2.3.1: mobile, wireless and forensics were named by the referenced surfaces
    # and absent from the catalogue. They are ordinary governed entries: unknown
    # flags refused, unavailable binaries reported "unavailable", never faked.
    "mobile": ("adb", "frida", "objection", "apktool", "jadx", "mobsf",
               "drozer", "aapt", "class-dump"),
    "wireless": ("airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng", "wifite",
                 "bettercap", "kismet", "reaver", "bully", "hostapd-wpe", "mdk4",
                 "wash", "eaphammer", "pixiewps"),
    "forensics": ("volatility", "volatility3", "binwalk", "bulk_extractor", "foremost",
                  "scalpel", "sleuthkit", "fls", "icat", "autopsy", "photorec",
                  "testdisk", "dc3dd", "guymager", "regripper", "usn-journal-parser"),
}

# Flags that are refused for the named tool even if a policy row lists them.
# These are refusal-set seeds; the authoritative list lives in the policy row so
# an engagement can move a flag deliberately, but the builder still refuses
# anything it does not recognise as an allow-listed flag for that tool.
BASELINE_REFUSED_FLAGS: dict[str, tuple[str, ...]] = {
    "sqlmap": ("--os-shell", "--os-pwn", "--os-cmd", "--os-smbrelay", "--file-write",
               "--file-read", "--priv-esc"),
    "nmap": ("--script", "--script-args", "-iR", "-D", "--interactive", "--resume"),
    "nuclei": ("-interactsh-url", "-headless", "-fuzz"),
    "ffuf": ("-X", "--request", "-H", "-b"),
    "hydra": ("-M", "-I", "-t"),
    "masscan": ("--adapter-ip", "--adapter-mac", "--router-mac", "--source-ip"),
    "hping3": ("--flood", "--rand-source", "--spoof", "-a"),
    "responder": ("-I", "-i"),
    # Wireless: monitor-mode injection and deauth floods are the classic way to
    # hurt bystanders' traffic, so they stay refused regardless of policy.
    "aireplay-ng": ("--deauth", "-0", "--interactive", "-9"),
    "mdk4": ("m", "d", "a", "b"),
    "hostapd-wpe": (),
    "eaphammer": ("--hostile-portal", "--capture-essid", "--wpa3-transition"),
    # Mobile: silent app installation and live instrumentation of a device the
    # operator may not own are refused at the builder, not in a doc.
    "adb": ("install", "uninstall", "root", "remount", "push", "pull", "reboot", "sideload"),
    "frida": ("--spawn", "-f", "-U"),
}


@dataclass(frozen=True)
class CatalogEntry:
    name: str
    category: str
    binary: str
    description: str
    default_risk: str
    mode_flag: str = "ARGS"
    target_flag: str | None = None
    requires_root: bool = False
    requires_privileged_network: bool = False
    offline: bool = False
    needs_projectdiscovery: bool = False
    needs_pip: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "binary": self.binary,
            "description": self.description,
            "default_risk": self.default_risk,
            "offline": self.offline,
            "requires_root": self.requires_root,
            "needs_projectdiscovery": self.needs_projectdiscovery,
            "needs_pip": self.needs_pip,
        }


def _e(
    name: str,
    category: str,
    binary: str,
    description: str,
    risk: str = "medium",
    **kw: Any,
) -> CatalogEntry:
    return CatalogEntry(
        name=name, category=category, binary=binary, description=description,
        default_risk=risk, **kw,
    )


_CATALOG_ROWS: list[CatalogEntry] = [
    # ---------------- DNS ----------------
    _e("dig", "dns", "dig", "DNS record query", "low"),
    _e("host", "dns", "host", "Simple DNS lookup", "low"),
    _e("whois", "dns", "whois", "Registration data lookup", "low"),
    _e("dnsrecon", "dns", "dnsrecon", "DNS enumeration and zone transfer attempt", "medium"),
    _e("dnsenum", "dns", "dnsenum", "DNS enumeration", "medium"),
    _e("fierce", "dns", "fierce", "DNS reconnaissance", "medium"),
    _e("subfinder", "dns", "subfinder", "Passive subdomain discovery", "low"),
    _e("amass", "dns", "amass", "Attack-surface enumeration", "medium"),
    _e("dnsx", "dns", "dnsx", "Bulk DNS resolution", "low"),
    _e("massdns", "dns", "massdns", "High-volume DNS resolver", "medium"),
    _e("shuffledns", "dns", "shuffledns", "Mass DNS brute force with resolver rotation", "medium"),
    _e("puredns", "dns", "puredns", "DNS brute force and wildcard filtering", "medium"),
    _e("knockpy", "dns", "knockpy", "Subdomain scanning", "low"),
    _e("dnsgen", "dns", "dnsgen", "Subdomain permutation generator (offline)", "low", offline=True),
    # ---------------- network ----------------
    _e("nmap", "network", "nmap", "Service and port detection", "medium"),
    _e("masscan", "network", "masscan", "High-speed port scanner", "high"),
    _e("zmap", "network", "zmap", "Internet-scale scanner", "high", requires_privileged_network=True),
    _e("naabu", "network", "naabu", "Fast port scanner", "medium"),
    _e("unicornscan", "network", "unicornscan", "Asynchronous port scanner", "medium"),
    _e("hping3", "network", "hping3", "Custom packet crafting", "high", requires_root=True),
    _e("arp-scan", "network", "arp-scan", "Layer-2 host discovery", "medium", requires_root=True),
    _e("netdiscover", "network", "netdiscover", "Passive/active ARP discovery", "medium", requires_root=True),
    _e("tcpdump", "network", "tcpdump", "Packet capture", "medium", requires_root=True),
    _e("responder", "network", "responder", "LLMNR/NBT-NS/mDNS poisoner", "critical", requires_root=True),
    _e("nbtscan", "network", "nbtscan", "NetBIOS name scanning", "low"),
    _e("enum4linux", "network", "enum4linux", "SMB/NetBIOS enumeration", "medium"),
    _e("smbmap", "network", "smbmap", "SMB share enumeration", "medium"),
    _e("smbclient", "network", "smbclient", "SMB client access", "medium"),
    _e("rpcclient", "network", "rpcclient", "MS-RPC enumeration", "medium"),
    _e("snmpwalk", "network", "snmpwalk", "SNMP tree walk", "medium"),
    _e("onesixtyone", "network", "onesixtyone", "SNMP community brute force", "medium"),
    _e("ike-scan", "network", "ike-scan", "IPsec/IKE discovery", "medium"),
    # ---------------- web ----------------
    _e("nikto", "web", "nikto", "Web server scanner", "medium"),
    _e("nuclei", "web", "nuclei", "Template-driven vulnerability scanner", "medium"),
    _e("gobuster", "web", "gobuster", "Content and vhost discovery", "medium"),
    _e("ffuf", "web", "ffuf", "Fast web fuzzer", "medium"),
    _e("feroxbuster", "web", "feroxbuster", "Recursive content discovery", "medium"),
    _e("dirsearch", "web", "dirsearch", "Path brute forcing", "medium"),
    _e("wfuzz", "web", "wfuzz", "Web fuzzer", "medium"),
    _e("whatweb", "web", "whatweb", "Technology fingerprinting", "low"),
    _e("wafw00f", "web", "wafw00f", "WAF detection", "low"),
    _e("wpscan", "web", "wpscan", "WordPress vulnerability scanner", "medium"),
    _e("joomscan", "web", "joomscan", "Joomla scanner", "medium"),
    _e("droopescan", "web", "droopescan", "Drupal/CMS scanner", "medium"),
    _e("dirb", "web", "dirb", "Legacy content scanner", "medium"),
    _e("katana", "web", "katana", "Crawling framework", "low"),
    _e("hakrawler", "web", "hakrawler", "Fast web crawler", "low"),
    _e("gau", "web", "gau", "Fetch known URLs from archives", "low"),
    _e("waybackurls", "web", "waybackurls", "Wayback URL extraction", "low"),
    _e("httpx", "web", "httpx", "HTTP probing and fingerprinting", "low"),
    _e("aquatone", "web", "aquatone", "Visual site inventory", "low"),
    _e("gospider", "web", "gospider", "Fast web spider", "low"),
    _e("arjun", "web", "arjun", "HTTP parameter discovery", "medium"),
    _e("paramspider", "web", "paramspider", "Parameter mining from archives", "low"),
    _e("x8", "web", "x8", "Hidden parameter discovery", "medium"),
    _e("kiterunner", "web", "kr", "API endpoint brute forcing", "medium"),
    _e("graphql-cop", "web", "graphql-cop", "GraphQL security checks", "medium"),
    _e("jwt_tool", "web", "jwt_tool", "JWT analysis and tampering", "medium"),
    _e("corsy", "web", "corsy", "CORS misconfiguration scanner", "low"),
    _e("dalfox", "web", "dalfox", "XSS scanning", "medium"),
    _e("xsstrike", "web", "xsstrike", "XSS detection suite", "medium"),
    _e("commix", "web", "commix", "Command injection exploitation", "critical"),
    _e("crlfuzz", "web", "crlfuzz", "CRLF injection scanner", "medium"),
    _e("smuggler", "web", "smuggler", "HTTP request smuggling detection", "medium"),
    _e("h2csmuggler", "web", "h2csmuggler", "H2C smuggling checks", "medium"),
    _e("retire", "web", "retire", "Vulnerable JS library detection", "low"),
    _e("trufflehog", "web", "trufflehog", "Secret scanning", "low"),
    _e("gitleaks", "web", "gitleaks", "Git secret scanning", "low"),
    _e("git-dumper", "web", "git-dumper", "Exposed .git extraction", "medium"),
    _e("subjack", "web", "subjack", "Subdomain takeover detection", "medium"),
    _e("tko-subs", "web", "tko-subs", "Subdomain takeover checks", "medium"),
    _e("cmsmap", "web", "cmsmap", "CMS fingerprint and scan", "medium"),
    _e("sshaudit", "web", "sshaudit", "SSH server configuration audit", "low"),
    # ---------------- injection ----------------
    _e("sqlmap", "injection", "sqlmap", "SQL injection detection and exploitation", "critical"),
    _e("nosqlmap", "injection", "nosqlmap", "NoSQL injection testing", "high"),
    _e("ssrfmap", "injection", "ssrfmap", "SSRF exploitation", "high"),
    _e("xxeinjector", "injection", "xxeinjector", "XXE exploitation", "high"),
    _e("ldapdomaindump", "injection", "ldapdomaindump", "LDAP domain data dump", "high"),
    # ---------------- tls ----------------
    _e("testssl.sh", "tls", "testssl.sh", "Comprehensive TLS configuration test", "medium"),
    _e("sslyze", "tls", "sslyze", "TLS/SSL scanner", "low"),
    _e("sslscan", "tls", "sslscan", "TLS cipher enumeration", "low"),
    _e("tlssled", "tls", "tlssled", "TLS configuration grader", "low"),
    _e("ssldump", "tls", "ssldump", "TLS record decoder", "medium", requires_root=True),
    # ---------------- cloud ----------------
    _e("prowler", "cloud", "prowler", "Cloud security posture assessment", "medium"),
    _e("scoutsuite", "cloud", "scoutsuite", "Multi-cloud security auditing", "medium"),
    _e("cloud_enum", "cloud", "cloud_enum", "Public cloud asset enumeration", "medium"),
    _e("s3scanner", "cloud", "s3scanner", "S3 bucket enumeration", "medium"),
    _e("gcpbucketbrute", "cloud", "gcpbucketbrute", "GCS bucket discovery", "medium"),
    _e("azurehound", "cloud", "azurehound", "Azure AD enumeration", "high"),
    _e("trivy", "cloud", "trivy", "Container/filesystem vulnerability scan", "low"),
    _e("kube-bench", "cloud", "kube-bench", "Kubernetes CIS benchmark checks", "low"),
    _e("kube-hunter", "cloud", "kube-hunter", "Kubernetes penetration testing", "high"),
    _e("pacuke", "cloud", "pacuke", "Cloud audit checks", "low"),
    # ---------------- active directory ----------------
    _e("bloodhound-python", "ad", "bloodhound-python", "AD relationship collection", "high"),
    _e("impacket-secretsdump", "ad", "impacket-secretsdump", "Credential dumping", "critical"),
    _e("impacket-GetNPUsers", "ad", "impacket-GetNPUsers", "AS-REP roasting", "high"),
    _e("impacket-GetUserSPNs", "ad", "impacket-GetUserSPNs", "Kerberoasting", "high"),
    _e("impacket-psexec", "ad", "impacket-psexec", "Remote execution", "critical"),
    _e("impacket-wmiexec", "ad", "impacket-wmiexec", "Remote execution", "critical"),
    _e("crackmapexec", "ad", "crackmapexec", "AD credential spraying and enumeration", "critical"),
    _e("netexec", "ad", "netexec", "AD exploitation framework", "critical"),
    _e("ldapsearch", "ad", "ldapsearch", "LDAP directory queries", "low"),
    _e("kerbrute", "ad", "kerbrute", "Kerberos brute force", "high"),
    _e("rubeus", "ad", "rubeus", "Kerberos abuse toolkit", "critical"),
    _e("certipy", "ad", "certipy", "ADCS abuse", "high"),
    # ---------------- password ----------------
    _e("hydra", "password", "hydra", "Online credential testing", "critical"),
    _e("medusa", "password", "medusa", "Parallel login brute force", "critical"),
    _e("john", "password", "john", "Offline hash cracking", "high"),
    _e("hashcat", "password", "hashcat", "GPU hash cracking", "high"),
    _e("patator", "password", "patator", "Multi-protocol brute force", "critical"),
    _e("crowbar", "password", "crowbar", "Brute force for RDP/VNC/SSH", "critical"),
    _e("ncrack", "password", "ncrack", "Network authentication cracking", "critical"),
    # ---------------- osint ----------------
    _e("theHarvester", "osint", "theHarvester", "OSINT email/host harvesting", "low"),
    _e("recon-ng", "osint", "recon-ng", "OSINT framework", "low"),
    _e("sherlock", "osint", "sherlock", "Username enumeration", "low"),
    _e("holehe", "osint", "holehe", "Email registration checks", "medium"),
    _e("mosint", "osint", "mosint", "Email OSINT", "low"),
    _e("spiderfoot", "osint", "spiderfoot", "OSINT automation", "medium"),
    _e("metagoofil", "osint", "metagoofil", "Metadata harvesting", "low"),
    _e("exiftool", "osint", "exiftool", "Metadata extraction (local files)", "low", offline=True),
    _e("shodan", "osint", "shodan", "Shodan CLI queries", "low", needs_pip=True),
    _e("censys", "osint", "censys", "Censys CLI queries", "low", needs_pip=True),
    _e("fofa", "osint", "fofa", "FOFA CLI queries", "low", needs_pip=True),
    _e("waybackpy", "osint", "waybackpy", "Wayback snapshot retrieval", "low", needs_pip=True),
    # ---------------- binary ----------------
    _e("checksec", "binary", "checksec", "ELF hardening flags (pwntools entry point)", "low",
       offline=True, needs_pip=True),
    # In-process: the Gateway parses ELF headers itself (see binary_triage.py);
    # there is no external binary to resolve, so the sentinel is explicit.
    _e("elf_info", "binary", "in-process:binary_triage", "Local ELF metadata (in-tree parser)",
       "low", offline=True),
    _e("ropgadget", "binary", "ROPgadget", "ROP gadget discovery", "medium", offline=True, needs_pip=True),
    _e("one_gadget", "binary", "one_gadget", "glibc one-gadget search", "medium", offline=True),
    _e("readelf", "binary", "readelf", "ELF header/section dump", "low", offline=True),
    _e("objdump", "binary", "objdump", "Disassembly and section dump", "low", offline=True),
    _e("strings", "binary", "strings", "Printable string extraction", "low", offline=True),
    _e("nm", "binary", "nm", "Symbol table dump", "low", offline=True),
    _e("gdb", "binary", "gdb", "Debugger / crash analysis", "high", offline=True),
    _e("ltrace", "binary", "ltrace", "Library call tracing", "medium", offline=True),
    _e("strace", "binary", "strace", "Syscall tracing", "medium", offline=True),
    _e("patchelf", "binary", "patchelf", "ELF interpreter/RPATH patching", "medium", offline=True),
    # ``pwn`` is a Python library, not a PATH binary: resolution is importable-based
    # (see gateway/pwntools_layer.py), never a shutil.which() success.
    _e("pwntools", "binary", "python-lib:pwn", "pwntools exploit development toolkit", "high",
       offline=True, needs_pip=True),
    # ---------------- web search / vuln intel ----------------
    _e("searchsploit", "web_search", "searchsploit", "Exploit-DB search", "low", offline=True),
    _e("exploitdb-sync", "web_search", "searchsploit", "Update the local Exploit-DB mirror", "low"),
    _e("cve-search", "web_search", "cve-search", "Local CVE database query", "low", offline=True),
    _e("nvd-lookup", "web_search", "nvd-lookup", "NVD API lookup by CVE id", "low"),
    # ---------------- reporting ----------------
    _e("pandoc", "reporting", "pandoc", "Report format conversion", "low", offline=True),
    _e("markdown-link-check", "reporting", "markdown-link-check", "Validate report links", "low"),
    _e("sarif-validate", "reporting", "sarif-validate", "Validate SARIF output", "low", offline=True),
    # ---------------- mobile (authorised app assessment) ----------------
    # Everything here takes a *local artifact* (an APK/IPA already in the
    # artifact root) or an explicitly listed device, never an arbitrary host.
    _e("adb", "mobile", "adb", "Android device bridge: device inventory and logcat", "medium"),
    _e("frida", "mobile", "frida", "Dynamic instrumentation of a listed process", "high"),
    _e("objection", "mobile", "objection", "Runtime mobile exploration on a listed device", "high",
       needs_pip=True),
    _e("apktool", "mobile", "apktool", "APK decode/rebuild (manifest and resources)", "low",
       offline=True),
    _e("jadx", "mobile", "jadx", "Dex-to-Java decompilation", "low", offline=True),
    _e("mobsf", "mobile", "mobsf", "Local MobSF static/dynamic scan of an artifact", "medium"),
    _e("drozer", "mobile", "drozer", "Android attack-surface enumeration via agent", "medium",
       needs_pip=True),
    _e("aapt", "mobile", "aapt", "APK manifest and permission dump", "low", offline=True),
    _e("class-dump", "mobile", "class-dump", "Objective-C class metadata from a Mach-O", "low",
       offline=True),
    # ---------------- wireless (authorised RF engagement) ----------------
    _e("airmon-ng", "wireless", "airmon-ng", "Monitor-mode interface inventory", "medium",
       requires_root=True),
    _e("airodump-ng", "wireless", "airodump-ng", "Passive capture inventory", "medium",
       requires_root=True),
    _e("aireplay-ng", "wireless", "aireplay-ng", "Frame injection (deauth refused)", "high",
       requires_root=True),
    _e("aircrack-ng", "wireless", "aircrack-ng", "Offline capture key recovery", "medium",
       offline=True),
    _e("wifite", "wireless", "wifite", "Assisted wireless audit driver", "high",
       requires_root=True),
    _e("bettercap", "wireless", "bettercap", "MITM/802.11 assessment framework", "high",
       requires_root=True),
    _e("kismet", "wireless", "kismet", "Passive wireless survey", "medium", requires_root=True),
    _e("reaver", "wireless", "reaver", "WPS PIN audit", "high", requires_root=True),
    _e("bully", "wireless", "bully", "WPS PIN audit (alternate)", "high", requires_root=True),
    _e("hostapd-wpe", "wireless", "hostapd-wpe", "Rogue AP for EAP credential capture", "high",
       requires_root=True),
    _e("mdk4", "wireless", "mdk4", "802.11 fuzzing (flood verbs refused)", "high",
       requires_root=True),
    _e("wash", "wireless", "wash", "WPS-enabled AP discovery", "medium", requires_root=True),
    _e("eaphammer", "wireless", "eaphammer", "EAP-based rogue AP assessment", "high",
       requires_root=True),
    _e("pixiewps", "wireless", "pixiewps", "Offline WPS pixie-dust recovery", "medium",
       offline=True),
    # ---------------- forensics (post-engagement evidence work) ----------------
    _e("volatility", "forensics", "volatility", "Memory image analysis (v2 CLI)", "low",
       offline=True, needs_pip=True),
    _e("volatility3", "forensics", "vol.py", "Memory image analysis (v3 CLI)", "low",
       offline=True, needs_pip=True),
    _e("binwalk", "forensics", "binwalk", "Firmware/file signature carving", "low", offline=True),
    _e("bulk_extractor", "forensics", "bulk_extractor", "Stream carving for artefacts", "low",
       offline=True),
    _e("foremost", "forensics", "foremost", "File carving by header/footer", "low", offline=True),
    _e("scalpel", "forensics", "scalpel", "Configurable file carving", "low", offline=True),
    _e("sleuthkit", "forensics", "icat", "Disk image file extraction (TSK suite)", "low",
       offline=True),
    _e("fls", "forensics", "fls", "List filesystem entries in an image", "low", offline=True),
    _e("icat", "forensics", "icat", "Extract a file by inode from an image", "low", offline=True),
    _e("autopsy", "forensics", "autopsy", "Autopsy CLI case ingestion", "low", offline=True),
    _e("photorec", "forensics", "photorec", "Photo/file recovery from an image", "low", offline=True),
    _e("testdisk", "forensics", "testdisk", "Partition recovery/analysis", "medium", offline=True),
    _e("dc3dd", "forensics", "dc3dd", "Forensically-sound imaging", "low", offline=True),
    _e("guymager", "forensics", "guymager", "Acquisition front-end (CLI absent is honest)", "low",
       offline=True),
    _e("regripper", "forensics", "rip.pl", "Windows registry hive parsing", "low", offline=True),
    _e("usn-journal-parser", "forensics", "usn.py", "USN journal parsing", "low", offline=True),
]

CATALOG: dict[str, CatalogEntry] = {entry.name: entry for entry in _CATALOG_ROWS}


def catalog_size() -> int:
    return len(CATALOG)


def grouped() -> dict[str, list[dict[str, Any]]]:
    """Tools grouped by category, matching the grouped-MCP surface."""
    out: dict[str, list[dict[str, Any]]] = {}
    for entry in _CATALOG_ROWS:
        out.setdefault(entry.category, []).append(entry.to_dict())
    return {name: sorted(items, key=lambda x: x["name"]) for name, items in sorted(out.items())}


def list_tools(category: str | None = None) -> list[dict[str, Any]]:
    rows = [e.to_dict() for e in _CATALOG_ROWS]
    if category:
        rows = [r for r in rows if r["category"] == category]
    return sorted(rows, key=lambda x: x["name"])


def get_entry(name: str) -> CatalogEntry | None:
    return CATALOG.get(name)


def category_counts() -> dict[str, int]:
    counts: dict[str, int] = {}
    for entry in _CATALOG_ROWS:
        counts[entry.category] = counts.get(entry.category, 0) + 1
    return counts


# =============================================================================
# argv construction
# =============================================================================
#: Tools whose argv accepts ``--`` as an end-of-options marker before the target.
DASHDASH_TOOLS: frozenset[str] = frozenset(
    {"nmap", "masscan", "naabu", "nikto", "nuclei", "httpx", "ffuf", "gobuster",
     "feroxbuster", "dirsearch", "wfuzz", "whatweb", "wafw00f", "katana", "gospider",
     "subfinder", "dnsx", "dig", "host", "whois", "testssl.sh", "sslyze", "sslscan"}
)

#: Tools whose target must be passed as ``key=value`` after the flags.
TARGET_EQUALS_TOOLS: frozenset[str] = frozenset({"ffuf", "wfuzz", "sqlmap"})

#: Absolute ceiling on operator-supplied flag count, independent of policy.
MAX_FLAGS = 12
#: Characters that must never appear in a flag token.
_FLAG_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.:=/@%+,-]{1,120}$")


#: Binaries that are not PATH-resolvable and must never count as "installed".
NON_BINARY_PREFIXES: tuple[str, ...] = ("in-process:", "python-lib:")


def is_path_binary(entry: CatalogEntry) -> bool:
    """True when the entry names a real binary that ``shutil.which`` can find."""
    return not entry.binary.startswith(NON_BINARY_PREFIXES)


def takes_artifact(entry: CatalogEntry) -> bool:
    """True when the tool's argument is a local file, not a network target.

    Binary tooling (readelf, objdump, strings, nm, checksec, …) reads a file that
    the operator already has. Passing a host name to ``readelf`` is a category
    error, and treating it as a scope-checked network target would be worse: it
    would imply the tool reaches the network when it never does.
    """
    return entry.category in {"binary", "forensics"} or (
        entry.category == "mobile" and entry.offline
    )


class ArgvBuildError(ValueError):
    """The requested argv cannot be built safely."""


def _clean_flag(token: str) -> str:
    text = str(token).strip()
    if not text or not _FLAG_TOKEN_RE.match(text):
        raise ArgvBuildError(f"Flag token {token!r} contains characters or structure that are not allowed.")
    return text


def build_argv(
    tool_name: str,
    target: str,
    *,
    flags: list[str] | None = None,
    allowed_flags: list[str] | tuple[str, ...] | None = None,
    refused_flags: list[str] | tuple[str, ...] | None = None,
    target_flag: str | None = None,
    extra_positional: list[str] | None = None,
    binary_path: str | None = None,
) -> list[str]:
    """Build a validated argv vector for a catalogued tool.

    The default is deny: a flag is accepted only when it appears in
    ``allowed_flags`` and is not in ``refused_flags`` (which always wins). The
    baseline refusal set in :data:`BASELINE_REFUSED_FLAGS` applies on top, so
    even a permissive policy row cannot re-enable e.g. ``sqlmap --os-shell``
    unless a maintainer edits this module deliberately.

    Raises :class:`ArgvBuildError` with an auditable reason on any violation.
    """
    entry = get_entry(tool_name)
    if entry is None:
        raise ArgvBuildError(f"Tool '{tool_name}' is not in the catalog.")

    allowed = [str(f) for f in (allowed_flags if allowed_flags is not None else [])]
    denied = {str(f) for f in (refused_flags or [])} | set(BASELINE_REFUSED_FLAGS.get(tool_name, ()))
    raw_flags = [str(f) for f in (flags or [])]
    if len(raw_flags) > MAX_FLAGS:
        raise ArgvBuildError(f"At most {MAX_FLAGS} flags may be passed to '{tool_name}'.")
    if not raw_flags and allowed:
        raw_flags = [allowed[0]]

    clean: list[str] = []
    for token in raw_flags:
        candidate = _clean_flag(token)
        base = candidate.split("=", 1)[0]
        if candidate in denied or base in denied:
            raise ArgvBuildError(
                f"'{tool_name} {candidate}' is refused by policy (destructive, evasive, "
                "or file-system affecting)."
            )
        if allowed and candidate not in allowed and base not in allowed:
            raise ArgvBuildError(
                f"'{tool_name} {candidate}' is not in this engagement's allowed_flags. "
                f"Allowed: {sorted(allowed)}."
            )
        if candidate not in clean:
            clean.append(candidate)

    cleaned_target = str(target).strip()
    if not cleaned_target or cleaned_target.startswith("-"):
        raise ArgvBuildError("Target is empty or looks like a flag.")
    if any(ch in cleaned_target for ch in " \t\r\n;&|$`<>\"'\\"):
        raise ArgvBuildError("Target contains whitespace, quotes, or shell metacharacters.")
    if takes_artifact(entry) and (
        "/" in cleaned_target or "\\" in cleaned_target or cleaned_target in {".", ".."}
    ):
        raise ArgvBuildError(
            f"'{tool_name}' takes an artifact name inside the configured artifact root, "
            "not a path."
        )

    positional = [_clean_flag(p) for p in (extra_positional or [])]
    argv = [binary_path or entry.binary]
    argv += positional
    argv += clean

    flag_name = target_flag or entry.target_flag
    if flag_name:
        argv += [flag_name, cleaned_target]
    elif tool_name in TARGET_EQUALS_TOOLS and tool_name == "sqlmap":
        argv += ["-u", cleaned_target]
    elif tool_name in TARGET_EQUALS_TOOLS:
        argv += [f"{'url' if tool_name != 'ffuf' else 'u'}={cleaned_target}"]
    elif tool_name in DASHDASH_TOOLS:
        argv += ["--", cleaned_target]
    else:
        argv += [cleaned_target]
    return argv
