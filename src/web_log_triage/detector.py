from dataclasses import dataclass
from collections import defaultdict
from typing import Iterable, Optional
from web_log_triage.parser import LogEntry
import re

@dataclass
class ThreatMatch:
    category: str
    severity: str
    description: str
    matched_payload: str
    entry: LogEntry
    mitre_id: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None

@dataclass
class SignatureRule:
    name: str
    category: str
    severity: str
    description: str
    pattern: re.Pattern
    target_field: str="decoded_uri"  # default target field is decoded_uri
    mitre_id: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None

### signature rules for various types of attacks
# SQLi signature rule
sqlli_rule = SignatureRule(
    name="SQL Injection",
    category="SQLi",
    severity="High",
    description="Detects SQL injection attempts in the URI.",
    pattern=re.compile(
    r"(?i)(\bUNION\b\s+(?:ALL\s+)?\bSELECT\b|"
    r"\bSELECT\b\s+.*\bFROM\b|"
    r"\bINSERT\b\s+INTO\b|"
    r"\bDROP\b\s+(?:TABLE|DATABASE)\b|"
    r"'\s*OR\s+['\d\w]+=['\d\w]+|"
    r"--\s*|/\*|\*/|"
    r"@@version|CHAR\(|CONVERT\()"
    ),
    target_field="decoded_uri",
    mitre_id="T1190",
    mitre_technique="Exploit Public-Facing Application",
    mitre_tactic="Initial Access"
)

# local file inclusion/path trversal signature rule
lfi_rule = SignatureRule(
    name="Local File Inclusion",
    category="LFI",
    severity="High",
    description="Detects local file inclusion or path traversal attempts in the URI.",
    pattern=re.compile(r"(?i)(\.\./|\.\.\\|/etc/passwd|/proc/self/environ|/var/www/html|/boot.ini)"),
    target_field="decoded_uri",
    mitre_id="T1190",
    mitre_technique="Exploit Public-Facing Application",
    mitre_tactic="Initial Access"
)

# remote code execution signature rule
rce_rule = SignatureRule(
    name="Remote Code Execution",
    category="RCE",
    severity="Critical",
    description="Detects remote code execution attempts in the URI.",
    pattern=re.compile(r"(?i)(\bexec\b|\bsystem\b|\bpopen\b|\bpassthru\b|\beval\b|\bwhoami\b|\bid\b\s*;|;\s*\bid\b|\bcat\s+/etc/|\bphpinfo\b)"),
    target_field="decoded_uri",
    mitre_id="T1059.004",
    mitre_technique="Command and Scripting Interpreter: Unix Shell",
    mitre_tactic="Execution"
)

# malicious scanner user agent signature rule
scanner_rule = SignatureRule(
    name="Malicious Scanner",
    category="Scanner",
    severity="Medium",
    description="Detects known malicious scanner user agents.",
    pattern=re.compile(r"(?i)\b(nmap|nikto|sqlmap|acunetix|nessus|openvas|fimap|dirbuster|gobuster|ffuf|wfuzz)\b"),
    target_field="user_agent",
    mitre_id="T1595.002",
    mitre_technique="Active Scanning: Vulnerability Scanning",
    mitre_tactic="Reconnaissance"
)

# sensitive file access signature rule
sensitive_file_rule = SignatureRule(
    name="Sensitive File Access",
    category="Sensitive File Access",
    severity="High",
    description="Detects attempts to access sensitive files.",
    pattern=re.compile(r"(?i)(/\.env|/\.git|/etc/passwd|/etc/shadow|/proc/self/environ|/boot\.ini|win\.ini|wp-config\.php)"),
    target_field="decoded_uri",
    mitre_id="T1552.001",
    mitre_technique="Unsecured Credentials: Credentials in Files",
    mitre_tactic="Credential Access"
)

# XSS signature rule
xss_rule = SignatureRule(
    name="Cross-Site Scripting",
    category="XSS",
    severity="High",
    description="Detects cross-site scripting attempts in the URI.",
    pattern=re.compile(r"(?i)(<script\b>|</script>|javascript:|onerror\s*=|onload\s*=|alert\(|prompt\(|confirm\()"),
    target_field="decoded_uri",
    mitre_id="T1059.007",
    mitre_technique="Command and Scripting Interpreter: JavaScript",
    mitre_tactic="Execution"
)

# cloud metadata probing signature rule
cloud_metadata_rule = SignatureRule(
    name="Cloud Metadata Probing",
    category="Cloud Metadata Probing",
    severity="Critical",
    description="Detects attempts to access cloud metadata.",
    pattern=re.compile(r"(?i)(169\.254\.169\.254|/latest/meta-data/?)"),
    target_field="decoded_uri",
    mitre_id="T1552.005",
    mitre_technique="Unsecured Credentials: Cloud Instance Metadata API",
    mitre_tactic="Credential Access"
)

### matching function to check log entry against signature rules
RULES: list[SignatureRule] = [
    sqlli_rule,
    lfi_rule,
    rce_rule,
    scanner_rule,
    sensitive_file_rule,
    xss_rule,
    cloud_metadata_rule
]

def check_signatures(entry: LogEntry, rules: Optional[list[SignatureRule]] = None) -> list[ThreatMatch]:
    if rules is None:
        rules = RULES
    matches: list[ThreatMatch] = []
    for rule in rules:
        # dynamically get the target field from the log entry
        target_value = getattr(entry, rule.target_field, "")
        match = rule.pattern.search(target_value)
        if match:
            matches.append(
                ThreatMatch(
                    category=rule.category,
                    severity=rule.severity,
                    description=rule.description,
                    matched_payload=match.group(0),
                    entry=entry,
                    mitre_id=rule.mitre_id,
                    mitre_technique=rule.mitre_technique,
                    mitre_tactic=rule.mitre_tactic
                )
            )
    return matches

### brute force detection based on failed login attempts
def detect_brute_force(
        entries: Iterable[LogEntry],
        threshold: int = 3,
        status_codes: tuple[int] = (401, 403, 404)
) -> list[ThreatMatch]:
    failed_requests_by_ip = defaultdict(list)
    for entry in entries:
        if entry.status_code in status_codes:
            failed_requests_by_ip[entry.ip].append(entry)

    matches: list[ThreatMatch] = []
    for ip, failed_list in failed_requests_by_ip.items():
        if len(failed_list) >= threshold:
            matches.append(
                ThreatMatch(
                    category="Brute Force",
                    severity="High",
                    description=f"Detected {len(failed_list)} failed requests from IP {ip}.",
                    matched_payload=f"Potential directory brute-force: {len(failed_list)} | Sample targets: {','.join(e.decoded_uri for e in failed_list[:3])}",
                    entry=failed_list[-1], # use the last entry as a representative sample
                    mitre_id="T1595.003",
                    mitre_technique="Active Scanning: Wordlist Scanning",
                    mitre_tactic="Reconnaissance"
                    )
                )
    return matches


### unified function to detect threats in log entries
class ThreatDetector:
    def __init__(self, rules: Optional[list[SignatureRule]] = None, brute_force_threshold: int = 3):
        self.rules = rules or RULES
        self.brute_force_threshold = brute_force_threshold

    def analyze(self, entries: Iterable[LogEntry]) -> list[ThreatMatch]:
        # Runs both signature-based and brute-force detection on the provided log entries
        entry_list = list(entries) # pass multiple checks with generator
        all_matches: list[ThreatMatch] = []

        # per-entry signature detection
        for entry in entry_list:
            all_matches.extend(check_signatures(entry, self.rules))

        # multi-entry behavioral detection
        brute_force_matches = detect_brute_force(entry_list, threshold=self.brute_force_threshold, status_codes=(401, 403, 404))
        all_matches.extend(brute_force_matches)

        return all_matches