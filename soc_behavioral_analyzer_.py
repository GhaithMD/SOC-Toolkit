"""
SOC Behavioral Analyzer - L1 Investigation Assistant
----------------------------------------------------
Paste SIEM alerts from: Elastic, Security Onion, AlienVault, QRadar, Splunk,
Wazuh, CrowdStrike, Darktrace, etc. Get: IOC extraction, FP/TP assessment,
MITRE ATT&CK mapping, severity, and L1 checklist.
"""

import re
import json
import argparse
from collections import defaultdict
from datetime import datetime

# ==========================================
# IOC REGEX
# ==========================================

IP_REGEX = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
DOMAIN_REGEX = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
URL_REGEX = r"https?://[^\s\"'<>]+"
HASH_MD5 = r"\b[a-fA-F0-9]{32}\b"
HASH_SHA = r"\b[a-fA-F0-9]{40,64}\b"
HASH_REGEX = r"\b[a-fA-F0-9]{32,64}\b"
EMAIL_REGEX = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
USERNAME_REGEX = r"user(?:name)?[=\s:]+([A-Za-z0-9_\-\\\.]+)"
FILE_PATH_REGEX = r"(?:[A-Za-z]:)?[\\/][\w\\/\.\-]+\.(?:exe|dll|ps1|bat|vbs|js|scr)"

# Known benign / FP-prone patterns (reduce TP confidence)
FP_INDICATORS = [
    "windows update", "microsoft", "svchost", "system", "local service",
    "health check", "monitoring", "backup", "scheduled task", "legitimate",
    "known good", "whitelist", "internal scan", "vulnerability scan",
    "nessus", "qualys", "rapid7", "tanium", "crowdstrike sensor",
    "defender", "antivirus", "windows defender", "wdfmgr"
]

# Strong TP indicators (increase confidence)
TP_INDICATORS = [
    "c2", "command and control", "beacon", "ransomware", "malware",
    "credential dump", "mimikatz", "psexec", "lateral movement",
    "privilege escalation", "persistence", "suspicious powershell",
    "encoded command", "bypass", "injection", "exploit"
]

# ==========================================
# SIEM FORMAT DETECTION & NORMALIZATION
# ==========================================

def detect_siem_format(raw_text):
    """Detect which SIEM/platform the pasted content likely came from."""
    text_lower = raw_text[:2000].lower()
    if '"rule":' in text_lower and '"@timestamp"' in text_lower:
        return "elastic"
    if '"event":' in text_lower and '"@timestamp"' in text_lower:
        return "elastic"
    if "sourcetype" in text_lower and ("splunk" in text_lower or "index=" in text_lower):
        return "splunk"
    if "qradar" in text_lower or "ariel" in text_lower or "logsourceid" in text_lower:
        return "qradar"
    if "alienvault" in text_lower or "otx" in text_lower or "pulse" in text_lower:
        return "alienvault"
    if "wazuh" in text_lower or '"agent":' in text_lower and '"rule":' in text_lower:
        return "wazuh"
    if "crowdstrike" in text_lower or "falcon" in text_lower or "cid" in text_lower:
        return "crowdstrike"
    if "darktrace" in text_lower or "antigena" in text_lower:
        return "darktrace"
    if "securityonion" in text_lower or "suricata" in text_lower or "zeek" in text_lower:
        return "security_onion"
    # Try JSON array/object
    stripped = raw_text.strip()
    if (stripped.startswith("{") or stripped.startswith("[")) and ("}" in stripped or "]" in stripped):
        try:
            j = json.loads(raw_text)
            return "json_generic"
        except json.JSONDecodeError:
            pass
    return "raw"

def normalize_alert_text(raw_text, fmt):
    """Extract searchable text from known SIEM formats."""
    if fmt == "raw":
        return raw_text
    try:
        if fmt == "elastic" or fmt == "json_generic":
            data = json.loads(raw_text) if isinstance(raw_text, str) else raw_text
            if isinstance(data, list):
                parts = [json.dumps(e) if isinstance(e, dict) else str(e) for e in data]
                return " ".join(parts)
            if isinstance(data, dict):
                return json.dumps(data)
        return raw_text
    except (json.JSONDecodeError, TypeError):
        return raw_text

# ==========================================
# DETECTION PATTERNS + MITRE MAPPING (expanded)
# ==========================================

DETECTIONS = {
    "Brute Force": {
        "keywords": ["brute", "login failed", "invalid password", "hydra", "authentication failure", "failed logon", "logon_failure", "4625"],
        "mitre": "T1110 - Brute Force",
        "weight": 3
    },
    "Port Scan": {
        "keywords": ["scan", "nmap", "masscan", "port sweep", "reconnaissance", "port scan"],
        "mitre": "T1046 - Network Service Discovery",
        "weight": 2
    },
    "Credential Access": {
        "keywords": ["pwd=", "password=", "credential", "ntlm", "logon_failure", "lsass", "mimikatz", "sekurlsa", "credential dump"],
        "mitre": "T1003 - Credential Dumping",
        "weight": 4
    },
    "Web Attack": {
        "keywords": ["sqlmap", "union select", "' or 1=1", "<script>", "wp-login", "sqli", "xss", "path traversal"],
        "mitre": "T1190 - Exploit Public-Facing Application",
        "weight": 3
    },
    "Malware/C2": {
        "keywords": ["c2", "beacon", "payload", "ransomware", "trojan", "command and control", "callback", "cnc"],
        "mitre": "T1071 - Application Layer Protocol",
        "weight": 5
    },
    "Privilege Escalation": {
        "keywords": ["sudo", "admin access granted", "privilege escalation", "elevation", "uac bypass"],
        "mitre": "T1068 - Exploitation for Privilege Escalation",
        "weight": 4
    },
    "Lateral Movement": {
        "keywords": ["smb", "psexec", "remote service", "wmi", "winrm", "lateral movement", "pass the hash"],
        "mitre": "T1021 - Remote Services",
        "weight": 4
    },
    "Persistence": {
        "keywords": ["registry run", "scheduled task", "startup", "persistence", "boot", "logon script"],
        "mitre": "T1547 - Boot or Logon Autostart Execution",
        "weight": 4
    },
    "Execution": {
        "keywords": ["powershell", "encoded", "invoke-", "script block", "wscript", "cscript", "mshta"],
        "mitre": "T1059 - Command and Scripting Interpreter",
        "weight": 4
    },
    "Defense Evasion": {
        "keywords": ["disable def", "tampering", "clear log", "event log", "obfuscation", "bypass"],
        "mitre": "T1562 - Impair Defenses",
        "weight": 4
    },
    "Reconnaissance": {
        "keywords": ["whoami", "systeminfo", "ipconfig", "nslookup", "net user", "net group"],
        "mitre": "T1087 - Account Discovery",
        "weight": 2
    },
    "Exfiltration": {
        "keywords": ["exfil", "upload", "data transfer", "large transfer", "external upload"],
        "mitre": "T1048 - Exfiltration Over Alternative Protocol",
        "weight": 5
    },
}

# ==========================================
# SPLIT ALERTS (multi-format)
# ==========================================

def split_alerts(raw_text, fmt="raw"):
    if fmt == "elastic" or fmt == "json_generic":
        try:
            data = json.loads(raw_text)
            if isinstance(data, list):
                return [json.dumps(e) for e in data]
            return [raw_text]
        except (json.JSONDecodeError, TypeError):
            pass
    separators = ["\n\n", "\r\n\r\n", "-----", "Alert:", "Event ID"]
    alerts = [raw_text]
    for sep in separators:
        if sep in raw_text:
            alerts = raw_text.split(sep)
            break
    return [a.strip() for a in alerts if a.strip()]


# Benign domain/IP patterns to flag (optional filter in report)
BENIGN_DOMAINS = {"microsoft.com", "windows.com", "windowsupdate.com", "google.com", "googleapis.com", "apple.com", "amazonaws.com"}
PRIVATE_IP_PREFIX = ("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.")

# ==========================================
# IOC EXTRACTION
# ==========================================

def extract_iocs(text):
    ips = list(set(re.findall(IP_REGEX, text)))
    domains = list(set(re.findall(DOMAIN_REGEX, text)))
    urls = list(set(re.findall(URL_REGEX, text)))
    hashes = list(set(re.findall(HASH_REGEX, text)))
    # Filter 32-64 hex to avoid non-file hashes (e.g. IDs)
    hashes = [h for h in hashes if len(h) in (32, 40, 64)]
    emails = list(set(re.findall(EMAIL_REGEX, text)))
    users = list(set(re.findall(USERNAME_REGEX, text, re.IGNORECASE)))
    file_paths = list(set(re.findall(FILE_PATH_REGEX, text, re.IGNORECASE)))
    return {
        "ips": ips,
        "domains": domains,
        "urls": urls,
        "hashes": hashes,
        "emails": emails,
        "users": users,
        "file_paths": file_paths,
        "public_ips": [ip for ip in ips if not ip.startswith(PRIVATE_IP_PREFIX)],
        "private_ips": [ip for ip in ips if ip.startswith(PRIVATE_IP_PREFIX)],
    }


# ==========================================
# ANALYSIS ENGINE
# ==========================================

def analyze(alerts):
    findings = []
    total_score = 0
    ip_counter = defaultdict(int)
    full_text = " ".join(alerts).lower()

    for alert in alerts:
        lower_alert = alert.lower()
        ips_found = re.findall(IP_REGEX, alert)
        for ip in ips_found:
            ip_counter[ip] += 1

        for name, data in DETECTIONS.items():
            for keyword in data["keywords"]:
                if keyword in lower_alert:
                    findings.append({
                        "type": name,
                        "mitre": data["mitre"],
                        "keyword": keyword,
                        "weight": data["weight"]
                    })
                    total_score += data["weight"]
                    break

    for ip, count in ip_counter.items():
        if count >= 3:
            findings.append({
                "type": "Repeated Suspicious Activity",
                "mitre": "T1498 - Network DoS / Recon",
                "keyword": f"{count} events from {ip}",
                "weight": 3
            })
            total_score += 3

    return findings, total_score, full_text


# ==========================================
# FALSE POSITIVE / TRUE POSITIVE ASSESSMENT
# ==========================================

def assess_fp_tp(full_text_lower, findings, score):
    """
    Returns: verdict ("TRUE_POSITIVE", "LIKELY_TRUE_POSITIVE", "UNCERTAIN", "LIKELY_FALSE_POSITIVE", "FALSE_POSITIVE"),
             confidence (0-100), reasons list.
    """
    reasons = []
    fp_score = 0
    tp_score = 0

    for phrase in FP_INDICATORS:
        if phrase in full_text_lower:
            fp_score += 2
            reasons.append(f"FP indicator: '{phrase}'")

    for phrase in TP_INDICATORS:
        if phrase in full_text_lower:
            tp_score += 3
            reasons.append(f"TP indicator: '{phrase}'")

    # Score-based: high score suggests TP
    if score >= 12:
        tp_score += 2
        reasons.append("High risk score suggests meaningful detection")
    elif score <= 3 and not findings:
        fp_score += 2
        reasons.append("Low/no detection score")

    # Many IOCs can indicate real incident (we don't have IOC count here; could pass it)
    # Multiple MITRE techniques = more likely TP
    if findings:
        mitre_count = len(set(f["mitre"] for f in findings))
        if mitre_count >= 2:
            tp_score += 1
            reasons.append("Multiple MITRE techniques observed")

    # Verdict
    delta = tp_score - fp_score
    if delta >= 4:
        verdict = "TRUE_POSITIVE"
        confidence = min(90, 60 + delta * 5)
    elif delta >= 2:
        verdict = "LIKELY_TRUE_POSITIVE"
        confidence = min(75, 50 + delta * 5)
    elif delta <= -4:
        verdict = "FALSE_POSITIVE"
        confidence = min(85, 50 + abs(delta) * 5)
    elif delta <= -2:
        verdict = "LIKELY_FALSE_POSITIVE"
        confidence = min(70, 45 + abs(delta) * 5)
    else:
        verdict = "UNCERTAIN"
        confidence = 50
        reasons.append("Mixed signals; manual review required")

    return verdict, confidence, reasons


# ==========================================
# RISK & SEVERITY CLASSIFICATION
# ==========================================

def classify(score):
    """Returns (severity_label, cvss_like_level 0-10 for reporting)."""
    if score >= 15:
        return "CRITICAL", 9
    elif score >= 10:
        return "HIGH", 7
    elif score >= 5:
        return "MEDIUM", 5
    elif score >= 2:
        return "LOW", 3
    else:
        return "INFO", 1


# ==========================================
# INCIDENT SUMMARY & L1 CHECKLIST
# ==========================================

def generate_summary(findings, iocs, risk, severity_num, verdict, confidence, verdict_reasons):
    summary = "\n===== INCIDENT SUMMARY (L1 Ticket Ready) =====\n\n"
    summary += f"Severity: {risk} (score ~{severity_num}/10)\n"
    summary += f"Verdict: {verdict} (confidence: {confidence}%)\n"
    summary += f"Detected Techniques: {len(findings)}\n\n"

    if verdict_reasons:
        summary += "Verdict reasons:\n"
        for r in verdict_reasons[:8]:
            summary += f" - {r}\n"
        summary += "\n"

    techniques = sorted(set(f["mitre"] for f in findings))
    summary += "MITRE ATT&CK Mapping:\n"
    for t in techniques:
        summary += f" - {t}\n"

    summary += "\n--- IOCs Identified (for TI enrichment) ---\n"
    for key in ("ips", "public_ips", "domains", "urls", "hashes", "emails", "users", "file_paths"):
        values = iocs.get(key, [])
        if values:
            summary += f" {key.upper()}:\n"
            for v in values[:25]:  # cap for readability
                summary += f"   - {v}\n"
            if len(values) > 25:
                summary += f"   ... and {len(values) - 25} more\n"

    summary += "\n--- Analyst Assessment ---\n"
    if verdict in ("TRUE_POSITIVE", "LIKELY_TRUE_POSITIVE"):
        summary += "Alert appears actionable. Proceed with containment and escalation per playbook.\n"
    elif verdict in ("FALSE_POSITIVE", "LIKELY_FALSE_POSITIVE"):
        summary += "Alert likely benign or expected activity. Document and close or whitelist if appropriate.\n"
    else:
        summary += "Inconclusive. Validate IOCs, correlate with other alerts, and escalate if needed.\n"
    summary += "Recommend: Threat intel enrichment on IPs/hashes/domains before closing.\n"
    return summary


def generate_l1_checklist(verdict, risk, iocs):
    """L1 investigation checklist to standardize next steps."""
    lines = [
        "\n===== L1 INVESTIGATION CHECKLIST =====\n",
        "[ ] Confirm alert source and time range",
        "[ ] Verify asset/host identity (hostname, IP, user)",
        "[ ] Run IOC extraction (done above) and enrich:",
        "    - IPs: VirusTotal / AbuseIPDB / internal TI",
        "    - Hashes: VirusTotal / hybrid-analysis",
        "    - Domains/URLs: URLhaus / domain reputation",
        "[ ] Check for related alerts (same host/user/IP in last 24h)",
        "[ ] If CRITICAL/HIGH and TP: escalate to L2 and initiate containment per playbook",
        "[ ] If FP: document reason and suggest rule tuning or exception",
        "[ ] Update ticket with: Verdict, Severity, MITRE, IOCs, and next steps",
    ]
    if iocs.get("hashes"):
        lines.insert(5, "[ ] Run file hashes in sandbox or threat intel")
    if risk in ("CRITICAL", "HIGH"):
        lines.append("[ ] Consider blocking IOCs at EDR/ firewall (per policy)")
    return "\n".join(lines)


# ==========================================
# MAIN
# ==========================================

def main():
    parser = argparse.ArgumentParser(description="SOC Behavioral Analyzer - L1 investigation assistant")
    parser.add_argument("--export-iocs", metavar="FILE", help="Export extracted IOCs to JSON file for ioc_enrichment.py")
    args = parser.parse_args()

    print("===== SOC Behavioral Analyzer - L1 Assistant =====")
    print("Paste SIEM alerts (Elastic, Splunk, QRadar, Wazuh, CrowdStrike, Darktrace, Security Onion, etc.)")
    print("Type END on a new line when done.")
    print("--------------------------------")

    raw_text = ""
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip().upper() == "END":
            break
        raw_text += line + "\n"

    if not raw_text.strip():
        print("No input.")
        return

    fmt = detect_siem_format(raw_text)
    print(f"\n[Detected format: {fmt}]")

    normalized = normalize_alert_text(raw_text, fmt)
    alerts = split_alerts(raw_text, fmt)
    if not alerts:
        print("No alerts detected.")
        return

    iocs = extract_iocs(normalized)
    if args.export_iocs:
        with open(args.export_iocs, "w", encoding="utf-8") as f:
            json.dump({k: v for k, v in iocs.items() if v}, f, indent=2)
        print("\n[IOCs exported to %s – run: python ioc_enrichment.py %s -o report.json]" % (args.export_iocs, args.export_iocs))

    findings, score, full_text_lower = analyze(alerts)
    risk, severity_num = classify(score)
    verdict, confidence, verdict_reasons = assess_fp_tp(full_text_lower, findings, score)

    print("\n===== DETECTION RESULTS =====\n")
    if findings:
        for i, f in enumerate(findings, 1):
            print(f"[{i}] {f['type']}")
            print(f"    MITRE: {f['mitre']}")
            print(f"    Triggered by: {f['keyword']}")
            print("-" * 50)
    else:
        print("No major suspicious patterns detected.")

    print(f"\nTotal Risk Score: {score}")
    print(f"Severity: {risk} (~{severity_num}/10)")
    print(f"Verdict: {verdict} (confidence: {confidence}%)")

    print(generate_summary(findings, iocs, risk, severity_num, verdict, confidence, verdict_reasons))
    print(generate_l1_checklist(verdict, risk, iocs))


if __name__ == "__main__":
    main()
