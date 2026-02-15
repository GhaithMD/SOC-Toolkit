import re
from collections import defaultdict
from datetime import datetime

# ==========================================
# IOC REGEX
# ==========================================

IP_REGEX = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
DOMAIN_REGEX = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
URL_REGEX = r"https?://[^\s]+"
HASH_REGEX = r"\b[a-fA-F0-9]{32,64}\b"
EMAIL_REGEX = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"

USERNAME_REGEX = r"user(?:name)?[=\s:]+([A-Za-z0-9_\-\\]+)"

# ==========================================
# DETECTION PATTERNS + MITRE MAPPING
# ==========================================

DETECTIONS = {
    "Brute Force": {
        "keywords": ["brute", "login failed", "invalid password", "hydra", "authentication failure"],
        "mitre": "T1110 - Brute Force",
        "weight": 3
    },
    "Port Scan": {
        "keywords": ["scan", "nmap", "masscan", "port sweep"],
        "mitre": "T1046 - Network Service Discovery",
        "weight": 2
    },
    "Credential Access": {
        "keywords": ["pwd=", "password=", "credential", "ntlm", "logon_failure"],
        "mitre": "T1003 - Credential Dumping",
        "weight": 4
    },
    "Web Attack": {
        "keywords": ["sqlmap", "union select", "' or 1=1", "<script>", "wp-login"],
        "mitre": "T1190 - Exploit Public-Facing Application",
        "weight": 3
    },
    "Malware Activity": {
        "keywords": ["c2", "beacon", "payload", "ransomware", "trojan"],
        "mitre": "T1071 - Application Layer Protocol",
        "weight": 5
    },
    "Privilege Escalation": {
        "keywords": ["sudo", "admin access granted", "privilege escalation"],
        "mitre": "T1068 - Exploitation for Privilege Escalation",
        "weight": 4
    },
    "Lateral Movement": {
        "keywords": ["smb", "psexec", "remote service"],
        "mitre": "T1021 - Remote Services",
        "weight": 4
    }
}

# ==========================================
# SPLIT ALERTS
# ==========================================

def split_alerts(raw_text):
    separators = ["\n\n", "-----", "Alert:", "Event ID"]
    alerts = [raw_text]

    for sep in separators:
        if sep in raw_text:
            alerts = raw_text.split(sep)
            break

    return [a.strip() for a in alerts if a.strip()]


# ==========================================
# IOC EXTRACTION
# ==========================================

def extract_iocs(text):
    return {
        "ips": list(set(re.findall(IP_REGEX, text))),
        "domains": list(set(re.findall(DOMAIN_REGEX, text))),
        "urls": list(set(re.findall(URL_REGEX, text))),
        "hashes": list(set(re.findall(HASH_REGEX, text))),
        "emails": list(set(re.findall(EMAIL_REGEX, text))),
        "users": list(set(re.findall(USERNAME_REGEX, text, re.IGNORECASE)))
    }


# ==========================================
# ANALYSIS ENGINE
# ==========================================

def analyze(alerts):
    findings = []
    total_score = 0
    ip_counter = defaultdict(int)

    for alert in alerts:
        lower_alert = alert.lower()

        # Count IP repetition
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

    # Repeated IP behavior
    for ip, count in ip_counter.items():
        if count >= 3:
            findings.append({
                "type": "Repeated Suspicious Activity",
                "mitre": "T1498 - Network DoS / Recon",
                "keyword": f"{count} events from {ip}",
                "weight": 3
            })
            total_score += 3

    return findings, total_score


# ==========================================
# RISK CLASSIFICATION
# ==========================================

def classify(score):
    if score >= 15:
        return "CRITICAL"
    elif score >= 10:
        return "HIGH"
    elif score >= 5:
        return "MEDIUM"
    else:
        return "LOW"


# ==========================================
# INCIDENT SUMMARY GENERATOR
# ==========================================

def generate_summary(findings, iocs, risk):
    summary = "\n===== INCIDENT SUMMARY =====\n\n"
    summary += f"Risk Level: {risk}\n"
    summary += f"Detected Techniques: {len(findings)}\n\n"

    techniques = set([f["mitre"] for f in findings])
    summary += "MITRE ATT&CK Mapping:\n"
    for t in techniques:
        summary += f" - {t}\n"

    summary += "\nIOCs Identified:\n"

    for key, values in iocs.items():
        if values:
            summary += f" {key.upper()}:\n"
            for v in values:
                summary += f"   - {v}\n"

    summary += "\nAnalyst Assessment:\n"
    summary += "The logs indicate potentially malicious behavior based on keyword analysis and behavioral correlation.\n"
    summary += "Further validation and threat intelligence enrichment is recommended.\n"

    return summary


# ==========================================
# MAIN
# ==========================================

def main():
    print("===== SOC RAW ANALYZER v5 =====")
    print("Paste raw SIEM logs. Type END when done.")
    print("--------------------------------")

    raw_text = ""

    while True:
        line = input()
        if line.strip() == "END":
            break
        raw_text += line + "\n"

    alerts = split_alerts(raw_text)

    if not alerts:
        print("No alerts detected.")
        return

    iocs = extract_iocs(raw_text)
    findings, score = analyze(alerts)
    risk = classify(score)

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
    print(f"Overall Risk Level: {risk}")

    print(generate_summary(findings, iocs, risk))


if __name__ == "__main__":
    main()
