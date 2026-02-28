"""
L1 Playbook / Checklist Runner
------------------------------
Provides step-by-step checklists per detection type (brute force, malware/C2,
lateral movement, etc.) so analysts know what to do next. Aligned with
SOC Behavioral Analyzer detection categories.

Usage: run from SOC Toolkit menu or directly with `python playbook_runner.py`
"""

from __future__ import annotations

import sys
from typing import Dict, List, Tuple

# Detection types aligned with soc_behavioral_analyzer_.py + common L1 scenarios
PLAYBOOKS: Dict[str, List[str]] = {
    "Brute Force": [
        "Block source IP at perimeter firewall (or WAF if web login).",
        "Identify targeted account(s) and reset password; revoke active sessions.",
        "Check for successful logon after last failure (possible compromise).",
        "Review account lockout policy and consider temporary lockout for targeted account.",
        "If critical asset or successful logon found: escalate to L2.",
        "Document IOCs (source IP, targeted user/host) and add to ticket.",
    ],
    "Port Scan": [
        "Confirm scan scope (single host vs. subnet) and source IP.",
        "Block source IP if external; if internal, identify user/host and verify authorization.",
        "Check if scan targeted critical assets (DB, DC, backup).",
        "Review scan timing and correlate with other alerts (recon before exploitation).",
        "If part of a campaign or targeting critical assets: escalate to L2.",
        "Document source IP and target range in ticket.",
    ],
    "Credential Access": [
        "Isolate affected host(s) if credential dump suspected (LSASS, Mimikatz, etc.).",
        "Reset credentials for potentially compromised accounts; revoke sessions.",
        "Capture triage package / memory if approved and host not yet rebooted.",
        "Search for lateral movement or use of stolen creds (logons, SMB, RDP).",
        "Escalate to L2; preserve evidence (logs, disk if needed).",
        "Document hashes, tools, and accounts in ticket.",
    ],
    "Malware/C2": [
        "Isolate affected host from network (EDR isolate or disconnect).",
        "Capture triage package (process list, connections, persistence) per procedure.",
        "Block IOCs (IPs, domains, hashes) at firewall and EDR.",
        "Identify initial access vector (email, drive-by, RDP) and scope (one host vs. multiple).",
        "Escalate to L2 immediately; do not wait for full containment.",
        "Preserve evidence; document all IOCs and timeline in ticket.",
    ],
    "Lateral Movement": [
        "Identify source and destination hosts and user/account used.",
        "Isolate destination host if compromise confirmed; consider isolating source.",
        "Reset password and revoke sessions for account used in lateral movement.",
        "Check for credential dumping or theft on source host.",
        "Search for further lateral movement from the same account or host.",
        "Escalate to L2; document movement path and IOCs in ticket.",
    ],
    "Persistence": [
        "Identify persistence mechanism (scheduled task, registry, service, startup).",
        "Isolate host if malware-related; capture triage package before removal.",
        "Remove persistence artifact per procedure (document before removal).",
        "Check for associated malware or C2 (run hash/URL in enrichment).",
        "Search for same persistence on other hosts (same user, same OU).",
        "Escalate if unknown binary or critical asset; document in ticket.",
    ],
    "Execution": [
        "Identify process and parent process; check file hash and path.",
        "Enrich hash/URL (VirusTotal / IOC enrichment script); isolate host if malicious.",
        "If script (PowerShell, script block): capture command line and script content.",
        "Check for persistence or follow-up activity (network, new processes).",
        "Escalate if encoded/obfuscated or high-severity; document in ticket.",
    ],
    "Web Attack": [
        "Identify target application and source IP; block source at WAF/firewall if appropriate.",
        "Confirm attack type (SQLi, XSS, path traversal) and whether it was successful.",
        "Check application and DB logs for signs of exploitation or data access.",
        "If successful: involve app owner and L2; consider temporary takedown if critical.",
        "Document payload, parameters, and IOCs in ticket.",
    ],
    "Defense Evasion": [
        "Identify what was disabled or tampered (AV, logging, event log).",
        "Isolate host; treat as potential compromise (attacker likely present).",
        "Capture triage package; preserve logs from backup or central logging if available.",
        "Search for persistence and lateral movement from same host/user.",
        "Escalate to L2; document actions and timeline in ticket.",
    ],
    "Reconnaissance": [
        "Identify scope (whoami, systeminfo, net user, etc.) and source host/user.",
        "Correlate with other alerts (recon often precedes exploitation or lateral movement).",
        "If external source: block IP; if internal, verify if authorized (admin, pentest).",
        "Check for follow-up execution or lateral movement from same host.",
        "Document commands and source in ticket; escalate if critical asset targeted.",
    ],
    "Exfiltration": [
        "Identify data flow (source host, destination IP/domain, volume).",
        "Contain channel: block destination at firewall; isolate source host if needed.",
        "Determine data type (PII, credentials, intellectual property) and volume.",
        "Preserve evidence (logs, netflow, EDR); do not power off without L2 approval.",
        "Escalate to L2 and incident response; document in ticket.",
    ],
    "Phishing": [
        "Identify recipient(s) and whether link was clicked or attachment opened.",
        "If clicked: run URL and any file hashes through IOC enrichment; block URL/attachment.",
        "Disable or reset account if credentials entered; revoke sessions.",
        "Search inbox and sent items for further phishing or lateral spread.",
        "Escalate if multiple users or executive; document in ticket.",
    ],
    "Privilege Escalation": [
        "Identify vulnerable component and current/user privileges after escalation.",
        "Isolate host if exploitation confirmed; capture triage package.",
        "Block exploit path (patch or mitigate) and reset compromised accounts.",
        "Search for lateral movement or persistence using elevated account.",
        "Escalate to L2; document exploit and IOCs in ticket.",
    ],
    "Other / General": [
        "Document alert summary, IOCs, and severity in ticket.",
        "Enrich IOCs (IPs, hashes, domains) using IOC Enrichment tool.",
        "If HIGH/CRITICAL: contain (block IP, isolate host) and escalate to L2.",
        "Complete client incident report if required; attach evidence.",
        "Update ticket with verdict, timeline, and next steps.",
    ],
}


def _print_playbook(name: str, steps: List[str], severity: str) -> None:
    """Print playbook title, severity note, and steps with [ ] checkboxes."""
    print("\n" + "=" * 60)
    print(f"  Playbook: {name}")
    print("=" * 60)
    if severity:
        print(f"  Severity: {severity} – prioritize containment and escalation if needed.\n")
    print("  Steps:")
    for i, step in enumerate(steps, 1):
        print(f"  [ ] {i}. {step}")
    print()


def main() -> None:
    print("\n===== L1 Playbook / Checklist Runner =====")
    print("Select a detection type to get a step-by-step checklist.\n")

    names = list(PLAYBOOKS.keys())
    for i, n in enumerate(names, 1):
        print(f"  [{i}] {n}")
    print(f"  [0] Exit")
    print()

    try:
        choice = input("Select detection type (number): ").strip()
    except EOFError:
        return
    if not choice or choice == "0":
        print("Exiting.")
        return

    try:
        idx = int(choice)
        if idx < 1 or idx > len(names):
            print("Invalid option.")
            return
        selected = names[idx - 1]
    except ValueError:
        # Allow typing name (partial match)
        choice_lower = choice.lower()
        matches = [n for n in names if choice_lower in n.lower()]
        if len(matches) == 1:
            selected = matches[0]
        elif len(matches) > 1:
            print(f"Multiple matches: {matches}. Please choose by number.")
            return
        else:
            selected = "Other / General"

    steps = PLAYBOOKS[selected]
    severity_prompt = (
        "Enter severity from analyzer if known (CRITICAL/HIGH/MEDIUM/LOW, or Enter to skip): "
    )
    try:
        severity = input(severity_prompt).strip().upper() or ""
    except EOFError:
        severity = ""

    _print_playbook(selected, steps, severity)

    export_prompt = "Export checklist to file? (path or Enter to skip, e.g. checklist_bruteforce.txt): "
    try:
        path = input(export_prompt).strip()
    except EOFError:
        path = ""

    if path:
        if not path.endswith(".txt"):
            path = path + ".txt"
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"Playbook: {selected}\n")
                if severity:
                    f.write(f"Severity: {severity}\n\n")
                f.write("Steps:\n")
                for i, step in enumerate(steps, 1):
                    f.write(f"[ ] {i}. {step}\n")
            print(f"[Checklist saved to: {path}]")
        except OSError as e:
            print(f"[!] Could not save file: {e}")
    else:
        print("Checklist not exported. You can copy the steps above into your ticket.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(130)
