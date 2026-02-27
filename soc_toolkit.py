"""
SOC Toolkit - Console Frontend
------------------------------
Single entrypoint to the two main tools in this repo:

1) soc_behavioral_analyzer_.py
   - L1 investigation assistant
   - Paste SIEM alerts, get:
     * IOC extraction
     * Detection findings + MITRE mapping
     * TP/FP assessment and severity
     * L1 checklist + IOC JSON export (for enrichment)

2) ioc_enrichment.py
   - IOC reputation & context
   - Enrich IPs / hashes using:
     * VirusTotal (IP + file reputation)
     * AbuseIPDB (IP abuse reputation)
   - Interactive mode or from exported IOC JSON

Run:
  python soc_toolkit.py
and follow the menu. Designed to minimize typing and speed up L1 work.
"""

from __future__ import annotations

import os
import subprocess
import sys
from typing import Optional


def _script_path(name: str) -> str:
    """Return absolute path to a script in the same directory as this file."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, name)


def _run_subprocess(script: str, *extra_args: str) -> int:
    """Run a Python script as a child process and stream its output."""
    cmd = [sys.executable, script, *extra_args]
    try:
        return subprocess.call(cmd)
    except KeyboardInterrupt:
        # Child already saw Ctrl+C; just return to menu
        return 130
    except OSError as e:
        print(f"[!] Failed to run {script}: {e}")
        return 1


def _print_header() -> None:
    print("===== SOC Toolkit =====")
    print("Single-console helper for L1 investigations.\n")
    print("Tools included:")
    print("  [1] SOC Behavioral Analyzer")
    print("      - Paste SIEM alerts, get verdict, severity, MITRE, and IOC JSON export.")
    print("  [2] IOC Enrichment (VirusTotal + AbuseIPDB)")
    print("      - Enrich IPs / hashes with reputation and context (interactive or from JSON).\n")


def _menu() -> Optional[str]:
    print("Main menu:")
    print("  [1] Run SOC Behavioral Analyzer")
    print("  [2] Run IOC Enrichment")
    print("  [3] Exit")
    choice = input("Select an option [1-3]: ").strip()
    if choice not in {"1", "2", "3"}:
        print("Please choose 1, 2, or 3.\n")
        return None
    return choice


def main() -> None:
    analyzer_path = _script_path("soc_behavioral_analyzer_.py")
    enrichment_path = _script_path("ioc_enrichment.py")

    if not os.path.exists(analyzer_path):
        print(f"[!] Could not find soc_behavioral_analyzer_.py at: {analyzer_path}")
    if not os.path.exists(enrichment_path):
        print(f"[!] Could not find ioc_enrichment.py at: {enrichment_path}")

    while True:
        _print_header()
        choice = _menu()
        if choice is None:
            continue

        if choice == "1":
            print("\nLaunching SOC Behavioral Analyzer...\n")
            _run_subprocess(analyzer_path)
            input("\n[Press ENTER to return to the SOC Toolkit menu]")
        elif choice == "2":
            print("\nLaunching IOC Enrichment...\n")
            _run_subprocess(enrichment_path)
            input("\n[Press ENTER to return to the SOC Toolkit menu]")
        elif choice == "3":
            print("Exiting SOC Toolkit.")
            break


if __name__ == "__main__":
    main()

