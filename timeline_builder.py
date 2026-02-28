"""
Timeline Builder
----------------
Paste log lines or events (with timestamps); get a sorted event timeline.
Useful for ticket write-ups and incident reports.

Supports common timestamp formats at the start of each line, e.g.:
  2026-02-28 14:32:00  User login
  28-02-2026 14:35:00  Alert triggered
  2026-02-28T14:32:00Z  Event from SIEM

Usage: run from SOC Toolkit menu or directly with `python timeline_builder.py`
"""

from __future__ import annotations

import re
import sys
from datetime import datetime
from typing import List, Optional, Tuple

# Patterns: (regex, strptime format or None for ISO-style)
# Order matters: more specific first
TIMESTAMP_PATTERNS: List[Tuple[str, Optional[str]]] = [
    # ISO with T and optional Z
    (r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)", None),
    # YYYY-MM-DD HH:MM:SS or YYYY-MM-DD HH:MM
    (r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", "%Y-%m-%d %H:%M:%S"),
    (r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})", "%Y-%m-%d %H:%M"),
    # DD-MM-YYYY HH:MM:SS or DD-MM-YYYY HH:MM
    (r"^(\d{2}-\d{2}-\d{4}\s+\d{2}:\d{2}:\d{2})", "%d-%m-%Y %H:%M:%S"),
    (r"^(\d{2}-\d{2}-\d{4}\s+\d{2}:\d{2})", "%d-%m-%Y %H:%M"),
    # DD/MM/YYYY HH:MM:SS or DD/MM/YYYY HH:MM
    (r"^(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})", "%d/%m/%Y %H:%M:%S"),
    (r"^(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2})", "%d/%m/%Y %H:%M"),
    # MM/DD/YYYY (US)
    (r"^(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})", "%m/%d/%Y %H:%M:%S"),
    (r"^(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2})", "%m/%d/%Y %H:%M"),
]


def _parse_timestamp(s: str) -> Optional[datetime]:
    """Parse a timestamp string; return datetime or None."""
    s = s.strip()
    for pattern, fmt in TIMESTAMP_PATTERNS:
        m = re.match(pattern, s, re.IGNORECASE)
        if m:
            raw = m.group(1)
            if fmt is None:
                # ISO-style: try fromisoformat
                try:
                    raw_clean = raw.replace("Z", "+00:00")
                    return datetime.fromisoformat(raw_clean).replace(tzinfo=None)
                except Exception:
                    try:
                        return datetime.fromisoformat(raw.replace("Z", ""))
                    except Exception:
                        pass
                continue
            try:
                return datetime.strptime(raw, fmt)
            except ValueError:
                continue
    return None


def _extract_time_and_rest(line: str) -> Tuple[Optional[datetime], str]:
    """Return (parsed_datetime, rest_of_line)."""
    dt = _parse_timestamp(line)
    if dt is None:
        return None, line.strip()
    # Remove the matched part from the line to get the rest
    for pattern, _ in TIMESTAMP_PATTERNS:
        m = re.match(pattern, line, re.IGNORECASE)
        if m:
            rest = line[m.end() :].strip()
            # Trim leading dash or space
            rest = re.sub(r"^[\s\-–:]+\s*", "", rest)
            return dt, rest or "(no description)"
    return dt, line.strip()


def main() -> None:
    print("\n===== Timeline Builder =====")
    print("Paste event lines (each line can start with a timestamp).")
    print("Supported formats: 2026-02-28 14:32:00  |  28-02-2026 14:35  |  2026-02-28T14:32:00Z")
    print("Type END on a new line when done (or leave empty line twice).\n")

    lines: List[str] = []
    empty_count = 0
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip().upper() == "END":
            break
        if not line.strip():
            empty_count += 1
            if empty_count >= 2:
                break
            continue
        empty_count = 0
        lines.append(line)

    if not lines:
        print("No input. Exiting.")
        return

    # Parse and sort
    parsed: List[Tuple[datetime, str, str]] = []  # (dt, rest, original)
    no_ts: List[str] = []
    for line in lines:
        dt, rest = _extract_time_and_rest(line)
        if dt is not None:
            parsed.append((dt, rest, line))
        else:
            no_ts.append(line)

    parsed.sort(key=lambda x: x[0])

    # Output
    print("\n" + "=" * 60)
    print("  EVENT TIMELINE (sorted by time)")
    print("=" * 60 + "\n")

    for i, (dt, rest, _) in enumerate(parsed, 1):
        ts_str = dt.strftime("%Y-%m-%d %H:%M:%S")
        print(f"  {i}. {ts_str}  |  {rest}")
    if no_ts:
        print("\n  --- Events without recognized timestamp (append manually if needed) ---")
        for line in no_ts:
            print(f"      {line.strip()}")

    print()

    # Export
    export_prompt = "Export timeline to file? (path or Enter to skip, e.g. timeline.txt): "
    try:
        path = input(export_prompt).strip()
    except EOFError:
        path = ""

    if path:
        if not path.endswith(".txt"):
            path = path + ".txt"
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("EVENT TIMELINE (sorted by time)\n")
                f.write("=" * 50 + "\n\n")
                for i, (dt, rest, _) in enumerate(parsed, 1):
                    ts_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                    f.write(f"{i}. {ts_str}  |  {rest}\n")
                if no_ts:
                    f.write("\n--- No recognized timestamp ---\n")
                    for line in no_ts:
                        f.write(line.strip() + "\n")
            print(f"[Timeline saved to: {path}]")
        except OSError as e:
            print(f"[!] Could not save file: {e}")
    else:
        print("Timeline not exported. You can copy the output above into your ticket or report.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(130)
