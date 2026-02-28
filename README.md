## SOC Toolkit

A lightweight, console-based toolkit to speed up Level 1 SOC investigations.  
It covers the full L1 flow:

- **Alert triage & behavioral analysis**
- **IOC reputation & contextual enrichment**
- **Client incident report generation**
- **Playbook / checklist** (step-by-step per detection type)
- **Timeline builder** (sort events by time for ticket or report)

Everything is driven from a single entrypoint script: `soc_toolkit.py`.

---

### Features

- **Unified console (`soc_toolkit.py`)**
  - One command to launch the toolkit.
  - Simple menu: behavioral analyzer, IOC enrichment, report generation, playbook, timeline builder.
  - Designed so L1 analysts don’t need to remember Python commands.

- **SOC Behavioral Analyzer (`soc_behavioral_analyzer_.py`)**
  - Works with **raw SIEM output** (Elastic, Splunk, QRadar, Wazuh, Security Onion, CrowdStrike, etc.).
  - **IOC extraction**: IPs, domains, URLs, hashes, emails, usernames, file paths.
  - **Behavioral detection engine**:
    - Brute force, port scan, web attack, C2, lateral movement, privilege escalation, persistence, etc.
  - **MITRE ATT&CK mapping** for each detected behavior.
  - **Risk scoring & verdict**:
    - Classifies alerts as TRUE_POSITIVE / LIKELY_TRUE_POSITIVE / UNCERTAIN / LIKELY_FALSE_POSITIVE / FALSE_POSITIVE.
  - **L1-ready output**:
    - Incident summary, severity, verdict reasons, and investigation checklist.
  - Optional: **export IOCs to JSON** for the enrichment script.

- **IOC Enrichment (`ioc_enrichment.py`)**
  - Accepts:
    - IOC JSON exported from the behavioral analyzer, or
    - Manually entered IPs / hashes (interactive mode).
  - **Threat intel backends**:
    - **VirusTotal v3**: IP + file hash reputation.
    - **AbuseIPDB v2**: IP abuse reports and confidence score.
  - **Interactive console flow**:
    - Paste IPs/hashes.
    - See clean, SOC-friendly reputation blocks in the terminal.
    - Optionally save an investigation report.
  - **Word report export**:
    - Saves a structured **.docx** report (using `python-docx`) with:
      - Risk level
      - VT / AbuseIPDB stats
      - Threat labels (for hashes)
      - ASN, ISP, country, network, hostnames (for IPs)
    - Ready to attach to tickets or hand over to L2.

- **Report Generation (`report_generation.py`)**
  - Builds a **client-facing Word report** (.docx) after an alert/incident investigation.
  - **Interactive prompts** with examples for each field:
    - Alert number, report date, case title, alert ID, GLPI ID, creation date
    - Description, preuve (screenshots/evidence), actif source, actif destination, recommendation
  - **Document layout**:
    - Word **header** on every page (e.g. `Alert 02  28-02-2026`)
    - **Vertical summary table** (Champ | Valeur) with consistent margins and spacing
    - Editable in Word so you can add screenshots or adjust text before sending to the client
  - Requires `python-docx` (same as IOC enrichment Word export).

- **Playbook / Checklist (`playbook_runner.py`)**
  - **Step-by-step checklists** per detection type (aligned with the Behavioral Analyzer):
    - Brute Force, Port Scan, Credential Access, Web Attack, Malware/C2, Lateral Movement, Persistence, Execution, Defense Evasion, Reconnaissance, Exfiltration, Privilege Escalation, Phishing, Other/General.
  - Optional **severity** input (CRITICAL/HIGH/MEDIUM/LOW) for context.
  - **Export to .txt** so you can attach the checklist to the ticket or tick steps offline.
  - Use after triage to know what to do next without losing time.

- **Timeline Builder (`timeline_builder.py`)**
  - **Paste event lines** (each line can start with a timestamp); get a **sorted timeline**.
  - Supports common formats: `2026-02-28 14:32:00`, `28-02-2026 14:35`, `2026-02-28T14:32:00Z`, `28/02/2026 14:32`.
  - **Export to .txt** for pasting into the ticket or client report.
  - Type `END` or two empty lines when done pasting.

---

### Requirements

- **Python**: 3.9+ recommended
- **Dependencies**:
  - Standard library only for behavioral analyzer and toolkit menu.
  - **Word reports** (IOC enrichment + Report Generation) require:
    ```bash
    pip install python-docx
    ```

- **API keys**:
  - `ioc_enrichment.py` reads from a `.env` file in the project root:
    ```env
    VT_API_KEY=your_virustotal_api_key_here
    ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
    ```

---

### Quick Start

#### 1. Clone & set up

```bash
git clone <your-repo-url> soc-toolkit
cd soc-toolkit

# (Optional, recommended)
python -m venv venv
source venv/bin/activate    # Linux/macOS
# or
venv\Scripts\activate       # Windows

pip install python-docx     # if you want .docx reports
```

Create `.env`:

```env
VT_API_KEY=your_virustotal_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
```

#### 2. Run the SOC Toolkit

```bash
python soc_toolkit.py
```

You’ll see a menu like:

```text
===== SOC Toolkit =====
Single-console helper for L1 investigations.

Tools included:
  [1] SOC Behavioral Analyzer
  [2] IOC Enrichment (VirusTotal + AbuseIPDB)
  [3] Report Generation (client incident report)
  [4] Playbook / Checklist (L1 steps per detection type)
  [5] Timeline Builder (sort events by time)

Main menu:
  [1] Run SOC Behavioral Analyzer
  [2] Run IOC Enrichment
  [3] Run Report Generation (client incident report)
  [4] Run Playbook / Checklist
  [5] Run Timeline Builder
  [6] Exit
Select an option [1-6]:
```

---

### Workflow Examples

#### A. From alert to IOC report (end-to-end)

1. **Run the toolkit**:

   ```bash
   python soc_toolkit.py
   ```

2. **Option 1 – Behavioral Analyzer**:
   - Paste the raw SIEM alert(s).
   - Type `END` on a blank line.
   - Review:
     - Detected behaviors
     - MITRE techniques
     - Severity & verdict
     - Extracted IOCs
   - Optionally export IOCs:

     ```bash
     python soc_behavioral_analyzer_.py --export-iocs iocs.json
     ```

3. **Option 2 – IOC Enrichment**:
   - From the toolkit menu choose IOC Enrichment.
   - Either:
     - Run interactively and paste IPs/hashes, **or**
     - Run with the exported JSON:

       ```bash
       python ioc_enrichment.py iocs.json -o enrichment_report.docx
       ```

   - Save the `.docx` report and attach it to your ticket.

4. **Option 3 – Report Generation** (client incident report):
   - From the toolkit menu choose Report Generation.
   - Answer the prompts (case title, alert ID, GLPI ID, description, preuve, actif source/destination, recommendation, etc.); each prompt shows an example.
   - Choose an output filename (default uses alert number and date).
   - Open the generated Word file, add screenshots or tweak text if needed, then send it to the client.

5. **Option 4 – Playbook / Checklist**:
   - From the toolkit menu choose Playbook.
   - Select a detection type by number (e.g. 1 = Brute Force) or name; optionally enter severity.
   - Copy the checklist from the console or export to a .txt file and attach to your ticket.

6. **Option 5 – Timeline Builder**:
   - From the toolkit menu choose Timeline Builder.
   - Paste lines that start with a timestamp (e.g. from SIEM or logs); type `END` when done.
   - Copy the sorted timeline or export to .txt, then paste into your ticket or report.

---

### Notes & Future Plans

- The toolkit is built to be **CLI-first**, fast, and easy for L1 analysts.
- Possible future additions:
  - Containment suggestions from enrichment results
  - Phishing/URL quick check
  - Evidence/screenshot organizer for reports
  - EDR triage helpers

Contributions, ideas, and feedback are welcome—especially from analysts working in real SOC environments.

# SOC-Toolkit
Fully dependable toolkit that improves speed, accuracy, and efficiency in SOC operations.
