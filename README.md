## SOC Toolkit

A lightweight, console-based toolkit to speed up Level 1 SOC investigations.  
It focuses on two core tasks:

- **Alert triage & behavioral analysis**
- **IOC reputation & contextual enrichment**

Everything is driven from a single entrypoint script: `soc_toolkit.py`.

---

### Features

- **Unified console (`soc_toolkit.py`)**
  - One command to launch the toolkit.
  - Simple menu: pick behavioral analysis or IOC enrichment.
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

---

### Requirements

- **Python**: 3.9+ recommended
- **Dependencies**:
  - Standard library only for core functions.
  - Optional for Word export:
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

Main menu:
  [1] Run SOC Behavioral Analyzer
  [2] Run IOC Enrichment
  [3] Exit
Select an option [1-3]:
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

---

### Notes & Future Plans

- The toolkit is built to be **CLI-first**, fast, and easy for L1 analysts.
- Additional modules can be plugged into `soc_toolkit.py` as the project grows:
  - EDR triage helpers
  - Timeline generators
  - Playbook-driven response checklists

Contributions, ideas, and feedback are welcome—especially from analysts working in real SOC environments.

# SOC-Toolkit
Fully dependable toolkit that improves speed, accuracy, and efficiency in SOC operations.
