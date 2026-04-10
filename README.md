<<<<<<< HEAD
# DNS-Audit
=======
# ISO 27001 Annex A.8 — Audit App

A Flask web application that audits system configurations against **ISO 27001:2022 Annex A Section 8** (Technology Controls). Supports two audit modes:

1. **Offline Audit** — Upload a `system_config.json` collected from an Ubuntu/Linux server
2. **Online AD Audit** — Connect to a Windows Active Directory Domain Controller via WinRM and audit remotely

---

## Quick Start

### 1. Install Dependencies

```bash
# Create a virtual environment (recommended)
python -m venv .venv

# Activate it
# Windows:
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

# Install requirements
pip install -r requirements.txt
```

> **Note:** `weasyprint` (for PDF reports) requires system-level libraries.
> - **Windows:** Install GTK3 runtime — see [weasyprint docs](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#windows)
> - **Ubuntu/Debian:** `sudo apt install libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0`
> - PDF generation is optional — HTML reports work without it.

### 2. Run the App

```bash
python app.py
```

Open **http://localhost:5000** in your browser.

---

## Usage

### Mode 1: Offline Audit (Linux Server)

1. **Collect config** on your target Ubuntu server:
   ```bash
   # Copy collector files to the target server, then:
   sudo bash collect.sh
   ```
   This produces a `system_config.json` file.

2. **Upload** the JSON file via the web dashboard at `http://localhost:5000`

3. **Review results** — pass/fail per control with remediation steps

4. **Download reports** — HTML or PDF

### Mode 2: Online AD Audit (Windows Domain Controller)

1. Navigate to **http://localhost:5000/online-audit**

2. Fill in the connection form:
   | Field | Example |
   |---|---|
   | **AD Server IP / Hostname** | `192.168.1.10` or `dc01.domain.com` |
   | **Username** | `DOMAIN\Administrator` or `admin@domain.com` |
   | **Password** | Your domain admin password |
   | **Connection Type** | HTTP (NTLM) on port 5985, or HTTPS (SSL) on port 5986 |

3. Click **Run AD Audit** — the engine connects via WinRM, runs 34 playbooks with PowerShell checks, and returns results.

#### AD Audit Prerequisites

- **WinRM enabled** on the Domain Controller: `winrm quickconfig`
- **Domain Admin account** for full audit coverage
- **AD PowerShell module** installed on the DC: `Install-WindowsFeature RSAT-AD-PowerShell`
- **Port 5985** (HTTP) or **5986** (HTTPS) accessible from the machine running this app
- **For NTLM over HTTP:** The audit machine's IP must be in the DC's TrustedHosts:
  ```powershell
  Set-Item WSMan:\localhost\Client\TrustedHosts -Value "AUDIT_MACHINE_IP" -Force
  ```

---

## Project Structure

```
ISO Audit App/
├── app.py                  # Flask web application (main entry point)
├── audit_engine.py         # Offline audit engine (evaluates JSON config)
├── ad_audit_engine.py      # Online AD audit engine (WinRM + PowerShell)
├── report_generator.py     # HTML/PDF report generation
├── requirements.txt        # Python dependencies
├── rules/
│   └── rules.yml           # Audit rules for offline mode
├── playbooks/
│   └── A8_*.yaml           # 34 YAML playbooks for online AD audit
├── collector/
│   ├── collect.sh           # Bash script to collect Linux config
│   └── collector.yml        # Ansible-style collector config
├── templates/               # Jinja2 HTML templates
├── static/                  # CSS and JS assets
├── uploads/                 # Uploaded config files (auto-created)
├── reports/                 # Generated reports (auto-created)
└── logs/                    # Application logs (auto-created)
```

---

## API

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Dashboard / upload page |
| `/upload` | POST | Upload config JSON and run offline audit |
| `/online-audit` | GET | Online AD audit connection form |
| `/online-audit/run` | POST | Execute online AD audit |
| `/results/<audit_id>` | GET | View audit results |
| `/download/<audit_id>/<fmt>` | GET | Download report (fmt: `html` or `pdf`) |
| `/api/audit/<audit_id>` | GET | Get results as JSON |
| `/delete/<audit_id>` | POST | Delete an audit |
>>>>>>> 9584235 (Initial commit)
