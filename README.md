# ISO 27001 AD Audit Tool

A web application that audits a Windows Active Directory against ISO 27001:2022 Annex A.8 controls. It connects to your AD over WinRM, runs PowerShell checks, and gives you a compliance report you can download as HTML or PDF.

---

## Requirements

- Git
- Docker Desktop

That's it. No Python, no MySQL, nothing else to install.

---

## How to Run

```bash
# 1. Clone the repo
git clone <your-repo-url>
cd "ISO Audit App"

# 2. Start the app
docker compose up --build
```

First run takes a few minutes to download everything. After that just use:

```bash
docker compose up
```

Open **http://localhost:5000** in your browser.

Default login is created on first run.

---

## How to Stop

```bash
docker compose down
```

Your data (audit results, reports) is saved and will be there next time you start it.

---

## Setting Up the Active Directory Server

Before running an audit, someone with admin access to the AD server needs to run these commands once on the Domain Controller (as Administrator):

```powershell
winrm quickconfig -y
winrm set winrm/config/service/auth '@{NTLM="true"}'
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
netsh advfirewall firewall add rule name="WinRM HTTP" protocol=TCP dir=in localport=5985 action=allow
```

The account you use for the audit must be a **Domain Admin**.

---

## Running an Audit

1. Go to **http://localhost:5000/online-audit**
2. Fill in the form:

| Field | What to enter |
|---|---|
| Host | IP address of the AD server |
| Username | `DOMAIN\Administrator` |
| Password | Domain Admin password |
| Transport | `ntlm` |

3. Click **Run AD Audit**
4. Watch the live log, then download your report when done

---

## Useful Commands

| What you want to do | Command |
|---|---|
| Start the app | `docker compose up` |
| Start in background | `docker compose up -d` |
| Stop the app | `docker compose down` |
| See logs (background mode) | `docker compose logs -f` |
| Rebuild after code changes | `docker compose up --build` |
| Wipe all data and start fresh | `docker compose down -v` |
