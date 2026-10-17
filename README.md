# Automated Web Server Access Log Threat Hunter (`web-log-triage`)

A lightweight Python forensic command-line tool that parses standard web server access logs (Apache, Nginx, or IIS Common/Combined Log Format), applies high-fidelity regular expressions to detect common attack vectors mapped to **MITRE ATT&CK®**, enriches IP addresses, and outputs structured **JSON** and interactive **HTML** forensic reports.

---

## Architecture & Operational Pipeline
![web-log-triage Operational Architecture](assets/architecture_flowchart.png)

---

## Quickstart & Installation

Choose your preferred setup method:

### Linux & macOS (Using `make`)

If you are on Linux or macOS, you can use the automated `Makefile`:

```bash
# 1. Setup virtual environment and install in editable mode
make install

# 2. Run the test suite
make test

# 3. Run triage on sample logs
make run

# 4. Generate visual HTML report
make html

# 5. Generate JSON report for tool ingestion
make json

# 6. Remove virtualenv, caches, and report file
make clean
```

### Windows (PowerShell/Python)

If you are on Windows, you can use the automated `wlt-setup.ps1`

```powershell
# 1. Setup virtual environment and install dependencies
.\wlt-setup.ps1 install

# 2. Run the test suite
.\wlt-setup.ps1 test

# 3. Run triage on sample logs
.\wlt-setup.ps1 run

# 4. Generate visual HTML report
.\wlt-setup.ps1 html

# 5. Generate JSON report
.\wlt-setup.ps1 json

# 6. Remove virtualenv, caches, and report file
.\wlt-setup.ps1 clean
```

---

## CLI Usage & Options

```bash
usage: web-log-triage [-h] [-f {console,html,json}] [-o OUTPUT] [--threshold THRESHOLD] [--no-geoip] log_file

Automated Web Server Access Log Threat Hunter & Forensic Triage Tool

positional arguments:
  log_file              Path to access log file (Combined or Common log format)

options:
  -h, --help            Show this help message and exit
  -f, --format {console,html,json}
                        Report format: console, html, or json (default: console)
  -o, --output OUTPUT   Output file path for html/json reports
  --threshold THRESHOLD
                        Brute-force 404/403 request threshold (default: 3)
  --no-geoip            Disable online GeoIP lookups (offline mode)
```

---

## Threat Detection & MITRE ATT&CK® Mapping


| Threat Category | Target Field | MITRE Technique | MITRE Tactic | Description |
| -------- | -------- | -------- | -------- | -------- |
| SQL Injection (SQLi)    | decoded_uri   | T1190   | Initial Access | **UNION SELECT**, **OR 1=1**, database function injection |
| Local File Inclusion (LFI)    | decoded_uri   | T1190   | Initial Access | Path traversal *(../, ..\\)* and */etc/passwd* probing |
| Remote Code Execution (RCE) | decoded_uri | T1059.004 | Execution | Command injection **whoami;id** |
| Malicious Scanners | user_agent | T1595.002 | Reconnaissance | Known offensive tools (sqlmap, gobuster, nikto, nmap) |
| Directory Brute-Force | multi-entry | T1595.003 | Reconnaissance | High-frequency 404/403 bursts from a single IP |
| Sensitive File Probing | decoded_uri | T1552.001 | Credential Access | Attempts to access */.env*, */.git*, config files |
| Cross-Site Scripting (XSS) | decoded_uri | T1059.007 | Execution | *\<script\>* injection, DOM event handlers, **javascript\:** |
| Cloud Metadata / SSRF | decoded_uri | T1552.005 | Credential Access | Probing AWS/Azure/GCP instance metadata (169.254.169.254) | 

---

## Troubleshooting, Common Issues, & Tips

### Linux / macOS

- **Check Virtual Environment Execution Permissions:**
  If you see a `Permission denied` error when running `make` commands:
  Ensure the generated binaries in `.venv` have execute permissions:
  ```bash
  chmod +x .venv/bin/*
  ```
- **Avoid Using 'sudo':**
  Never run *sudo make* or *sudo pip*. If *.venv* was accidentally created with *sudo*, fix file ownership to your current user:
  ```bash
  sudo chown -R $USER:$USER .
  ```
  Or remove and rebuild the environment cleanly:
  ```bash
  make clean
  make install
  ```
- **Filesystem Mount Flags (noexec):**
  If your project directory is located on an external drive or a network share mounted with the **noexec** flag, Linux/macOS will block binaries from running inside *.venv*. Move the project to your local home directory (e.g. *~/workspace/*).

### Windows

- **PowerShell Script Execution Disabled on Windows:**
  If PowerShell prevents script execution, run:
  ```powershell
  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
  ```