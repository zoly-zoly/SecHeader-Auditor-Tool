<div align="center">

# 🛡️ SecHeader-Auditor

**High-Performance, Asynchronous HTTP Security Header, Cookie & CORS Compliance Analyzer**

[![Python Version](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![OWASP Aligned](https://img.shields.io/badge/OWASP-Secure_Headers-000000?style=for-the-badge&logo=owasp&logoColor=white)](https://owasp.org/www-project-secure-headers/)
[![Docker Ready](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-10B981?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/Tests-Pytest_Passing-22C55E?style=for-the-badge&logo=pytest&logoColor=white)]()

*An automated defensive security auditing utility built for security engineers, DevSecOps pipelines, and web developers to evaluate HTTP response headers, inspect `Set-Cookie` security flags, detect permissive CORS policies, and enforce OWASP security standards at scale.*

[✨ Features](#-key-features) •
[🖥️ Output Preview](#️-terminal-output-preview) •
[📂 Architecture](#-project-structure--file-breakdown) •
[📦 Setup Guide](#-step-by-step-setup--installation) •
[🚀 Usage](#-usage-guide--examples) •
[🐳 Docker](#-docker-deployment-guide) •
[📊 Grading Logic](#-scoring--grading-methodology)

</div>

---

## ✨ Key Features

* **⚡ Asynchronous Engine:** Powered by Python `asyncio` and `httpx` to audit dozens of endpoints concurrently in a fraction of a second.
* **📊 Automated Security Grading (`A+` to `F`):** Calculates a deterministic security score (`0–100`) based on the presence, configuration quality, and weight of HTTP headers and cookies.
* **🍪 Deep `Set-Cookie` Auditing:** Parses multiple `Set-Cookie` headers to verify `Secure`, `HttpOnly`, and `SameSite` (`Strict`/`Lax`/`None`) attributes, as well as `__Host-` and `__Secure-` cookie prefixes.
* **🌐 CORS Misconfiguration Detection:** Identifies overly permissive Cross-Origin Resource Sharing policies (`Access-Control-Allow-Origin: *`) and dangerous credential combinations.
* **🕵️ Information Disclosure Checks:** Flags verbose backend headers (`Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator`) that leak software versions to attackers.
* **🛠️ Actionable Remediation Advice:** Provides ready-to-use configuration snippets for every missing or weakly configured header/cookie (`unsafe-inline`, `unsafe-eval`, `max-age=0`).
* **🎨 Rich Terminal UI & JSON Export:** Renders clean, color-coded tables in the terminal via `Rich` and exports structured JSON reports for CI/CD integration.

---

## 🖥️ Terminal Output Preview

When you execute an audit, **SecHeader-Auditor** renders an instant visual breakdown in your terminal:

```text
╭────────────────────── 🛡️ Audit Report: [https://example.com](https://example.com) ──────────────────────╮
│ Final URL: [https://example.com/](https://example.com/)  |  Status: 200  |  Score: 72/100  |  Grade: C  │
╰──────────────────────────────────────────────────────────────────────────────────╯
                               HTTP Security Headers                                
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┓
┃ Status   ┃ Header Name                         ┃ Impact / Weight  ┃ Details      ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━┩
│ ✔ PASS   │ Strict-Transport-Security (HSTS)    │ +20 pts          │ max-age=...  │
│ ✔ PASS   │ X-Content-Type-Options              │ +15 pts          │ nosniff      │
│ ✘ MISS   │ Content-Security-Policy (CSP)       │ HIGH (-25)       │ Define a...  │
└──────────┴─────────────────────────────────────┴──────────────────┴──────────────┘
                            🍪 Set-Cookie Security Audit                            
┏━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Cookie Name   ┃ Secure   ┃ HttpOnly ┃ SameSite ┃ Findings / Remediation          ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ session_id    │ ✔ Yes    │ ✔ Yes    │ Strict   │ All security flags configured.  │
│ tracking_id   │ ✘ No     │ ✘ No     │ ✘ Miss   │ Missing Secure, HttpOnly...     │
└───────────────┴──────────┴──────────┴──────────┴─────────────────────────────────┘
🕵️  Information Disclosure headers detected: server: nginx/1.24.0
⚠️  Warning: CSP contains 'unsafe-inline', which weakens XSS protection.
```

---

## 📂 Project Structure & File Breakdown

Understanding the project architecture helps if you want to customize rules or extend the scanner:

```text
SecHeader-Auditor/
├── secheader/
│   ├── __init__.py      # Package metadata and version definition.
│   ├── rules.py         # OWASP header rules, scoring weights, grading thresholds, and remediation strings.
│   ├── auditor.py       # Core async HTTP engine: inspects headers, cookies, CORS, and server leaks.
│   └── cli.py           # Command-Line Interface built with Typer & Rich for visual terminal reporting.
├── tests/
│   └── test_auditor.py  # Automated unit test suite verifying header, grading, and cookie logic.
├── Dockerfile           # Lightweight Python 3.11 container specification for isolated execution.
├── pyproject.toml       # Packaging configuration, dependencies, pytest setup, and CLI entrypoint.
├── requirements.txt     # External Python package dependencies list.
├── SECURITY.md          # Responsible vulnerability disclosure policy.
└── README.md            # Comprehensive documentation and setup guide.
```

---

## 📦 Step-by-Step Setup & Installation

Follow these exact steps from the moment you clone the repository to run the tool smoothly on **Linux**, **macOS**, or **Windows**.

### Step 1: Clone the Repository
Open your terminal, clone the repository from GitHub, and enter the project folder:
```bash
git clone [https://github.com/yourusername/SecHeader-Auditor.git](https://github.com/yourusername/SecHeader-Auditor.git)
cd SecHeader-Auditor
```

### Step 2: Create an Isolated Virtual Environment
Using a virtual environment prevents dependency conflicts with your system Python packages:
```bash
python3 -m venv venv
```

### Step 3: Activate the Virtual Environment
* **On Linux / macOS (Bash / Zsh):**
  ```bash
  source venv/bin/activate
  ```
* **On Windows (Command Prompt):**
  ```cmd
  venv\Scripts\activate.bat
  ```
* **On Windows (PowerShell):**
  ```powershell
  venv\Scripts\Activate.ps1
  ```

### Step 4: Install the Package & Dependencies
Install the project in editable mode (`-e`). This installs `httpx`, `typer`, `rich`, and registers the `secheader` command globally inside your virtual environment:
```bash
pip install -e .
```

### Step 5: Verify the Installation
Check that the CLI tool is properly installed and view the help menu:
```bash
secheader --help
```

---

## 🚀 Usage Guide & Examples

Once your virtual environment is active, you can run `secheader` from anywhere in your terminal.

### 1. Audit a Single Website or API Endpoint
Scan a single URL to inspect its HTTP security headers, cookies, CORS policy, and overall grade:
```bash
secheader --url "[https://example.com](https://example.com)"
```
*(Note: If you omit `https://`, the tool automatically defaults to `https://`)*

### 2. Batch Audit Multiple Domains from a File
Create a text file (e.g., `targets.txt`) with one URL per line:
```text
[https://example.com](https://example.com)
[https://github.com](https://github.com)
[https://owasp.org](https://owasp.org)
```
Run a high-speed concurrent scan with 20 workers:
```bash
secheader --file targets.txt --concurrency 20
```

### 3. Export Audit Findings to a JSON Report
Save the full detailed analysis (including missing headers, cookie flags, and remediation advice) into a structured JSON file for documentation or CI/CD pipelines:
```bash
secheader -u "[https://example.com](https://example.com)" -o audit_report.json
```

### 4. Audit Internal or Self-Signed Staging Servers
When testing local development servers or internal staging environments with self-signed SSL certificates, pass the `--insecure` (`-k`) flag:
```bash
secheader -u "https://localhost:8443" --insecure
```

### 5. Customizing Request Timeout
For slow-responding servers, increase the timeout limit (in seconds):
```bash
secheader -u "[https://example.com](https://example.com)" --timeout 15.0
```

---

## ⚙️ CLI Option Reference

Here is the complete list of command-line switches and flags supported by `secheader`:

| Option / Flag | Shorthand | Type | Default | Description |
| :--- | :---: | :---: | :---: | :--- |
| `--url` | `-u` | `TEXT` | `None` | Single target URL or domain to audit. |
| `--file` | `-f` | `PATH` | `None` | Path to a text file containing multiple target URLs (one per line). |
| `--concurrency` | `-c` | `INTEGER` | `10` | Maximum number of concurrent asynchronous HTTP requests. |
| `--timeout` | `-t` | `FLOAT` | `8.0` | HTTP request timeout limit in seconds. |
| `--insecure` | `-k` | `FLAG` | `False` | Bypass SSL/TLS certificate verification for self-signed targets. |
| `--output` | `-o` | `PATH` | `None` | File path to export structured audit results in JSON format. |
| `--help` | *None* | `FLAG` | `False` | Display the help menu and exit. |

---

## 🐳 Docker Deployment Guide

Don't want to set up Python or virtual environments on your host OS? You can build and run **SecHeader-Auditor** inside an isolated Docker container in two steps.

### Step 1: Build the Docker Image
From the root directory of the project (where the `Dockerfile` is located), run:
```bash
docker build -t secheader-auditor .
```

### Step 2: Run a Single Target Audit
Pass any CLI arguments directly to the `docker run` command:
```bash
docker run --rm -it secheader-auditor --url "[https://example.com](https://example.com)"
```

### Step 3: Batch Scan & Save Reports to Host Machine
To read a `targets.txt` file from your current folder and save the `report.json` back onto your host system, mount your working directory using `-v $(pwd):/app`:
```bash
docker run --rm -it -v $(pwd):/app secheader-auditor --file targets.txt --output report.json
```

---

## 📊 Scoring & Grading Methodology

Every scanned target starts with a base evaluation across **7 core OWASP security headers** totaling **100 points**, minus any penalties for insecure `Set-Cookie` attributes (capped at `-20 points`).

### 1. Security Header Weights

| Security Header | Severity | Weight | Primary Protection |
| :--- | :---: | :---: | :--- |
| `Content-Security-Policy (CSP)` | **HIGH** | `25 pts` | Mitigates Cross-Site Scripting (XSS) & data injection. |
| `Strict-Transport-Security (HSTS)` | **HIGH** | `20 pts` | Enforces encrypted HTTPS connections & prevents downgrade attacks. |
| `X-Frame-Options` | **MEDIUM** | `15 pts` | Prevents Clickjacking via unauthorized `<iframe>` embedding. |
| `X-Content-Type-Options` | **MEDIUM** | `15 pts` | Stops browser MIME-sniffing (`nosniff`). |
| `Referrer-Policy` | **LOW** | `10 pts` | Controls sensitive URL leakage in the `Referer` header. |
| `Permissions-Policy` | **LOW** | `10 pts` | Restricts powerful browser APIs (Camera, Mic, Geolocation). |
| `Cross-Origin-Opener-Policy` | **LOW** | `5 pts` | Isolates browsing context against cross-origin attacks. |

### 2. Cookie Security Penalties (`Set-Cookie`)
* Missing `Secure` flag: **`-5 pts`**
* Missing `HttpOnly` flag: **`-5 pts`**
* Missing `SameSite` attribute: **`-3 pts`**
* `SameSite=None` without `Secure` flag: **`-5 pts`**
* Broken `__Host-` or `__Secure-` prefix rules: **`-5 pts`**

### 3. Final Grade Scale

| Score Range | Grade | Security Posture |
| :---: | :---: | :--- |
| `95 – 100` | **🟢 A+** | Exemplary security header & cookie hardening. |
| `85 – 94` | **🟢 A** | Strong security posture with minor optional improvements. |
| `75 – 84` | **🟡 B** | Good baseline, missing one medium-impact header or cookie flag. |
| `60 – 74` | **🟡 C** | Moderate posture; missing key policies like CSP or HSTS. |
| `45 – 59` | **🟠 D** | Weak configuration; multiple high/medium headers missing. |
| `0 – 44` | **🔴 F** | Critical lack of HTTP security controls. |

---

## 🧪 Running Unit Tests & Troubleshooting

We use `pytest` to validate scoring calculations, header parsing, and cookie security verification.

### Run the Test Suite
Make sure your virtual environment is activated (`source venv/bin/activate`), then run:
```bash
python3 -m pytest tests/
```

> **💡 Troubleshooting `ModuleNotFoundError: No module named 'secheader'`:**  
> If running `pytest` directly throws an import error, either run `python3 -m pytest tests/` or ensure you have installed the package in editable mode (`pip install -e .`) inside your active virtual environment.

---

## 🛡️ Responsible Use & Ethics

> **Disclaimer:** **SecHeader-Auditor** performs passive, non-intrusive HTTP `GET` requests to analyze response headers. However, always ensure you have proper authorization before auditing internal or third-party infrastructure at scale.

---

## 📄 License

Distributed under the **MIT License**. See `LICENSE` for more information.
