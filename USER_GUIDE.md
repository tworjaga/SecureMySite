# SecureMySite - User Guide

## Overview

SecureMySite is a local security analyzer for AI-generated web projects. It detects vulnerabilities through static analysis (SAST), secret detection, dependency scanning, infrastructure checks (Docker, GitHub Actions) and localhost web scanning. It works offline unless you explicitly enable the OSV.dev dependency lookup.

## Installation

### Requirements
- Python 3.11 or higher
- Windows 10/11, macOS, or Linux

### Install Dependencies
```bash
pip install -r requirements.txt
```

## Quick Start

### GUI Mode (Recommended)
Double-click `start.bat` or run:
```bash
python main.py
```

### CLI Mode
```bash
# Basic scan
python main.py /path/to/your/project

# Scan with web analysis
python main.py /path/to/project --url http://localhost:8000

# Export results (format taken from the file extension)
python main.py /path/to/project -o report.html
```

## Using the GUI

### Domain scan
1. Click **Domain** at the top of the sidebar
2. Type a domain (e.g. `example.com`) and press **Scan Domain**
3. Review the KPI cards (email spoofing protection, TLS certificate, DNSSEC, CDN/WAF), the **Findings** and the **Domain Profile** tab
4. Only for sites you own or may test: tick "I own this domain or am authorized to test it" to enable exposed-file probing

The domain scan is online: it uses Cloudflare DNS-over-HTTPS, rdap.org and connects to the website.

### Project scan

1. **Select Project**: click **Browse** or drag a folder onto the window
2. **Optional Web URL**: enter a localhost URL (e.g. `http://127.0.0.1:3000`) and press **Validate**
3. **Options**: hide low-severity findings, enable the online OSV.dev lookup, or show only findings that are new since your baseline
4. **Start Scan**: click **Start Security Analysis** (click again to cancel; partial results are kept)
5. **Review Results**: filter by severity, search, and use the arrow keys to move through findings
6. **Act on a finding**: **Open File**, **AI Prompt for This Issue**, or **CWE Reference**
7. **Export**: **Export HTML Report** or **File > Export** (JSON, HTML, Markdown, SARIF, CSV)
8. **Baseline**: **File > Save as Baseline** records the current findings for the project

## Understanding Results

### Security Score
- **80-100 (A+)**: Safe - minor or no issues
- **55-79 (A to B-)**: Moderate - address high severity issues
- **40-54 (C)**: High Risk - multiple concerns require attention
- **0-39 (D/F)**: Critical Risk - immediate action required

Any unresolved CRITICAL finding caps the score at 49. Each severity has a maximum deduction so the score keeps improving as you fix issues.

### Severity Levels
- **CRITICAL**: remote code execution, exposed secrets, SQL/command injection
- **HIGH**: XSS, open CORS, disabled TLS verification, missing CSP
- **MEDIUM**: weak hashes, missing headers, insecure cookies, exposed database ports
- **LOW**: best-practice issues (unpinned dependencies, missing SRI, TODOs)

## Scanners

| Scanner | Detects |
|---------|---------|
| Python SAST | eval/exec, SQL & command injection, SSTI, pickle/yaml, hardcoded secrets, debug mode |
| JavaScript | DOM XSS, React/Vue raw HTML, eval, SQL in template literals, CORS, TLS, cookies, tokens in Web Storage |
| HTML | inline scripts, missing SRI, mixed content, tabnabbing, unescaped template output |
| Config | `.env` exposure (git-ignored or not), credentials, DEBUG, cookie/HTTPS/CORS settings |
| Dependency | Vulnerable packages from the local CVE database (and OSV.dev when enabled) |
| Secrets | Cloud/API tokens, private keys, webhook URLs, credentials in URLs |
| IaC | Dockerfile, docker-compose, GitHub Actions workflows |
| Web | Security headers, cookies, CORS reflection, exposed `/.env` / `/.git`, debug pages |
| Domain (online) | DNS/DNSSEC, CAA, SPF/DMARC, WHOIS expiry & lock, TLS certificate & legacy TLS, HTTPS redirect, headers, CDN/WAF |

## Suppressions and Ignores

- Add `securemysite: ignore` (or `nosec`) in a comment on a line to suppress findings on it
- Put `securemysite: ignore-next-line` on the line above to suppress the next line
- Create `.securemysiteignore` in the project root with one glob per line to skip paths

## Security Constraints

- **Localhost Only**: the web scanner accepts only localhost, 127.0.0.0/8, ::1, *.localhost and *.local
- **No Code Execution**: never executes code from scanned projects
- **Path Traversal Protection**: files resolving outside the project (e.g. via symlinks) are skipped
- **Limits**: 10MB per file, 500MB total project size
- **Masked Secrets**: detected secrets are redacted in all reports

## AI Fix Prompts

**Generate AI Fix Prompt** builds a prompt for the whole project; **AI Prompt for This Issue** builds one for the selected finding. Both are copied to the clipboard and can be saved to a file. Prompts include the vulnerability analysis, code snippets, CWE references and fix requirements.

## Export Formats

- **HTML**: self-contained report with severity filters and search
- **JSON**: machine-readable; also usable as a baseline
- **SARIF**: for GitHub code scanning and other SARIF viewers
- **Markdown**: documentation-friendly
- **CSV**: spreadsheets and issue trackers

## Troubleshooting

### GUI Won't Start
```bash
# Check PyQt6 installation
pip install PyQt6 --upgrade
```
The CLI works without PyQt6.

### Scan Errors
- Ensure the project path exists and is readable
- Files over 10MB are skipped; projects over 500MB are refused
- Run with `-v` to see warnings

### Web Scanner Rejected
- Only local URLs are allowed (http://localhost:*, http://127.0.0.1:*)
- Make sure the app is running before scanning

## Best Practices

1. **Scan Before Deployment**: always scan AI-generated code before production
2. **Fix Critical First**: address CRITICAL and HIGH severity immediately
3. **Use AI Prompts**: generate fix prompts for complex vulnerabilities
4. **Re-scan**: verify fixes by scanning again
5. **Automate**: run the CLI in CI with `--fail-on high` and a baseline

## Command Line Reference

```text
python main.py [PROJECT_PATH] [OPTIONS]

  PROJECT_PATH            Project directory (omit to open the GUI)
  -u, --url URL           Localhost URL for web scanning
  -d, --domain DOMAIN     Online scan of a live domain (instead of PROJECT_PATH)
  --active                Domain scan: probe for exposed files (needs --authorized)
  --authorized            Confirm you own or may test the domain
  -e, --export FORMAT     json, html, markdown, sarif, csv
  -o, --output PATH       Output file ("-" for stdout)
  -p, --prompt            Print an AI fix prompt
  --fail-on LEVEL         critical, high, medium, low or none
  --min-severity LEVEL    Only report findings at/above LEVEL
  --baseline FILE         Hide findings present in a previous JSON report
  --exclude GLOB          Skip matching paths (repeatable)
  --scanners LIST         Comma-separated scanners to run
  --list-scanners         List scanners and exit
  --online                Query OSV.dev for dependency vulnerabilities
  -q, --quiet             One-line summary
  --no-color              Disable colors
  -v, --verbose           Verbose logging
  --version               Show version
```

Exit codes: `0` no high/critical, `1` high found (or `--fail-on` threshold met), `2` critical found, `3` error.

## Support

For issues or questions, refer to the README.md or create an issue on GitHub.
