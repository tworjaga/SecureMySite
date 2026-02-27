# SecureMySite - User Guide

## Overview

SecureMySite is an offline security analyzer for AI-generated web projects. It detects vulnerabilities through static analysis (SAST), dependency scanning, and localhost web scanning.

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
python main.py --project /path/to/your/project

# Scan with web analysis
python main.py --project /path/to/project --url http://localhost:8000

# Export results
python main.py --project /path/to/project --export json --output report.json
```

## Using the GUI

1. **Select Project**: Click "Browse..." and choose your project folder
2. **Optional Web URL**: Enter localhost URL (e.g., `http://127.0.0.1:3000`)
3. **Start Scan**: Click "Start Security Analysis"
4. **Review Results**: View security score and vulnerability list
5. **Generate Prompt**: Click "Generate Fix Prompt" to create AI fix instructions
6. **Export**: Save results as JSON, HTML, or Markdown

## Understanding Results

### Security Score
- **80-100 (A)**: Safe - Minor or no issues
- **60-79 (B)**: Moderate - Address high severity issues
- **40-59 (C)**: High Risk - Multiple concerns require attention
- **0-39 (D/F)**: Critical Risk - Immediate action required

### Severity Levels
- **CRITICAL**: Remote code execution, exposed secrets, SQL injection
- **HIGH**: XSS, missing security headers, open CORS
- **MEDIUM**: Debug configs, verbose errors, insecure cookies
- **LOW**: Best practice violations, missing minor headers

## Scanners

| Scanner | Detects |
|---------|---------|
| Python SAST | eval/exec, SQL injection, hardcoded secrets, debug mode |
| JavaScript | DOM XSS, eval, exposed API keys, localStorage tokens |
| Config | .env exposure, DEBUG=True, hardcoded credentials |
| Dependency | Vulnerable packages (CVE database) |
| Web | Security headers, cookie flags, exposed endpoints |

## Security Constraints

- **Localhost Only**: Web scanner only accepts localhost, 127.0.0.1, or *.local domains
- **No Code Execution**: Never executes code from scanned projects
- **Path Traversal Protection**: All file operations stay within target directory
- **Memory Limits**: 10MB per file, 500MB total project size

## AI Fix Prompts

Click "Generate Fix Prompt" to create a detailed prompt for AI assistants (ChatGPT, Claude, etc.). The prompt includes:
- Complete vulnerability analysis
- Code snippets with line numbers
- CWE references
- Required security fixes
- File-by-file replacement instructions

Copy the prompt and paste it into your AI assistant to receive production-ready secure code.

## Export Formats

- **JSON**: Machine-readable for CI/CD integration
- **HTML**: Human-readable report with styling
- **Markdown**: Documentation-friendly format

## Troubleshooting

### GUI Won't Start
```bash
# Check PyQt6 installation
pip install PyQt6 --upgrade
```

### Scan Errors
- Ensure project path exists and is readable
- Check that files are under 10MB each
- Verify total project size under 500MB

### Web Scanner Rejected
- Only localhost URLs allowed (http://localhost:*, http://127.0.0.1:*)
- External domains are blocked for security

## Best Practices

1. **Scan Before Deployment**: Always scan AI-generated code before production
2. **Fix Critical First**: Address CRITICAL and HIGH severity immediately
3. **Use AI Prompts**: Generate fix prompts for complex vulnerabilities
4. **Regular Scans**: Re-scan after applying fixes to verify
5. **Keep Updated**: Update the vulnerability database regularly

## Command Line Reference

```bash
python main.py [OPTIONS]

Options:
  --project PATH        Project directory to scan (required)
  --url URL            Localhost URL for web scanning (optional)
  --export FORMAT      Export format: json, html, markdown
  --output PATH        Output file path
  --no-gui             Force CLI mode
  --verbose            Enable verbose logging
  --help               Show help message
```

## Support

For issues or questions, refer to the README.md or create an issue on GitHub.
