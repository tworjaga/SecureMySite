# Secure My Site

A fully offline, local desktop security analyzer for AI-generated web projects. Detects vulnerabilities before deployment through static analysis (SAST), dynamic analysis (DAST on localhost only), and dependency review.

## Features

- **100% Offline Operation** - No data leaves your machine
- **Static Analysis (SAST)** - Python, JavaScript/TypeScript code scanning
- **Dependency Scanning** - requirements.txt, package.json vulnerability detection
- **Configuration Analysis** - .env, settings.py security checks
- **Local Web Scanning** - Security headers and endpoint analysis (localhost only)
- **AI Fix Prompts** - Generate structured prompts for ChatGPT/Claude
- **Professional GUI** - Dark theme PyQt6 interface
- **CLI Mode** - Command-line operation for CI/CD integration

## Installation

### Requirements

- Python 3.11 or higher
- Windows, macOS, or Linux

### Install from Source

```bash
# Clone repository
git clone https://github.com/tworjaga/SecureMySite.git
cd SecureMySite

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### GUI Mode

Launch the application without arguments:

```bash
python main.py
```

### CLI Mode

Scan a project directory:

```bash
python main.py /path/to/project
```

With web scanning:

```bash
python main.py /path/to/project --url http://localhost:8000
```

Export results:

```bash
python main.py /path/to/project --export json --output report.json
```

Generate AI fix prompt:

```bash
python main.py /path/to/project --prompt
```

## Security Score

The application calculates a security score from 0-100:

| Score | Grade | Risk Level |
|-------|-------|------------|
| 80-100 | A+ to A | Safe |
| 60-79 | B+ to B | Moderate |
| 40-59 | C+ to C | High Risk |
| 0-39 | D+ to F | Critical Risk |

## Vulnerability Severity Levels

- **CRITICAL** (-15 points): RCE, exposed secrets, SQL injection
- **HIGH** (-10 points): XSS, open CORS, missing CSP
- **MEDIUM** (-5 points): Missing headers, debug configs
- **LOW** (-2 points): Best practice violations

## Scanners

### Python SAST
- Detects eval/exec usage
- SQL injection patterns
- Hardcoded credentials
- Debug mode enabled
- Unsafe deserialization
- Path traversal risks

### JavaScript Scanner
- DOM XSS (innerHTML)
- eval() usage
- localStorage token storage
- Exposed API keys
- CORS misconfigurations

### Config Scanner
- .env file exposure
- Debug settings
- Hardcoded secrets
- Insecure cookie flags

### Dependency Scanner
- requirements.txt analysis
- package.json analysis
- Local vulnerability database (100+ CVEs)

### Web Scanner (Localhost Only)
- Security headers check
- Cookie flag analysis
- Dangerous endpoint detection
- CORS policy validation

## Project Structure

```
secure_my_site/
├── main.py                 # Entry point
├── app.py                  # Application controller
├── core/
│   ├── engine.py          # Analysis orchestrator
│   ├── file_loader.py     # Safe file discovery
│   └── config.py          # Configuration
├── scanners/
│   ├── base_scanner.py    # Abstract base class
│   ├── python_sast.py     # Python analysis
│   ├── js_scanner.py      # JavaScript analysis
│   ├── config_scanner.py  # Config file analysis
│   ├── dependency_scanner.py  # Dependency audit
│   └── web_scanner.py     # Localhost web scan
├── models/
│   ├── vulnerability.py   # Data model
│   └── scan_result.py     # Results container
├── scoring/
│   ├── severity.py        # Classification rules
│   └── score_engine.py    # Score calculation
├── prompt_engine/
│   └── prompt_builder.py  # AI prompt generation
├── gui/
│   ├── main_window.py     # Primary window
│   ├── components.py      # UI widgets
│   └── theme.py           # Dark theme
└── utils/
    ├── helpers.py         # Utilities
    └── validators.py      # Input validation
```

## Building Executable

### Windows

```bash
pip install pyinstaller
pyinstaller build.spec
```

The executable will be in `dist/SecureMySite.exe`.

## Development

### Running Tests

```bash
pip install -r requirements-dev.txt
pytest
```

### Code Formatting

```bash
black .
```

### Type Checking

```bash
mypy .
```

## Security Constraints

1. **Path Traversal Prevention** - All file operations resolve paths within target directory only
2. **No Code Execution** - Never executes code from scanned projects
3. **Memory Limits** - 10MB per file, 500MB total project size
4. **URL Validation** - Web scanner rejects non-localhost URLs

## License

MIT License - See LICENSE file for details.

## Contributing

Contributions welcome. Please follow conventional commit format:
- `feat:` New features
- `fix:` Bug fixes
- `refactor:` Code refactoring
- `docs:` Documentation
- `style:` Formatting

## Support

- GitHub Issues: https://github.com/tworjaga/SecureMySite/issues
- Telegram: @al7exy
