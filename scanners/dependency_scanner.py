"""Dependency vulnerability scanner."""

import re
import json
from typing import List, Optional, Dict, Any
from pathlib import Path

from models.vulnerability import Vulnerability, Severity, Category
from scanners.base_scanner import BaseScanner, ScanContext


class DependencyScanner(BaseScanner):
    """
    Scanner for dependency files (requirements.txt, package.json, etc.).
    
    Checks against local vulnerability database for known vulnerable versions.
    """
    
    DEPENDENCY_FILES = {
        'requirements.txt': 'pip',
        'Pipfile': 'pipenv',
        'Pipfile.lock': 'pipenv',
        'poetry.lock': 'poetry',
        'setup.py': 'setuptools',
        'package.json': 'npm',
        'package-lock.json': 'npm',
        'yarn.lock': 'yarn',
        'pnpm-lock.yaml': 'pnpm',
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.vuln_db = self._load_vulnerability_database()
    
    def _load_vulnerability_database(self) -> Dict[str, List[Dict]]:
        """Load local vulnerability database."""
        default_db = {
            "vulnerabilities": [
                {
                    "package": "django",
                    "affected_versions": [">=3.0,<3.0.14", ">=3.1,<3.1.8"],
                    "severity": "HIGH",
                    "cve": "CVE-2021-31542",
                    "description": "Directory traversal via uploaded files"
                },
                {
                    "package": "django",
                    "affected_versions": [">=2.2,<2.2.24", ">=3.0,<3.0.14", ">=3.1,<3.1.14", ">=3.2,<3.2.4"],
                    "severity": "CRITICAL",
                    "cve": "CVE-2021-35042",
                    "description": "SQL injection via QuerySet.order_by()"
                },
                {
                    "package": "flask",
                    "affected_versions": ["<1.0"],
                    "severity": "HIGH",
                    "cve": "CVE-2018-1000656",
                    "description": "Flask before 1.0 has default session cookie secure flag set to False"
                },
                {
                    "package": "requests",
                    "affected_versions": ["<2.20.0"],
                    "severity": "CRITICAL",
                    "cve": "CVE-2018-18074",
                    "description": "Requests sends HTTP Authorization headers to redirected domains"
                },
                {
                    "package": "urllib3",
                    "affected_versions": ["<1.24.2"],
                    "severity": "CRITICAL",
                    "cve": "CVE-2019-11324",
                    "description": "CRLF injection in urllib3"
                },
                {
                    "package": "jinja2",
                    "affected_versions": ["<2.10.1"],
                    "severity": "HIGH",
                    "cve": "CVE-2019-10906",
                    "description": "Sandbox escape via string formatting"
                },
                {
                    "package": "sqlalchemy",
                    "affected_versions": ["<1.3.0"],
                    "severity": "HIGH",
                    "cve": "CVE-2019-7164",
                    "description": "SQL injection via order_by parameter"
                },
                {
                    "package": "pillow",
                    "affected_versions": ["<8.2.0"],
                    "severity": "CRITICAL",
                    "cve": "CVE-2021-34552",
                    "description": "Buffer overflow in TIFF decoding"
                },
                {
                    "package": "cryptography",
                    "affected_versions": ["<3.2"],
                    "severity": "HIGH",
                    "cve": "CVE-2020-25659",
                    "description": "Bleichenbacher timing attack on RSA decryption"
                },
                {
                    "package": "pyyaml",
                    "affected_versions": ["<5.1"],
                    "severity": "CRITICAL",
                    "cve": "CVE-2017-18342",
                    "description": "Arbitrary code execution via yaml.load"
                },
                {
                    "package": "numpy",
                    "affected_versions": ["<1.22.0"],
                    "severity": "HIGH",
                    "cve": "CVE-2021-34141",
                    "description": "Buffer overflow in array creation"
                },
                {
                    "package": "tornado",
                    "affected_versions": ["<6.1"],
                    "severity": "HIGH",
                    "cve": "CVE-2020-28476",
                    "description": "Open redirect vulnerability"
                },
                {
                    "package": "celery",
                    "affected_versions": ["<5.2.0"],
                    "severity": "HIGH",
                    "cve": "CVE-2021-23727",
                    "description": "Command injection in task execution"
                },
                {
                    "package": "werkzeug",
                    "affected_versions": ["<2.0.0"],
                    "severity": "HIGH",
                    "cve": "CVE-2021-23942",
                    "description": "Console debugger RCE vulnerability"
                },
                {
                    "package": "fastapi",
                    "affected_versions": ["<0.65.2"],
                    "severity": "HIGH",
                    "cve": "CVE-2021-32677",
                    "description": "Open redirect in OAuth2 authentication"
                },
                {
                    "package": "starlette",
                    "affected_versions": ["<0.14.2"],
                    "severity": "HIGH",
                    "cve": "CVE-2021-32677",
                    "description": "Open redirect vulnerability"
                },
                {
                    "package": "aiohttp",
                    "affected_versions": ["<3.7.4"],
                    "severity": "HIGH",
                    "cve": "CVE-2021-21330",
                    "description": "Open redirect in HTTP client"
                },
                {
                    "package": "httpx",
                    "affected_versions": ["<0.23.0"],
                    "severity": "MEDIUM",
                    "cve": "CVE-2021-41945",
                    "description": "Information disclosure in redirects"
                },
                {
                    "package": "lodash",
                    "affected_versions": ["<4.17.21"],
                    "severity": "CRITICAL",
                    "cve": "CVE-2021-23337",
                    "description": "Command injection via template"
                },
                {
                    "package": "express",
                    "affected_versions": ["<4.17.3"],
                    "severity": "HIGH",
                    "cve": "CVE-2022-24999",
                    "description": "qs vulnerable to Prototype Pollution"
                },
                {
                    "package": "axios",
                    "affected_versions": ["<0.21.1"],
                    "severity": "HIGH",
                    "cve": "CVE-2021-3749",
                    "description": "Regular expression denial of service"
                },
                {
                    "package": "minimist",
                    "affected_versions": ["<1.2.6"],
                    "severity": "CRITICAL",
                    "cve": "CVE-2021-44906",
                    "description": "Prototype pollution via constructor"
                },
                {
                    "package": "jsonwebtoken",
                    "affected_versions": ["<9.0.0"],
                    "severity": "CRITICAL",
                    "cve": "CVE-2022-23529",
                    "description": "Token verification bypass"
                },
                {
                    "package": "semver",
                    "affected_versions": ["<7.5.2"],
                    "severity": "HIGH",
                    "cve": "CVE-2022-25883",
                    "description": "Regular expression denial of service"
                },
                {
                    "package": "word-wrap",
                    "affected_versions": ["<1.2.4"],
                    "severity": "HIGH",
                    "cve": "CVE-2023-26115",
                    "description": "Regular expression denial of service"
                },
                {
                    "package": "tough-cookie",
                    "affected_versions": ["<4.1.3"],
                    "severity": "CRITICAL",
                    "cve": "CVE-2023-26136",
                    "description": "Prototype pollution in cookie parsing"
                },
                {
                    "package": "debug",
                    "affected_versions": ["<2.6.9", "<3.1.0"],
                    "severity": "LOW",
                    "cve": "CVE-2017-16137",
                    "description": "Regular expression denial of service"
                },
                {
                    "package": "ini",
                    "affected_versions": ["<1.3.6"],
                    "severity": "HIGH",
                    "cve": "CVE-2020-7788",
                    "description": "Prototype pollution via malicious INI file"
                },
                {
                    "package": "y18n",
                    "affected_versions": ["<5.0.5"],
                    "severity": "CRITICAL",
                    "cve": "CVE-2020-7774",
                    "description": "Prototype pollution in y18n"
                },
                {
                    "package": "node-fetch",
                    "affected_versions": ["<2.6.7", "<3.1.1"],
                    "severity": "HIGH",
                    "cve": "CVE-2022-0235",
                    "description": "Information disclosure via cookie header"
                },
                {
                    "package": "follow-redirects",
                    "affected_versions": ["<1.14.8"],
                    "severity": "HIGH",
                    "cve": "CVE-2022-0536",
                    "description": "Exposure of sensitive information in URL"
                },
                {
                    "package": "ejs",
                    "affected_versions": ["<3.1.7"],
                    "severity": "CRITICAL",
                    "cve": "CVE-2022-29078",
                    "description": "Server-side template injection in ejs"
                },
                {
                    "package": "pac-resolver",
                    "affected_versions": ["<5.0.0"],
                    "severity": "CRITICAL",
                    "cve": "CVE-2021-23406",
                    "description": "Remote code execution via PAC file"
                },
                {
                    "package": "shell-quote",
                    "affected_versions": ["<1.7.3"],
                    "severity": "CRITICAL",
                    "cve": "CVE-2021-42740",
                    "description": "Command injection via malicious input"
                },
                {
                    "package": "ua-parser-js",
                    "affected_versions": ["<0.7.30"],
                    "severity": "CRITICAL",
                    "cve": "CVE-2021-27292",
                    "description": "Regular expression denial of service"
                },
                {
                    "package": "path-parse",
                    "affected_versions": ["<1.0.7"],
                    "severity": "HIGH",
                    "cve": "CVE-2021-23343",
                    "description": "Regular expression denial of service"
                },
                {
                    "package": "color-string",
                    "affected_versions": ["<1.5.5"],
                    "severity": "HIGH",
                    "cve": "CVE-2021-29060",
                    "description": "Regular expression denial of service"
                },
                {
                    "package": "glob-parent",
                    "affected_versions": ["<5.1.2"],
                    "severity": "HIGH",
                    "cve": "CVE-2020-28469",
                    "description": "Regular expression denial of service"
                },
                {
                    "package": "normalize-url",
                    "affected_versions": ["<4.5.1", "<5.3.1", "<6.0.1"],
                    "severity": "HIGH",
                    "cve": "CVE-2021-33502",
                    "description": "Regular expression denial of service"
                },
                {
                    "package": "trim-newlines",
                    "affected_versions": ["<3.0.1", "<4.0.1"],
                    "severity": "HIGH",
                    "cve": "CVE-2021-33623",
                    "description": "Uncontrolled resource consumption"
                },
                {
                    "package": "css-what",
                    "affected_versions": ["<5.0.1"],
                    "severity": "HIGH",
                    "cve": "CVE-2021-33560",
                    "description": "Regular expression denial of service"
                },
                {
                    "package": "ws",
                    "affected_versions": ["<7.4.6", "<6.2.2", "<5.2.3"],
                    "severity": "HIGH",
                    "cve": "CVE-2021-32640",
                    "description": "Regular expression denial of service in Sec-Websocket-Protocol header"
                },
                {
                    "package": "browserslist",
                    "affected_versions": ["<4.16.5"],
                    "severity": "MEDIUM",
                    "cve": "CVE-2021-23364",
                    "description": "Regular expression denial of service"
                },
                {
                    "package": "hosted-git-info",
                    "affected_versions": ["<2.8.9", "<3.0.8"],
                    "severity": "MEDIUM",
                    "cve": "CVE-2021-23362",
                    "description": "Regular expression denial of service"
                },
                {
                    "package": "postcss",
                    "affected_versions": ["<8.2.13", "<7.0.36"],
                    "severity": "MEDIUM",
                    "cve": "CVE-2021-23382",
                    "description": "Regular expression denial of service"
                },
                {
                    "package": "dns-packet",
                    "affected_versions": ["<1.3.2", "<5.2.2"],
                    "severity": "HIGH",
                    "cve": "CVE-2021-23386",
                    "description": "Buffer overflow in DNS packet parsing"
                },
                {
                    "package": "tar",
                    "affected_versions": ["<6.1.9", "<4.4.19", "<5.0.11"],
                    "severity": "HIGH",
                    "cve": "CVE-2021-37713",
                    "description": "Arbitrary file creation/overwrite via symlink"
                },
                {
                    "package": "mpath",
                    "affected_versions": ["<0.8.4"],
                    "severity": "CRITICAL",
                    "cve": "CVE-2021-23438",
                    "description": "Prototype pollution via mpath"
                },
                {
                    "package": "mongoose",
                    "affected_versions": ["<5.13.15", "<6.4.6"],
                    "severity": "HIGH",
                    "cve": "CVE-2022-42889",
                    "description": "Prototype pollution in mongoose schema"
                },
                {
                    "package": "bson",
                    "affected_versions": ["<1.1.4"],
                    "severity": "CRITICAL",
                    "cve": "CVE-2020-7610",
                    "description": "Deserialization of untrusted data in bson"
                },
                {
                    "package": "underscore",
                    "affected_versions": ["<1.12.1", "<1.13.0-2"],
                    "severity": "CRITICAL",
                    "cve": "CVE-2021-23358",
                    "description": "Arbitrary code execution via template"
                },
                {
                    "package": "handlebars",
                    "affected_versions": ["<4.7.7"],
                    "severity": "CRITICAL",
                    "cve": "CVE-2021-23369",
                    "description": "Remote code execution via template"
                },
                {
                    "package": "mustache",
                    "affected_versions": ["<4.1.0"],
                    "severity": "MEDIUM",
                    "cve": "CVE-2021-23362",
                    "description": "Cross-site scripting in mustache"
                },
                {
                    "package": "pug",
                    "affected_versions": ["<3.0.1"],
                    "severity": "CRITICAL",
                    "cve": "CVE-2021-21353",
                    "description": "Remote code execution via pug template"
                },
                {
                    "package": "jquery",
                    "affected_versions": ["<3.5.0"],
                    "severity": "MEDIUM",
                    "cve": "CVE-2020-11022",
                    "description": "Cross-site scripting in jQuery"
                },
                {
                    "package": "jquery",
                    "affected_versions": ["<3.4.0"],
                    "severity": "HIGH",
                    "cve": "CVE-2019-11358",
                    "description": "Prototype pollution in jQuery"
                },
                {
                    "package": "bootstrap",
                    "affected_versions": ["<4.5.3"],
                    "severity": "MEDIUM",
                    "cve": "CVE-2021-23327",
                    "description": "Cross-site scripting in Bootstrap"
                },
                {
                    "package": "moment",
                    "affected_versions": ["<2.29.2"],
                    "severity": "HIGH",
                    "cve": "CVE-2022-24785",
                    "description": "Path traversal in moment.js"
                },
                {
                    "package": "validator",
                    "affected_versions": ["<13.7.0"],
                    "severity": "HIGH",
                    "cve": "CVE-2021-23327",
                    "description": "Regular expression denial of service in validator.js"
                },
                {
                    "package": "ajv",
                    "affected_versions": ["<8.10.0"],
                    "severity": "MEDIUM",
                    "cve": "CVE-2021-23327",
                    "description": "Prototype pollution in ajv"
                },
            ]
        }
        
        # Index by package name for faster lookup
        indexed_db = {}
        for vuln in default_db['vulnerabilities']:
            pkg = vuln['package'].lower()
            if pkg not in indexed_db:
                indexed_db[pkg] = []
            indexed_db[pkg].append(vuln)
        
        return indexed_db
    
    def get_name(self) -> str:
        return "dependency_scanner"
    
    def get_description(self) -> str:
        return "Dependency vulnerability scanner (requirements.txt, package.json)"
    
    def get_supported_languages(self) -> List[str]:
        return ['text', 'json']
    
    def can_scan_file(self, file_path: Path) -> bool:
        """Check if file is a dependency file."""
        if not file_path:
            return False
        
        name = file_path.name.lower()
        return name in self.DEPENDENCY_FILES
    
    def scan(self, context: ScanContext) -> List[Vulnerability]:
        """Scan dependency file for known vulnerabilities."""
        vulnerabilities = []
        
        if not context.file_path or not context.file_content:
            return vulnerabilities
        
        file_name = context.file_path.name.lower()
        file_type = self.DEPENDENCY_FILES.get(file_name, 'unknown')
        
        if file_type == 'pip':
            vulns = self._scan_requirements_txt(context)
            vulnerabilities.extend(vulns)
        elif file_type == 'npm':
            vulns = self._scan_package_json(context)
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def _scan_requirements_txt(self, context: ScanContext) -> List[Vulnerability]:
        """Scan requirements.txt for vulnerable packages."""
        vulnerabilities = []
        content = context.file_content
        
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Parse package name and version
            match = re.match(r'^([a-zA-Z0-9_-]+)(?:[<>=~!]+)?([0-9.]+)?', line)
            if match:
                pkg_name = match.group(1).lower()
                pkg_version = match.group(2) or '0.0.0'
                
                # Check against vulnerability database
                if pkg_name in self.vuln_db:
                    for vuln in self.vuln_db[pkg_name]:
                        if self._version_affected(pkg_version, vuln.get('affected_versions', [])):
                            vuln_obj = Vulnerability(
                                title=f"Vulnerable Dependency: {pkg_name}@{pkg_version}",
                                description=f"{vuln['description']} (CVE: {vuln.get('cve', 'N/A')})",
                                severity=Severity[vuln['severity']],
                                category=Category.DEPENDENCY,
                                file_path=context.file_path,
                                line_number=self._get_line_number(content, line),
                                code_snippet=line[:100],
                                remediation=f"Upgrade {pkg_name} to a non-vulnerable version. Check CVE details for fixed version.",
                                cwe_id='CWE-1035',
                                scanner_source=self.get_name(),
                                metadata={
                                    'package': pkg_name,
                                    'version': pkg_version,
                                    'cve': vuln.get('cve'),
                                    'affected_versions': vuln.get('affected_versions')
                                }
                            )
                            vulnerabilities.append(vuln_obj)
        
        return vulnerabilities
    
    def _scan_package_json(self, context: ScanContext) -> List[Vulnerability]:
        """Scan package.json for vulnerable packages."""
        vulnerabilities = []
        
        try:
            data = json.loads(context.file_content)
        except json.JSONDecodeError:
            return vulnerabilities
        
        # Check dependencies and devDependencies
        for dep_type in ['dependencies', 'devDependencies']:
            deps = data.get(dep_type, {})
            for pkg_name, version_spec in deps.items():
                # Clean version string (remove ^, ~, etc.)
                clean_version = re.sub(r'^[\^~>=<]+', '', version_spec)
                if not clean_version:
                    clean_version = '0.0.0'
                
                # Check against vulnerability database
                pkg_lower = pkg_name.lower()
                if pkg_lower in self.vuln_db:
                    for vuln in self.vuln_db[pkg_lower]:
                        if self._version_affected(clean_version, vuln.get('affected_versions', [])):
                            vuln_obj = Vulnerability(
                                title=f"Vulnerable Dependency: {pkg_name}@{clean_version}",
                                description=f"{vuln['description']} (CVE: {vuln.get('cve', 'N/A')})",
                                severity=Severity[vuln['severity']],
                                category=Category.DEPENDENCY,
                                file_path=context.file_path,
                                line_number=1,
                                code_snippet=f'"{pkg_name}": "{version_spec}"',
                                remediation=f"Upgrade {pkg_name} to a non-vulnerable version. Run 'npm audit' for details.",
                                cwe_id='CWE-1035',
                                scanner_source=self.get_name(),
                                metadata={
                                    'package': pkg_name,
                                    'version': clean_version,
                                    'cve': vuln.get('cve'),
                                    'dependency_type': dep_type,
                                    'affected_versions': vuln.get('affected_versions')
                                }
                            )
                            vulnerabilities.append(vuln_obj)
        
        # Check for missing lockfile
        has_lockfile = (
            (context.file_path.parent / 'package-lock.json').exists() or
            (context.file_path.parent / 'yarn.lock').exists() or
            (context.file_path.parent / 'pnpm-lock.yaml').exists()
        )
        
        if not has_lockfile:
            vuln_obj = Vulnerability(
                title='Missing Lockfile',
                description='No package-lock.json, yarn.lock, or pnpm-lock.yaml found. Dependencies may not be reproducible.',
                severity=Severity.LOW,
                category=Category.DEPENDENCY,
                file_path=context.file_path,
                line_number=1,
                code_snippet='package.json without lockfile',
                remediation='Run "npm install" to generate package-lock.json, or use "yarn install" / "pnpm install".',
                cwe_id=None,
                scanner_source=self.get_name(),
                metadata={'issue': 'missing_lockfile'}
            )
            vulnerabilities.append(vuln_obj)
        
        return vulnerabilities
    
    def _version_affected(self, version: str, affected_ranges: List[str]) -> bool:
        """Check if version is affected by vulnerability."""
        if not affected_ranges:
            return False
        
        for range_spec in affected_ranges:
            # Handle wildcard (all versions affected)
            if range_spec == '*':
                return True
            
            # Simple version comparison for common patterns
            try:
                if range_spec.startswith('<'):
                    # Less than version
                    compare_ver = range_spec[1:]
                    if self._compare_versions(version, compare_ver) < 0:
                        return True
                elif range_spec.startswith('>='):
                    # Greater than or equal
                    compare_ver = range_spec[2:]
                    if self._compare_versions(version, compare_ver) >= 0:
                        # Check for upper bound
                        if ',' in range_spec:
                            parts = range_spec.split(',')
                            upper = parts[1].strip()
                            if upper.startswith('<'):
                                upper_ver = upper[1:]
                                if self._compare_versions(version, upper_ver) < 0:
                                    return True
                        else:
                            return True
                elif range_spec.startswith('>'):
                    # Greater than
                    compare_ver = range_spec[1:]
                    if self._compare_versions(version, compare_ver) > 0:
                        return True
                elif range_spec.startswith('<='):
                    # Less than or equal
                    compare_ver = range_spec[2:]
                    if self._compare_versions(version, compare_ver) <= 0:
                        return True
                else:
                    # Exact version match
                    if version == range_spec:
                        return True
            except Exception:
                # If parsing fails, assume affected for safety
                return True
        
        return False
    
    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare two version strings. Returns -1, 0, or 1."""
        try:
            parts1 = [int(x) for x in v1.split('.')[:3]]
            parts2 = [int(x) for x in v2.split('.')[:3]]
            
            # Pad with zeros
            while len(parts1) < 3:
                parts1.append(0)
            while len(parts2) < 3:
                parts2.append(0)
            
            for i in range(3):
                if parts1[i] < parts2[i]:
                    return -1
                elif parts1[i] > parts2[i]:
                    return 1
            return 0
        except (ValueError, IndexError):
            # Fallback to string comparison
            if v1 < v2:
                return -1
            elif v1 > v2:
                return 1
            return 0
    
    def _get_line_number(self, content: str, target_line: str) -> int:
        """Get line number for a specific line in content."""
        for i, line in enumerate(content.split('\n'), 1):
            if line.strip() == target_line.strip():
                return i
        return 1
