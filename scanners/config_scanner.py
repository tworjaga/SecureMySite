"""Configuration file security scanner."""

import re
import json
from typing import List, Optional, Dict, Any
from pathlib import Path

from models.vulnerability import Vulnerability, Severity, Category
from scanners.base_scanner import BaseScanner, ScanContext


class ConfigScanner(BaseScanner):
    """
    Scanner for configuration files (.env, .ini, .yaml, settings.py, etc.).
    
    Detects:
    - Exposed .env files in repository
    - Debug mode enabled
    - Hardcoded secrets in config
    - Insecure cookie settings
    - Missing HTTPS enforcement
    """
    
    PATTERNS = {
        'env_file_exposed': {
            'pattern': r'\.env',
            'severity': Severity.CRITICAL,
            'category': Category.EXPOSURE,
            'title': 'Environment File Exposed',
            'description': '.env file may contain sensitive credentials and should not be in repository',
            'remediation': 'Add .env to .gitignore. Use .env.example for templates without real values.',
            'cwe': 'CWE-798',
            'file_patterns': ['.env']
        },
        'debug_true': {
            'pattern': r'(?i)^\s*DEBUG\s*[=:]\s*(?:true|1|yes|on)',
            'severity': Severity.CRITICAL,
            'category': Category.CONFIGURATION,
            'title': 'Debug Mode Enabled',
            'description': 'Debug mode is enabled which exposes sensitive information',
            'remediation': 'Set DEBUG=false or DEBUG=0 in production configuration.',
            'cwe': 'CWE-489',
            'file_patterns': ['.env', '.ini', '.cfg', 'config']
        },
        'secret_key_hardcoded': {
            'pattern': r'(?i)(?:SECRET_KEY|SECRET|JWT_SECRET)\s*[=:]\s*["\'][^"\']+["\']',
            'severity': Severity.CRITICAL,
            'category': Category.EXPOSURE,
            'title': 'Hardcoded Secret Key',
            'description': 'Secret key is hardcoded in configuration file',
            'remediation': 'Load secret keys from environment variables or secure vault.',
            'cwe': 'CWE-798',
            'file_patterns': ['.env', '.ini', 'settings', 'config']
        },
        'database_password_plain': {
            'pattern': r'(?i)(?:DATABASE_URL|DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD)\s*[=:]\s*["\'][^"\']+["\']',
            'severity': Severity.CRITICAL,
            'category': Category.EXPOSURE,
            'title': 'Database Credentials in Config',
            'description': 'Database password stored in plain text in configuration',
            'remediation': 'Use environment variables or connection string from secure source.',
            'cwe': 'CWE-798',
            'file_patterns': ['.env', '.ini', 'settings', 'config']
        },
        'api_key_exposed': {
            'pattern': r'(?i)(?:API_KEY|APIKEY|API_SECRET|ACCESS_TOKEN|AUTH_TOKEN)\s*[=:]\s*["\'][^"\']{10,}["\']',
            'severity': Severity.CRITICAL,
            'category': Category.EXPOSURE,
            'title': 'API Key Exposed',
            'description': 'API key or access token stored in configuration file',
            'remediation': 'Move API keys to environment variables or secure key management.',
            'cwe': 'CWE-798',
            'file_patterns': ['.env', '.ini', 'settings', 'config']
        },
        'aws_key_exposed': {
            'pattern': r'(?i)(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["\'][^"\']+["\']',
            'severity': Severity.CRITICAL,
            'category': Category.EXPOSURE,
            'title': 'AWS Credentials Exposed',
            'description': 'AWS credentials stored in configuration file',
            'remediation': 'Use IAM roles or AWS Secrets Manager. Never commit AWS credentials.',
            'cwe': 'CWE-798',
            'file_patterns': ['.env', '.ini', 'settings', 'config']
        },
        'disable_https': {
            'pattern': r'(?i)(?:SECURE_SSL_REDIRECT|FORCE_HTTPS|ENFORCE_HTTPS)\s*[=:]\s*(?:false|0|off)',
            'severity': Severity.HIGH,
            'category': Category.TRANSPORT,
            'title': 'HTTPS Enforcement Disabled',
            'description': 'HTTPS redirection is explicitly disabled',
            'remediation': 'Enable HTTPS enforcement in production. Set to true.',
            'cwe': 'CWE-319',
            'file_patterns': ['.env', '.ini', 'settings', 'config']
        },
        'insecure_cookie': {
            'pattern': r'(?i)(?:SESSION_COOKIE_SECURE|CSRF_COOKIE_SECURE|COOKIE_SECURE)\s*[=:]\s*(?:false|0|off)',
            'severity': Severity.HIGH,
            'category': Category.CONFIGURATION,
            'title': 'Insecure Cookie Settings',
            'description': 'Secure flag disabled for cookies - sent over HTTP',
            'remediation': 'Set cookie secure flags to true in production.',
            'cwe': 'CWE-614',
            'file_patterns': ['.env', '.ini', 'settings', 'config']
        },
        'cookie_httpless': {
            'pattern': r'(?i)(?:SESSION_COOKIE_HTTPONLY|CSRF_COOKIE_HTTPONLY)\s*[=:]\s*(?:false|0|off)',
            'severity': Severity.HIGH,
            'category': Category.CONFIGURATION,
            'title': 'Cookie HttpOnly Disabled',
            'description': 'HttpOnly flag disabled - cookies accessible to JavaScript/XSS',
            'remediation': 'Enable HttpOnly flag for all sensitive cookies.',
            'cwe': 'CWE-1004',
            'file_patterns': ['.env', '.ini', 'settings', 'config']
        },
        'cors_allow_all': {
            'pattern': r'(?i)(?:CORS_ALLOWED_ORIGINS|CORS_ORIGIN_ALLOW_ALL|CORS_ALLOW_ALL)\s*[=:]\s*(?:true|1|\[.*\*.*\])',
            'severity': Severity.CRITICAL,
            'category': Category.CONFIGURATION,
            'title': 'CORS Allows All Origins',
            'description': 'CORS configuration allows requests from any origin',
            'remediation': 'Specify exact allowed origins. Remove wildcard configuration.',
            'cwe': 'CWE-942',
            'file_patterns': ['.env', '.ini', 'settings', 'config']
        },
        'allowed_hosts_wildcard': {
            'pattern': r'(?i)ALLOWED_HOSTS\s*[=:]\s*\[.*\*.*\]',
            'severity': Severity.HIGH,
            'category': Category.CONFIGURATION,
            'title': 'ALLOWED_HOSTS Contains Wildcard',
            'description': 'ALLOWED_HOSTS includes * which allows any host header',
            'remediation': 'Specify exact domain names in ALLOWED_HOSTS.',
            'cwe': 'CWE-644',
            'file_patterns': ['settings', 'config']
        },
    }
    
    # Sensitive file patterns that should not be in repo
    SENSITIVE_FILES = [
        ('.env', 'Environment file with credentials'),
        ('.env.local', 'Local environment file'),
        ('.env.production', 'Production environment file'),
        ('.env.development', 'Development environment file'),
        ('id_rsa', 'SSH private key'),
        ('id_dsa', 'SSH private key'),
        ('id_ecdsa', 'SSH private key'),
        ('id_ed25519', 'SSH private key'),
        ('.htpasswd', 'Apache password file'),
        ('.netrc', 'Netrc credentials file'),
        ('credentials.json', 'Credentials file'),
        ('secrets.json', 'Secrets file'),
        ('*.pem', 'PEM certificate/key file'),
        ('*.key', 'Private key file'),
        ('*.p12', 'PKCS12 certificate file'),
        ('*.pfx', 'PFX certificate file'),
    ]
    
    def get_name(self) -> str:
        return "config_scanner"
    
    def get_description(self) -> str:
        return "Configuration file security scanner (.env, settings, secrets detection)"
    
    def get_supported_languages(self) -> List[str]:
        return ['env', 'ini', 'yaml', 'json', 'config']
    
    def can_scan_file(self, file_path: Path) -> bool:
        """Check if file is a configuration file."""
        if not file_path:
            return False
        
        name = file_path.name.lower()
        suffix = file_path.suffix.lower()
        
        # Check for sensitive file names
        for pattern, _ in self.SENSITIVE_FILES:
            if pattern.startswith('*'):
                if name.endswith(pattern[1:]):
                    return True
            elif name == pattern or name.startswith(pattern):
                return True
        
        # Check extensions
        config_extensions = {'.env', '.ini', '.cfg', '.conf', '.yaml', '.yml', '.json', '.toml'}
        if suffix in config_extensions:
            return True
        
        # Check for settings/config files
        if 'settings' in name or 'config' in name:
            return True
        
        return False
    
    def scan(self, context: ScanContext) -> List[Vulnerability]:
        """Scan configuration file for security issues."""
        vulnerabilities = []
        
        if not context.file_path:
            return vulnerabilities
        
        # Check for sensitive file exposure
        vuln = self._check_sensitive_file_exposure(context)
        if vuln:
            vulnerabilities.append(vuln)
        
        # If no content, return early
        if not context.file_content:
            return vulnerabilities
        
        # Run pattern-based detection
        pattern_vulns = self._scan_with_patterns(context)
        vulnerabilities.extend(pattern_vulns)
        
        # Parse structured configs (JSON, YAML)
        structured_vulns = self._scan_structured_config(context)
        vulnerabilities.extend(structured_vulns)
        
        return vulnerabilities
    
    def _check_sensitive_file_exposure(self, context: ScanContext) -> Optional[Vulnerability]:
        """Check if a sensitive file is being scanned (indicates exposure)."""
        name = context.file_path.name.lower()
        
        for pattern, description in self.SENSITIVE_FILES:
            matches = False
            if pattern.startswith('*'):
                if name.endswith(pattern[1:]):
                    matches = True
            elif name == pattern:
                matches = True
            
            if matches:
                return Vulnerability(
                    title=f'Sensitive File Exposed: {pattern}',
                    description=f'{description} found in repository. These files should never be committed.',
                    severity=Severity.CRITICAL,
                    category=Category.EXPOSURE,
                    file_path=context.file_path,
                    line_number=1,
                    code_snippet=f"File: {context.file_path.name}",
                    remediation=f'Add {pattern} to .gitignore immediately. Rotate any exposed credentials.',
                    cwe_id='CWE-798',
                    scanner_source=self.get_name(),
                    metadata={'file_pattern': pattern}
                )
        
        return None
    
    def _scan_with_patterns(self, context: ScanContext) -> List[Vulnerability]:
        """Scan using regex patterns."""
        vulnerabilities = []
        content = context.file_content
        file_name = context.file_path.name.lower()
        
        for pattern_name, pattern_info in self.PATTERNS.items():
            # Check if pattern applies to this file type
            file_patterns = pattern_info.get('file_patterns', [])
            if file_patterns:
                matches_file = any(fp in file_name for fp in file_patterns)
                if not matches_file:
                    continue
            
            try:
                for match in re.finditer(
                    pattern_info['pattern'], 
                    content, 
                    re.IGNORECASE | re.MULTILINE
                ):
                    # Find line number
                    line_num = content[:match.start()].count('\n') + 1
                    
                    # Extract code snippet
                    snippet = self.extract_code_snippet(content, line_num)
                    
                    # Create vulnerability
                    vuln = Vulnerability(
                        title=pattern_info['title'],
                        description=pattern_info['description'],
                        severity=pattern_info['severity'],
                        category=pattern_info['category'],
                        file_path=context.file_path,
                        line_number=line_num,
                        code_snippet=snippet,
                        remediation=pattern_info['remediation'],
                        cwe_id=pattern_info.get('cwe'),
                        scanner_source=self.get_name(),
                        metadata={
                            'pattern': pattern_name,
                            'match': match.group(0)[:100]
                        }
                    )
                    vulnerabilities.append(vuln)
                    
            except re.error as e:
                self.log_error(f"Regex error in pattern {pattern_name}: {e}")
        
        return vulnerabilities
    
    def _scan_structured_config(self, context: ScanContext) -> List[Vulnerability]:
        """Scan structured config files (JSON, YAML)."""
        vulnerabilities = []
        suffix = context.file_path.suffix.lower()
        content = context.file_content
        
        # JSON specific checks
        if suffix == '.json':
            try:
                data = json.loads(content)
                vulns = self._check_json_config(data, context)
                vulnerabilities.extend(vulns)
            except json.JSONDecodeError:
                pass
        
        return vulnerabilities
    
    def _check_json_config(self, data: Dict, context: ScanContext) -> List[Vulnerability]:
        """Check JSON configuration for security issues."""
        vulnerabilities = []
        
        # Check for debug mode in various common locations
        debug_paths = [
            ['debug'], ['DEBUG'], ['config', 'debug'], ['app', 'debug'],
            ['development', 'debug'], ['server', 'debug']
        ]
        
        for path in debug_paths:
            value = self._get_nested_value(data, path)
            if value is True:
                vuln = Vulnerability(
                    title='Debug Mode Enabled in JSON Config',
                    description=f'DEBUG is set to true at path: {". ".join(path)}',
                    severity=Severity.CRITICAL,
                    category=Category.CONFIGURATION,
                    file_path=context.file_path,
                    line_number=1,
                    code_snippet=str(value),
                    remediation='Set debug to false in production configuration files.',
                    cwe_id='CWE-489',
                    scanner_source=self.get_name(),
                    metadata={'config_path': '. '.join(path)}
                )
                vulnerabilities.append(vuln)
        
        # Check for exposed secrets
        secret_keys = ['secret', 'password', 'api_key', 'token', 'private_key']
        for key in secret_keys:
            for path, value in self._find_keys_recursive(data, key):
                if isinstance(value, str) and len(value) > 8:
                    vuln = Vulnerability(
                        title=f'Potential Secret in Config: {key}',
                        description=f'Key "{key}" found at path {". ".join(path)} may contain sensitive data',
                        severity=Severity.CRITICAL,
                        category=Category.EXPOSURE,
                        file_path=context.file_path,
                        line_number=1,
                        code_snippet=f'{key}: {"*" * min(len(value), 20)}',
                        remediation='Move secrets to environment variables or secure vault.',
                        cwe_id='CWE-798',
                        scanner_source=self.get_name(),
                        metadata={'config_path': '. '.join(path), 'key': key}
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _get_nested_value(self, data: Dict, path: List[str]) -> Any:
        """Get value from nested dictionary."""
        current = data
        for key in path:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        return current
    
    def _find_keys_recursive(self, data: Dict, search_key: str, current_path: List[str] = None) -> List[tuple]:
        """Recursively find keys in nested dictionary."""
        if current_path is None:
            current_path = []
        
        results = []
        search_key_lower = search_key.lower()
        
        if isinstance(data, dict):
            for key, value in data.items():
                new_path = current_path + [key]
                if search_key_lower in key.lower():
                    results.append((new_path, value))
                if isinstance(value, (dict, list)):
                    results.extend(self._find_keys_recursive(value, search_key, new_path))
        elif isinstance(data, list):
            for i, item in enumerate(data):
                new_path = current_path + [str(i)]
                results.extend(self._find_keys_recursive(item, search_key, new_path))
        
        return results
