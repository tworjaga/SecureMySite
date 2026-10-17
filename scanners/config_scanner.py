"""Configuration file security scanner."""

import re
import json
import fnmatch
from typing import List, Optional, Dict, Any, Tuple
from pathlib import Path

from models.vulnerability import Vulnerability, Severity, Category
from scanners.base_scanner import BaseScanner, ScanContext, mask_secret, redact_secrets, SECRET_KEY


# key = value  /  key: value  (quoted or not), capturing the value
_VALUE = r'\s*[=:]\s*(?P<q>["\']?)(?P<val>[^"\'\s#,;]{%d,})(?P=q)'

# Values that are references or placeholders rather than real secrets
NON_SECRET_VALUE_RE = re.compile(
    r'^(?:\$\{?.*|%\(.*|\{\{.*|<.*>|!(?:Ref|Sub|GetAtt).*|os\.environ.*|process\.env.*|env\(.*|'
    r'x+|\*+|changeme|change[-_]?me|your[-_].*|example.*|placeholder|dummy|test|none|null|false|true|'
    r'secret|password|todo|fixme|\.\.\.)$',
    re.IGNORECASE
)

TEMPLATE_SUFFIXES = ('.example', '.sample', '.template', '.dist', '.defaults', '.tmpl')

CODE_SUFFIXES = {'.py', '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue', '.svelte'}


class ConfigScanner(BaseScanner):
    """
    Scanner for configuration files (.env, .ini, .yaml, .toml, .json, etc.).

    Detects:
    - Sensitive files present in the project (and whether they are git-ignored)
    - Debug mode enabled
    - Hardcoded secrets, API keys, database credentials (quoted or unquoted)
    - Insecure cookie settings / disabled HTTPS
    - Permissive CORS / ALLOWED_HOSTS
    """

    PATTERNS = {
        'debug_true': {
            'pattern': r'^\s*["\']?(?:DEBUG|FLASK_DEBUG|APP_DEBUG|DJANGO_DEBUG)["\']?\s*[=:]\s*["\']?(?:true|1|yes|on)\b',
            'severity': Severity.HIGH,
            'category': Category.CONFIGURATION,
            'title': 'Debug Mode Enabled',
            'description': 'Debug mode is enabled in configuration, exposing stack traces and internals',
            'remediation': 'Set DEBUG=false in production configuration.',
            'cwe': 'CWE-489',
        },
        'secret_key_hardcoded': {
            'pattern': r'^\s*["\']?(?:[A-Z0-9_]*SECRET[A-Z0-9_]*|SECRET_KEY|JWT_SECRET|SESSION_SECRET|SIGNING_KEY)["\']?' + (_VALUE % 8),
            'secret': True,
            'severity': Severity.CRITICAL,
            'category': Category.EXPOSURE,
            'title': 'Hardcoded Secret',
            'description': 'A secret value is stored in plain text in a configuration file',
            'remediation': 'Keep secrets out of the repository: inject them via environment variables or a secrets manager, '
                           'and rotate the exposed value.',
            'cwe': 'CWE-798',
        },
        'database_password_plain': {
            'pattern': r'^\s*["\']?(?:DB_PASS(?:WORD)?|DATABASE_PASSWORD|MYSQL_(?:ROOT_)?PASSWORD|POSTGRES_PASSWORD|REDIS_PASSWORD|MONGO_\w*PASSWORD|PASSWORD)["\']?' + (_VALUE % 4),
            'secret': True,
            'severity': Severity.CRITICAL,
            'category': Category.EXPOSURE,
            'title': 'Database Credentials in Config',
            'description': 'A password is stored in plain text in configuration',
            'remediation': 'Use environment variables or a secrets manager for database credentials.',
            'cwe': 'CWE-798',
        },
        'database_url_credentials': {
            'pattern': r'(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp)://[^:\s/"\']+:(?P<val>[^@\s"\']{3,})@',
            'secret': True,
            'severity': Severity.CRITICAL,
            'category': Category.EXPOSURE,
            'title': 'Credentials in Connection String',
            'description': 'A connection URL contains an embedded username and password',
            'remediation': 'Build the connection string from environment variables at runtime.',
            'cwe': 'CWE-798',
        },
        'api_key_exposed': {
            'pattern': r'^\s*["\']?(?:[A-Z0-9_]*API_?KEY|[A-Z0-9_]*ACCESS_TOKEN|[A-Z0-9_]*AUTH_TOKEN|API_SECRET|CLIENT_SECRET)["\']?' + (_VALUE % 10),
            'secret': True,
            'severity': Severity.CRITICAL,
            'category': Category.EXPOSURE,
            'title': 'API Key Exposed',
            'description': 'An API key or access token is stored in a configuration file',
            'remediation': 'Move API keys to environment variables or a secrets manager and rotate the exposed key.',
            'cwe': 'CWE-798',
        },
        'aws_key_exposed': {
            'pattern': r'^\s*["\']?(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)["\']?' + (_VALUE % 16),
            'secret': True,
            'severity': Severity.CRITICAL,
            'category': Category.EXPOSURE,
            'title': 'AWS Credentials Exposed',
            'description': 'AWS credentials stored in configuration file',
            'remediation': 'Use IAM roles or AWS Secrets Manager. Never commit AWS credentials; rotate them now.',
            'cwe': 'CWE-798',
        },
        'disable_https': {
            'pattern': r'(?:SECURE_SSL_REDIRECT|FORCE_HTTPS|ENFORCE_HTTPS|REQUIRE_HTTPS)["\']?\s*[=:]\s*["\']?(?:false|0|off|no)\b',
            'severity': Severity.HIGH,
            'category': Category.TRANSPORT,
            'title': 'HTTPS Enforcement Disabled',
            'description': 'HTTPS redirection is explicitly disabled',
            'remediation': 'Enable HTTPS enforcement in production.',
            'cwe': 'CWE-319',
        },
        'insecure_cookie': {
            'pattern': r'(?:SESSION_COOKIE_SECURE|CSRF_COOKIE_SECURE|COOKIE_SECURE)["\']?\s*[=:]\s*["\']?(?:false|0|off|no)\b',
            'severity': Severity.HIGH,
            'category': Category.CONFIGURATION,
            'title': 'Insecure Cookie Settings',
            'description': 'Secure flag disabled for cookies - they will be sent over plain HTTP',
            'remediation': 'Set cookie secure flags to true in production.',
            'cwe': 'CWE-614',
        },
        'cookie_httponly_disabled': {
            'pattern': r'(?:SESSION_COOKIE_HTTPONLY|CSRF_COOKIE_HTTPONLY|COOKIE_HTTPONLY)["\']?\s*[=:]\s*["\']?(?:false|0|off|no)\b',
            'severity': Severity.HIGH,
            'category': Category.CONFIGURATION,
            'title': 'Cookie HttpOnly Disabled',
            'description': 'HttpOnly flag disabled - cookies accessible to JavaScript/XSS',
            'remediation': 'Enable HttpOnly flag for all sensitive cookies.',
            'cwe': 'CWE-1004',
        },
        'cors_allow_all': {
            'pattern': r'(?:CORS_ALLOWED_ORIGINS|CORS_ORIGIN_ALLOW_ALL|CORS_ALLOW_ALL(?:_ORIGINS)?|CORS_ORIGINS?|ALLOWED_ORIGINS)["\']?\s*[=:]\s*(?:["\']?(?:true|1|\*)["\']?\s*$|\[[^\]]*["\']\*["\'])',
            'severity': Severity.HIGH,
            'category': Category.CONFIGURATION,
            'title': 'CORS Allows All Origins',
            'description': 'CORS configuration allows requests from any origin',
            'remediation': 'Specify exact allowed origins. Remove wildcard configuration.',
            'cwe': 'CWE-942',
        },
        'allowed_hosts_wildcard': {
            'pattern': r'ALLOWED_HOSTS["\']?\s*[=:]\s*(?:\[[^\]]*["\']\*["\']|["\']?\*["\']?\s*$)',
            'severity': Severity.HIGH,
            'category': Category.CONFIGURATION,
            'title': 'ALLOWED_HOSTS Contains Wildcard',
            'description': 'ALLOWED_HOSTS includes * which allows any host header',
            'remediation': 'Specify exact domain names in ALLOWED_HOSTS.',
            'cwe': 'CWE-644',
        },
    }

    # Sensitive file patterns that should not be in a repository / deployment
    SENSITIVE_FILES = [
        ('.env', 'Environment file with credentials'),
        ('.env.*', 'Environment file'),
        ('id_rsa', 'SSH private key'),
        ('id_dsa', 'SSH private key'),
        ('id_ecdsa', 'SSH private key'),
        ('id_ed25519', 'SSH private key'),
        ('.htpasswd', 'Apache password file'),
        ('.netrc', 'Netrc credentials file'),
        ('credentials.json', 'Credentials file'),
        ('secrets.json', 'Secrets file'),
        ('service-account*.json', 'Cloud service account key'),
        ('*.pem', 'PEM certificate/key file'),
        ('*.key', 'Private key file'),
        ('*.p12', 'PKCS12 certificate file'),
        ('*.pfx', 'PFX certificate file'),
    ]

    CONFIG_EXTENSIONS = {'.env', '.ini', '.cfg', '.conf', '.yaml', '.yml', '.json', '.toml', '.properties'}

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self._gitignore_cache: Dict[Path, List[str]] = {}

    def get_name(self) -> str:
        return "config_scanner"

    def get_description(self) -> str:
        return "Configuration file security scanner (.env, settings, secrets detection)"

    def get_supported_languages(self) -> List[str]:
        return ['env', 'ini', 'yaml', 'json', 'config', 'toml']

    @staticmethod
    def _is_template(name: str) -> bool:
        return name.endswith(TEMPLATE_SUFFIXES)

    def _sensitive_match(self, name: str) -> Optional[Tuple[str, str]]:
        if self._is_template(name):
            return None
        for pattern, description in self.SENSITIVE_FILES:
            if fnmatch.fnmatch(name, pattern):
                return pattern, description
        return None

    def can_scan_file(self, file_path: Path) -> bool:
        """Check if file is a configuration file."""
        if not file_path:
            return False

        name = file_path.name.lower()
        suffix = file_path.suffix.lower()

        # Source code is handled by the language scanners
        if suffix in CODE_SUFFIXES:
            return False

        if self._sensitive_match(name) or name.startswith('.env'):
            return True

        if suffix in self.CONFIG_EXTENSIONS:
            return True

        return False

    def scan(self, context: ScanContext) -> List[Vulnerability]:
        """Scan configuration file for security issues."""
        vulnerabilities = []

        if not context.file_path:
            return vulnerabilities

        vuln = self._check_sensitive_file_exposure(context)
        if vuln:
            vulnerabilities.append(vuln)

        if not context.file_content:
            return vulnerabilities

        name = context.file_path.name.lower()
        is_template = self._is_template(name)

        # Lock files are machine-generated and huge; nothing to configure there
        if name in ('package-lock.json', 'composer.lock', 'pnpm-lock.yaml', 'yarn.lock', 'poetry.lock', 'pipfile.lock'):
            return vulnerabilities

        vulnerabilities.extend(self._scan_with_patterns(context, skip_secrets=is_template))

        if context.file_path.suffix.lower() == '.json' and not is_template:
            vulnerabilities.extend(self._scan_json(context))

        return redact_secrets(vulnerabilities)

    # ----------------------------------------------------------- sensitive files

    def _gitignore_patterns(self, project_path: Path) -> List[str]:
        root = Path(project_path)
        if root not in self._gitignore_cache:
            patterns: List[str] = []
            gitignore = root / '.gitignore'
            if gitignore.is_file():
                try:
                    for line in gitignore.read_text(encoding='utf-8', errors='replace').splitlines():
                        line = line.strip()
                        if line and not line.startswith('#') and not line.startswith('!'):
                            patterns.append(line.strip('/'))
                except OSError:
                    pass
            self._gitignore_cache[root] = patterns
        return self._gitignore_cache[root]

    def _is_gitignored(self, context: ScanContext) -> bool:
        patterns = self._gitignore_patterns(context.project_path)
        name = context.file_path.name
        try:
            rel = context.file_path.resolve().relative_to(Path(context.project_path).resolve()).as_posix()
        except (ValueError, OSError):
            rel = name
        return any(fnmatch.fnmatch(name, p) or fnmatch.fnmatch(rel, p) for p in patterns)

    def _check_sensitive_file_exposure(self, context: ScanContext) -> Optional[Vulnerability]:
        """Report sensitive files found in the project."""
        name = context.file_path.name.lower()
        match = self._sensitive_match(name)
        if not match:
            return None
        pattern, description = match

        if self._is_gitignored(context):
            return Vulnerability(
                title=f'Sensitive File Present: {context.file_path.name}',
                description=f'{description} exists in the project folder. It is git-ignored, but make sure it is '
                            'excluded from Docker images, archives and static file deployments too.',
                severity=Severity.LOW,
                category=Category.EXPOSURE,
                file_path=context.file_path,
                line_number=1,
                code_snippet=f"File: {context.file_path.name} (listed in .gitignore)",
                remediation='Add the file to .dockerignore and never serve the project root as static files.',
                cwe_id='CWE-538',
                scanner_source=self.get_name(),
                metadata={'file_pattern': pattern, 'gitignored': True}
            )

        return Vulnerability(
            title=f'Sensitive File Exposed: {context.file_path.name}',
            description=f'{description} found in the project and NOT listed in .gitignore. '
                        'It will be committed and possibly deployed.',
            severity=Severity.CRITICAL,
            category=Category.EXPOSURE,
            file_path=context.file_path,
            line_number=1,
            code_snippet=f"File: {context.file_path.name}",
            remediation=f'Add {pattern} to .gitignore (and .dockerignore), remove it from git history if it was '
                        'committed, and rotate any credentials it contains. Ship a .env.example with dummy values instead.',
            cwe_id='CWE-538',
            scanner_source=self.get_name(),
            metadata={'file_pattern': pattern, 'gitignored': False}
        )

    # ----------------------------------------------------------- patterns

    def _scan_with_patterns(self, context: ScanContext, skip_secrets: bool) -> List[Vulnerability]:
        """Scan using regex patterns."""
        vulnerabilities = []
        content = context.file_content

        for pattern_name, info in self.PATTERNS.items():
            is_secret = info.get('secret', False)
            if is_secret and skip_secrets:
                continue
            if pattern_name == 'debug_true' and context.file_path.suffix.lower() == '.json':
                continue  # handled structurally by _scan_json
            try:
                for match in re.finditer(info['pattern'], content, re.IGNORECASE | re.MULTILINE):
                    value = match.groupdict().get('val')
                    if is_secret and value and NON_SECRET_VALUE_RE.match(value):
                        continue
                    vuln = self.finding_from_match(context, match, info, pattern_name)
                    if is_secret and value:
                        masked = mask_secret(value)
                        if vuln.code_snippet:
                            vuln.code_snippet = vuln.code_snippet.replace(value, masked)
                        vuln.metadata['match'] = vuln.metadata['match'].replace(value, masked)
                        vuln.metadata[SECRET_KEY] = value
                    vulnerabilities.append(vuln)
            except re.error as e:
                self.log_error(f"Regex error in pattern {pattern_name}: {e}")

        return vulnerabilities

    # ----------------------------------------------------------- JSON

    def _scan_json(self, context: ScanContext) -> List[Vulnerability]:
        """Check JSON configuration for debug flags and embedded secrets."""
        try:
            data = json.loads(context.file_content)
        except (json.JSONDecodeError, ValueError):
            return []

        vulnerabilities = []
        content = context.file_content

        for path, value in self._walk_json(data):
            key = path[-1] if path else ''
            key_l = key.lower()
            dotted = '.'.join(path)

            if key_l == 'debug' and value is True:
                line = self._find_line(content, key)
                vulnerabilities.append(Vulnerability(
                    title='Debug Mode Enabled in JSON Config',
                    description=f'debug is set to true at "{dotted}"',
                    severity=Severity.HIGH,
                    category=Category.CONFIGURATION,
                    file_path=context.file_path,
                    line_number=line,
                    code_snippet=self.extract_code_snippet(content, line),
                    remediation='Set debug to false in production configuration files.',
                    cwe_id='CWE-489',
                    scanner_source=self.get_name(),
                    metadata={'config_path': dotted}
                ))

            if (
                isinstance(value, str)
                and re.search(r'secret|password|passwd|api_?key|apikey|private_?key|access_?token|auth_?token|client_?secret', key_l)
                and len(value) >= 8
                and not NON_SECRET_VALUE_RE.match(value)
            ):
                line = self._find_line(content, key)
                snippet = self.extract_code_snippet(content, line).replace(value, mask_secret(value))
                vulnerabilities.append(Vulnerability(
                    title=f'Secret in JSON Config: {key}',
                    description=f'"{dotted}" contains what looks like a hardcoded secret',
                    severity=Severity.CRITICAL,
                    category=Category.EXPOSURE,
                    file_path=context.file_path,
                    line_number=line,
                    code_snippet=snippet,
                    remediation='Move secrets to environment variables or a secrets manager and rotate the value.',
                    cwe_id='CWE-798',
                    scanner_source=self.get_name(),
                    metadata={'config_path': dotted, 'key': key, 'match': mask_secret(value), SECRET_KEY: value}
                ))

        return vulnerabilities

    def _walk_json(self, data: Any, path: Optional[List[str]] = None):
        path = path or []
        if isinstance(data, dict):
            for key, value in data.items():
                new_path = path + [str(key)]
                yield new_path, value
                yield from self._walk_json(value, new_path)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                yield from self._walk_json(item, path + [str(i)])

    @staticmethod
    def _find_line(content: str, key: str) -> int:
        needle = f'"{key}"'
        idx = content.find(needle)
        return content.count('\n', 0, idx) + 1 if idx >= 0 else 1

    # Kept for backwards compatibility with older callers
    def _get_nested_value(self, data: Dict, path: List[str]) -> Any:
        current = data
        for key in path:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        return current
