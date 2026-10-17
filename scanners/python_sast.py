"""Python Static Application Security Testing (SAST) scanner."""

import ast
import bisect
import io
import re
import tokenize
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple

from models.vulnerability import Vulnerability, Severity, Category
from scanners.base_scanner import BaseScanner, ScanContext, mask_secret, redact_secrets, SECRET_KEY


# Variable / key names that usually hold credentials
SECRET_NAME_RE = re.compile(
    r'(?:^|_)(?:password|passwd|pwd|secret|secret_key|api_?key|apikey|token|access_token|'
    r'auth_token|private_key|client_secret|jwt_secret|signing_key)$',
    re.IGNORECASE
)

# Values that are obviously placeholders, not real secrets
PLACEHOLDER_RE = re.compile(
    r'^(?:|x+|\*+|\.+|changeme|change[-_ ]?me|password|secret|example|sample|dummy|test|'
    r'todo|fixme|none|null|your[-_ ].*|<.*>|\$\{.*\}|\{\{.*\}\}|%\(.*\)s)$',
    re.IGNORECASE
)

SQL_KEYWORDS_RE = re.compile(r'\b(?:SELECT|INSERT|UPDATE|DELETE|REPLACE|CREATE|DROP|ALTER|WHERE)\b', re.IGNORECASE)

SQL_SINKS = {'execute', 'executemany', 'executescript', 'raw', 'extra', 'text', 'query', 'read_sql', 'read_sql_query'}
COMMAND_SINKS = {
    ('os', 'system'), ('os', 'popen'), ('os', 'popen2'), ('os', 'popen3'),
    ('subprocess', 'getoutput'), ('subprocess', 'getstatusoutput'), ('commands', 'getoutput'),
}
SUBPROCESS_FUNCS = {'call', 'run', 'Popen', 'check_output', 'check_call'}
SAFE_YAML_LOADERS = {'SafeLoader', 'CSafeLoader', 'BaseLoader'}


def _call_name(node: ast.Call) -> str:
    """Return dotted name of a call target (e.g. 'os.system', 'eval')."""
    parts = []
    target = node.func
    while isinstance(target, ast.Attribute):
        parts.append(target.attr)
        target = target.value
    if isinstance(target, ast.Name):
        parts.append(target.id)
    return '.'.join(reversed(parts))


def _is_constant_str(node: Optional[ast.AST]) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes))


def _keyword(node: ast.Call, name: str) -> Optional[ast.AST]:
    for kw in node.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _is_true(node: Optional[ast.AST]) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _target_name(target: ast.AST) -> Optional[str]:
    """Name of an assignment target: x, obj.x, d['x']."""
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    if isinstance(target, ast.Subscript) and _is_constant_str(target.slice):
        return str(target.slice.value)
    return None


def _is_test_path(context: ScanContext) -> bool:
    """True if the file looks like a test module (judged relative to the project root)."""
    path = context.file_path
    if not path:
        return False
    try:
        parts = path.resolve().relative_to(Path(context.project_path).resolve()).parts
    except (ValueError, OSError):
        parts = path.parts
    return (
        path.name.startswith('test_') or path.name.endswith('_test.py') or path.name == 'conftest.py'
        or any(p in ('tests', 'test') for p in parts[:-1])
    )


class PythonSASTScanner(BaseScanner):
    """
    Python SAST scanner using AST analysis plus regex patterns.

    Detects:
    - Code injection (eval, exec, compile)
    - Command injection (os.system, subprocess shell=True)
    - SQL injection (f-strings / concatenation / .format / % in queries, incl. via variables)
    - Server-side template injection (render_template_string)
    - Hardcoded secrets (including app.config['SECRET_KEY'])
    - Unsafe deserialization (pickle, marshal, yaml.load)
    - Debug mode / insecure framework settings
    - Disabled TLS verification, weak hashes, insecure randomness
    """

    # Regex patterns. Patterns marked 'ast' are only used when the file
    # cannot be parsed (the AST checks cover them more precisely).
    PATTERNS = {
        'eval_exec': {
            'pattern': r'\b(?:eval|exec)\s*\(',
            'ast': True,
            'severity': Severity.CRITICAL,
            'category': Category.INJECTION,
            'title': 'Dynamic Code Execution',
            'description': 'Use of eval() or exec() with potentially untrusted input can lead to arbitrary code execution',
            'remediation': 'Replace eval() with ast.literal_eval() for literals, or use safer alternatives. Avoid exec() entirely.',
            'cwe': 'CWE-95'
        },
        'subprocess_shell': {
            'pattern': r'subprocess\.\w+\([^)]*shell\s*=\s*True',
            'ast': True,
            'severity': Severity.CRITICAL,
            'category': Category.INJECTION,
            'title': 'Shell Command Injection',
            'description': 'subprocess with shell=True allows shell injection if user input is passed',
            'remediation': 'Use shell=False and pass command as list. Validate inputs with shlex.quote() if shell required.',
            'cwe': 'CWE-78'
        },
        'os_system': {
            'pattern': r'os\.(?:system|popen)\s*\(',
            'ast': True,
            'severity': Severity.CRITICAL,
            'category': Category.INJECTION,
            'title': 'Command Injection via os.system()',
            'description': 'Shell command built from variable input enables command injection',
            'remediation': 'Use subprocess with shell=False and an argument list. Never pass user input to a shell.',
            'cwe': 'CWE-78'
        },
        'sql_format_string': {
            'pattern': r'\.execute\s*\(\s*(?:f["\']|["\'][^"\']*["\']\s*(?:%|\+|\.format))',
            'ast': True,
            'severity': Severity.CRITICAL,
            'category': Category.INJECTION,
            'title': 'SQL Injection',
            'description': 'SQL query constructed with string formatting or concatenation',
            'remediation': 'Use parameterized queries with placeholders. Never use f-strings or % formatting for SQL.',
            'cwe': 'CWE-89'
        },
        'hardcoded_secret': {
            'pattern': r'\b(?:password|passwd|pwd|secret|secret_key|api_key|apikey|token|access_token)\b["\']?\]?\s*=\s*["\'][^"\']{8,}["\']',
            'ast': True,
            'severity': Severity.CRITICAL,
            'category': Category.EXPOSURE,
            'title': 'Hardcoded Credential',
            'description': 'Credential or secret hardcoded in source code',
            'remediation': 'Load from environment variables or secure vault. Use python-dotenv or key management services.',
            'cwe': 'CWE-798'
        },
        'pickle_loads': {
            'pattern': r'\b(?:pickle|cPickle|dill)\.loads?\s*\(',
            'ast': True,
            'severity': Severity.CRITICAL,
            'category': Category.INJECTION,
            'title': 'Unsafe Deserialization',
            'description': 'pickle.load()/loads() can execute arbitrary code during deserialization',
            'remediation': 'Use JSON for data serialization. If pickle required, implement cryptographic signing.',
            'cwe': 'CWE-502'
        },
        'yaml_unsafe': {
            'pattern': r'yaml\.load\s*\((?![^)]*Loader\s*=\s*(?:yaml\.)?C?SafeLoader)',
            'ast': True,
            'severity': Severity.CRITICAL,
            'category': Category.INJECTION,
            'title': 'Unsafe YAML Loading',
            'description': 'yaml.load() without SafeLoader allows arbitrary code execution',
            'remediation': 'Use yaml.safe_load() or specify Loader=yaml.SafeLoader explicitly.',
            'cwe': 'CWE-502'
        },
        'flask_debug': {
            'pattern': r'\.run\s*\([^)]*debug\s*=\s*True',
            'ast': True,
            'severity': Severity.CRITICAL,
            'category': Category.CONFIGURATION,
            'title': 'Flask Debug Mode',
            'description': 'Flask debug mode exposes Werkzeug debugger with console access',
            'remediation': 'Remove debug=True before deployment. Control it via an environment variable.',
            'cwe': 'CWE-489'
        },
        'debug_true': {
            'pattern': r'^\s*DEBUG\s*=\s*True\b',
            'severity': Severity.CRITICAL,
            'category': Category.CONFIGURATION,
            'title': 'Debug Mode Enabled',
            'description': 'DEBUG=True exposes sensitive information and stack traces',
            'remediation': 'Set DEBUG=False in production. Use an environment variable to control debug mode.',
            'cwe': 'CWE-489'
        },
        'md5_hash': {
            'pattern': r'hashlib\.md5\s*\((?![^)]*usedforsecurity\s*=\s*False)',
            'severity': Severity.MEDIUM,
            'category': Category.CRYPTOGRAPHY,
            'title': 'Weak Hash Algorithm (MD5)',
            'description': 'MD5 is cryptographically broken and unsuitable for security use',
            'remediation': 'Use SHA-256 or stronger. Use bcrypt/Argon2 for password hashing. '
                           'Pass usedforsecurity=False if this is a non-security checksum.',
            'cwe': 'CWE-328'
        },
        'sha1_hash': {
            'pattern': r'hashlib\.sha1\s*\((?![^)]*usedforsecurity\s*=\s*False)',
            'severity': Severity.MEDIUM,
            'category': Category.CRYPTOGRAPHY,
            'title': 'Weak Hash Algorithm (SHA1)',
            'description': 'SHA1 is cryptographically weak and being deprecated',
            'remediation': 'Use SHA-256 or stronger hash algorithms.',
            'cwe': 'CWE-328'
        },
        'verify_ssl_false': {
            'pattern': r'\bverify\s*=\s*False\b|\bverify_ssl\s*=\s*False\b|ssl\._create_unverified_context|CERT_NONE',
            'severity': Severity.HIGH,
            'category': Category.TRANSPORT,
            'title': 'SSL Verification Disabled',
            'description': 'Certificate validation disabled - vulnerable to MITM attacks',
            'remediation': 'Never disable SSL verification in production. Properly configure certificates.',
            'cwe': 'CWE-295'
        },
        'tempnam': {
            'pattern': r'os\.tempnam|os\.tmpnam|tempfile\.mktemp\s*\(',
            'severity': Severity.MEDIUM,
            'category': Category.EXPOSURE,
            'title': 'Insecure Temporary File',
            'description': 'mktemp()/tempnam() are vulnerable to race conditions',
            'remediation': 'Use tempfile.mkstemp() or NamedTemporaryFile instead.',
            'cwe': 'CWE-377'
        },
        'wildcard_import': {
            'pattern': r'^\s*from\s+\S+\s+import\s+\*',
            'severity': Severity.LOW,
            'category': Category.CONFIGURATION,
            'title': 'Wildcard Import',
            'description': 'Wildcard imports pollute namespace and may shadow builtins',
            'remediation': 'Import only specific names needed, or use module import with prefix.',
            'cwe': None
        },
        'todo_security': {
            'pattern': r'#\s*(?:TODO|FIXME|XXX|HACK)\b.*?\b(?:security|vuln\w*|insecure|unsafe|auth\w*|password|xss|csrf|sqli?)\b',
            'comment': True,
            'severity': Severity.LOW,
            'category': Category.CONFIGURATION,
            'title': 'Security TODO Comment',
            'description': 'Security-related TODO/FIXME comment found',
            'remediation': 'Address security TODOs before production deployment.',
            'cwe': None
        },
        'django_csrf_disabled': {
            'pattern': r'@csrf_exempt\b|CSRF_COOKIE_SECURE\s*=\s*False|WTF_CSRF_ENABLED\s*[\]\'"]*\s*=\s*False',
            'severity': Severity.HIGH,
            'category': Category.CONFIGURATION,
            'title': 'CSRF Protection Disabled',
            'description': 'CSRF protection is disabled, allowing cross-site request forgery attacks',
            'remediation': 'Remove @csrf_exempt / re-enable CSRF protection. Set CSRF_COOKIE_SECURE = True in production.',
            'cwe': 'CWE-352'
        },
        'django_allowed_hosts_wildcard': {
            'pattern': r'ALLOWED_HOSTS\s*=\s*\[[^\]]*["\']\*["\']',
            'severity': Severity.HIGH,
            'category': Category.CONFIGURATION,
            'title': 'Django ALLOWED_HOSTS Set to Wildcard',
            'description': 'ALLOWED_HOSTS = ["*"] allows any host header, enabling HTTP Host header attacks',
            'remediation': 'Specify exact domain names in ALLOWED_HOSTS. Never use wildcard in production.',
            'cwe': 'CWE-644'
        },
        'cors_allow_all': {
            'pattern': r'CORS_(?:ORIGIN_)?ALLOW_ALL(?:_ORIGINS)?\s*=\s*True|CORS\s*\(\s*\w+\s*\)|origins\s*=\s*["\']\*["\']|allow_origins\s*=\s*\[\s*["\']\*["\']',
            'severity': Severity.HIGH,
            'category': Category.CONFIGURATION,
            'title': 'CORS Allows All Origins',
            'description': 'CORS is configured to accept requests from any origin',
            'remediation': 'Restrict CORS to an explicit allow-list of trusted origins.',
            'cwe': 'CWE-942'
        },
        'jwt_no_verify': {
            'pattern': r'jwt\.decode\s*\([^)]*(?:verify\s*=\s*False|["\']verify_signature["\']\s*:\s*False|algorithms\s*=\s*\[\s*["\']none["\'])',
            'severity': Severity.CRITICAL,
            'category': Category.AUTHENTICATION,
            'title': 'JWT Signature Verification Disabled',
            'description': 'JWT tokens are decoded without verifying the signature - anyone can forge tokens',
            'remediation': 'Always verify JWT signatures and pin the expected algorithms, e.g. algorithms=["HS256"].',
            'cwe': 'CWE-347'
        },
    }

    def get_name(self) -> str:
        return "python_sast"

    def get_description(self) -> str:
        return "Python Static Application Security Testing (AST + regex analysis)"

    def get_supported_languages(self) -> List[str]:
        return ['python']

    def scan(self, context: ScanContext) -> List[Vulnerability]:
        """Scan Python file for security issues."""
        if not context.file_path or not context.file_content:
            return []

        tree: Optional[ast.Module] = None
        try:
            tree = ast.parse(context.file_content)
        except (SyntaxError, ValueError):
            tree = None

        vulnerabilities = self._scan_with_regex(context, ast_available=tree is not None)

        if tree is not None:
            try:
                vulnerabilities.extend(_AstChecker(self, context).run(tree))
            except Exception as e:  # pragma: no cover - defensive
                self.log_error(f"AST analysis failed on {context.file_path}: {e}")

        return redact_secrets(vulnerabilities)

    # ------------------------------------------------------------------ regex

    def _token_regions(self, content: str) -> Tuple[Dict[int, int], List[Tuple[int, int]]]:
        """
        Locate comments and string literals.

        Returns:
            (line number -> column where a comment starts,
             sorted (start, end) character offsets of string literals)
        """
        comments: Dict[int, int] = {}
        strings: List[Tuple[int, int]] = []
        line_offsets = [0]
        for line in content.splitlines(keepends=True):
            line_offsets.append(line_offsets[-1] + len(line))

        def offset(pos: Tuple[int, int]) -> int:
            return line_offsets[pos[0] - 1] + pos[1]

        string_types = {tokenize.STRING}
        for name in ('FSTRING_START', 'TSTRING_START'):
            if hasattr(tokenize, name):
                string_types.add(getattr(tokenize, name))
        try:
            fstring_start = None
            for tok in tokenize.generate_tokens(io.StringIO(content).readline):
                if tok.type == tokenize.COMMENT:
                    comments[tok.start[0]] = tok.start[1]
                elif tok.type == tokenize.STRING:
                    strings.append((offset(tok.start), offset(tok.end)))
                elif tok.type in string_types and fstring_start is None:
                    fstring_start = offset(tok.start)
                elif tok.type in (getattr(tokenize, 'FSTRING_END', -1), getattr(tokenize, 'TSTRING_END', -1)) \
                        and fstring_start is not None:
                    strings.append((fstring_start, offset(tok.end)))
                    fstring_start = None
        except (tokenize.TokenError, IndentationError, SyntaxError, IndexError):
            pass
        return comments, sorted(strings)

    @staticmethod
    def _inside(spans: List[Tuple[int, int]], pos: int) -> bool:
        idx = bisect.bisect_right(spans, (pos, float('inf'))) - 1
        return idx >= 0 and spans[idx][0] <= pos < spans[idx][1]

    def _scan_with_regex(self, context: ScanContext, ast_available: bool) -> List[Vulnerability]:
        """Scan using regex patterns, ignoring matches inside comments and string literals."""
        vulnerabilities = []
        content = context.file_content
        comments, strings = self._token_regions(content)

        for pattern_name, info in self.PATTERNS.items():
            if info.get('ast') and ast_available:
                continue
            try:
                for match in re.finditer(info['pattern'], content, re.IGNORECASE | re.MULTILINE):
                    vuln = self.finding_from_match(context, match, info, pattern_name)
                    in_comment = (
                        vuln.line_number in comments
                        and vuln.column_start >= comments[vuln.line_number]
                    )
                    if in_comment != bool(info.get('comment')):
                        continue
                    # Rule text, docs and messages inside string literals are not code
                    first_code_char = match.start() + (len(match.group(0)) - len(match.group(0).lstrip()))
                    if not info.get('comment') and self._inside(strings, first_code_char):
                        continue
                    if pattern_name == 'hardcoded_secret':
                        vuln = self._mask(vuln, match.group(0))
                    vulnerabilities.append(vuln)
            except re.error as e:
                self.log_error(f"Regex error in pattern {pattern_name}: {e}")

        return vulnerabilities

    @staticmethod
    def _mask(vuln: Vulnerability, secret_text: str) -> Vulnerability:
        masked = mask_secret(secret_text)
        if vuln.code_snippet:
            vuln.code_snippet = vuln.code_snippet.replace(secret_text, masked)
        vuln.metadata['match'] = masked
        vuln.metadata[SECRET_KEY] = secret_text
        return vuln


class _AstChecker:
    """AST visitor implementing the precise Python checks."""

    def __init__(self, scanner: PythonSASTScanner, context: ScanContext):
        self.scanner = scanner
        self.context = context
        self.findings: List[Vulnerability] = []
        # name -> list of assigned value nodes (module-wide, flow-insensitive)
        self.assignments: Dict[str, List[ast.AST]] = {}
        self.is_test_file = _is_test_path(context)

    # -- helpers --------------------------------------------------------------

    def _add(
        self,
        node: ast.AST,
        title: str,
        description: str,
        severity: Severity,
        category: Category,
        remediation: str,
        cwe: Optional[str],
        rule: str,
        mask: Optional[str] = None,
    ) -> None:
        line = getattr(node, 'lineno', 1)
        snippet = self.scanner.extract_code_snippet(self.context.file_content, line)
        metadata: Dict[str, Any] = {'rule': rule, 'engine': 'ast'}
        if mask:
            masked = mask_secret(mask)
            snippet = snippet.replace(mask, masked)
            metadata['match'] = masked
            metadata[SECRET_KEY] = mask
        self.findings.append(Vulnerability(
            title=title,
            description=description,
            severity=severity,
            category=category,
            file_path=self.context.file_path,
            line_number=line,
            column_start=getattr(node, 'col_offset', None),
            column_end=getattr(node, 'end_col_offset', None),
            code_snippet=snippet,
            remediation=remediation,
            cwe_id=cwe,
            scanner_source=self.scanner.get_name(),
            metadata=metadata,
        ))

    def _is_dynamic_string(self, node: ast.AST, depth: int = 0) -> bool:
        """True if node builds a string from non-constant parts."""
        if depth > 4:
            return False
        if isinstance(node, ast.JoinedStr):
            return any(isinstance(v, ast.FormattedValue) for v in node.values)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return not (_is_constant_str(node.left) and _is_constant_str(node.right))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == 'format' and (node.args or node.keywords):
                return True
            if node.func.attr == 'join':
                return True
        if isinstance(node, ast.Name):
            return any(self._is_dynamic_string(v, depth + 1) for v in self.assignments.get(node.id, []))
        return False

    def _string_text(self, node: ast.AST, depth: int = 0) -> str:
        """Best-effort literal text of a (possibly dynamic) string expression."""
        if depth > 4:
            return ''
        if _is_constant_str(node):
            return str(node.value)
        if isinstance(node, ast.JoinedStr):
            return ''.join(self._string_text(v, depth + 1) for v in node.values)
        if isinstance(node, ast.BinOp):
            return self._string_text(node.left, depth + 1) + self._string_text(node.right, depth + 1)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            return self._string_text(node.func.value, depth + 1)
        if isinstance(node, ast.Name):
            return ' '.join(self._string_text(v, depth + 1) for v in self.assignments.get(node.id, []))
        return ''

    def _is_variable_input(self, node: Optional[ast.AST]) -> bool:
        """True if an argument is not a plain literal."""
        if node is None:
            return False
        if isinstance(node, ast.Constant):
            return False
        if isinstance(node, (ast.List, ast.Tuple)):
            return any(self._is_variable_input(e) for e in node.elts)
        if isinstance(node, ast.Name):
            values = self.assignments.get(node.id)
            if values and all(isinstance(v, ast.Constant) for v in values):
                return False
        return True

    # -- driver ---------------------------------------------------------------

    def run(self, tree: ast.Module) -> List[Vulnerability]:
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        self.assignments.setdefault(target.id, []).append(node.value)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                self._check_call(node)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                self._check_assignment(node)
            elif isinstance(node, ast.Assert) and not self.is_test_file:
                self._add(
                    node, 'Assert Used for Runtime Check',
                    'assert statements are stripped when Python runs with -O, so checks relying on them disappear',
                    Severity.LOW, Category.CONFIGURATION,
                    'Use explicit if/raise for security or validation checks.', 'CWE-617', 'assert_usage'
                )
        return self.findings

    # -- checks ---------------------------------------------------------------

    def _check_assignment(self, node: ast.AST) -> None:
        value = node.value
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            name = _target_name(target)
            if not name:
                continue

            # app.config['DEBUG'] = True  /  self.debug = True
            if name.upper() == 'DEBUG' and _is_true(value) and not isinstance(target, ast.Name):
                self._add(
                    node, 'Debug Mode Enabled',
                    'Application debug mode is enabled, exposing stack traces and (in Flask) an interactive debugger',
                    Severity.CRITICAL, Category.CONFIGURATION,
                    'Disable debug mode in production; read it from an environment variable.', 'CWE-489', 'debug_config'
                )

            if (
                SECRET_NAME_RE.search(name)
                and _is_constant_str(value)
                and len(str(value.value)) >= 8
                and not PLACEHOLDER_RE.match(str(value.value).strip())
                and not self.is_test_file
            ):
                secret = str(value.value)
                title = 'Hardcoded Secret Key' if 'secret' in name.lower() or 'key' in name.lower() else 'Hardcoded Credential'
                self._add(
                    node, title,
                    f'"{name}" is assigned a hardcoded value. Anyone with access to the source can read it.',
                    Severity.CRITICAL, Category.EXPOSURE,
                    f'Load {name} from an environment variable or secrets manager (e.g. os.environ["{name.upper()}"]) '
                    'and rotate the exposed value.',
                    'CWE-798', 'hardcoded_secret', mask=secret
                )

    def _check_call(self, node: ast.Call) -> None:
        name = _call_name(node)
        short = name.rsplit('.', 1)[-1]
        first = node.args[0] if node.args else None

        # --- code execution
        if name in ('eval', 'exec', 'compile', 'builtins.eval', 'builtins.exec'):
            if self._is_variable_input(first):
                self._add(
                    node, 'Dynamic Code Execution',
                    f'{short}() executes code built from a variable - arbitrary code execution if it is user-controlled',
                    Severity.CRITICAL, Category.INJECTION,
                    'Use ast.literal_eval() for literals or a dedicated parser. Never execute user input.',
                    'CWE-95', 'eval_exec'
                )
            return

        # --- command injection
        parts = tuple(name.split('.')[-2:])
        if parts in COMMAND_SINKS:
            if self._is_variable_input(first):
                self._add(
                    node, f'Command Injection via {name}()',
                    f'{name}() runs its argument through the system shell; variable input enables command injection',
                    Severity.CRITICAL, Category.INJECTION,
                    'Use subprocess.run([...], shell=False) with an argument list and validate inputs.',
                    'CWE-78', 'os_system'
                )
            return

        if short in SUBPROCESS_FUNCS and (name.startswith('subprocess.') or name == short):
            if _is_true(_keyword(node, 'shell')):
                dynamic = self._is_variable_input(first)
                self._add(
                    node, 'Shell Command Injection',
                    'subprocess called with shell=True' + (' and a variable command' if dynamic else ''),
                    Severity.CRITICAL if dynamic else Severity.MEDIUM, Category.INJECTION,
                    'Use shell=False and pass the command as a list. Validate all inputs.',
                    'CWE-78', 'subprocess_shell'
                )
            return

        # --- SQL injection
        if short in SQL_SINKS and first is not None and self._is_dynamic_string(first):
            text = self._string_text(first)
            if short in ('execute', 'executemany', 'executescript', 'raw') or SQL_KEYWORDS_RE.search(text):
                how = 'an f-string' if isinstance(first, ast.JoinedStr) else 'string building'
                self._add(
                    node, 'SQL Injection',
                    f'SQL query passed to {short}() is constructed with {how}; attacker input can change the query',
                    Severity.CRITICAL, Category.INJECTION,
                    'Use parameterized queries: cursor.execute("... WHERE id = ?", (value,)).',
                    'CWE-89', 'sql_injection'
                )
            return

        # --- template injection / unescaped HTML
        if short == 'render_template_string' and first is not None and self._is_variable_input(first):
            self._add(
                node, 'Server-Side Template Injection',
                'render_template_string() renders a template built from variable input - leads to XSS and RCE (SSTI)',
                Severity.CRITICAL, Category.INJECTION,
                'Use render_template() with a static template file and pass data as context variables.',
                'CWE-1336', 'ssti'
            )
            return
        if short in ('Markup', 'mark_safe', 'SafeString') and first is not None and self._is_dynamic_string(first):
            self._add(
                node, 'Unescaped HTML Output',
                f'{short}() marks a dynamically built string as safe, bypassing auto-escaping (XSS)',
                Severity.HIGH, Category.INJECTION,
                'Escape user input (markupsafe.escape) before marking it safe, or let the template engine escape it.',
                'CWE-79', 'mark_safe'
            )
            return

        # --- deserialization
        if name in ('pickle.load', 'pickle.loads', 'cPickle.loads', 'dill.loads', 'marshal.loads',
                    'marshal.load', 'shelve.open', 'jsonpickle.decode'):
            self._add(
                node, 'Unsafe Deserialization',
                f'{name}() can execute arbitrary code while deserializing untrusted data',
                Severity.CRITICAL, Category.INJECTION,
                'Use JSON for untrusted data. If pickle is required, sign the payload (hmac) and verify before loading.',
                'CWE-502', 'pickle_loads'
            )
            return
        if name == 'yaml.load':
            loader = _keyword(node, 'Loader') or (node.args[1] if len(node.args) > 1 else None)
            loader_name = ''
            if isinstance(loader, ast.Attribute):
                loader_name = loader.attr
            elif isinstance(loader, ast.Name):
                loader_name = loader.id
            if loader_name not in SAFE_YAML_LOADERS:
                self._add(
                    node, 'Unsafe YAML Loading',
                    'yaml.load() without SafeLoader can instantiate arbitrary Python objects',
                    Severity.CRITICAL, Category.INJECTION,
                    'Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).',
                    'CWE-502', 'yaml_unsafe'
                )
            return

        # --- framework run() settings
        if short == 'run' and isinstance(node.func, ast.Attribute):
            if _is_true(_keyword(node, 'debug')):
                self._add(
                    node, 'Flask Debug Mode',
                    'app.run(debug=True) exposes the Werkzeug interactive debugger (remote code execution)',
                    Severity.CRITICAL, Category.CONFIGURATION,
                    'Remove debug=True; control debug mode with an environment variable that is off in production.',
                    'CWE-489', 'flask_debug'
                )
            host = _keyword(node, 'host')
            if _is_constant_str(host) and host.value in ('0.0.0.0', '::'):
                self._add(
                    node, 'Server Bound to All Interfaces',
                    'The development server listens on every network interface, exposing it to the local network',
                    Severity.MEDIUM, Category.CONFIGURATION,
                    'Bind to 127.0.0.1 during development and use a production WSGI server behind a proxy.',
                    'CWE-1327', 'bind_all'
                )
            return

        # --- insecure randomness used for secrets
        if name in ('random.random', 'random.randint', 'random.choice', 'random.choices',
                    'random.getrandbits', 'random.randrange', 'random.sample'):
            line_text = self.context.file_content.splitlines()[node.lineno - 1].lower()
            if re.search(r'token|password|passwd|secret|otp|salt|nonce|session|key|code', line_text):
                self._add(
                    node, 'Insecure Randomness',
                    'The random module is predictable and must not be used for tokens, passwords or keys',
                    Severity.HIGH, Category.CRYPTOGRAPHY,
                    'Use the secrets module (secrets.token_urlsafe(), secrets.choice()).',
                    'CWE-338', 'insecure_random'
                )
            return

        # --- path traversal
        if name in ('open', 'io.open', 'send_file', 'flask.send_file', 'os.path.join') and first is not None:
            target = node.args[-1] if name == 'os.path.join' else first
            if name != 'os.path.join' and self._is_dynamic_string(target):
                self._add(
                    node, 'Potential Path Traversal',
                    f'File path passed to {short}() is built dynamically; "../" sequences may escape the intended directory',
                    Severity.MEDIUM, Category.INJECTION,
                    'Resolve the path and verify it stays within an allowed base directory (Path.resolve().is_relative_to()), '
                    'or use werkzeug.utils.safe_join / send_from_directory.',
                    'CWE-22', 'path_traversal'
                )
            return
