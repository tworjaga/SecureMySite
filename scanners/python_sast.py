"""Python Static Application Security Testing (SAST) scanner."""

import ast
import re
from typing import List, Optional, Dict, Any, Tuple
from pathlib import Path

from models.vulnerability import Vulnerability, Severity, Category
from scanners.base_scanner import BaseScanner, ScanContext


class PythonSASTScanner(BaseScanner):
    """
    Python SAST scanner using AST analysis and regex patterns.
    
    Detects:
    - Code injection (eval, exec)
    - Command injection (subprocess, os.system)
    - SQL injection
    - Hardcoded secrets
    - Unsafe deserialization
    - Debug mode enabled
    - Path traversal
    - Insecure randomness
    """
    
    # Regex patterns for quick detection
    PATTERNS = {
        'eval_exec': {
            'pattern': r'\b(eval|exec)\s*\(',
            'severity': Severity.CRITICAL,
            'category': Category.INJECTION,
            'title': 'Dynamic Code Execution',
            'description': 'Use of eval() or exec() with potentially untrusted input can lead to arbitrary code execution',
            'remediation': 'Replace eval() with ast.literal_eval() for literals, or use safer alternatives. Avoid exec() entirely.',
            'cwe': 'CWE-95'
        },
        'subprocess_shell': {
            'pattern': r'subprocess\..*shell\s*=\s*True',
            'severity': Severity.CRITICAL,
            'category': Category.INJECTION,
            'title': 'Shell Command Injection',
            'description': 'subprocess with shell=True allows shell injection if user input is passed',
            'remediation': 'Use shell=False and pass command as list. Validate inputs with shlex.quote() if shell required.',
            'cwe': 'CWE-78'
        },
        'os_system_concat': {
            'pattern': r'os\.system\s*\([^)]*[\+\%]',
            'severity': Severity.CRITICAL,
            'category': Category.INJECTION,
            'title': 'Command Injection via os.system()',
            'description': 'User input concatenated into os.system() call enables command injection',
            'remediation': 'Use subprocess with shell=False. Never concatenate user input into shell commands.',
            'cwe': 'CWE-78'
        },
        'sql_format_string': {
            'pattern': r'(?:execute|cursor\.execute|\.query)\s*\(\s*(?:f["\']|["\'][^"\']*%s)',
            'severity': Severity.CRITICAL,
            'category': Category.INJECTION,
            'title': 'SQL Injection',
            'description': 'SQL query constructed with string formatting or concatenation',
            'remediation': 'Use parameterized queries with placeholders. Never use f-strings or % formatting for SQL.',
            'cwe': 'CWE-89'
        },
        'hardcoded_secret': {
            'pattern': r'(?:password|passwd|pwd|secret|api_key|apikey|token|access_token)\s*=\s*["\'][^"\']{8,}["\']',
            'severity': Severity.CRITICAL,
            'category': Category.EXPOSURE,
            'title': 'Hardcoded Credential',
            'description': 'Credential or secret hardcoded in source code',
            'remediation': 'Load from environment variables or secure vault. Use python-dotenv or key management services.',
            'cwe': 'CWE-798'
        },
        'debug_true': {
            'pattern': r'^\s*DEBUG\s*=\s*True',
            'severity': Severity.CRITICAL,
            'category': Category.CONFIGURATION,
            'title': 'Debug Mode Enabled',
            'description': 'DEBUG=True exposes sensitive information and enables code execution in errors',
            'remediation': 'Set DEBUG=False in production. Use environment variable to control debug mode.',
            'cwe': 'CWE-489'
        },
        'pickle_loads': {
            'pattern': r'pickle\.loads?',
            'severity': Severity.CRITICAL,
            'category': Category.INJECTION,
            'title': 'Unsafe Deserialization',
            'description': 'pickle.loads() can execute arbitrary code during deserialization',
            'remediation': 'Use JSON for data serialization. If pickle required, implement cryptographic signing.',
            'cwe': 'CWE-502'
        },
        'yaml_unsafe': {
            'pattern': r'yaml\.load\s*\((?!.*Loader\s*=)',
            'severity': Severity.CRITICAL,
            'category': Category.INJECTION,
            'title': 'Unsafe YAML Loading',
            'description': 'yaml.load() without explicit SafeLoader allows arbitrary code execution',
            'remediation': 'Use yaml.safe_load() or specify Loader=yaml.SafeLoader explicitly.',
            'cwe': 'CWE-502'
        },
        'flask_debug': {
            'pattern': r'app\.run\s*\([^)]*debug\s*=\s*True',
            'severity': Severity.CRITICAL,
            'category': Category.CONFIGURATION,
            'title': 'Flask Debug Mode',
            'description': 'Flask debug mode exposes Werkzeug debugger with console access',
            'remediation': 'Remove debug=True before deployment. Set FLASK_ENV=production.',
            'cwe': 'CWE-489'
        },
        'insecure_random': {
            'pattern': r'random\.(?:choice|shuffle|randint|random)',
            'severity': Severity.HIGH,
            'category': Category.CRYPTOGRAPHY,
            'title': 'Insecure Randomness',
            'description': 'random module not suitable for security-sensitive operations',
            'remediation': 'Use secrets module for tokens, passwords, and security-sensitive randomness.',
            'cwe': 'CWE-338'
        },
        'md5_hash': {
            'pattern': r'hashlib\.md5|md5\s*\(',
            'severity': Severity.HIGH,
            'category': Category.CRYPTOGRAPHY,
            'title': 'Weak Hash Algorithm (MD5)',
            'description': 'MD5 is cryptographically broken and unsuitable for security use',
            'remediation': 'Use SHA-256 or stronger. Use bcrypt/Argon2 for password hashing.',
            'cwe': 'CWE-328'
        },
        'sha1_hash': {
            'pattern': r'hashlib\.sha1|sha1\s*\(',
            'severity': Severity.HIGH,
            'category': Category.CRYPTOGRAPHY,
            'title': 'Weak Hash Algorithm (SHA1)',
            'description': 'SHA1 is cryptographically weak and being deprecated',
            'remediation': 'Use SHA-256 or stronger hash algorithms.',
            'cwe': 'CWE-328'
        },
        'path_concat': {
            'pattern': r'open\s*\(\s*[^)]*\+',
            'severity': Severity.HIGH,
            'category': Category.INJECTION,
            'title': 'Potential Path Traversal',
            'description': 'User input concatenated into file path may allow directory traversal',
            'remediation': 'Use pathlib and validate paths. Ensure resolved path stays within allowed directory.',
            'cwe': 'CWE-22'
        },
        'verify_ssl_false': {
            'pattern': r'verify\s*=\s*False|verify_ssl\s*=\s*False',
            'severity': Severity.MEDIUM,
            'category': Category.TRANSPORT,
            'title': 'SSL Verification Disabled',
            'description': 'Certificate validation disabled - vulnerable to MITM attacks',
            'remediation': 'Never disable SSL verification in production. Properly configure certificates.',
            'cwe': 'CWE-295'
        },
        'tempnam': {
            'pattern': r'os\.tempnam|os\.tmpnam',
            'severity': Severity.HIGH,
            'category': Category.EXPOSURE,
            'title': 'Insecure Temporary File',
            'description': 'os.tempnam() is insecure and deprecated',
            'remediation': 'Use tempfile module with proper permissions.',
            'cwe': 'CWE-377'
        },
        'mktemp': {
            'pattern': r'tempfile\.mktemp',
            'severity': Severity.MEDIUM,
            'category': Category.EXPOSURE,
            'title': 'Insecure Temporary File Creation',
            'description': 'mktemp() is insecure - race condition possible',
            'remediation': 'Use tempfile.mkstemp() or NamedTemporaryFile instead.',
            'cwe': 'CWE-377'
        },
        'assert_usage': {
            'pattern': r'^\s*assert\s+',
            'severity': Severity.LOW,
            'category': Category.CONFIGURATION,
            'title': 'Assert Statement Used',
            'description': 'assert statements are removed in optimized Python (-O flag)',
            'remediation': 'Use proper error handling with if/raise instead of assert for security checks.',
            'cwe': 'CWE-617'
        },
        'wildcard_import': {
            'pattern': r'from\s+\S+\s+import\s+\*',
            'severity': Severity.LOW,
            'category': Category.CONFIGURATION,
            'title': 'Wildcard Import',
            'description': 'Wildcard imports pollute namespace and may shadow builtins',
            'remediation': 'Import only specific names needed, or use module import with prefix.',
            'cwe': None
        },
        'todo_security': {
            'pattern': r'#\s*(?:TODO|FIXME|XXX).*?(?:security|vuln|fix|patch)',
            'severity': Severity.LOW,
            'category': Category.CONFIGURATION,
            'title': 'Security TODO Comment',
            'description': 'Security-related TODO/FIXME comment found',
            'remediation': 'Address security TODOs before production deployment.',
            'cwe': None
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
        vulnerabilities = []
        
        if not context.file_path or not context.file_content:
            return vulnerabilities
        
        # Run regex-based detection
        regex_vulns = self._scan_with_regex(context)
        vulnerabilities.extend(regex_vulns)
        
        # Run AST-based detection
        try:
            ast_vulns = self._scan_with_ast(context)
            vulnerabilities.extend(ast_vulns)
        except SyntaxError:
            # File has syntax errors, skip AST analysis
            pass
        except Exception as e:
            self.log_error(f"AST analysis failed: {e}")
        
        return vulnerabilities
    
    def _scan_with_regex(self, context: ScanContext) -> List[Vulnerability]:
        """Scan using regex patterns."""
        vulnerabilities = []
        content = context.file_content
        lines = content.split('\n')
        
        for pattern_name, pattern_info in self.PATTERNS.items():
            try:
                for match in re.finditer(pattern_info['pattern'], content, re.IGNORECASE | re.MULTILINE):
                    # Find line number
                    line_num = content[:match.start()].count('\n') + 1
                    
                    # Extract code snippet
                    snippet = self.extract_code_snippet(content, line_num)
                    
                    # Create vulnerability
                    vuln = self.create_vulnerability(
                        title=pattern_info['title'],
                        description=pattern_info['description'],
                        severity=pattern_info['severity'],
                        category=pattern_info['category'],
                        line_number=line_num,
                        code_snippet=snippet,
                        remediation=pattern_info['remediation'],
                        cwe_id=pattern_info.get('cwe'),
                        metadata={
                            'pattern': pattern_name,
                            'match': match.group(0)[:100]
                        }
                    )
                    vuln = Vulnerability(
                        id=vuln.id,
                        title=vuln.title,
                        description=vuln.description,
                        severity=vuln.severity,
                        category=vuln.category,
                        file_path=context.file_path,
                        line_number=vuln.line_number,
                        column_start=match.start() - content.rfind('\n', 0, match.start()),
                        column_end=match.end() - content.rfind('\n', 0, match.end()),
                        code_snippet=vuln.code_snippet,
                        remediation=vuln.remediation,
                        cwe_id=vuln.cwe_id,
                        scanner_source=vuln.scanner_source,
                        metadata=vuln.metadata,
                        timestamp=vuln.timestamp
                    )
                    vulnerabilities.append(vuln)
                    
            except re.error as e:
                self.log_error(f"Regex error in pattern {pattern_name}: {e}")
        
        return vulnerabilities
    
    def _scan_with_ast(self, context: ScanContext) -> List[Vulnerability]:
        """Scan using Python AST analysis."""
        vulnerabilities = []
        
        try:
            tree = ast.parse(context.file_content)
        except SyntaxError:
            return vulnerabilities
        
        # AST-based checks
        for node in ast.walk(tree):
            # Check for f-strings in SQL-like contexts
            if isinstance(node, ast.Call):
                vuln = self._check_sql_call(node, context)
                if vuln:
                    vulnerabilities.append(vuln)
            
            # Check for dangerous functions
            if isinstance(node, ast.Call):
                vuln = self._check_dangerous_call(node, context)
                if vuln:
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_sql_call(self, node: ast.Call, context: ScanContext) -> Optional[Vulnerability]:
        """Check for SQL injection in database calls."""
        # Check if this is an execute() call
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ('execute', 'executemany'):
                # Check if first argument is an f-string or contains user input
                if node.args:
                    first_arg = node.args[0]
                    
                    # Check for f-string (JoinedStr in Python 3.6+)
                    if isinstance(first_arg, ast.JoinedStr):
                        line_num = getattr(node, 'lineno', 1)
                        snippet = self.extract_code_snippet(context.file_content, line_num)
                        
                        return Vulnerability(
                            title='SQL Injection via f-string',
                            description='SQL query uses f-string formatting, allowing injection',
                            severity=Severity.CRITICAL,
                            category=Category.INJECTION,
                            file_path=context.file_path,
                            line_number=line_num,
                            code_snippet=snippet,
                            remediation='Use parameterized queries with %s placeholders. Never use f-strings for SQL.',
                            cwe_id='CWE-89',
                            scanner_source=self.get_name(),
                            metadata={'ast_node': 'JoinedStr in execute()'}
                        )
                    
                    # Check for string concatenation
                    if isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Add):
                        line_num = getattr(node, 'lineno', 1)
                        snippet = self.extract_code_snippet(context.file_content, line_num)
                        
                        return Vulnerability(
                            title='SQL Injection via string concatenation',
                            description='SQL query constructed with string concatenation',
                            severity=Severity.CRITICAL,
                            category=Category.INJECTION,
                            file_path=context.file_path,
                            line_number=line_num,
                            code_snippet=snippet,
                            remediation='Use parameterized queries with placeholders.',
                            cwe_id='CWE-89',
                            scanner_source=self.get_name(),
                            metadata={'ast_node': 'BinOp in execute()'}
                        )
        
        return None
    
    def _check_dangerous_call(self, node: ast.Call, context: ScanContext) -> Optional[Vulnerability]:
        """Check for dangerous function calls."""
        line_num = getattr(node, 'lineno', 1)
        
        # Check for eval/exec
        if isinstance(node.func, ast.Name):
            if node.func.id in ('eval', 'exec'):
                snippet = self.extract_code_snippet(context.file_content, line_num)
                
                return Vulnerability(
                    title='Dynamic Code Execution',
                    description=f'Use of {node.func.id}() with potentially untrusted input',
                    severity=Severity.CRITICAL,
                    category=Category.INJECTION,
                    file_path=context.file_path,
                    line_number=line_num,
                    code_snippet=snippet,
                    remediation=f'Replace {node.func.id}() with safer alternatives. Never use with user input.',
                    cwe_id='CWE-95',
                    scanner_source=self.get_name(),
                    metadata={'function': node.func.id}
                )
        
        # Check for subprocess with shell=True
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ('call', 'run', 'Popen', 'check_output', 'check_call'):
                # Check for shell=True keyword argument
                for keyword in node.keywords:
                    if keyword.arg == 'shell':
                        if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                            snippet = self.extract_code_snippet(context.file_content, line_num)
                            
                            return Vulnerability(
                                title='Shell Command Injection',
                                description='subprocess called with shell=True enables command injection',
                                severity=Severity.CRITICAL,
                                category=Category.INJECTION,
                                file_path=context.file_path,
                                line_number=line_num,
                                code_snippet=snippet,
                                remediation='Use shell=False and pass command as list. Validate all inputs.',
                                cwe_id='CWE-78',
                                scanner_source=self.get_name(),
                                metadata={'function': f'subprocess.{node.func.attr}'}
                            )
        
        return None
