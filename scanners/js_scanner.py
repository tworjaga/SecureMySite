"""JavaScript/TypeScript security scanner."""

import re
from typing import List, Optional, Dict, Any
from pathlib import Path

from models.vulnerability import Vulnerability, Severity, Category
from scanners.base_scanner import BaseScanner, ScanContext


class JavaScriptScanner(BaseScanner):
    """
    JavaScript and TypeScript security scanner.
    
    Detects:
    - DOM XSS (innerHTML, document.write)
    - eval() usage
    - localStorage token storage
    - Exposed API keys
    - CORS misconfigurations
    - Inline event handlers
    - JSONP usage
    """
    
    PATTERNS = {
        'innerhtml_assignment': {
            'pattern': r'\.innerHTML\s*=',
            'severity': Severity.HIGH,
            'category': Category.INJECTION,
            'title': 'DOM XSS via innerHTML',
            'description': 'Unsafe innerHTML assignment allows XSS if user input is not sanitized',
            'remediation': 'Use textContent for plain text, or sanitize with DOMPurify before innerHTML assignment.',
            'cwe': 'CWE-79'
        },
        'document_write': {
            'pattern': r'document\.write\s*\(',
            'severity': Severity.HIGH,
            'category': Category.INJECTION,
            'title': 'Dangerous document.write()',
            'description': 'document.write() is dangerous and deprecated - XSS risk',
            'remediation': 'Use modern DOM manipulation methods. Avoid document.write() entirely.',
            'cwe': 'CWE-79'
        },
        'eval_usage': {
            'pattern': r'\beval\s*\(',
            'severity': Severity.CRITICAL,
            'category': Category.INJECTION,
            'title': 'Code Injection via eval()',
            'description': 'eval() executes arbitrary code - critical injection risk',
            'remediation': 'Use JSON.parse() for JSON data. Never use eval() with user input.',
            'cwe': 'CWE-95'
        },
        'function_constructor': {
            'pattern': r'new\s+Function\s*\(',
            'severity': Severity.HIGH,
            'category': Category.INJECTION,
            'title': 'Dynamic Code Execution',
            'description': 'Function constructor executes code from string - injection risk',
            'remediation': 'Avoid dynamic code generation. Use safer alternatives.',
            'cwe': 'CWE-95'
        },
        'settimeout_string': {
            'pattern': r'setTimeout\s*\(\s*["\']',
            'severity': Severity.HIGH,
            'category': Category.INJECTION,
            'title': 'Implied eval() via setTimeout',
            'description': 'setTimeout with string argument executes like eval()',
            'remediation': 'Use function reference instead of string: setTimeout(fn, delay)',
            'cwe': 'CWE-95'
        },
        'setinterval_string': {
            'pattern': r'setInterval\s*\(\s*["\']',
            'severity': Severity.HIGH,
            'category': Category.INJECTION,
            'title': 'Implied eval() via setInterval',
            'description': 'setInterval with string argument executes like eval()',
            'remediation': 'Use function reference instead of string: setInterval(fn, delay)',
            'cwe': 'CWE-95'
        },
        'localstorage_token': {
            'pattern': r'localStorage\.(?:setItem\s*\(\s*["\'][^"\']*token|[^=]*token\s*=)',
            'severity': Severity.HIGH,
            'category': Category.EXPOSURE,
            'title': 'Sensitive Token in localStorage',
            'description': 'Authentication tokens stored in localStorage are accessible to XSS attacks',
            'remediation': 'Store tokens in httpOnly cookies or use secure session storage mechanisms.',
            'cwe': 'CWE-522'
        },
        'sessionstorage_token': {
            'pattern': r'sessionStorage\.(?:setItem\s*\(\s*["\'][^"\']*token|[^=]*token\s*=)',
            'severity': Severity.MEDIUM,
            'category': Category.EXPOSURE,
            'title': 'Token in sessionStorage',
            'description': 'Tokens in sessionStorage are vulnerable to XSS',
            'remediation': 'Use httpOnly cookies for sensitive tokens.',
            'cwe': 'CWE-522'
        },
        'exposed_api_key': {
            'pattern': r'[\'"]?(?:api[_-]?key|apikey|api[_-]?secret)[\'"]?\s*[:=]\s*[\'\"][a-zA-Z0-9_\-]{20,}[\'\"]',
            'severity': Severity.CRITICAL,
            'category': Category.EXPOSURE,
            'title': 'Exposed API Key',
            'description': 'API key hardcoded in client-side JavaScript',
            'remediation': 'Move API calls to server-side. Never expose keys in frontend code.',
            'cwe': 'CWE-798'
        },
        'exposed_private_key': {
            'pattern': r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
            'severity': Severity.CRITICAL,
            'category': Category.EXPOSURE,
            'title': 'Private Key Exposed',
            'description': 'Private key found in source code',
            'remediation': 'Remove immediately. Rotate compromised keys. Use secure key management.',
            'cwe': 'CWE-798'
        },
        'postmessage_wildcard': {
            'pattern': r'postMessage\s*\([^,]+,\s*["\']\*["\']',
            'severity': Severity.HIGH,
            'category': Category.CONFIGURATION,
            'title': 'Insecure postMessage Target',
            'description': 'postMessage with wildcard target allows any origin to receive messages',
            'remediation': 'Specify exact target origin instead of wildcard.',
            'cwe': 'CWE-345'
        },
        'cors_wildcard': {
            'pattern': r'Access-Control-Allow-Origin.*\*',
            'severity': Severity.CRITICAL,
            'category': Category.CONFIGURATION,
            'title': 'Open CORS Policy',
            'description': 'CORS allows any origin to access resources',
            'remediation': 'Specify allowed origins explicitly. Remove wildcard in production.',
            'cwe': 'CWE-942'
        },
        'inline_event_handler': {
            'pattern': r'on\w+\s*=',
            'severity': Severity.MEDIUM,
            'category': Category.INJECTION,
            'title': 'Inline Event Handler',
            'description': 'Inline event handlers can be XSS vectors',
            'remediation': 'Use addEventListener() instead of inline handlers.',
            'cwe': 'CWE-79'
        },
        'javascript_protocol': {
            'pattern': r'href\s*=\s*["\']javascript:',
            'severity': Severity.MEDIUM,
            'category': Category.INJECTION,
            'title': 'javascript: Protocol in href',
            'description': 'javascript: protocol in href enables XSS',
            'remediation': 'Use event handlers or proper URLs. Avoid javascript: protocol.',
            'cwe': 'CWE-79'
        },
        'jsonp_callback': {
            'pattern': r'callback\s*=\s*["\']?\w+',
            'severity': Severity.MEDIUM,
            'category': Category.INJECTION,
            'title': 'JSONP Callback Parameter',
            'description': 'JSONP callback parameter can lead to XSS if not validated',
            'remediation': 'Use CORS instead of JSONP. Validate callback names strictly.',
            'cwe': 'CWE-942'
        },
        'dynamic_script_src': {
            'pattern': r'script\.src\s*=.*\+',
            'severity': Severity.HIGH,
            'category': Category.INJECTION,
            'title': 'Dynamic Script Source',
            'description': 'Script source constructed dynamically - potential injection',
            'remediation': 'Validate all URLs before assignment. Use allowlist of trusted domains.',
            'cwe': 'CWE-79'
        },
        'jquery_html': {
            'pattern': r'\$\([^)]*\)\.html\s*\(',
            'severity': Severity.HIGH,
            'category': Category.INJECTION,
            'title': 'XSS via jQuery .html()',
            'description': 'jQuery .html() with user input allows XSS',
            'remediation': 'Use .text() for plain text. Sanitize input if HTML required.',
            'cwe': 'CWE-79'
        },
        'insecure_random': {
            'pattern': r'Math\.random\s*\(\)',
            'severity': Severity.MEDIUM,
            'category': Category.CRYPTOGRAPHY,
            'title': 'Insecure Randomness',
            'description': 'Math.random() not cryptographically secure',
            'remediation': 'Use crypto.getRandomValues() for security-sensitive operations.',
            'cwe': 'CWE-338'
        },
        'child_process_exec': {
            'pattern': r'child_process\.(?:exec|execSync)\s*\(',
            'severity': Severity.CRITICAL,
            'category': Category.INJECTION,
            'title': 'Command Injection via child_process',
            'description': 'child_process.exec() with user input allows command injection',
            'remediation': 'Use execFile() or spawn() with array arguments. Sanitize all inputs.',
            'cwe': 'CWE-78'
        },
        'todo_security': {
            'pattern': r'(?:\/\/|\/\*|\*)\s*(?:TODO|FIXME|XXX).*?(?:security|vuln|fix|patch)',
            'severity': Severity.LOW,
            'category': Category.CONFIGURATION,
            'title': 'Security TODO Comment',
            'description': 'Security-related TODO/FIXME comment found',
            'remediation': 'Address security TODOs before production deployment.',
            'cwe': None
        },
        'debugger_statement': {
            'pattern': r'^\s*debugger\s*;?',
            'severity': Severity.LOW,
            'category': Category.CONFIGURATION,
            'title': 'Debugger Statement',
            'description': 'debugger statement found in code',
            'remediation': 'Remove debugger statements before production.',
            'cwe': None
        },
        'console_log_sensitive': {
            'pattern': r'console\.(?:log|debug|warn|error)\s*\([^)]*(?:password|token|key|secret)',
            'severity': Severity.MEDIUM,
            'category': Category.EXPOSURE,
            'title': 'Sensitive Data in Console',
            'description': 'Potentially sensitive data logged to console',
            'remediation': 'Remove console logging of sensitive data.',
            'cwe': 'CWE-532'
        },
    }
    
    def get_name(self) -> str:
        return "javascript_scanner"
    
    def get_description(self) -> str:
        return "JavaScript/TypeScript security scanner (DOM XSS, eval, API keys, CORS)"
    
    def get_supported_languages(self) -> List[str]:
        return ['javascript', 'typescript']
    
    def scan(self, context: ScanContext) -> List[Vulnerability]:
        """Scan JavaScript/TypeScript file for security issues."""
        vulnerabilities = []
        
        if not context.file_path or not context.file_content:
            return vulnerabilities
        
        content = context.file_content
        
        for pattern_name, pattern_info in self.PATTERNS.items():
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
                        column_start=match.start() - content.rfind('\n', 0, match.start()),
                        column_end=match.end() - content.rfind('\n', 0, match.end()),
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
