"""JavaScript/TypeScript security scanner."""

import re
from typing import List, Dict, Any, Optional, Tuple

from models.vulnerability import Vulnerability, Severity, Category
from scanners.base_scanner import BaseScanner, ScanContext, redact_secrets


PLACEHOLDER_VALUE_RE = re.compile(
    r'^(?:x+|\*+|changeme|change[-_ ]?me|your[-_ ].*|<.*>|\$\{.*\}|process\.env.*|example|placeholder|dummy|todo)$',
    re.IGNORECASE
)

SENSITIVE_WORDS = r'(?:token|jwt|auth|session|password|passwd|secret|api[_-]?key|credential)'


class JavaScriptScanner(BaseScanner):
    """
    JavaScript and TypeScript security scanner.

    Detects:
    - DOM XSS sinks (innerHTML, outerHTML, insertAdjacentHTML, document.write, dangerouslySetInnerHTML, v-html)
    - Code injection (eval, Function, string timers)
    - Command and SQL injection in Node.js
    - Tokens stored in Web Storage, hardcoded API keys / secrets
    - Insecure CORS, cookies, TLS verification, postMessage
    - Prototype pollution
    """

    # Optional keys per pattern:
    #   'line_requires': regex the matched line must also contain
    #   'mask': redact matched text (secrets)
    #   'comment': pattern only applies to comments
    PATTERNS: Dict[str, Dict[str, Any]] = {
        'innerhtml_assignment': {
            'pattern': r'\.(?:innerHTML|outerHTML)\s*\+?=(?!=)\s*+(?![\'"`]\s*[\'"`;]|[\'"`][^\'"`$+]*[\'"`]\s*;?\s*$)',
            'severity': Severity.HIGH,
            'category': Category.INJECTION,
            'title': 'DOM XSS via innerHTML',
            'description': 'Assigning dynamic content to innerHTML/outerHTML allows XSS if the value contains user input',
            'remediation': 'Use textContent for plain text, or sanitize with DOMPurify before assigning HTML.',
            'cwe': 'CWE-79'
        },
        'insert_adjacent_html': {
            'pattern': r'\.insertAdjacentHTML\s*\(',
            'severity': Severity.HIGH,
            'category': Category.INJECTION,
            'title': 'DOM XSS via insertAdjacentHTML',
            'description': 'insertAdjacentHTML() parses its argument as HTML - XSS risk with user input',
            'remediation': 'Build elements with createElement/textContent, or sanitize with DOMPurify.',
            'cwe': 'CWE-79'
        },
        'document_write': {
            'pattern': r'document\.write(?:ln)?\s*\(',
            'severity': Severity.HIGH,
            'category': Category.INJECTION,
            'title': 'Dangerous document.write()',
            'description': 'document.write() injects raw HTML into the page - XSS risk',
            'remediation': 'Use modern DOM manipulation methods. Avoid document.write() entirely.',
            'cwe': 'CWE-79'
        },
        'react_dangerous_html': {
            'pattern': r'dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?!DOMPurify|sanitize)',
            'severity': Severity.HIGH,
            'category': Category.INJECTION,
            'title': 'XSS via dangerouslySetInnerHTML',
            'description': 'React dangerouslySetInnerHTML renders raw HTML without escaping',
            'remediation': 'Avoid raw HTML; if unavoidable wrap the value with DOMPurify.sanitize().',
            'cwe': 'CWE-79'
        },
        'vue_svelte_raw_html': {
            'pattern': r'\bv-html\s*=|\{@html\s',
            'severity': Severity.HIGH,
            'category': Category.INJECTION,
            'title': 'XSS via Raw HTML Binding',
            'description': 'v-html / {@html} render unescaped HTML',
            'remediation': 'Bind text instead, or sanitize the HTML with DOMPurify first.',
            'cwe': 'CWE-79'
        },
        'jquery_html': {
            'pattern': r'\$\([^)]*\)\.(?:html|append|prepend|after|before|replaceWith)\s*\(\s*(?![\'"`][^\'"`$]*[\'"`]\s*\))[^)]',
            'severity': Severity.MEDIUM,
            'category': Category.INJECTION,
            'title': 'XSS via jQuery HTML Insertion',
            'description': 'jQuery .html()/.append() parse strings as HTML - XSS with user input',
            'remediation': 'Use .text() for plain text. Sanitize input if HTML is required.',
            'cwe': 'CWE-79'
        },
        'eval_usage': {
            'pattern': r'(?<![\w.])eval\s*\(',
            'severity': Severity.CRITICAL,
            'category': Category.INJECTION,
            'title': 'Code Injection via eval()',
            'description': 'eval() executes arbitrary code - critical injection risk',
            'remediation': 'Use JSON.parse() for JSON data. Never use eval() with user input.',
            'cwe': 'CWE-95'
        },
        'function_constructor': {
            'pattern': r'\bnew\s+Function\s*\(',
            'severity': Severity.HIGH,
            'category': Category.INJECTION,
            'title': 'Dynamic Code Execution',
            'description': 'Function constructor executes code from string - injection risk',
            'remediation': 'Avoid dynamic code generation. Use safer alternatives.',
            'cwe': 'CWE-95'
        },
        'timer_string': {
            'pattern': r'\bset(?:Timeout|Interval)\s*\(\s*[\'"`]',
            'severity': Severity.HIGH,
            'category': Category.INJECTION,
            'title': 'Implied eval() via Timer',
            'description': 'setTimeout/setInterval with a string argument executes it like eval()',
            'remediation': 'Pass a function instead of a string: setTimeout(fn, delay)',
            'cwe': 'CWE-95'
        },
        'storage_token': {
            'pattern': r'(?:localStorage|sessionStorage)\s*(?:\.setItem\s*\(\s*[\'"`][^\'"`]*' + SENSITIVE_WORDS
                       + r'|\[\s*[\'"`][^\'"`]*' + SENSITIVE_WORDS + r'[^\'"`]*[\'"`]\s*\]\s*=(?!=)|\.\w*'
                       + SENSITIVE_WORDS + r'\w*\s*=(?!=))',
            'severity': Severity.HIGH,
            'category': Category.EXPOSURE,
            'title': 'Sensitive Token in Web Storage',
            'description': 'Authentication tokens in localStorage/sessionStorage can be stolen by any XSS',
            'remediation': 'Store session tokens in HttpOnly, Secure, SameSite cookies instead.',
            'cwe': 'CWE-522'
        },
        'exposed_api_key': {
            'pattern': r'[\'"]?\b(?:api[_-]?key|apikey|api[_-]?secret|client[_-]?secret)[\'"]?\s*[:=]\s*[\'"`][A-Za-z0-9_\-]{16,}[\'"`]',
            'mask': True,
            'severity': Severity.CRITICAL,
            'category': Category.EXPOSURE,
            'title': 'Exposed API Key',
            'description': 'API key hardcoded in JavaScript - anyone loading the bundle can read it',
            'remediation': 'Move API calls to the server side and load keys from environment variables. Rotate the key.',
            'cwe': 'CWE-798'
        },
        'hardcoded_secret': {
            'pattern': r'\b(?:password|passwd|secret|jwt[_-]?secret|session[_-]?secret|private[_-]?key|auth[_-]?token)\b[\'"]?\s*[:=]\s*[\'"`]([^\'"`\s]{8,})[\'"`]',
            'mask': True,
            'severity': Severity.HIGH,
            'category': Category.EXPOSURE,
            'title': 'Hardcoded Secret',
            'description': 'A password or secret is hardcoded in source code',
            'remediation': 'Load secrets from environment variables (process.env) or a secrets manager.',
            'cwe': 'CWE-798'
        },
        'exposed_private_key': {
            'pattern': r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----',
            'severity': Severity.CRITICAL,
            'category': Category.EXPOSURE,
            'title': 'Private Key Exposed',
            'description': 'Private key found in source code',
            'remediation': 'Remove immediately. Rotate compromised keys. Use secure key management.',
            'cwe': 'CWE-321'
        },
        'postmessage_wildcard': {
            'pattern': r'\.postMessage\s*\([^;]*,\s*[\'"]\*[\'"]\s*\)',
            'severity': Severity.MEDIUM,
            'category': Category.CONFIGURATION,
            'title': 'Insecure postMessage Target',
            'description': 'postMessage with "*" target lets any origin receive the message',
            'remediation': 'Specify the exact target origin instead of "*".',
            'cwe': 'CWE-345'
        },
        'message_listener_no_origin': {
            'pattern': r'addEventListener\s*\(\s*[\'"]message[\'"]',
            'line_requires': r'^(?!.*origin)',
            'severity': Severity.LOW,
            'category': Category.CONFIGURATION,
            'title': 'Message Listener May Skip Origin Check',
            'description': 'A "message" event handler should verify event.origin before trusting data',
            'remediation': 'Check event.origin against an allow-list at the top of the handler.',
            'cwe': 'CWE-346'
        },
        'cors_wildcard': {
            'pattern': r'[\'"]Access-Control-Allow-Origin[\'"]\s*[,:]\s*[\'"]\*[\'"]|\bcors\s*\(\s*\)|\borigin\s*:\s*(?:[\'"]\*[\'"]|true)\b',
            'severity': Severity.HIGH,
            'category': Category.CONFIGURATION,
            'title': 'Open CORS Policy',
            'description': 'CORS allows any origin to read responses from this API',
            'remediation': 'Pass an explicit origin allow-list to cors({ origin: [...] }).',
            'cwe': 'CWE-942'
        },
        'javascript_protocol': {
            'pattern': r'href\s*=\s*[\'"{`]\s*javascript:',
            'severity': Severity.MEDIUM,
            'category': Category.INJECTION,
            'title': 'javascript: Protocol in href',
            'description': 'javascript: URLs execute code and bypass many XSS defences',
            'remediation': 'Use event handlers or proper URLs. Avoid the javascript: protocol.',
            'cwe': 'CWE-79'
        },
        'jsonp_callback': {
            'pattern': r'[?&](?:callback|jsonp)=[\'"`]?\s*\+',
            'severity': Severity.MEDIUM,
            'category': Category.INJECTION,
            'title': 'JSONP Callback Parameter',
            'description': 'JSONP executes the remote response as script and is an XSS vector',
            'remediation': 'Use fetch() with CORS instead of JSONP.',
            'cwe': 'CWE-830'
        },
        'dynamic_script_src': {
            'pattern': r'\.src\s*=\s*[^;\n]*(?:\+|\$\{)',
            'line_requires': r'script',
            'severity': Severity.HIGH,
            'category': Category.INJECTION,
            'title': 'Dynamic Script Source',
            'description': 'Script source constructed dynamically - attacker may load arbitrary script',
            'remediation': 'Load scripts from a fixed allow-list of trusted URLs.',
            'cwe': 'CWE-829'
        },
        'insecure_random': {
            'pattern': r'Math\.random\s*\(\s*\)',
            'line_requires': SENSITIVE_WORDS + r'|nonce|salt|otp|\bid\b|uuid',
            'severity': Severity.MEDIUM,
            'category': Category.CRYPTOGRAPHY,
            'title': 'Insecure Randomness',
            'description': 'Math.random() is predictable and must not generate tokens or IDs',
            'remediation': 'Use crypto.getRandomValues() or crypto.randomUUID().',
            'cwe': 'CWE-338'
        },
        'child_process_exec': {
            'pattern': r'\b(?:child_process\.)?exec(?:Sync)?\s*\(\s*(?:`[^`]*\$\{|[^,)]*\+|[a-zA-Z_$][\w$.]*\s*[,)])',
            'line_requires': r'exec(?:Sync)?\s*\(',
            'severity': Severity.CRITICAL,
            'category': Category.INJECTION,
            'title': 'Command Injection via child_process',
            'description': 'child_process.exec() runs a shell command built from variable input',
            'remediation': 'Use execFile() or spawn() with an argument array. Never pass user input to a shell.',
            'cwe': 'CWE-78'
        },
        'sql_template_literal': {
            'pattern': r'\.(?:query|execute|raw|run|all|get)\s*\(\s*(?:`[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{|[\'"][^\'"]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^\'"]*[\'"]\s*\+)',
            'severity': Severity.CRITICAL,
            'category': Category.INJECTION,
            'title': 'SQL Injection',
            'description': 'SQL query built with template literal interpolation or concatenation',
            'remediation': 'Use parameterized queries (placeholders such as ? or $1) supplied by the driver.',
            'cwe': 'CWE-89'
        },
        'reflected_xss_express': {
            'pattern': r'\bres\.(?:send|write|end)\s*\([^)]*\breq\.(?:query|params|body)\b',
            'severity': Severity.HIGH,
            'category': Category.INJECTION,
            'title': 'Reflected XSS',
            'description': 'Request input is written directly into the HTTP response without encoding',
            'remediation': 'Encode output (e.g. escape-html) or render through a template engine with auto-escaping.',
            'cwe': 'CWE-79'
        },
        'open_redirect': {
            'pattern': r'\bres\.redirect\s*\(\s*req\.(?:query|params|body)\b',
            'severity': Severity.MEDIUM,
            'category': Category.INJECTION,
            'title': 'Open Redirect',
            'description': 'Redirect target taken directly from request input',
            'remediation': 'Redirect only to relative paths or an allow-list of known URLs.',
            'cwe': 'CWE-601'
        },
        'prototype_pollution': {
            'pattern': r'\[\s*[\'"]__proto__[\'"]\s*\]|\.__proto__\s*=(?!=)|Object\.assign\s*\(\s*\{\s*\}\s*,\s*req\.(?:body|query)',
            'severity': Severity.MEDIUM,
            'category': Category.INJECTION,
            'title': 'Potential Prototype Pollution',
            'description': 'Writing to __proto__ or merging request input into objects can pollute Object.prototype',
            'remediation': 'Use Object.create(null) or Map for user-keyed data and reject __proto__/constructor keys.',
            'cwe': 'CWE-1321'
        },
        'tls_reject_disabled': {
            'pattern': r'rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED[\'"]?\s*\]?\s*=\s*[\'"]?0',
            'severity': Severity.HIGH,
            'category': Category.TRANSPORT,
            'title': 'TLS Certificate Validation Disabled',
            'description': 'Certificate validation is turned off - traffic can be intercepted (MITM)',
            'remediation': 'Remove rejectUnauthorized:false / NODE_TLS_REJECT_UNAUTHORIZED=0 and fix the certificate chain.',
            'cwe': 'CWE-295'
        },
        'insecure_cookie_options': {
            'pattern': r'\b(?:httpOnly|secure)\s*:\s*false\b',
            'severity': Severity.MEDIUM,
            'category': Category.CONFIGURATION,
            'title': 'Insecure Cookie Options',
            'description': 'Cookie configured without HttpOnly or Secure flag',
            'remediation': 'Set httpOnly: true, secure: true and sameSite: "lax" (or "strict") for session cookies.',
            'cwe': 'CWE-614'
        },
        'jwt_weak_verify': {
            'pattern': r'algorithms\s*:\s*\[[^\]]*[\'"]none[\'"]|ignoreExpiration\s*:\s*true',
            'severity': Severity.HIGH,
            'category': Category.AUTHENTICATION,
            'title': 'Weak JWT Verification',
            'description': 'JWT verification accepts the "none" algorithm or ignores expiry',
            'remediation': 'Pin a strong algorithm (e.g. HS256/RS256) and keep expiration checks enabled.',
            'cwe': 'CWE-347'
        },
        'insecure_http_request': {
            'pattern': r'(?:fetch|axios(?:\.\w+)?|\$\.(?:get|post|ajax)|new\s+WebSocket)\s*\(\s*[\'"`](?:http|ws)://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])',
            'severity': Severity.MEDIUM,
            'category': Category.TRANSPORT,
            'title': 'Request over Unencrypted Connection',
            'description': 'Data is sent over plain HTTP/WS and can be read or modified in transit',
            'remediation': 'Use https:// and wss:// endpoints.',
            'cwe': 'CWE-319'
        },
        'todo_security': {
            'pattern': r'(?://|/\*|\*)\s*(?:TODO|FIXME|XXX|HACK)\b.*?\b(?:security|vuln\w*|insecure|unsafe|auth\w*|password|xss|csrf|sqli?)\b',
            'comment': True,
            'severity': Severity.LOW,
            'category': Category.CONFIGURATION,
            'title': 'Security TODO Comment',
            'description': 'Security-related TODO/FIXME comment found',
            'remediation': 'Address security TODOs before production deployment.',
            'cwe': None
        },
        'debugger_statement': {
            'pattern': r'^\s*debugger\s*;?\s*$',
            'severity': Severity.LOW,
            'category': Category.CONFIGURATION,
            'title': 'Debugger Statement',
            'description': 'debugger statement left in code',
            'remediation': 'Remove debugger statements before production.',
            'cwe': 'CWE-489'
        },
        'console_log_sensitive': {
            'pattern': r'console\.(?:log|debug|info|warn|error)\s*\([^)]*\b(?:password|passwd|token|secret|apiKey|api_key)\b',
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
        return "JavaScript/TypeScript security scanner (DOM XSS, eval, injection, secrets, CORS, cookies)"

    def get_supported_languages(self) -> List[str]:
        return ['javascript', 'typescript']

    def scan(self, context: ScanContext) -> List[Vulnerability]:
        """Scan JavaScript/TypeScript file for security issues."""
        if not context.file_path or not context.file_content:
            return []
        return self.scan_source(context)

    def scan_source(self, context: ScanContext, line_offset: int = 0) -> List[Vulnerability]:
        """
        Scan JavaScript source held in context.file_content.

        Args:
            context: Scan context
            line_offset: Added to reported line numbers (for inline <script> blocks)
        """
        vulnerabilities: List[Vulnerability] = []
        content = context.file_content
        lines = content.split('\n')
        comment_lines = _comment_line_ranges(content)

        for pattern_name, info in self.PATTERNS.items():
            try:
                regex = re.compile(info['pattern'], re.MULTILINE | (0 if pattern_name == 'sql_template_literal' else re.IGNORECASE))
            except re.error as e:
                self.log_error(f"Regex error in pattern {pattern_name}: {e}")
                continue

            for match in regex.finditer(content):
                vuln = self.finding_from_match(context, match, info, pattern_name, mask_match=info.get('mask', False))
                line_text = lines[vuln.line_number - 1]

                in_comment = _in_comment(comment_lines, vuln.line_number, vuln.column_start, line_text)
                if in_comment != bool(info.get('comment')):
                    continue

                if info.get('line_requires') and not re.search(info['line_requires'], line_text, re.IGNORECASE):
                    continue

                if info.get('mask') and match.groups():
                    if PLACEHOLDER_VALUE_RE.match(match.group(match.lastindex or 1) or ''):
                        continue

                if line_offset:
                    vuln.line_number += line_offset
                    vuln.code_snippet = self.extract_code_snippet(
                        context.metadata_full_content, vuln.line_number
                    ) if getattr(context, 'metadata_full_content', None) else vuln.code_snippet
                vulnerabilities.append(vuln)

        return redact_secrets(vulnerabilities)


def _comment_line_ranges(content: str) -> List[Tuple[int, int]]:
    """Return (start_line, end_line) ranges of /* ... */ block comments."""
    ranges = []
    for m in re.finditer(r'/\*.*?\*/', content, re.DOTALL):
        start = content.count('\n', 0, m.start()) + 1
        end = content.count('\n', 0, m.end()) + 1
        ranges.append((start, end))
    return ranges


def _in_comment(block_ranges: List[Tuple[int, int]], line: int, column: Optional[int], line_text: str) -> bool:
    """Approximate check whether a match position lies inside a comment."""
    stripped = line_text.lstrip()
    if stripped.startswith('//') or stripped.startswith('*') or stripped.startswith('/*'):
        return True
    if column is not None:
        idx = line_text.find('//')
        # ignore '//' inside URLs like https://
        while idx != -1 and idx > 0 and line_text[idx - 1] == ':':
            idx = line_text.find('//', idx + 2)
        if idx != -1 and idx < column:
            return True
    return any(start < line <= end for start, end in block_ranges)
