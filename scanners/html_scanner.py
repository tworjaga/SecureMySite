"""HTML and server-side template security scanner."""

import re
from typing import List, Optional
from urllib.parse import urlparse

from models.vulnerability import Vulnerability, Severity, Category
from scanners.base_scanner import BaseScanner, ScanContext
from scanners.js_scanner import JavaScriptScanner
from utils.validators import is_local_hostname


TAG_RE = re.compile(r'<(script|link|iframe|img|form|a|input)\b([^>]*)>', re.IGNORECASE | re.DOTALL)
ATTR_RE = re.compile(r'([:\w-]+)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))', re.DOTALL)
SCRIPT_BLOCK_RE = re.compile(r'(<script\b[^>]*>)(.*?)</script\s*>', re.IGNORECASE | re.DOTALL)
INLINE_HANDLER_RE = re.compile(r'<[a-zA-Z][^>]*?\s(on[a-z]+)\s*=\s*["\']', re.IGNORECASE)


def _attrs(raw: str) -> dict:
    return {m.group(1).lower(): (m.group(2) or m.group(3) or m.group(4) or '') for m in ATTR_RE.finditer(raw)}


def _is_external(url: str) -> bool:
    if url.startswith('//'):
        url = 'https:' + url
    parsed = urlparse(url)
    return parsed.scheme in ('http', 'https') and not is_local_hostname(parsed.hostname)


class HTMLScanner(BaseScanner):
    """
    Scans HTML files and server-side templates.

    Detects:
    - Script issues inside inline <script> blocks (re-uses the JavaScript rules)
    - Third-party scripts/styles without Subresource Integrity
    - Mixed content (http:// resources) and insecure form targets
    - target="_blank" without rel="noopener"
    - Unescaped template output (Jinja |safe, autoescape off, {{{ }}}, <%- %>)
    - Inline event handlers (block a strict CSP)
    """

    TEMPLATE_PATTERNS = {
        'jinja_safe': {
            'pattern': r'\{\{[^}]*\|\s*safe\b[^}]*\}\}',
            'title': 'Unescaped Template Output (|safe)',
            'description': 'The |safe filter disables auto-escaping; user data rendered this way causes XSS',
        },
        'autoescape_off': {
            'pattern': r'\{%-?\s*autoescape\s+(?:false|off)\s*-?%\}',
            'title': 'Template Auto-escaping Disabled',
            'description': 'Auto-escaping is turned off for a block of the template',
        },
        'handlebars_triple': {
            'pattern': r'\{\{\{[^}]+\}\}\}',
            'title': 'Unescaped Template Output ({{{ }}})',
            'description': 'Triple-stash output in Handlebars/Mustache is not HTML-escaped',
        },
        'ejs_unescaped': {
            'pattern': r'<%-(?!\s*include)[^%]+%>',
            'title': 'Unescaped Template Output (<%- %>)',
            'description': 'EJS <%- %> writes raw HTML without escaping',
        },
    }

    def __init__(self, config=None):
        super().__init__(config)
        self._js = JavaScriptScanner(config)

    def get_name(self) -> str:
        return "html_scanner"

    def get_description(self) -> str:
        return "HTML & template scanner (inline scripts, SRI, mixed content, unescaped template output)"

    def get_supported_languages(self) -> List[str]:
        return ['html']

    def scan(self, context: ScanContext) -> List[Vulnerability]:
        if not context.file_path or not context.file_content:
            return []
        vulns: List[Vulnerability] = []

        vulns.extend(self._scan_inline_scripts(context))
        vulns.extend(self._scan_tags(context))
        vulns.extend(self._scan_templates(context))

        handler = self._inline_handlers(context)
        if handler:
            vulns.append(handler)
        return vulns

    def _line(self, content: str, pos: int) -> int:
        return content.count('\n', 0, pos) + 1

    def _make(self, context: ScanContext, pos: int, title: str, description: str, severity: Severity,
              remediation: str, cwe: Optional[str], rule: str, category: Category = Category.CONFIGURATION) -> Vulnerability:
        line = self._line(context.file_content, pos)
        return Vulnerability(
            title=title,
            description=description,
            severity=severity,
            category=category,
            file_path=context.file_path,
            line_number=line,
            code_snippet=self.extract_code_snippet(context.file_content, line),
            remediation=remediation,
            cwe_id=cwe,
            scanner_source=self.get_name(),
            metadata={'rule': rule},
        )

    def _scan_inline_scripts(self, context: ScanContext) -> List[Vulnerability]:
        """Run JS rules on inline <script> bodies, keeping original line numbers."""
        content = context.file_content
        blocks = [m for m in SCRIPT_BLOCK_RE.finditer(content) if 'src=' not in m.group(1).lower()]
        if not blocks:
            return []

        # Blank out everything that is not script, preserving newlines/offsets
        chars = [c if c == '\n' else ' ' for c in content]
        for m in blocks:
            start, end = m.start(2), m.end(2)
            chars[start:end] = content[start:end]
        js_context = ScanContext(
            project_path=context.project_path,
            file_path=context.file_path,
            file_content=''.join(chars),
            language='javascript',
            config=context.config,
        )
        findings = self._js.scan_source(js_context)
        for vuln in findings:
            vuln.scanner_source = self.get_name()
            vuln.code_snippet = self.extract_code_snippet(content, vuln.line_number)
            vuln.metadata['inline_script'] = True
        return findings

    def _scan_tags(self, context: ScanContext) -> List[Vulnerability]:
        vulns = []
        content = context.file_content
        has_password_field = re.search(r'<input[^>]+type\s*=\s*["\']?password', content, re.IGNORECASE) is not None

        for m in TAG_RE.finditer(content):
            tag = m.group(1).lower()
            attrs = _attrs(m.group(2))
            pos = m.start()

            if tag == 'script' and attrs.get('src'):
                src = attrs['src']
                if src.startswith('http://') and _is_external(src):
                    vulns.append(self._make(
                        context, pos, 'Script Loaded over HTTP',
                        f'Script {src} is fetched over plain HTTP - a network attacker can replace it',
                        Severity.HIGH, 'Load the script over https://.', 'CWE-319', 'mixed_script',
                        Category.TRANSPORT))
                elif _is_external(src) and 'integrity' not in attrs:
                    vulns.append(self._make(
                        context, pos, 'Third-Party Script Without SRI',
                        f'{src} is loaded without an integrity hash; a compromised CDN could inject code',
                        Severity.LOW, 'Add integrity="sha384-..." and crossorigin="anonymous", or self-host the file.',
                        'CWE-353', 'missing_sri'))

            elif tag == 'link' and 'stylesheet' in attrs.get('rel', '').lower():
                href = attrs.get('href', '')
                if href.startswith('http://') and _is_external(href):
                    vulns.append(self._make(
                        context, pos, 'Stylesheet Loaded over HTTP',
                        f'Stylesheet {href} is fetched over plain HTTP', Severity.MEDIUM,
                        'Load the stylesheet over https://.', 'CWE-319', 'mixed_style', Category.TRANSPORT))

            elif tag == 'iframe' and attrs.get('src', '').startswith('http://') and _is_external(attrs['src']):
                vulns.append(self._make(
                    context, pos, 'Iframe Loaded over HTTP', f'Iframe {attrs["src"]} uses plain HTTP',
                    Severity.MEDIUM, 'Use https:// for embedded content.', 'CWE-319', 'mixed_iframe', Category.TRANSPORT))

            elif tag == 'a' and attrs.get('target', '').lower() == '_blank':
                rel = attrs.get('rel', '').lower()
                if 'noopener' not in rel and 'noreferrer' not in rel and _is_external(attrs.get('href', '')):
                    vulns.append(self._make(
                        context, pos, 'target="_blank" Without rel="noopener"',
                        'The opened page can access window.opener and redirect this tab (reverse tabnabbing)',
                        Severity.LOW, 'Add rel="noopener noreferrer" to external links that open in a new tab.',
                        'CWE-1022', 'tabnabbing'))

            elif tag == 'form':
                action = attrs.get('action', '')
                method = attrs.get('method', 'get').lower()
                if action.startswith('http://') and _is_external(action):
                    vulns.append(self._make(
                        context, pos, 'Form Submits over HTTP',
                        f'Form data is sent unencrypted to {action}', Severity.HIGH,
                        'Use an https:// form action.', 'CWE-319', 'form_http', Category.TRANSPORT))
                if has_password_field and method == 'get':
                    form_end = content.find('</form', pos)
                    form_html = content[pos:form_end if form_end != -1 else None]
                    if re.search(r'type\s*=\s*["\']?password', form_html, re.IGNORECASE):
                        vulns.append(self._make(
                            context, pos, 'Password Sent in URL',
                            'A form with a password field uses GET, putting the password in the URL, logs and history',
                            Severity.MEDIUM, 'Use method="post" for forms containing credentials.', 'CWE-598',
                            'password_get', Category.EXPOSURE))
        return vulns

    def _scan_templates(self, context: ScanContext) -> List[Vulnerability]:
        vulns = []
        for rule, info in self.TEMPLATE_PATTERNS.items():
            for m in re.finditer(info['pattern'], context.file_content, re.IGNORECASE):
                vulns.append(self._make(
                    context, m.start(), info['title'], info['description'], Severity.HIGH,
                    'Keep auto-escaping on; sanitize HTML with a vetted sanitizer (e.g. bleach / DOMPurify) '
                    'before marking it safe.', 'CWE-79', rule, Category.INJECTION))
        return vulns

    def _inline_handlers(self, context: ScanContext) -> Optional[Vulnerability]:
        matches = list(INLINE_HANDLER_RE.finditer(context.file_content))
        if not matches:
            return None
        names = sorted({m.group(1).lower() for m in matches})
        vuln = self._make(
            context, matches[0].start(1), 'Inline Event Handlers',
            f'{len(matches)} inline event handler(s) ({", ".join(names[:5])}) found. They prevent using a strict '
            'Content-Security-Policy and are a common XSS vector.',
            Severity.LOW, 'Attach handlers with addEventListener() in a separate script file.', 'CWE-79',
            'inline_handlers', Category.INJECTION)
        vuln.metadata['count'] = len(matches)
        return vuln
