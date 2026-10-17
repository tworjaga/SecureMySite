"""Web security scanner for localhost-only dynamic analysis."""

import uuid
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Tuple
from urllib.parse import urlparse, urljoin

from models.vulnerability import Vulnerability, Severity, Category
from scanners.base_scanner import BaseScanner, ScanContext
from utils.validators import validate_url


@dataclass
class HttpResult:
    """Minimal response snapshot used by the checks."""
    url: str
    status: int
    headers: Dict[str, str]                       # lower-cased names
    set_cookies: List[str] = field(default_factory=list)
    body: str = ''


class WebScanner(BaseScanner):
    """
    Web security scanner for localhost-only applications.

    CRITICAL: Only accepts localhost, 127.0.0.0/8, ::1 or *.local hosts.
    Redirects are only followed while they stay on an allowed host.

    Checks:
    - Security headers (CSP, X-Frame-Options, nosniff, HSTS, Referrer/Permissions-Policy)
    - Information disclosure headers (Server, X-Powered-By)
    - Cookie security flags (Secure, HttpOnly, SameSite)
    - CORS misconfiguration (wildcard, reflected origin with credentials)
    - Exposed sensitive files (/.env, /.git, backups, API docs)
    - Debug error pages and directory listings

    For offline/unit testing, 'headers', 'cookies' and 'exposed_endpoints'
    may be supplied in the context config instead of making requests.
    """

    SECURITY_HEADERS = {
        'Content-Security-Policy': {
            'severity': Severity.HIGH,
            'title': 'Missing Content Security Policy',
            'description': 'CSP header not present - injected scripts run without restriction',
            'remediation': "Add a CSP header, e.g. Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'",
            'cwe': 'CWE-693'
        },
        'X-Frame-Options': {
            'severity': Severity.MEDIUM,
            'title': 'Missing Clickjacking Protection',
            'description': 'Neither X-Frame-Options nor CSP frame-ancestors is set, so the page can be framed',
            'remediation': "Add X-Frame-Options: DENY (or CSP frame-ancestors 'none')",
            'cwe': 'CWE-1021'
        },
        'X-Content-Type-Options': {
            'severity': Severity.MEDIUM,
            'title': 'Missing X-Content-Type-Options',
            'description': 'MIME type sniffing not disabled',
            'remediation': 'Add header: X-Content-Type-Options: nosniff',
            'cwe': 'CWE-693'
        },
        'Strict-Transport-Security': {
            'severity': Severity.MEDIUM,
            'title': 'Missing HSTS Header',
            'description': 'HTTP Strict Transport Security not enabled on an HTTPS site',
            'remediation': 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains',
            'cwe': 'CWE-319',
            'https_only': True,
        },
        'Referrer-Policy': {
            'severity': Severity.LOW,
            'title': 'Missing Referrer-Policy',
            'description': 'Full URLs (including tokens in query strings) may leak to third parties via Referer',
            'remediation': 'Add header: Referrer-Policy: strict-origin-when-cross-origin',
            'cwe': 'CWE-200'
        },
        'Permissions-Policy': {
            'severity': Severity.LOW,
            'title': 'Missing Permissions-Policy',
            'description': 'Powerful browser features (camera, microphone, geolocation) are not restricted',
            'remediation': 'Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()',
            'cwe': None
        },
    }

    # path -> (body signature or None, severity)
    DANGEROUS_ENDPOINTS: Dict[str, Tuple[Optional[str], Severity]] = {
        '/.env': ('=', Severity.CRITICAL),
        '/.env.local': ('=', Severity.CRITICAL),
        '/.env.production': ('=', Severity.CRITICAL),
        '/.git/config': ('[core]', Severity.CRITICAL),
        '/.git/HEAD': ('ref:', Severity.CRITICAL),
        '/.svn/entries': (None, Severity.HIGH),
        '/.htpasswd': (':', Severity.CRITICAL),
        '/.DS_Store': ('Bud1', Severity.MEDIUM),
        '/config.json': ('{', Severity.HIGH),
        '/config.php.bak': (None, Severity.HIGH),
        '/wp-config.php.bak': (None, Severity.CRITICAL),
        '/backup.sql': ('INSERT', Severity.CRITICAL),
        '/dump.sql': ('INSERT', Severity.CRITICAL),
        '/db.sqlite3': ('SQLite', Severity.CRITICAL),
        '/docker-compose.yml': ('services', Severity.HIGH),
        '/Dockerfile': ('FROM', Severity.MEDIUM),
        '/requirements.txt': (None, Severity.LOW),
        '/package.json': ('"dependencies"', Severity.LOW),
        '/phpinfo.php': ('phpinfo', Severity.HIGH),
        '/server-status': ('Apache', Severity.MEDIUM),
        '/actuator/env': ('propertySources', Severity.CRITICAL),
        '/swagger.json': ('swagger', Severity.LOW),
        '/openapi.json': ('openapi', Severity.LOW),
        '/admin/': (None, Severity.LOW),
    }

    DEBUG_SIGNATURES = {
        "You're seeing this error because you have <code>DEBUG = True</code>": 'Django',
        'Werkzeug Debugger': 'Flask/Werkzeug',
        '__debugger__': 'Flask/Werkzeug',
        'Whoops! There was an error': 'Laravel',
        'at Layer.handle [as handle_request]': 'Express',
        'Traceback (most recent call last)': 'Python',
    }

    EVIL_ORIGIN = 'https://securemysite-cors-check.invalid'

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self._last_error: Optional[str] = None
        self.timeout = float(self.config.get('timeout', 5))
        self.max_redirects = 5

    def get_name(self) -> str:
        return "web_scanner"

    def get_description(self) -> str:
        return "Localhost-only web security scanner (headers, cookies, CORS, exposed files, debug pages)"

    def get_supported_languages(self) -> List[str]:
        return ['http']

    def can_scan_file(self, file_path) -> bool:
        return False

    def _validate_url(self, url: str) -> bool:
        """Validate URL is localhost-only."""
        ok, error = validate_url(url, allow_localhost_only=True)
        self._last_error = error
        return ok

    def get_last_error(self) -> Optional[str]:
        """Get last error message."""
        return self._last_error

    # ------------------------------------------------------------------ main

    def scan(self, context: ScanContext) -> List[Vulnerability]:
        """Scan the web application at the localhost URL in context.config['url']."""
        config = context.config or {}
        url = config.get('url')
        if not url:
            return []

        if not self._validate_url(url):
            return [self._vuln(
                'Invalid URL for Web Scan', self._last_error or 'URL validation failed',
                Severity.LOW, Category.CONFIGURATION, f'URL: {url}',
                'Use a localhost, 127.0.0.1, ::1 or *.local URL. Scanning remote hosts is not allowed.',
                None, {'url': url, 'error': 'non_localhost_url'}
            )]

        simulated = any(k in config for k in ('headers', 'cookies', 'exposed_endpoints'))
        if simulated:
            return self._scan_simulated(config, url)

        try:
            import requests
        except ImportError:
            self._last_error = 'requests is not installed'
            return []

        session = requests.Session()
        session.headers['User-Agent'] = 'SecureMySite/2.0 (local security scan)'

        main = self._fetch(session, url)
        if main is None:
            raise ConnectionError(f"Could not connect to {url}: {self._last_error}")

        vulns: List[Vulnerability] = []
        vulns.extend(self._check_headers(main.headers, main.url))
        vulns.extend(self._check_cookies([self._parse_set_cookie(c) for c in main.set_cookies], main.url))
        vulns.extend(self._check_cors(session, main.url))
        vulns.extend(self._check_endpoints(session, main.url))
        vulns.extend(self._check_debug_and_listing(session, main))
        vulns.extend(self._check_methods(session, main.url))
        return vulns

    def _scan_simulated(self, config: Dict[str, Any], url: str) -> List[Vulnerability]:
        """Analyze headers/cookies/endpoints supplied in config (offline mode)."""
        headers = {k.lower(): v for k, v in config.get('headers', {}).items()}
        vulns = self._check_headers(headers, url)
        vulns.extend(self._check_cookies(config.get('cookies', []), url))
        for endpoint in config.get('exposed_endpoints', []):
            if endpoint in self.DANGEROUS_ENDPOINTS:
                vulns.append(self._endpoint_vuln(endpoint, self.DANGEROUS_ENDPOINTS[endpoint][1], url))
        return vulns

    # ------------------------------------------------------------------ HTTP

    def _redirect_allowed(self, url: str) -> bool:
        """Redirect policy: stay on localhost (the domain scanner overrides this)."""
        return validate_url(url)[0]
    
    def _fetch(self, session, url: str, method: str = 'GET', headers: Optional[Dict[str, str]] = None) -> Optional[HttpResult]:
        """Request url, following redirects only while they stay on localhost."""
        current = url
        for _ in range(self.max_redirects + 1):
            try:
                resp = session.request(
                    method, current, headers=headers, timeout=self.timeout,
                    allow_redirects=False, stream=True,
                )
                body = ''
                try:
                    raw = resp.raw.read(256 * 1024, decode_content=True) or b''
                    body = raw.decode(resp.encoding or 'utf-8', errors='replace')
                finally:
                    resp.close()
            except Exception as e:
                self._last_error = str(e)
                return None

            set_cookies = []
            try:
                set_cookies = list(resp.raw.headers.getlist('Set-Cookie'))
            except AttributeError:
                if 'set-cookie' in resp.headers:
                    set_cookies = [resp.headers['set-cookie']]

            if resp.is_redirect and 'location' in resp.headers:
                target = urljoin(current, resp.headers['location'])
                if not self._redirect_allowed(target):
                    # Do not leave localhost; analyse the redirect response itself
                    return HttpResult(current, resp.status_code, {k.lower(): v for k, v in resp.headers.items()},
                                      set_cookies, body)
                current = target
                continue

            return HttpResult(current, resp.status_code, {k.lower(): v for k, v in resp.headers.items()},
                              set_cookies, body)
        return None

    # ------------------------------------------------------------------ checks

    def _vuln(self, title, description, severity, category, snippet, remediation, cwe, metadata) -> Vulnerability:
        return Vulnerability(
            title=title,
            description=description,
            severity=severity,
            category=category,
            file_path=None,
            line_number=None,
            code_snippet=snippet,
            remediation=remediation,
            cwe_id=cwe,
            scanner_source=self.get_name(),
            metadata=metadata,
        )

    def _check_headers(self, headers: Dict[str, str], url: str) -> List[Vulnerability]:
        vulns = []
        is_https = urlparse(url).scheme == 'https'
        csp = headers.get('content-security-policy', '')

        for header_name, info in self.SECURITY_HEADERS.items():
            if info.get('https_only') and not is_https:
                continue
            value = headers.get(header_name.lower())
            if header_name == 'X-Frame-Options' and 'frame-ancestors' in csp:
                value = value or 'csp-frame-ancestors'
            if value is None:
                vulns.append(self._vuln(
                    info['title'], info['description'], info['severity'], Category.CONFIGURATION,
                    f'Missing: {header_name}', info['remediation'], info.get('cwe'),
                    {'missing_header': header_name, 'url': url}
                ))
            else:
                vulns.extend(self._check_header_value(header_name, value, url))

        for leaky in ('x-powered-by', 'server', 'x-aspnet-version', 'x-aspnetmvc-version'):
            value = headers.get(leaky)
            if value and (leaky != 'server' or any(ch.isdigit() for ch in value)):
                vulns.append(self._vuln(
                    f'Information Disclosure: {leaky.title()}',
                    f'Server technology/version exposed: {value}',
                    Severity.LOW, Category.EXPOSURE, f'{leaky.title()}: {value}',
                    f'Remove the {leaky.title()} header or strip version numbers from it.',
                    'CWE-200', {'header': leaky, 'value': value, 'url': url}
                ))

        acao = headers.get('access-control-allow-origin')
        if acao == '*':
            vulns.append(self._vuln(
                'Open CORS Policy', 'Access-Control-Allow-Origin: * lets any website read these responses',
                Severity.MEDIUM, Category.CONFIGURATION, 'Access-Control-Allow-Origin: *',
                'Return an explicit allowed origin instead of *.', 'CWE-942', {'header': 'access-control-allow-origin', 'url': url}
            ))
        return vulns

    def _check_header_value(self, header_name: str, header_value: str, url: str = '') -> List[Vulnerability]:
        """Check specific header values for weak configuration."""
        vulns = []
        if header_name == 'X-Frame-Options' and header_value.upper() == 'ALLOWALL':
            vulns.append(self._vuln(
                'Insecure X-Frame-Options Value', 'X-Frame-Options set to ALLOWALL allows any site to frame this page',
                Severity.HIGH, Category.CONFIGURATION, f'X-Frame-Options: {header_value}',
                'Use DENY or SAMEORIGIN instead of ALLOWALL.', 'CWE-1021', {'header': header_name, 'value': header_value}
            ))
        if header_name == 'Content-Security-Policy':
            for token, title, fix in (
                ("'unsafe-inline'", 'CSP Allows Unsafe Inline Scripts', 'Remove unsafe-inline; use nonces or hashes.'),
                ("'unsafe-eval'", 'CSP Allows Unsafe Eval', 'Remove unsafe-eval; avoid eval-like APIs.'),
            ):
                if token in header_value:
                    vulns.append(self._vuln(
                        title, f'CSP contains {token}, weakening XSS protection',
                        Severity.MEDIUM, Category.CONFIGURATION, f'CSP: {header_value[:120]}',
                        fix, 'CWE-693', {'header': header_name, 'value': header_value}
                    ))
            if 'default-src' not in header_value and 'script-src' not in header_value:
                vulns.append(self._vuln(
                    'Weak Content Security Policy', 'CSP has neither default-src nor script-src, so scripts are unrestricted',
                    Severity.MEDIUM, Category.CONFIGURATION, f'CSP: {header_value[:120]}',
                    "Add default-src 'self' (and script-src) to the policy.", 'CWE-693', {'header': header_name}
                ))
        if header_name == 'Strict-Transport-Security':
            try:
                max_age = int(header_value.lower().split('max-age=')[1].split(';')[0].strip())
            except (IndexError, ValueError):
                max_age = 0
            if max_age < 15552000:
                vulns.append(self._vuln(
                    'Short HSTS max-age', f'HSTS max-age is {max_age}s; at least 6 months is recommended',
                    Severity.LOW, Category.TRANSPORT, f'Strict-Transport-Security: {header_value}',
                    'Use max-age=31536000; includeSubDomains', 'CWE-319', {'header': header_name}
                ))
        return vulns

    @staticmethod
    def _parse_set_cookie(raw: str) -> Dict[str, Any]:
        parts = [p.strip() for p in raw.split(';')]
        name = parts[0].split('=', 1)[0] if parts else 'unknown'
        attrs = {p.split('=', 1)[0].lower(): (p.split('=', 1)[1] if '=' in p else True) for p in parts[1:] if p}
        return {
            'name': name,
            'secure': 'secure' in attrs,
            'httponly': 'httponly' in attrs,
            'samesite': str(attrs.get('samesite', '')) or None,
        }

    def _check_cookies(self, cookies: List[Dict[str, Any]], url: str) -> List[Vulnerability]:
        """Analyze cookie security flags."""
        vulns = []
        is_https = urlparse(url).scheme == 'https'
        for cookie in cookies:
            name = cookie.get('name', 'unknown')
            secure = cookie.get('secure', False)
            httponly = cookie.get('httponly', False)
            samesite = (cookie.get('samesite') or '').lower()
            sensitive = any(s in name.lower() for s in ('sess', 'token', 'auth', 'jwt', 'sid', 'remember', 'csrf'))

            if not secure:
                vulns.append(self._vuln(
                    f'Cookie Missing Secure Flag: {name}',
                    f'Cookie {name} can be sent over unencrypted HTTP' + ('' if is_https else
                    ' (expected on plain-http localhost, but make sure production sets Secure)'),
                    Severity.MEDIUM if sensitive else Severity.LOW, Category.CONFIGURATION,
                    f'Set-Cookie: {name}=...', 'Set the Secure attribute on cookies.', 'CWE-614',
                    {'cookie': name, 'missing': 'secure'}
                ))
            if not httponly and sensitive:
                vulns.append(self._vuln(
                    f'Sensitive Cookie Missing HttpOnly: {name}',
                    f'Cookie {name} is readable from JavaScript - any XSS can steal it',
                    Severity.HIGH, Category.CONFIGURATION, f'Set-Cookie: {name}=...',
                    'Set the HttpOnly attribute on session/auth cookies.', 'CWE-1004',
                    {'cookie': name, 'missing': 'httponly'}
                ))
            if samesite == 'none' and not secure:
                vulns.append(self._vuln(
                    f'Cookie SameSite=None without Secure: {name}',
                    f'Cookie {name} has SameSite=None but no Secure flag (browsers will reject it)',
                    Severity.MEDIUM, Category.CONFIGURATION, f'Set-Cookie: {name}=...; SameSite=None',
                    'Add Secure when using SameSite=None, or use SameSite=Lax/Strict.', 'CWE-1275',
                    {'cookie': name, 'samesite': samesite}
                ))
            elif not samesite and sensitive:
                vulns.append(self._vuln(
                    f'Cookie Without SameSite: {name}',
                    f'Cookie {name} has no SameSite attribute, increasing CSRF exposure',
                    Severity.LOW, Category.CONFIGURATION, f'Set-Cookie: {name}=...',
                    'Add SameSite=Lax (or Strict) to session cookies.', 'CWE-1275',
                    {'cookie': name, 'samesite': None}
                ))
        return vulns

    def _check_cors(self, session, url: str) -> List[Vulnerability]:
        result = self._fetch(session, url, headers={'Origin': self.EVIL_ORIGIN})
        if not result:
            return []
        acao = result.headers.get('access-control-allow-origin', '')
        acac = result.headers.get('access-control-allow-credentials', '').lower() == 'true'
        if acao == self.EVIL_ORIGIN or acao == 'null':
            return [self._vuln(
                'CORS Reflects Arbitrary Origin',
                'The server echoes any Origin in Access-Control-Allow-Origin'
                + (' and allows credentials - any website can make authenticated requests and read the responses'
                   if acac else ''),
                Severity.CRITICAL if acac else Severity.HIGH, Category.CONFIGURATION,
                f'Origin: {self.EVIL_ORIGIN}\nAccess-Control-Allow-Origin: {acao}'
                + ('\nAccess-Control-Allow-Credentials: true' if acac else ''),
                'Validate the Origin against an explicit allow-list before reflecting it.', 'CWE-942',
                {'url': url, 'credentials': acac}
            )]
        return []

    def _not_found_fingerprint(self, session, base_url: str) -> Tuple[int, int]:
        """Status/length of a guaranteed-missing page (detects SPA catch-all routes)."""
        probe = self._fetch(session, urljoin(base_url, f'/securemysite-{uuid.uuid4().hex}'))
        return (probe.status, len(probe.body)) if probe else (404, 0)

    def _check_endpoints(self, session, base_url: str) -> List[Vulnerability]:
        vulns = []
        nf_status, nf_len = self._not_found_fingerprint(session, base_url)
        for path, (signature, severity) in self.DANGEROUS_ENDPOINTS.items():
            result = self._fetch(session, urljoin(base_url, path))
            if not result or result.status != 200 or not result.body.strip():
                continue
            # SPA catch-all returning index.html for every path
            if nf_status == 200 and abs(len(result.body) - nf_len) < 32:
                continue
            if signature and signature.lower() not in result.body.lower():
                continue
            vulns.append(self._endpoint_vuln(path, severity, base_url))
        return vulns

    def _endpoint_vuln(self, path: str, severity: Severity, base_url: str) -> Vulnerability:
        return self._vuln(
            f'Exposed Sensitive Endpoint: {path}',
            f'{path} is publicly accessible and may leak source, configuration or credentials',
            severity, Category.EXPOSURE, f'GET {path} -> 200 OK',
            f'Block access to {path} in the web server / framework and make sure it is not deployed.',
            'CWE-538', {'endpoint': path, 'url': base_url}
        )

    def _check_debug_and_listing(self, session, main: HttpResult) -> List[Vulnerability]:
        vulns = []
        pages = [main]
        error_page = self._fetch(session, urljoin(main.url, f'/securemysite-debug-{uuid.uuid4().hex[:8]}'))
        if error_page:
            pages.append(error_page)

        reported = set()
        for page in pages:
            for signature, framework in self.DEBUG_SIGNATURES.items():
                if signature in page.body and framework not in reported:
                    reported.add(framework)
                    vulns.append(self._vuln(
                        f'Debug Error Page Exposed ({framework})',
                        f'{framework} debug output is shown to visitors, leaking source code and settings'
                        + (' - the Werkzeug console allows remote code execution' if 'Werkzeug' in framework else ''),
                        Severity.CRITICAL, Category.CONFIGURATION, f'GET {page.url} -> {page.status}',
                        'Disable debug mode and show generic error pages in production.', 'CWE-489',
                        {'url': page.url, 'framework': framework}
                    ))
            if ('<title>Index of /' in page.body or '<h1>Directory listing for' in page.body) and 'listing' not in reported:
                reported.add('listing')
                vulns.append(self._vuln(
                    'Directory Listing Enabled', 'The server lists directory contents, revealing files',
                    Severity.MEDIUM, Category.EXPOSURE, f'GET {page.url}',
                    'Disable directory indexes (autoindex off / Options -Indexes).', 'CWE-548', {'url': page.url}
                ))
        return vulns

    def _check_methods(self, session, url: str) -> List[Vulnerability]:
        result = self._fetch(session, url, method='TRACE')
        if result and result.status == 200 and 'TRACE' in result.body.upper():
            return [self._vuln(
                'HTTP TRACE Enabled', 'TRACE echoes requests back and can expose headers (Cross-Site Tracing)',
                Severity.LOW, Category.CONFIGURATION, f'TRACE {url} -> 200',
                'Disable the TRACE method in the web server.', 'CWE-693', {'url': url}
            )]
        return []

    # Backwards-compatible helpers used by older code paths
    def _analyze_security_headers(self, context: ScanContext) -> List[Vulnerability]:
        headers = {k.lower(): v for k, v in (context.config or {}).get('headers', {}).items()}
        return self._check_headers(headers, (context.config or {}).get('url', 'http://localhost'))

    def _analyze_cookies(self, context: ScanContext) -> List[Vulnerability]:
        return self._check_cookies((context.config or {}).get('cookies', []),
                                   (context.config or {}).get('url', 'http://localhost'))
