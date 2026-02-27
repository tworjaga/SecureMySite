"""Web security scanner for localhost-only analysis."""

import re
from typing import List, Optional, Dict, Any
from pathlib import Path
from urllib.parse import urlparse

from models.vulnerability import Vulnerability, Severity, Category
from scanners.base_scanner import BaseScanner, ScanContext


class WebScanner(BaseScanner):
    """
    Web security scanner for localhost-only security header analysis.
    
    CRITICAL: Only accepts localhost, 127.0.0.1, or *.local domains.
    Rejects all other URLs with error.
    
    Checks:
    - Security headers (CSP, X-Frame-Options, etc.)
    - Cookie security flags
    - Exposed sensitive endpoints
    """
    
    # Security headers to check
    SECURITY_HEADERS = {
        'Content-Security-Policy': {
            'severity': Severity.HIGH,
            'title': 'Missing Content Security Policy',
            'description': 'CSP header not present - XSS and injection attacks possible',
            'remediation': "Implement strict CSP header: Content-Security-Policy: default-src 'self'",
            'cwe': 'CWE-693'
        },
        'X-Frame-Options': {
            'severity': Severity.HIGH,
            'title': 'Missing X-Frame-Options',
            'description': 'Clickjacking protection not enabled',
            'remediation': 'Add header: X-Frame-Options: DENY or SAMEORIGIN',
            'cwe': 'CWE-1021'
        },
        'X-Content-Type-Options': {
            'severity': Severity.MEDIUM,
            'title': 'Missing X-Content-Type-Options',
            'description': 'MIME type sniffing not disabled',
            'remediation': 'Add header: X-Content-Type-Options: nosniff',
            'cwe': 'CWE-693'
        },
        'X-XSS-Protection': {
            'severity': Severity.LOW,
            'title': 'Missing X-XSS-Protection',
            'description': 'Legacy XSS filter not enabled',
            'remediation': 'Add header: X-XSS-Protection: 1; mode=block (or use CSP)',
            'cwe': 'CWE-693'
        },
        'Strict-Transport-Security': {
            'severity': Severity.MEDIUM,
            'title': 'Missing HSTS Header',
            'description': 'HTTP Strict Transport Security not enabled',
            'remediation': 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains',
            'cwe': 'CWE-319'
        },
        'Referrer-Policy': {
            'severity': Severity.LOW,
            'title': 'Missing Referrer-Policy',
            'description': 'Referrer information may leak to third parties',
            'remediation': 'Add header: Referrer-Policy: strict-origin-when-cross-origin',
            'cwe': 'CWE-200'
        },
        'Permissions-Policy': {
            'severity': Severity.LOW,
            'title': 'Missing Permissions-Policy',
            'description': 'Browser features not restricted',
            'remediation': 'Add header: Permissions-Policy with appropriate restrictions',
            'cwe': None
        },
    }
    
    # Dangerous endpoints to check
    DANGEROUS_ENDPOINTS = [
        '/.env',
        '/.git/config',
        '/.git/HEAD',
        '/.gitignore',
        '/.htaccess',
        '/.htpasswd',
        '/config.php',
        '/config.json',
        '/wp-config.php',
        '/admin/',
        '/administrator/',
        '/phpmyadmin/',
        '/api/docs',
        '/swagger.json',
        '/openapi.json',
        '/.DS_Store',
        '/Dockerfile',
        '/docker-compose.yml',
        '/requirements.txt',
        '/package.json',
    ]
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self._last_error = None
    
    def get_name(self) -> str:
        return "web_scanner"
    
    def get_description(self) -> str:
        return "Localhost-only web security scanner (headers, cookies, endpoints)"
    
    def get_supported_languages(self) -> List[str]:
        return ['http']
    
    def _validate_url(self, url: str) -> bool:
        """
        Validate URL is localhost-only.
        
        Only allows:
        - localhost
        - 127.0.0.1
        - *.local domains
        """
        try:
            parsed = urlparse(url)
            
            # Check scheme
            if parsed.scheme not in ('http', 'https'):
                self._last_error = f"Invalid scheme: {parsed.scheme}. Only HTTP/HTTPS allowed."
                return False
            
            # Get hostname
            hostname = parsed.hostname
            
            if not hostname:
                self._last_error = "No hostname in URL"
                return False
            
            # Check allowed hosts
            allowed_patterns = [
                'localhost',
                '127.0.0.1',
                '::1',
            ]
            
            # Check exact matches
            if hostname in allowed_patterns:
                return True
            
            # Check .local domain
            if hostname.endswith('.local'):
                return True
            
            # Check 127.x.x.x
            if hostname.startswith('127.'):
                return True
            
            self._last_error = f"URL not allowed: {hostname}. Only localhost, 127.0.0.1, and *.local permitted."
            return False
            
        except Exception as e:
            self._last_error = f"URL parsing error: {e}"
            return False
    
    def scan(self, context: ScanContext) -> List[Vulnerability]:
        """
        Scan web application at localhost URL.
        
        Note: This is a simulated scanner for offline use.
        In production, this would make actual HTTP requests.
        """
        vulnerabilities = []
        
        # Get URL from context
        url = context.config.get('url') if context.config else None
        if not url:
            return vulnerabilities
        
        # Validate URL is localhost-only
        if not self._validate_url(url):
            # Return error as vulnerability
            vuln = Vulnerability(
                title='Invalid URL for Web Scan',
                description=self._last_error or 'URL validation failed',
                severity=Severity.CRITICAL,
                category=Category.CONFIGURATION,
                file_path=None,
                line_number=None,
                code_snippet=f'URL: {url}',
                remediation='Use localhost, 127.0.0.1, or *.local domain only.',
                cwe_id='CWE-918',
                scanner_source=self.get_name(),
                metadata={'url': url, 'error': 'non_localhost_url'}
            )
            return [vuln]
        
        # In offline mode, we analyze based on configuration
        # rather than making actual HTTP requests
        header_vulns = self._analyze_security_headers(context)
        vulnerabilities.extend(header_vulns)
        
        cookie_vulns = self._analyze_cookies(context)
        vulnerabilities.extend(cookie_vulns)
        
        endpoint_vulns = self._check_dangerous_endpoints(context, url)
        vulnerabilities.extend(endpoint_vulns)
        
        return vulnerabilities
    
    def _analyze_security_headers(self, context: ScanContext) -> List[Vulnerability]:
        """Analyze security headers from context or simulated response."""
        vulnerabilities = []
        
        # Get headers from context (simulated or actual)
        headers = context.config.get('headers', {}) if context.config else {}
        
        # Check for missing headers
        for header_name, header_info in self.SECURITY_HEADERS.items():
            if header_name not in headers:
                vuln = Vulnerability(
                    title=header_info['title'],
                    description=header_info['description'],
                    severity=header_info['severity'],
                    category=Category.CONFIGURATION,
                    file_path=None,
                    line_number=None,
                    code_snippet=f'Missing: {header_name}',
                    remediation=header_info['remediation'],
                    cwe_id=header_info.get('cwe'),
                    scanner_source=self.get_name(),
                    metadata={'missing_header': header_name}
                )
                vulnerabilities.append(vuln)
            else:
                # Header present - check values
                header_value = headers[header_name]
                value_vulns = self._check_header_value(
                    header_name, header_value, context
                )
                vulnerabilities.extend(value_vulns)
        
        # Check for dangerous header values
        if 'X-Powered-By' in headers:
            vuln = Vulnerability(
                title='Information Disclosure: X-Powered-By',
                description=f'Server technology exposed: {headers["X-Powered-By"]}',
                severity=Severity.LOW,
                category=Category.EXPOSURE,
                file_path=None,
                line_number=None,
                code_snippet=f'X-Powered-By: {headers["X-Powered-By"]}',
                remediation='Remove X-Powered-By header to hide server technology.',
                cwe_id='CWE-200',
                scanner_source=self.get_name(),
                metadata={'header': 'X-Powered-By'}
            )
            vulnerabilities.append(vuln)
        
        if 'Server' in headers:
            server = headers['Server']
            if any(x in server.lower() for x in ['apache', 'nginx', 'iis', 'express']):
                vuln = Vulnerability(
                    title='Information Disclosure: Server Header',
                    description=f'Server software version exposed: {server}',
                    severity=Severity.LOW,
                    category=Category.EXPOSURE,
                    file_path=None,
                    line_number=None,
                    code_snippet=f'Server: {server}',
                    remediation='Remove or genericize Server header.',
                    cwe_id='CWE-200',
                    scanner_source=self.get_name(),
                    metadata={'header': 'Server'}
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_header_value(
        self,
        header_name: str,
        header_value: str,
        context: ScanContext
    ) -> List[Vulnerability]:
        """Check specific header values for security issues."""
        vulnerabilities = []
        
        # Check X-Frame-Options for unsafe values
        if header_name == 'X-Frame-Options':
            if header_value.upper() == 'ALLOWALL':
                vuln = Vulnerability(
                    title='Insecure X-Frame-Options Value',
                    description='X-Frame-Options set to ALLOWALL allows any site to frame this page',
                    severity=Severity.HIGH,
                    category=Category.CONFIGURATION,
                    file_path=None,
                    line_number=None,
                    code_snippet=f'X-Frame-Options: {header_value}',
                    remediation='Use DENY or SAMEORIGIN instead of ALLOWALL.',
                    cwe_id='CWE-1021',
                    scanner_source=self.get_name(),
                    metadata={'header': header_name, 'value': header_value}
                )
                vulnerabilities.append(vuln)
        
        # Check CSP for unsafe directives
        if header_name == 'Content-Security-Policy':
            if 'unsafe-inline' in header_value:
                vuln = Vulnerability(
                    title='CSP Allows Unsafe Inline Scripts',
                    description='CSP contains unsafe-inline which allows inline scripts',
                    severity=Severity.MEDIUM,
                    category=Category.CONFIGURATION,
                    file_path=None,
                    line_number=None,
                    code_snippet=f'CSP: {header_value[:100]}',
                    remediation='Remove unsafe-inline. Use nonces or hashes for inline scripts.',
                    cwe_id='CWE-693',
                    scanner_source=self.get_name(),
                    metadata={'header': header_name, 'unsafe': 'inline'}
                )
                vulnerabilities.append(vuln)
            
            if 'unsafe-eval' in header_value:
                vuln = Vulnerability(
                    title='CSP Allows Unsafe Eval',
                    description='CSP contains unsafe-eval which allows eval() and similar',
                    severity=Severity.MEDIUM,
                    category=Category.CONFIGURATION,
                    file_path=None,
                    line_number=None,
                    code_snippet=f'CSP: {header_value[:100]}',
                    remediation='Remove unsafe-eval. Avoid dynamic code execution.',
                    cwe_id='CWE-693',
                    scanner_source=self.get_name(),
                    metadata={'header': header_name, 'unsafe': 'eval'}
                )
                vulnerabilities.append(vuln)
        
        # Check CORS headers
        if header_name == 'Access-Control-Allow-Origin':
            if header_value == '*':
                vuln = Vulnerability(
                    title='Open CORS Policy',
                    description='Access-Control-Allow-Origin set to wildcard allows any origin',
                    severity=Severity.CRITICAL,
                    category=Category.CONFIGURATION,
                    file_path=None,
                    line_number=None,
                    code_snippet='Access-Control-Allow-Origin: *',
                    remediation='Specify exact allowed origins. Remove wildcard in production.',
                    cwe_id='CWE-942',
                    scanner_source=self.get_name(),
                    metadata={'header': header_name, 'value': header_value}
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _analyze_cookies(self, context: ScanContext) -> List[Vulnerability]:
        """Analyze cookie security settings."""
        vulnerabilities = []
        
        # Get cookies from context
        cookies = context.config.get('cookies', []) if context.config else []
        
        for cookie in cookies:
            cookie_name = cookie.get('name', 'unknown')
            cookie_value = cookie.get('value', '')
            secure = cookie.get('secure', False)
            httponly = cookie.get('httponly', False)
            samesite = cookie.get('samesite', 'None')
            
            # Check Secure flag
            if not secure:
                vuln = Vulnerability(
                    title=f'Cookie Missing Secure Flag: {cookie_name}',
                    description=f'Cookie {cookie_name} sent over HTTP - vulnerable to interception',
                    severity=Severity.MEDIUM,
                    category=Category.CONFIGURATION,
                    file_path=None,
                    line_number=None,
                    code_snippet=f'Set-Cookie: {cookie_name}=...',
                    remediation='Add Secure flag to all cookies. Set Secure=True.',
                    cwe_id='CWE-614',
                    scanner_source=self.get_name(),
                    metadata={'cookie': cookie_name, 'missing': 'secure'}
                )
                vulnerabilities.append(vuln)
            
            # Check HttpOnly flag
            if not httponly and any(s in cookie_name.lower() for s in ['session', 'token', 'auth', 'id']):
                vuln = Vulnerability(
                    title=f'Sensitive Cookie Missing HttpOnly: {cookie_name}',
                    description=f'Cookie {cookie_name} accessible to JavaScript - XSS risk',
                    severity=Severity.HIGH,
                    category=Category.CONFIGURATION,
                    file_path=None,
                    line_number=None,
                    code_snippet=f'Set-Cookie: {cookie_name}=...',
                    remediation='Add HttpOnly flag to sensitive cookies. Set HttpOnly=True.',
                    cwe_id='CWE-1004',
                    scanner_source=self.get_name(),
                    metadata={'cookie': cookie_name, 'missing': 'httponly'}
                )
                vulnerabilities.append(vuln)
            
            # Check SameSite
            if samesite.lower() == 'none' and not secure:
                vuln = Vulnerability(
                    title=f'Cookie SameSite=None without Secure: {cookie_name}',
                    description=f'Cookie {cookie_name} has SameSite=None but missing Secure flag',
                    severity=Severity.MEDIUM,
                    category=Category.CONFIGURATION,
                    file_path=None,
                    line_number=None,
                    code_snippet=f'Set-Cookie: {cookie_name}=...; SameSite=None',
                    remediation='Add Secure flag when using SameSite=None, or use SameSite=Strict/Lax.',
                    cwe_id='CWE-1275',
                    scanner_source=self.get_name(),
                    metadata={'cookie': cookie_name, 'samesite': samesite}
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_dangerous_endpoints(self, context: ScanContext, base_url: str) -> List[Vulnerability]:
        """Check for exposed dangerous endpoints."""
        vulnerabilities = []
        
        # Get exposed endpoints from context (simulated or actual)
        exposed = context.config.get('exposed_endpoints', []) if context.config else []
        
        for endpoint in exposed:
            if endpoint in self.DANGEROUS_ENDPOINTS:
                vuln = Vulnerability(
                    title=f'Exposed Sensitive Endpoint: {endpoint}',
                    description=f'Sensitive endpoint {endpoint} is accessible and may leak information',
                    severity=Severity.CRITICAL if endpoint.startswith('/.') else Severity.HIGH,
                    category=Category.EXPOSURE,
                    file_path=None,
                    line_number=None,
                    code_snippet=f'GET {endpoint} -> 200 OK',
                    remediation=f'Block access to {endpoint} or remove if not needed.',
                    cwe_id='CWE-548',
                    scanner_source=self.get_name(),
                    metadata={'endpoint': endpoint, 'url': base_url}
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def get_last_error(self) -> Optional[str]:
        """Get last error message."""
        return self._last_error
