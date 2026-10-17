"""
Online domain security scan: DNS / DNSSEC, email authentication, WHOIS (RDAP),
TLS and the public website.

Unlike every other scanner this one talks to the internet:
- DNS lookups go to Cloudflare's DNS-over-HTTPS resolver (Google as fallback)
- registration data comes from rdap.org
- TLS and HTTP checks connect to the domain itself

By default only passive checks run (comparable to a browser visit). Probing for
exposed files (/.env, /.git, ...) is "active" and must be enabled explicitly by
someone who owns or is authorized to test the domain.
"""

import re
import socket
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from models.scan_result import ScanResult
from models.vulnerability import Category, Severity, Vulnerability
from scanners.web_scanner import WebScanner
from utils.validators import normalize_domain


DOH_ENDPOINTS = ('https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve')
RDAP_URL = 'https://rdap.org/domain/{}'
USER_AGENT = 'SecureMySite/2.0 (domain security check)'

# Second-level suffixes where the registrable domain has three labels
MULTI_PART_SUFFIXES = {
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp',
    'ne.jp', 'or.jp', 'com.br', 'com.mx', 'com.ar', 'com.tr', 'com.cn', 'com.hk', 'com.sg', 'co.in',
    'co.za', 'co.kr', 'com.ua', 'com.pl', 'co.il', 'com.tw', 'com.my', 'com.ph',
}

CDN_SIGNATURES = (
    ('cf-ray', None, 'Cloudflare'),
    ('server', 'cloudflare', 'Cloudflare'),
    ('x-amz-cf-id', None, 'Amazon CloudFront'),
    ('x-served-by', 'cache-', 'Fastly'),
    ('x-fastly-request-id', None, 'Fastly'),
    ('x-akamai-transformed', None, 'Akamai'),
    ('server', 'akamaighost', 'Akamai'),
    ('x-vercel-id', None, 'Vercel'),
    ('x-nf-request-id', None, 'Netlify'),
    ('x-github-request-id', None, 'GitHub'),
    ('x-azure-ref', None, 'Azure Front Door'),
    ('x-sucuri-id', None, 'Sucuri WAF'),
    ('x-iinfo', None, 'Imperva Incapsula'),
    ('server', 'gws', 'Google'),
)

DnsQuery = Callable[[str, str], Dict[str, Any]]


def registrable_domain(host: str) -> str:
    """Best-effort registrable domain (no public suffix list needed for common cases)."""
    labels = host.split('.')
    if len(labels) >= 3 and '.'.join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return '.'.join(labels[-3:])
    return '.'.join(labels[-2:])


def txt_value(data: str) -> str:
    """Join the quoted chunks of a TXT record ("v=spf1 ..." "more")."""
    chunks = re.findall(r'"((?:[^"\\]|\\.)*)"', data)
    return ''.join(chunks) if chunks else data.strip('"')


class DomainScanner:
    """Runs the online checks for one domain and returns a ScanResult."""

    def __init__(
        self,
        active: bool = False,
        timeout: float = 8.0,
        dns_query: Optional[DnsQuery] = None,
        http_get: Optional[Callable[..., Any]] = None,
        tls_probe: Optional[Callable[[str], Dict[str, Any]]] = None,
        rdap_lookup: Optional[Callable[[str], Optional[Dict[str, Any]]]] = None,
    ):
        """
        Args:
            active: also probe for exposed files / debug pages (authorized targets only)
            timeout: per-request timeout in seconds
            dns_query, http_get, tls_probe, rdap_lookup: injectable network functions (tests)
        """
        self.active = active
        self.timeout = timeout
        self._session = None
        self.dns_query = dns_query or self._doh_query
        self.http_get = http_get or self._http_get
        self.tls_probe = tls_probe or self._tls_probe
        self.rdap_lookup = rdap_lookup or self._rdap_lookup
        self._cancelled = False

    def get_name(self) -> str:
        return "domain_scanner"

    def cancel(self) -> None:
        self._cancelled = True

    # ================================================================== network

    @property
    def session(self):
        if self._session is None:
            import requests
            self._session = requests.Session()
            self._session.headers['User-Agent'] = USER_AGENT
        return self._session

    def _doh_query(self, name: str, rtype: str) -> Dict[str, Any]:
        last_error: Optional[Exception] = None
        for endpoint in DOH_ENDPOINTS:
            try:
                resp = self.session.get(
                    endpoint, params={'name': name, 'type': rtype, 'do': '1'},
                    headers={'accept': 'application/dns-json'}, timeout=self.timeout,
                )
                resp.raise_for_status()
                return resp.json()
            except Exception as e:  # try the next resolver
                last_error = e
        raise ConnectionError(f"DNS-over-HTTPS lookup failed for {name} {rtype}: {last_error}")

    def _http_get(self, url: str, allow_redirects: bool = True, headers: Optional[Dict[str, str]] = None):
        return self.session.get(url, allow_redirects=allow_redirects, headers=headers,
                                timeout=self.timeout, stream=False)

    def _rdap_lookup(self, domain: str) -> Optional[Dict[str, Any]]:
        resp = self.session.get(RDAP_URL.format(domain), timeout=self.timeout,
                                headers={'accept': 'application/rdap+json'})
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()

    def _tls_probe(self, host: str) -> Dict[str, Any]:
        """Handshake with full verification, then test legacy protocol support."""
        info: Dict[str, Any] = {'reachable': False}
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, 443), timeout=self.timeout) as sock:
                info['reachable'] = True
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    info.update({
                        'verified': True,
                        'version': tls.version(),
                        'cipher': tls.cipher()[0] if tls.cipher() else None,
                        'not_after': cert.get('notAfter'),
                        'not_before': cert.get('notBefore'),
                        'issuer': _rdn(cert.get('issuer', ())),
                        'subject': _rdn(cert.get('subject', ())),
                        'san_count': len(cert.get('subjectAltName', ())),
                    })
        except ssl.SSLCertVerificationError as e:
            info.update({'verified': False, 'verify_error': e.verify_message or str(e)})
        except (ssl.SSLError, OSError) as e:
            info.setdefault('verified', False)
            info['error'] = str(e)

        legacy = []
        if info.get('reachable'):
            for name, version in (('TLSv1', ssl.TLSVersion.TLSv1), ('TLSv1.1', ssl.TLSVersion.TLSv1_1)):
                try:
                    lctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    lctx.check_hostname = False
                    lctx.verify_mode = ssl.CERT_NONE
                    lctx.minimum_version = version
                    lctx.maximum_version = version
                    lctx.set_ciphers('ALL:@SECLEVEL=0')
                    with socket.create_connection((host, 443), timeout=self.timeout) as sock:
                        with lctx.wrap_socket(sock, server_hostname=host):
                            legacy.append(name)
                except (ssl.SSLError, OSError, ValueError):
                    pass  # rejected by the server or unsupported by local OpenSSL
        info['legacy_protocols'] = legacy
        return info

    # ================================================================== scan

    def scan(self, target: str, progress: Optional[Callable[[str, int, int], None]] = None) -> ScanResult:
        host, error = normalize_domain(target)
        if not host:
            raise ValueError(error)

        domain = registrable_domain(host)
        self.host, self.domain = host, domain
        self.findings: List[Vulnerability] = []
        self.profile: Dict[str, Any] = {'host': host, 'domain': domain}
        result = ScanResult(project_path=Path(host))
        self.result = result

        steps = [
            ("Resolving DNS records", self._check_dns),
            ("Checking DNSSEC", self._check_dnssec),
            ("Checking email authentication (SPF / DMARC)", self._check_email),
            ("Looking up registration (RDAP / WHOIS)", self._check_registration),
            ("Inspecting TLS certificate", self._check_tls),
            ("Checking the website", self._check_http),
        ]
        if self.active:
            steps.append(("Probing for exposed files (active)", self._check_exposure))

        for index, (label, step) in enumerate(steps, 1):
            if self._cancelled:
                result.add_error("Scan cancelled by user")
                break
            if progress:
                progress(label, index, len(steps))
            try:
                step()
            except Exception as e:
                result.add_error(f"{label}: {e}")

        result.vulnerabilities = self.findings
        result.scanners_used = [self.get_name()]
        result.metadata.update({
            'scan_type': 'domain',
            'target': host,
            'domain_profile': self.profile,
            'active_checks': self.active,
            'cancelled': self._cancelled,
        })
        finalize_result(result)
        return result

    # ================================================================== helpers

    def _add(self, title: str, description: str, severity: Severity, category: Category,
             remediation: str, cwe: Optional[str], check: str, evidence: str = '',
             where: Optional[str] = None) -> None:
        self.findings.append(Vulnerability(
            title=title,
            description=description,
            severity=severity,
            category=category,
            remediation=remediation,
            scanner_source=self.get_name(),
            cwe_id=cwe,
            code_snippet=evidence or None,
            metadata={'url': where or f"{self.host} ({check})", 'check': check, 'rule': check},
        ))

    def _records(self, name: str, rtype: str) -> Tuple[List[str], Dict[str, Any]]:
        response = self.dns_query(name, rtype)
        type_codes = {'A': 1, 'NS': 2, 'CNAME': 5, 'MX': 15, 'TXT': 16, 'AAAA': 28, 'DS': 43,
                      'DNSKEY': 48, 'CAA': 257, 'SOA': 6}
        wanted = type_codes.get(rtype)
        data = [a.get('data', '') for a in response.get('Answer', []) or []
                if wanted is None or a.get('type') == wanted]
        return data, response

    # ================================================================== DNS

    def _check_dns(self):
        a, response = self._records(self.host, 'A')
        if response.get('Status') == 3:
            raise ValueError(f"{self.host} does not exist (NXDOMAIN)")
        aaaa, _ = self._records(self.host, 'AAAA')
        ns, _ = self._records(self.domain, 'NS')
        mx, _ = self._records(self.domain, 'MX')
        caa, _ = self._records(self.domain, 'CAA')
        self.profile.update({
            'ipv4': a, 'ipv6': aaaa,
            'nameservers': sorted(n.rstrip('.') for n in ns),
            'mx': sorted(_mx_host(m) for m in mx),
            'caa': caa,
        })

        if not a and not aaaa:
            self._add('Domain Has No Address Records',
                      f'{self.host} has no A or AAAA record, so the website is unreachable.',
                      Severity.LOW, Category.CONFIGURATION,
                      'Add A/AAAA (or CNAME) records pointing to your hosting provider.', None, 'dns')
        if ns and len(ns) < 2:
            self._add('Single Nameserver',
                      'Only one authoritative nameserver is configured - a single outage takes the domain offline.',
                      Severity.LOW, Category.CONFIGURATION,
                      'Configure at least two nameservers on different networks.', None, 'dns',
                      evidence='\n'.join(ns))
        if not caa:
            self._add('No CAA Record',
                      'Without a CAA record any certificate authority may issue certificates for this domain.',
                      Severity.LOW, Category.CONFIGURATION,
                      f'Add a CAA record naming your CA, e.g. {self.domain}. CAA 0 issue "letsencrypt.org"',
                      'CWE-16', 'dns')

    def _check_dnssec(self):
        ds, _ = self._records(self.domain, 'DS')
        _, response = self._records(self.domain, 'SOA')
        validated = bool(response.get('AD'))
        self.profile['dnssec'] = 'validated' if validated else ('broken' if ds else 'not enabled')
        if ds and not validated:
            self._add('DNSSEC Validation Failing',
                      'A DS record exists at the registry but responses do not validate. Validating resolvers '
                      'may refuse to resolve the domain.',
                      Severity.HIGH, Category.CONFIGURATION,
                      'Re-sign the zone or update the DS record at the registrar so the chain of trust matches.',
                      'CWE-345', 'dnssec', evidence='\n'.join(ds))
        elif not ds:
            self._add('DNSSEC Not Enabled',
                      'DNS answers for this domain are not signed, so they can be spoofed or hijacked in transit '
                      '(cache poisoning).',
                      Severity.LOW, Category.CONFIGURATION,
                      'Enable DNSSEC at your DNS provider (one click on Cloudflare) and add the DS record at the registrar.',
                      'CWE-345', 'dnssec')

    # ================================================================== email

    def _check_email(self):
        txt, _ = self._records(self.domain, 'TXT')
        spf = [txt_value(t) for t in txt if txt_value(t).lower().startswith('v=spf1')]
        dmarc_txt, _ = self._records(f'_dmarc.{self.domain}', 'TXT')
        dmarc = [txt_value(t) for t in dmarc_txt if txt_value(t).lower().startswith('v=dmarc1')]
        self.profile['spf'] = spf[0] if spf else None
        self.profile['dmarc'] = dmarc[0] if dmarc else None
        sends_mail = bool(self.profile.get('mx'))
        where = f"{self.domain} (email)"

        if not spf:
            self._add('No SPF Record',
                      'Anyone can send email that claims to come from this domain (phishing / spoofing).',
                      Severity.MEDIUM, Category.AUTHENTICATION,
                      'Publish an SPF record listing your mail senders, e.g. "v=spf1 include:_spf.google.com -all". '
                      'For domains that never send mail use "v=spf1 -all".',
                      'CWE-290', 'email', where=where)
        elif len(spf) > 1:
            self._add('Multiple SPF Records',
                      'More than one SPF record makes SPF evaluation fail (permerror).',
                      Severity.MEDIUM, Category.AUTHENTICATION,
                      'Merge them into a single v=spf1 record.', 'CWE-290', 'email',
                      evidence='\n'.join(spf), where=where)
        else:
            record = spf[0].lower()
            if re.search(r'(^|\s)\+?all\b', record) and '-all' not in record and '~all' not in record \
                    and '?all' not in record:
                self._add('SPF Allows Any Sender (+all)',
                          'The SPF record authorizes every server on the internet to send mail for this domain.',
                          Severity.HIGH, Category.AUTHENTICATION,
                          'End the SPF record with -all (or ~all while testing).', 'CWE-290', 'email',
                          evidence=spf[0], where=where)
            elif '?all' in record or 'all' not in record:
                self._add('SPF Policy Is Neutral',
                          'The SPF record does not tell receivers to reject unauthorized senders.',
                          Severity.LOW, Category.AUTHENTICATION,
                          'End the SPF record with -all (or ~all).', 'CWE-290', 'email',
                          evidence=spf[0], where=where)

        if not dmarc:
            self._add('No DMARC Policy',
                      'Without DMARC, receivers have no instruction to reject spoofed mail from this domain and you '
                      'get no reports about abuse.',
                      Severity.MEDIUM, Category.AUTHENTICATION,
                      f'Add a TXT record at _dmarc.{self.domain}: "v=DMARC1; p=quarantine; rua=mailto:dmarc@{self.domain}" '
                      'and move to p=reject once reports look clean.',
                      'CWE-290', 'email', where=where)
        else:
            policy = re.search(r'\bp\s*=\s*(\w+)', dmarc[0], re.IGNORECASE)
            if policy and policy.group(1).lower() == 'none':
                self._add('DMARC Policy Is "none"',
                          'DMARC is in monitoring mode only; spoofed mail is still delivered.',
                          Severity.LOW, Category.AUTHENTICATION,
                          'Move to p=quarantine and then p=reject after reviewing aggregate reports.',
                          'CWE-290', 'email', evidence=dmarc[0], where=where)

        if not sends_mail and spf and '-all' not in spf[0].lower():
            self.profile['mail_note'] = 'No MX records - domain does not receive mail'

    # ================================================================== registration

    def _check_registration(self):
        data = self.rdap_lookup(self.domain)
        if not data:
            self.profile['registration'] = 'not available'
            return
        events = {e.get('eventAction'): e.get('eventDate') for e in data.get('events', [])}
        status = [s.lower() for s in data.get('status', [])]
        registrar = None
        for entity in data.get('entities', []):
            if 'registrar' in entity.get('roles', []):
                for item in (entity.get('vcardArray') or [None, []])[1]:
                    if item and item[0] == 'fn':
                        registrar = item[3]
        self.profile.update({
            'registrar': registrar,
            'registered': events.get('registration'),
            'expires': events.get('expiration'),
            'domain_status': status,
        })

        expires = _parse_date(events.get('expiration'))
        if expires:
            days = (expires - datetime.now(timezone.utc)).days
            self.profile['expires_in_days'] = days
            where = f"{self.domain} (registration)"
            if days < 0:
                self._add('Domain Registration Expired',
                          f'The registration expired {-days} days ago - the domain can be lost or hijacked.',
                          Severity.CRITICAL, Category.CONFIGURATION,
                          'Renew the domain immediately and enable auto-renew.', None, 'whois', where=where)
            elif days <= 30:
                self._add('Domain Expires Soon',
                          f'The registration expires in {days} days. Expired domains are re-registered by attackers.',
                          Severity.HIGH, Category.CONFIGURATION,
                          'Renew now and enable auto-renew at the registrar.', None, 'whois', where=where)
            elif days <= 60:
                self._add('Domain Expires Within 60 Days',
                          f'The registration expires in {days} days.',
                          Severity.MEDIUM, Category.CONFIGURATION,
                          'Renew and enable auto-renew at the registrar.', None, 'whois', where=where)

        if status and not any('transfer prohibited' in s or 'transferprohibited' in s for s in status):
            self._add('Registrar Transfer Lock Disabled',
                      'The domain is not transfer-locked, making unauthorized registrar transfers (domain theft) easier.',
                      Severity.LOW, Category.AUTHENTICATION,
                      'Enable the transfer lock (clientTransferProhibited) at your registrar and use 2FA on the account.',
                      'CWE-284', 'whois', evidence=', '.join(status), where=f"{self.domain} (registration)")

    # ================================================================== TLS

    def _check_tls(self):
        info = self.tls_probe(self.host)
        self.profile['tls'] = info
        where = f"https://{self.host}/ (TLS)"
        if not info.get('reachable'):
            self._add('HTTPS Not Available',
                      f'Nothing answers on port 443 of {self.host}, so the site cannot be served over HTTPS.',
                      Severity.HIGH, Category.TRANSPORT,
                      'Serve the site over HTTPS (Let\'s Encrypt / your CDN can issue free certificates).',
                      'CWE-319', 'tls', where=where)
            return
        if not info.get('verified'):
            reason = info.get('verify_error') or info.get('error') or 'certificate could not be verified'
            expired = 'expired' in reason.lower()
            self._add('TLS Certificate Expired' if expired else 'Invalid TLS Certificate',
                      f'Browsers will show a security warning: {reason}.',
                      Severity.CRITICAL if expired else Severity.HIGH, Category.TRANSPORT,
                      'Install a valid certificate for this hostname from a trusted CA and automate renewal.',
                      'CWE-298' if expired else 'CWE-295', 'tls', evidence=reason, where=where)
        else:
            not_after = info.get('not_after')
            if not_after:
                days = int((ssl.cert_time_to_seconds(not_after) - time.time()) // 86400)
                info['expires_in_days'] = days
                if days <= 14:
                    self._add('TLS Certificate Expires Very Soon',
                              f'The certificate expires in {days} days.',
                              Severity.HIGH, Category.TRANSPORT,
                              'Renew the certificate now and automate renewal (certbot / ACME).',
                              'CWE-298', 'tls', evidence=f'notAfter: {not_after}', where=where)
                elif days <= 30:
                    self._add('TLS Certificate Expires Soon',
                              f'The certificate expires in {days} days.',
                              Severity.MEDIUM, Category.TRANSPORT,
                              'Check that automatic renewal is working.', 'CWE-298', 'tls',
                              evidence=f'notAfter: {not_after}', where=where)
        for proto in info.get('legacy_protocols', []):
            self._add(f'Legacy Protocol Accepted: {proto}',
                      f'The server still accepts {proto}, which is deprecated (RFC 8996) and has known weaknesses.',
                      Severity.MEDIUM, Category.TRANSPORT,
                      'Disable TLS 1.0 and 1.1; allow only TLS 1.2 and 1.3.', 'CWE-327', 'tls', where=where)

    # ================================================================== website

    def _web(self) -> WebScanner:
        web = WebScanner({'timeout': self.timeout})
        domain = self.domain

        def same_site(url: str) -> bool:
            """Follow redirects only within the scanned site, never to other domains."""
            from urllib.parse import urlparse
            host = (urlparse(url).hostname or '').lower()
            return host == domain or host.endswith('.' + domain)

        web._redirect_allowed = same_site
        return web

    def _check_http(self):
        base = f"https://{self.host}/"

        # Plain HTTP should redirect to HTTPS
        try:
            plain = self.http_get(f"http://{self.host}/", allow_redirects=False)
            location = plain.headers.get('location', '')
            self.profile['http_redirect'] = location or f'no redirect (HTTP {plain.status_code})'
            if plain.status_code < 300 or plain.status_code >= 400:
                self._add('HTTP Not Redirected to HTTPS',
                          f'http://{self.host}/ answers with {plain.status_code} instead of redirecting to HTTPS, '
                          'so first visits can be intercepted.',
                          Severity.MEDIUM, Category.TRANSPORT,
                          'Redirect all HTTP traffic to HTTPS with a 301/308 and enable HSTS.', 'CWE-319', 'http',
                          where=f"http://{self.host}/")
            elif not location.lower().startswith('https://'):
                self._add('HTTP Redirect Does Not Go to HTTPS',
                          f'http://{self.host}/ redirects to {location or "(no location)"} instead of an https:// URL.',
                          Severity.MEDIUM, Category.TRANSPORT,
                          'Redirect HTTP requests straight to the https:// version of the same URL.', 'CWE-319',
                          'http', where=f"http://{self.host}/")
        except Exception:
            self.profile['http_redirect'] = 'port 80 closed'

        tls = self.profile.get('tls') or {}
        if not tls.get('reachable'):
            return

        response = self.http_get(base, allow_redirects=True)
        headers = {k.lower(): v for k, v in response.headers.items()}
        final_url = getattr(response, 'url', base)
        self.profile.update({
            'final_url': final_url,
            'status': response.status_code,
            'server': headers.get('server'),
            'cdn': self._detect_cdn(headers),
        })

        web = self._web()
        for vuln in web._check_headers(headers, final_url):
            self._rehome(vuln, final_url)

        raw_cookies = []
        try:
            raw_cookies = list(response.raw.headers.getlist('Set-Cookie'))
        except AttributeError:
            if 'set-cookie' in headers:
                raw_cookies = [headers['set-cookie']]
        for vuln in web._check_cookies([web._parse_set_cookie(c) for c in raw_cookies], final_url):
            self._rehome(vuln, final_url)

        # CORS: does the site reflect an arbitrary Origin?
        try:
            cors = self.http_get(base, allow_redirects=True, headers={'Origin': WebScanner.EVIL_ORIGIN})
            acao = cors.headers.get('access-control-allow-origin', '')
            creds = cors.headers.get('access-control-allow-credentials', '').lower() == 'true'
            if acao in (WebScanner.EVIL_ORIGIN, 'null'):
                self._add('CORS Reflects Arbitrary Origin',
                          'The site echoes any Origin in Access-Control-Allow-Origin'
                          + (' and allows credentials - other websites can read authenticated responses' if creds else ''),
                          Severity.CRITICAL if creds else Severity.HIGH, Category.CONFIGURATION,
                          'Validate Origin against an explicit allow-list.', 'CWE-942', 'http',
                          evidence=f'Access-Control-Allow-Origin: {acao}', where=final_url)
        except Exception:
            pass

        # security.txt (RFC 9116)
        try:
            sec = self.http_get(f"https://{self.host}/.well-known/security.txt", allow_redirects=True)
            has = sec.status_code == 200 and 'contact:' in sec.text.lower()
        except Exception:
            has = False
        self.profile['security_txt'] = has
        if not has:
            self._add('No security.txt',
                      'There is no /.well-known/security.txt telling researchers how to report vulnerabilities.',
                      Severity.LOW, Category.CONFIGURATION,
                      'Publish /.well-known/security.txt with Contact: and Expires: fields (RFC 9116).',
                      None, 'http', where=f"https://{self.host}/.well-known/security.txt")

    def _rehome(self, vuln: Vulnerability, url: str) -> None:
        vuln.scanner_source = self.get_name()
        vuln.metadata.update({'url': url, 'check': 'http'})
        self.findings.append(vuln)

    @staticmethod
    def _detect_cdn(headers: Dict[str, str]) -> Optional[str]:
        for header, needle, name in CDN_SIGNATURES:
            value = headers.get(header)
            if value is not None and (needle is None or needle in value.lower()):
                return name
        return None

    # ================================================================== active

    def _check_exposure(self):
        web = self._web()
        session = self.session
        base = f"https://{self.host}/"
        main = web._fetch(session, base)
        if main is None:
            return
        for vuln in web._check_endpoints(session, main.url) + web._check_debug_and_listing(session, main):
            self._rehome(vuln, vuln.metadata.get('url') or base)


# ---------------------------------------------------------------------- helpers

def _mx_host(record: str) -> str:
    """'10 mail.example.com.' -> 'mail.example.com'; null MX '0 .' -> marker."""
    host = record.split()[-1].rstrip('.') if record.split() else ''
    return host or 'null MX (domain accepts no mail)'


def _rdn(rdns) -> str:
    parts = []
    for rdn in rdns:
        for key, value in rdn:
            if key in ('commonName', 'organizationName'):
                parts.append(value)
    return ', '.join(parts)


def _parse_date(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def finalize_result(result: ScanResult) -> None:
    """Sort findings, add fingerprints and the score (mirrors AnalysisEngine post-processing)."""
    import hashlib
    from core.config import APP_VERSION
    from scoring.score_engine import ScoreEngine

    for vuln in result.vulnerabilities:
        raw = f"{result.metadata.get('target', '')}|{vuln.title}|{vuln.metadata.get('check', '')}"
        vuln.metadata['fingerprint'] = hashlib.sha256(raw.encode()).hexdigest()[:20]
    result.vulnerabilities.sort(key=lambda v: (v.severity.value, v.metadata.get('check', ''), v.title))
    result.complete_scan()
    score = ScoreEngine().calculate(result.vulnerabilities)
    result.metadata.update({
        'score': {
            'score': score.score, 'risk_level': score.risk_level, 'grade': score.grade,
            'breakdown': score.breakdown, 'recommendations': score.recommendations,
        },
        'tool_version': APP_VERSION,
        'scanners_enabled': ['domain_scanner'],
        'files_skipped': 0,
    })
