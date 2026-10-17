"""Online domain scan - exercised offline with fake DNS / RDAP / TLS / HTTP responses."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from core import reporter
from scanners.domain_scanner import DomainScanner, registrable_domain, txt_value
from utils.validators import normalize_domain
from tests.conftest import titles


class FakeResponse:
    def __init__(self, status=200, headers=None, text="", url="https://shop.example.com/"):
        self.status_code = status
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.text = text
        self.url = url


def fake_dns(records, dnssec=False):
    codes = {'A': 1, 'NS': 2, 'MX': 15, 'TXT': 16, 'AAAA': 28, 'DS': 43, 'CAA': 257, 'SOA': 6}

    def query(name, rtype):
        answers = [{'name': name, 'type': codes[rtype], 'data': d} for d in records.get((name, rtype), [])]
        return {'Status': 0, 'AD': dnssec, 'Answer': answers}
    return query


def make_scanner(dns, http, tls=None, rdap=None):
    return DomainScanner(
        dns_query=dns,
        http_get=http,
        tls_probe=lambda host: tls or {'reachable': True, 'verified': True, 'version': 'TLSv1.3',
                                        'not_after': 'Jan  1 00:00:00 2099 GMT', 'legacy_protocols': []},
        rdap_lookup=lambda d: rdap,
    )


GOOD_HEADERS = {
    'Content-Security-Policy': "default-src 'self'",
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=()',
    'cf-ray': 'abc',
}


def good_http(url, allow_redirects=True, headers=None):
    if url.startswith('http://'):
        return FakeResponse(301, {'Location': 'https://shop.example.com/'})
    if url.endswith('security.txt'):
        return FakeResponse(200, text='Contact: mailto:sec@example.com')
    return FakeResponse(200, GOOD_HEADERS)


def test_well_configured_domain_is_clean():
    expires = (datetime.now(timezone.utc) + timedelta(days=400)).isoformat()
    dns = fake_dns({
        ('shop.example.com', 'A'): ['93.184.216.34'],
        ('example.com', 'NS'): ['a.ns.example.net.', 'b.ns.example.net.'],
        ('example.com', 'MX'): ['10 mail.example.com.'],
        ('example.com', 'CAA'): ['0 issue "letsencrypt.org"'],
        ('example.com', 'DS'): ['12345 13 2 ABCDEF'],
        ('example.com', 'TXT'): ['"v=spf1 include:_spf.example.net -all"'],
        ('_dmarc.example.com', 'TXT'): ['"v=DMARC1; p=reject"'],
    }, dnssec=True)
    rdap = {'events': [{'eventAction': 'expiration', 'eventDate': expires}],
            'status': ['client transfer prohibited'], 'entities': []}
    result = make_scanner(dns, good_http, rdap=rdap).scan('https://Shop.Example.com/login')

    assert result.vulnerabilities == []
    assert result.metadata['score']['score'] == 100
    profile = result.metadata['domain_profile']
    assert profile['host'] == 'shop.example.com' and profile['domain'] == 'example.com'
    assert profile['cdn'] == 'Cloudflare'
    assert profile['dnssec'] == 'validated'
    assert profile['mx'] == ['mail.example.com']


def test_misconfigured_domain_findings():
    soon = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
    dns = fake_dns({
        ('example.com', 'A'): ['93.184.216.34'],
        ('example.com', 'NS'): ['only.ns.example.net.'],
        ('example.com', 'DS'): ['12345 13 2 ABCDEF'],          # DS present but not validating
        ('example.com', 'TXT'): ['"v=spf1 +all"'],
        ('_dmarc.example.com', 'TXT'): ['"v=DMARC1; p=none"'],
    }, dnssec=False)

    def bad_http(url, allow_redirects=True, headers=None):
        if url.startswith('http://'):
            return FakeResponse(200)
        if url.endswith('security.txt'):
            return FakeResponse(404)
        if headers and 'Origin' in headers:
            return FakeResponse(200, {'Access-Control-Allow-Origin': headers['Origin'],
                                      'Access-Control-Allow-Credentials': 'true'})
        return FakeResponse(200, {'Server': 'Apache/2.4.1', 'X-Powered-By': 'PHP/7.2'})

    tls = {'reachable': True, 'verified': True, 'version': 'TLSv1.2',
           'not_after': 'Jan  1 00:00:00 2099 GMT', 'legacy_protocols': ['TLSv1']}
    rdap = {'events': [{'eventAction': 'expiration', 'eventDate': soon}], 'status': ['active'], 'entities': []}
    result = make_scanner(dns, bad_http, tls=tls, rdap=rdap).scan('example.com')
    found = set(titles(result.vulnerabilities))

    for expected in ('DNSSEC Validation Failing', 'Single Nameserver', 'No CAA Record',
                     'SPF Allows Any Sender (+all)', 'DMARC Policy Is "none"', 'Domain Expires Soon',
                     'Registrar Transfer Lock Disabled', 'Legacy Protocol Accepted: TLSv1',
                     'HTTP Not Redirected to HTTPS', 'Missing Content Security Policy',
                     'CORS Reflects Arbitrary Origin', 'No security.txt'):
        assert expected in found, expected
    cors = next(v for v in result.vulnerabilities if v.title == 'CORS Reflects Arbitrary Origin')
    assert cors.severity.name == 'CRITICAL'
    assert all(v.scanner_source == 'domain_scanner' for v in result.vulnerabilities)


def test_invalid_certificate_and_missing_email_auth():
    dns = fake_dns({('example.org', 'A'): ['1.2.3.4']})
    tls = {'reachable': True, 'verified': False, 'verify_error': 'certificate has expired', 'legacy_protocols': []}
    result = make_scanner(dns, good_http, tls=tls).scan('example.org')
    found = titles(result.vulnerabilities)
    assert 'TLS Certificate Expired' in found
    assert 'No SPF Record' in found and 'No DMARC Policy' in found
    assert 'DNSSEC Not Enabled' in found


def test_step_failures_are_reported_not_fatal():
    def broken_dns(name, rtype):
        raise ConnectionError("offline")
    result = make_scanner(broken_dns, good_http).scan('example.com')
    assert result.errors and any('DNS' in e for e in result.errors)
    assert result.metadata['score']['score'] is not None


def test_domain_reports_render():
    dns = fake_dns({('example.com', 'A'): ['1.2.3.4']})
    result = make_scanner(dns, good_http).scan('example.com')
    sarif = json.loads(reporter.to_sarif(result))
    assert 'originalUriBaseIds' not in sarif['runs'][0]
    assert 'for domain example.com' in reporter.to_html(result)
    assert '**Domain:** `example.com`' in reporter.to_markdown(result)


@pytest.mark.parametrize("raw, expected", [
    ("Example.COM", "example.com"),
    ("https://www.example.co.uk/path?x=1", "www.example.co.uk"),
    ("example.com.", "example.com"),
    ("bücher.de", "xn--bcher-kva.de"),
])
def test_normalize_domain_ok(raw, expected):
    assert normalize_domain(raw) == (expected, None)


@pytest.mark.parametrize("raw", ["", "localhost", "8.8.8.8", "intranet", "app.local", "-bad-.com", "a..com"])
def test_normalize_domain_rejects(raw):
    host, error = normalize_domain(raw)
    assert host is None and error


def test_helpers():
    assert registrable_domain("a.b.example.co.uk") == "example.co.uk"
    assert registrable_domain("www.example.com") == "example.com"
    assert txt_value('"v=spf1 include:a" " -all"') == "v=spf1 include:a -all"
