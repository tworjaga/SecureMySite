"""Derived security insights for dashboards and reports (OWASP mapping, hotspots, tables)."""

from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from models.scan_result import ScanResult
from models.vulnerability import Category, Severity, Vulnerability


OWASP_TOP10 = {
    'A01': 'Broken Access Control',
    'A02': 'Cryptographic Failures',
    'A03': 'Injection',
    'A04': 'Insecure Design',
    'A05': 'Security Misconfiguration',
    'A06': 'Vulnerable Components',
    'A07': 'Auth Failures',
    'A08': 'Integrity Failures',
    'A09': 'Logging Failures',
    'A10': 'SSRF',
}

# CWE -> OWASP Top 10 (2021) for the CWEs our scanners emit
CWE_TO_OWASP = {
    # A01 Broken Access Control
    'CWE-22': 'A01', 'CWE-200': 'A01', 'CWE-284': 'A01', 'CWE-352': 'A01', 'CWE-538': 'A01',
    'CWE-548': 'A01', 'CWE-601': 'A01', 'CWE-668': 'A01', 'CWE-732': 'A01', 'CWE-1022': 'A01',
    # A02 Cryptographic Failures
    'CWE-298': 'A02', 'CWE-319': 'A02', 'CWE-321': 'A02', 'CWE-327': 'A02', 'CWE-328': 'A02', 'CWE-338': 'A02',
    # A03 Injection
    'CWE-78': 'A03', 'CWE-79': 'A03', 'CWE-89': 'A03', 'CWE-94': 'A03', 'CWE-95': 'A03',
    'CWE-1336': 'A03',
    # A04 Insecure Design
    'CWE-598': 'A04',
    # A05 Security Misconfiguration
    'CWE-16': 'A05', 'CWE-250': 'A05', 'CWE-346': 'A05', 'CWE-489': 'A05', 'CWE-614': 'A05',
    'CWE-617': 'A05', 'CWE-644': 'A05', 'CWE-693': 'A05', 'CWE-942': 'A05', 'CWE-1004': 'A05',
    'CWE-1021': 'A05', 'CWE-1275': 'A05', 'CWE-1327': 'A05',
    # A06 Vulnerable and Outdated Components
    'CWE-1035': 'A06', 'CWE-1104': 'A06', 'CWE-1357': 'A06', 'CWE-1395': 'A06',
    # A07 Identification and Authentication Failures
    'CWE-290': 'A07', 'CWE-295': 'A07', 'CWE-347': 'A07', 'CWE-522': 'A07', 'CWE-798': 'A07',
    # A08 Software and Data Integrity Failures
    'CWE-345': 'A08', 'CWE-353': 'A08', 'CWE-494': 'A08', 'CWE-502': 'A08', 'CWE-829': 'A08',
    'CWE-830': 'A08', 'CWE-1321': 'A08',
    # A09 Logging and Monitoring Failures
    'CWE-117': 'A09', 'CWE-532': 'A09',
    # A10 SSRF
    'CWE-918': 'A10',
}

CATEGORY_TO_OWASP = {
    Category.INJECTION: 'A03',
    Category.AUTHENTICATION: 'A07',
    Category.EXPOSURE: 'A01',
    Category.CONFIGURATION: 'A05',
    Category.DEPENDENCY: 'A06',
    Category.TRANSPORT: 'A02',
    Category.CRYPTOGRAPHY: 'A02',
}

SEVERITY_WEIGHT = {Severity.CRITICAL: 10, Severity.HIGH: 5, Severity.MEDIUM: 2, Severity.LOW: 1}


def owasp_id(vuln: Vulnerability) -> str:
    """OWASP Top 10 (2021) category id for a finding."""
    if vuln.cwe_id and vuln.cwe_id in CWE_TO_OWASP:
        return CWE_TO_OWASP[vuln.cwe_id]
    return CATEGORY_TO_OWASP.get(vuln.category, 'A05')


def owasp_label(vuln: Vulnerability) -> str:
    code = owasp_id(vuln)
    return f"{code}:2021 {OWASP_TOP10[code]}"


def location(vuln: Vulnerability) -> str:
    rel = vuln.metadata.get('relative_path')
    if rel:
        return f"{rel}:{vuln.line_number}" if vuln.line_number else rel
    if vuln.file_path:
        return vuln.get_location_string()
    return vuln.metadata.get('url') or 'web application'


@dataclass
class DependencyRow:
    severity: Severity
    package: str
    version: str
    advisory: str
    fixed: str
    location: str
    vuln: Vulnerability


@dataclass
class SecretRow:
    severity: Severity
    kind: str
    location: str
    preview: str
    vuln: Vulnerability


@dataclass
class Insights:
    owasp: List[Tuple[str, int, Severity]]          # (label, count, worst severity)
    categories: List[Tuple[str, int, Severity]]
    hotspots: List[Tuple[str, int, Severity]]       # files ranked by weighted risk
    scanners: List[Tuple[str, int, Severity]]
    dependencies: List[DependencyRow]
    secrets: List[SecretRow]
    fix_first: List[Vulnerability]
    secret_count: int
    vulnerable_packages: int
    injection_count: int


def _worst(vulns: List[Vulnerability]) -> Severity:
    return min((v.severity for v in vulns), key=lambda s: s.value, default=Severity.LOW)


def _ranked(groups: Dict[str, List[Vulnerability]], limit: Optional[int] = None,
            by_weight: bool = False) -> List[Tuple[str, int, Severity]]:
    rows = [(name, len(items), _worst(items), sum(SEVERITY_WEIGHT[v.severity] for v in items))
            for name, items in groups.items()]
    rows.sort(key=lambda r: (-(r[3] if by_weight else r[1]), r[2].value, r[0]))
    return [(name, count, worst) for name, count, worst, _ in rows[:limit]]


def build_insights(result: ScanResult) -> Insights:
    vulns = result.vulnerabilities

    owasp_groups: Dict[str, List[Vulnerability]] = {}
    category_groups: Dict[str, List[Vulnerability]] = {}
    file_groups: Dict[str, List[Vulnerability]] = {}
    scanner_groups: Dict[str, List[Vulnerability]] = {}
    for v in vulns:
        code = owasp_id(v)
        owasp_groups.setdefault(f"{code} {OWASP_TOP10[code]}", []).append(v)
        category_groups.setdefault(v.category.name.title(), []).append(v)
        file_key = v.metadata.get('relative_path') or ('(web) ' + (v.metadata.get('url') or 'app'))
        file_groups.setdefault(file_key, []).append(v)
        scanner_groups.setdefault(v.scanner_source.replace('_', ' '), []).append(v)

    owasp = sorted(_ranked(owasp_groups), key=lambda r: r[0])

    dependencies = []
    for v in vulns:
        if v.category == Category.DEPENDENCY and v.metadata.get('package'):
            dependencies.append(DependencyRow(
                severity=v.severity,
                package=v.metadata.get('package', ''),
                version=str(v.metadata.get('version') or v.metadata.get('spec') or '?'),
                advisory=str(v.metadata.get('cve') or '').replace('osv:', 'OSV: ') or '-',
                fixed=str(v.metadata.get('fixed_version') or '-'),
                location=location(v),
                vuln=v,
            ))

    secrets = []
    for v in vulns:
        if v.cwe_id == 'CWE-798' or v.metadata.get('secret_type'):
            kind = v.metadata.get('secret_type') or v.title.split(':', 1)[-1].strip()
            secrets.append(SecretRow(v.severity, kind, location(v), str(v.metadata.get('match', '')), v))

    fix_first = sorted(vulns, key=lambda v: (v.severity.value, v.category != Category.INJECTION,
                                             v.metadata.get('relative_path') or ''))[:6]

    return Insights(
        owasp=owasp,
        categories=_ranked(category_groups),
        hotspots=_ranked(file_groups, limit=8, by_weight=True),
        scanners=_ranked(scanner_groups),
        dependencies=dependencies,
        secrets=secrets,
        fix_first=fix_first,
        secret_count=len(secrets),
        vulnerable_packages=len({d.package.lower() for d in dependencies}),
        injection_count=sum(1 for v in vulns if v.category == Category.INJECTION),
    )


def severity_counts(result: ScanResult) -> Dict[Severity, int]:
    counts = Counter(v.severity for v in result.vulnerabilities)
    return {s: counts.get(s, 0) for s in Severity}
