"""Dependency vulnerability scanner."""

import re
import json
import logging
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Dict, Any, Iterable, Tuple

from packaging.requirements import Requirement, InvalidRequirement
from packaging.specifiers import SpecifierSet, InvalidSpecifier
from packaging.version import Version, InvalidVersion

from models.vulnerability import Vulnerability, Severity, Category
from scanners.base_scanner import BaseScanner, ScanContext


ASSETS_DIR = Path(__file__).resolve().parent.parent / 'assets'
DEFAULT_DB_PATH = ASSETS_DIR / 'vuln_db.json'
LOCAL_DB_PATH = ASSETS_DIR / 'vuln_db.local.json'

OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch'

logger = logging.getLogger(__name__)


def normalize_name(name: str) -> str:
    """PEP 503 normalisation (also fine for npm names)."""
    return re.sub(r'[-_.]+', '-', name).lower()


@dataclass
class Dependency:
    """A dependency declared in a manifest or lockfile."""
    name: str
    version: Optional[str]          # exact version if pinned/resolved, else minimum allowed version
    spec: str                       # original specifier text
    ecosystem: str                  # 'PyPI' or 'npm'
    line: int = 1
    pinned: bool = False


class DependencyScanner(BaseScanner):
    """
    Scanner for dependency manifests and lockfiles.

    Checks declared/resolved versions against the bundled vulnerability
    database (assets/vuln_db.json, plus optional assets/vuln_db.local.json)
    and, when explicitly enabled, the OSV.dev online database.
    """

    DEPENDENCY_FILES = {
        'requirements.txt': 'pip',
        'pyproject.toml': 'pyproject',
        'pipfile': 'pipfile',
        'pipfile.lock': 'pipfile-lock',
        'poetry.lock': 'poetry-lock',
        'setup.py': 'setuptools',
        'package.json': 'npm',
        'package-lock.json': 'npm-lock',
        'npm-shrinkwrap.json': 'npm-lock',
        'yarn.lock': 'yarn',
        'pnpm-lock.yaml': 'pnpm',
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.vuln_db = self._load_vulnerability_database()
        self.online = bool(self.config.get('online', False))

    # ------------------------------------------------------------------ database

    def _load_vulnerability_database(self) -> Dict[str, List[Dict]]:
        """Load and index the local vulnerability database(s) by normalized package name."""
        paths = [DEFAULT_DB_PATH, LOCAL_DB_PATH]
        if self.config.get('vuln_db_path'):
            paths.append(Path(self.config['vuln_db_path']))

        indexed: Dict[str, List[Dict]] = {}
        seen = set()
        for path in paths:
            if not path.is_file():
                if path == DEFAULT_DB_PATH:
                    logger.warning(f"Vulnerability database not found: {path}")
                continue
            try:
                data = json.loads(path.read_text(encoding='utf-8'))
            except (OSError, json.JSONDecodeError) as e:
                logger.error(f"Could not load vulnerability database {path}: {e}")
                continue
            for entry in data.get('vulnerabilities', []):
                pkg = normalize_name(entry.get('package', ''))
                key = (pkg, entry.get('cve'), tuple(entry.get('affected_versions', [])))
                if not pkg or key in seen:
                    continue
                seen.add(key)
                indexed.setdefault(pkg, []).append(entry)
        return indexed

    def get_database_stats(self) -> Dict[str, int]:
        return {
            'packages': len(self.vuln_db),
            'advisories': sum(len(v) for v in self.vuln_db.values()),
        }

    # ------------------------------------------------------------------ scanner API

    def get_name(self) -> str:
        return "dependency_scanner"

    def get_description(self) -> str:
        return "Dependency vulnerability scanner (requirements, pyproject, Pipfile, package.json, lockfiles)"

    def get_supported_languages(self) -> List[str]:
        return ['text', 'json', 'toml', 'python']

    def _file_type(self, file_path: Path) -> Optional[str]:
        name = file_path.name.lower()
        if name in self.DEPENDENCY_FILES:
            return self.DEPENDENCY_FILES[name]
        if re.fullmatch(r'requirements[\w.-]*\.(?:txt|in)', name):
            return 'pip'
        if file_path.parent.name.lower() == 'requirements' and name.endswith('.txt'):
            return 'pip'
        return None

    def can_scan_file(self, file_path: Path) -> bool:
        """Check if file is a dependency file."""
        return bool(file_path) and self._file_type(file_path) is not None

    def scan(self, context: ScanContext) -> List[Vulnerability]:
        """Scan dependency file for known vulnerabilities."""
        if not context.file_path or not context.file_content:
            return []

        file_type = self._file_type(context.file_path)
        parsers = {
            'pip': self._parse_requirements,
            'pyproject': self._parse_pyproject,
            'pipfile': self._parse_pipfile,
            'pipfile-lock': self._parse_pipfile_lock,
            'poetry-lock': self._parse_poetry_lock,
            'npm': self._parse_package_json,
            'npm-lock': self._parse_package_lock,
        }
        parser = parsers.get(file_type)
        if not parser:
            return []

        try:
            deps = parser(context.file_content)
        except Exception as e:
            self.log_error(f"Could not parse {context.file_path}: {e}")
            return []

        vulnerabilities: List[Vulnerability] = []

        # A lockfile next to package.json is authoritative for versions
        check_versions = True
        if file_type == 'npm':
            lock_exists = any(
                (context.file_path.parent / lock).exists()
                for lock in ('package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml')
            )
            if not lock_exists:
                vulnerabilities.append(self._missing_lockfile(context))
            else:
                check_versions = not (context.file_path.parent / 'package-lock.json').exists()

        if check_versions:
            for dep in deps:
                vulnerabilities.extend(self._check_local_db(dep, context))
            if self.online:
                vulnerabilities.extend(self._check_osv(deps, context))

        if file_type in ('pip', 'pyproject', 'pipfile'):
            unpinned = self._unpinned_finding(deps, context)
            if unpinned:
                vulnerabilities.append(unpinned)

        return vulnerabilities

    # ------------------------------------------------------------------ parsers

    @staticmethod
    def _line_of(content: str, name: str) -> int:
        pattern = re.compile(r'(?im)^\s*["\']?' + re.escape(name).replace(r'\-', r'[-_.]'))
        m = pattern.search(content)
        if not m:
            m = re.search(re.escape(f'"{name}"'), content)
        return content.count('\n', 0, m.start()) + 1 if m else 1

    def _from_requirement(self, req_text: str, content: str) -> Optional[Dependency]:
        try:
            req = Requirement(req_text)
        except InvalidRequirement:
            return None
        if req.url:
            return None
        return self._from_spec(req.name, req.specifier, str(req.specifier), 'PyPI', content)

    def _from_spec(self, name: str, spec: SpecifierSet, spec_text: str, ecosystem: str, content: str) -> Dependency:
        pinned_version = None
        minimum = None
        for s in spec:
            if s.operator in ('==', '===') and '*' not in s.version:
                pinned_version = s.version
            elif s.operator in ('>=', '~=', '>'):
                minimum = s.version
        return Dependency(
            name=name,
            version=pinned_version or minimum,
            spec=spec_text or '*',
            ecosystem=ecosystem,
            line=self._line_of(content, name),
            pinned=pinned_version is not None,
        )

    def _parse_requirements(self, content: str) -> List[Dependency]:
        deps = []
        for raw in content.splitlines():
            line = raw.split(' #', 1)[0].strip()
            if not line or line.startswith(('#', '-', 'git+', 'http://', 'https://')):
                continue
            line = line.split(';', 1)[0].strip() if ' --hash' in line else line
            line = line.split(' --hash', 1)[0].strip()
            dep = self._from_requirement(line, content)
            if dep:
                deps.append(dep)
        return deps

    def _parse_pyproject(self, content: str) -> List[Dependency]:
        data = tomllib.loads(content)
        deps: List[Dependency] = []
        project = data.get('project', {})
        req_lists = [project.get('dependencies', [])]
        req_lists.extend(project.get('optional-dependencies', {}).values())
        for reqs in req_lists:
            for req_text in reqs:
                dep = self._from_requirement(req_text, content)
                if dep:
                    deps.append(dep)

        poetry = data.get('tool', {}).get('poetry', {})
        poetry_sections = [poetry.get('dependencies', {}), poetry.get('dev-dependencies', {})]
        for group in poetry.get('group', {}).values():
            poetry_sections.append(group.get('dependencies', {}))
        for section in poetry_sections:
            for name, spec in section.items():
                if name.lower() == 'python':
                    continue
                version = spec.get('version') if isinstance(spec, dict) else spec
                if isinstance(version, str):
                    deps.append(self._poetry_dep(name, version, content))
        return deps

    def _poetry_dep(self, name: str, version: str, content: str) -> Dependency:
        """Translate poetry/npm style constraints (^1.2, ~1.2, 1.2.3, *) to a Dependency."""
        version = version.strip()
        if version in ('*', '', 'latest'):
            return Dependency(name, None, version or '*', 'PyPI', self._line_of(content, name))
        m = re.match(r'^[\^~>=]*\s*v?(\d+(?:\.\d+)*(?:[-.]?\w+)?)', version)
        exact = bool(re.fullmatch(r'=?=?\s*v?\d+(?:\.\d+)*', version))
        return Dependency(
            name, m.group(1) if m else None, version, 'PyPI', self._line_of(content, name), pinned=exact
        )

    def _parse_pipfile(self, content: str) -> List[Dependency]:
        data = tomllib.loads(content)
        deps = []
        for section in ('packages', 'dev-packages'):
            for name, spec in data.get(section, {}).items():
                version = spec.get('version', '*') if isinstance(spec, dict) else spec
                if not isinstance(version, str):
                    continue
                if version.strip() == '*':
                    deps.append(Dependency(name, None, '*', 'PyPI', self._line_of(content, name)))
                    continue
                try:
                    spec_set = SpecifierSet(version)
                except InvalidSpecifier:
                    continue
                deps.append(self._from_spec(name, spec_set, version, 'PyPI', content))
        return deps

    def _parse_pipfile_lock(self, content: str) -> List[Dependency]:
        data = json.loads(content)
        deps = []
        for section in ('default', 'develop'):
            for name, info in data.get(section, {}).items():
                version = str(info.get('version', '')).lstrip('=')
                if version:
                    deps.append(Dependency(name, version, info.get('version', ''), 'PyPI',
                                           self._line_of(content, name), pinned=True))
        return deps

    def _parse_poetry_lock(self, content: str) -> List[Dependency]:
        data = tomllib.loads(content)
        return [
            Dependency(p['name'], p.get('version'), p.get('version', ''), 'PyPI',
                       self._line_of(content, p['name']), pinned=True)
            for p in data.get('package', []) if p.get('name')
        ]

    def _parse_package_json(self, content: str) -> List[Dependency]:
        data = json.loads(content)
        deps = []
        for dep_type in ('dependencies', 'devDependencies', 'optionalDependencies'):
            for name, spec in (data.get(dep_type) or {}).items():
                if not isinstance(spec, str):
                    continue
                spec = spec.strip()
                line = self._line_of(content, name)
                if spec.startswith(('file:', 'link:', 'git', 'http', 'workspace:', 'npm:')) or '/' in spec:
                    continue
                m = re.search(r'(\d+(?:\.\d+){0,2})', spec)
                exact = bool(re.fullmatch(r'=?v?\d+\.\d+\.\d+', spec))
                deps.append(Dependency(name, m.group(1) if m else None, spec, 'npm', line, pinned=exact))
        return deps

    def _parse_package_lock(self, content: str) -> List[Dependency]:
        data = json.loads(content)
        deps: Dict[Tuple[str, str], Dependency] = {}
        packages = data.get('packages')
        if isinstance(packages, dict):  # lockfileVersion 2/3
            for path, info in packages.items():
                if not path or 'node_modules/' not in path:
                    continue
                name = info.get('name') or path.rsplit('node_modules/', 1)[-1]
                version = info.get('version')
                if version:
                    deps[(name, version)] = Dependency(name, version, version, 'npm', 1, pinned=True)
        else:  # lockfileVersion 1
            def walk(tree: Dict[str, Any]) -> None:
                for name, info in (tree or {}).items():
                    version = info.get('version')
                    if version:
                        deps[(name, version)] = Dependency(name, version, version, 'npm', 1, pinned=True)
                    walk(info.get('dependencies'))
            walk(data.get('dependencies'))
        for dep in deps.values():
            dep.line = self._line_of(content, dep.name)
        return list(deps.values())

    # ------------------------------------------------------------------ matching

    @staticmethod
    def _parse_version(version: Optional[str]) -> Optional[Version]:
        if not version:
            return None
        try:
            return Version(version)
        except InvalidVersion:
            m = re.match(r'v?(\d+(?:\.\d+){0,2})', version)
            try:
                return Version(m.group(1)) if m else None
            except InvalidVersion:
                return None

    def _version_affected(self, version: str, affected_ranges: List[str]) -> bool:
        """Check if version falls in any of the affected ranges."""
        return self._matching_range(version, affected_ranges) is not None

    def _matching_range(self, version: str, affected_ranges: List[str]) -> Optional[str]:
        parsed = self._parse_version(version)
        if parsed is None:
            return None
        for range_spec in affected_ranges:
            range_spec = range_spec.strip()
            if range_spec == '*':
                return range_spec
            try:
                spec = SpecifierSet(range_spec.replace(' ', ''))
            except InvalidSpecifier:
                if range_spec.lstrip('=') == version:
                    return range_spec
                continue
            if spec.contains(parsed, prereleases=True):
                return range_spec
        return None

    @staticmethod
    def _fixed_version(range_spec: str) -> Optional[str]:
        m = re.search(r'<\s*([0-9][\w.\-]*)', range_spec)
        return m.group(1) if m else None

    def _check_local_db(self, dep: Dependency, context: ScanContext) -> List[Vulnerability]:
        findings = []
        if not dep.version:
            return findings
        seen_cves = set()
        for entry in self.vuln_db.get(normalize_name(dep.name), []):
            matched = self._matching_range(dep.version, entry.get('affected_versions', []))
            if not matched:
                continue
            cve = entry.get('cve', 'N/A')
            if cve in seen_cves:
                continue
            seen_cves.add(cve)

            severity = Severity[entry.get('severity', 'MEDIUM').upper()]
            fixed = self._fixed_version(matched)
            qualifier = '' if dep.pinned else ' (minimum version allowed by your constraint)'
            if not dep.pinned and severity != Severity.LOW:
                # A range might resolve to a fixed version - report one level lower
                severity = Severity(severity.value + 1)

            findings.append(self._dependency_finding(
                context, dep, severity,
                title=f"Vulnerable Dependency: {dep.name}@{dep.version}",
                description=f"{entry.get('description', 'Known vulnerability')} ({cve}). "
                            f"Affected range: {matched}{qualifier}.",
                fixed=fixed, advisory_id=cve, source='local-db',
            ))
        return findings

    def _dependency_finding(
        self, context: ScanContext, dep: Dependency, severity: Severity, title: str,
        description: str, fixed: Optional[str], advisory_id: str, source: str,
    ) -> Vulnerability:
        if fixed:
            remediation = f"Upgrade {dep.name} to {fixed} or later"
        else:
            remediation = f"Upgrade {dep.name} to a patched release"
        remediation += " (npm audit fix / npm install <pkg>@latest)." if dep.ecosystem == 'npm' else \
            " (pip install -U <pkg>) and re-pin the version."
        line_text = context.file_content.splitlines()[dep.line - 1] if dep.line else ''
        return Vulnerability(
            title=title,
            description=description,
            severity=severity,
            category=Category.DEPENDENCY,
            file_path=context.file_path,
            line_number=dep.line,
            code_snippet=line_text.strip()[:120] or f'{dep.name} {dep.spec}',
            remediation=remediation,
            cwe_id='CWE-1395',
            scanner_source=self.get_name(),
            metadata={
                'package': dep.name,
                'version': dep.version,
                'spec': dep.spec,
                'ecosystem': dep.ecosystem,
                'cve': advisory_id,
                'fixed_version': fixed,
                'source': source,
            }
        )

    # ------------------------------------------------------------------ OSV (opt-in)

    def _check_osv(self, deps: Iterable[Dependency], context: ScanContext) -> List[Vulnerability]:
        """Query OSV.dev for exact versions. Only runs when online mode is enabled."""
        exact = [d for d in deps if d.version and d.pinned]
        if not exact:
            return []
        try:
            import requests
        except ImportError:
            return []

        queries = [
            {'package': {'name': d.name, 'ecosystem': d.ecosystem}, 'version': d.version}
            for d in exact
        ]
        findings: List[Vulnerability] = []
        try:
            for start in range(0, len(queries), 500):
                response = requests.post(OSV_BATCH_URL, json={'queries': queries[start:start + 500]}, timeout=20)
                response.raise_for_status()
                for dep, result in zip(exact[start:start + 500], response.json().get('results', [])):
                    ids = sorted(v.get('id', 'OSV') for v in (result.get('vulns') or []))
                    if not ids:
                        continue
                    # One finding per package: a single old release can have dozens of advisories
                    shown = ', '.join(ids[:10]) + (f' and {len(ids) - 10} more' if len(ids) > 10 else '')
                    finding = self._dependency_finding(
                        context, dep, Severity.HIGH,
                        title=f"Known Vulnerabilities (OSV.dev): {dep.name}@{dep.version}",
                        description=f"OSV.dev lists {len(ids)} advisor{'y' if len(ids) == 1 else 'ies'} "
                                    f"for this version: {shown}. Details: https://osv.dev/vulnerability/{ids[0]}",
                        fixed=None, advisory_id=f"osv:{dep.name}", source='osv.dev',
                    )
                    finding.metadata['advisories'] = ids
                    findings.append(finding)
        except Exception as e:
            self.log_error(f"OSV lookup failed: {e}")
        return findings

    # ------------------------------------------------------------------ hygiene findings

    def _unpinned_finding(self, deps: List[Dependency], context: ScanContext) -> Optional[Vulnerability]:
        unpinned = [d for d in deps if not d.pinned]
        if not unpinned or context.file_path.name.lower() == 'pyproject.toml':
            # Libraries legitimately use ranges in pyproject.toml
            return None
        names = ', '.join(d.name for d in unpinned[:8]) + (' ...' if len(unpinned) > 8 else '')
        return Vulnerability(
            title='Unpinned Dependencies',
            description=f'{len(unpinned)} dependencies are not pinned to an exact version ({names}). '
                        'Builds are not reproducible and may silently pick up vulnerable or malicious releases.',
            severity=Severity.LOW,
            category=Category.DEPENDENCY,
            file_path=context.file_path,
            line_number=unpinned[0].line,
            code_snippet='\n'.join(f'{d.name} {d.spec}'.strip() for d in unpinned[:5]),
            remediation='Pin exact versions (pip-compile / pip freeze / poetry lock) and update them deliberately.',
            cwe_id='CWE-1357',
            scanner_source=self.get_name(),
            metadata={'issue': 'unpinned', 'packages': [d.name for d in unpinned]}
        )

    def _missing_lockfile(self, context: ScanContext) -> Vulnerability:
        return Vulnerability(
            title='Missing Lockfile',
            description='No package-lock.json, yarn.lock, or pnpm-lock.yaml found. Dependencies may not be reproducible.',
            severity=Severity.LOW,
            category=Category.DEPENDENCY,
            file_path=context.file_path,
            line_number=1,
            code_snippet='package.json without lockfile',
            remediation='Run "npm install" to generate package-lock.json and commit it.',
            cwe_id='CWE-1357',
            scanner_source=self.get_name(),
            metadata={'issue': 'missing_lockfile'}
        )
