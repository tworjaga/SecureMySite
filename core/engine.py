"""Central analysis orchestrator for SecureMySite."""

import hashlib
import json
import re
import time
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any, Type, Callable, Set

from models.vulnerability import Vulnerability, Severity
from models.scan_result import ScanResult
from scanners.base_scanner import BaseScanner, ScanContext, redact_secrets
from scanners.python_sast import PythonSASTScanner
from scanners.js_scanner import JavaScriptScanner
from scanners.html_scanner import HTMLScanner
from scanners.config_scanner import ConfigScanner
from scanners.dependency_scanner import DependencyScanner
from scanners.secrets_scanner import SecretsScanner
from scanners.iac_scanner import IaCScanner
from scanners.web_scanner import WebScanner
from scoring.score_engine import ScoreEngine
from core.file_loader import FileLoader
from core.config import Config


# Inline suppression markers, e.g.  eval(x)  # securemysite: ignore
SUPPRESS_RE = re.compile(r'(?:securemysite|sms)\s*:\s*(?:ignore|disable)|\bnosec\b', re.IGNORECASE)
SUPPRESS_NEXT_RE = re.compile(r'(?:securemysite|sms)\s*:\s*ignore-next-line', re.IGNORECASE)

ProgressCallback = Callable[[str, int, int], None]


class AnalysisEngine:
    """
    Central analysis orchestrator.

    Coordinates file loading, scanner execution, suppression, de-duplication,
    baseline comparison, scoring and export.
    """

    # Registry of available scanners
    SCANNER_REGISTRY: Dict[str, Type[BaseScanner]] = {
        'python_sast': PythonSASTScanner,
        'javascript_scanner': JavaScriptScanner,
        'html_scanner': HTMLScanner,
        'config_scanner': ConfigScanner,
        'dependency_scanner': DependencyScanner,
        'secrets_scanner': SecretsScanner,
        'iac_scanner': IaCScanner,
        'web_scanner': WebScanner,
    }

    def __init__(
        self,
        project_path: Path,
        config: Optional[Config] = None,
        scanner_config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize analysis engine.

        Args:
            project_path: Path to project to analyze
            config: Optional configuration
            scanner_config: Optional settings. Recognised keys:
                enabled_scanners: list of scanner names
                exclude: extra glob patterns to skip
                min_severity: drop findings below this severity name
                baseline: path to a previous JSON report; matching findings are hidden
                <scanner_name>: dict passed to that scanner (e.g. {'online': True})
        """
        self.project_path = Path(project_path).resolve()
        self.config = config or Config()
        self.scanner_config = scanner_config or {}
        self.logger = logging.getLogger(__name__)

        # Initialize components
        self.file_loader = FileLoader(self.project_path, self.config, self.scanner_config.get('exclude'))
        self.score_engine = ScoreEngine()

        # Initialize scanners
        self.scanners: List[BaseScanner] = []
        self._init_scanners()

        self._cancelled = False

        # Results
        self.scan_result: Optional[ScanResult] = None

    @classmethod
    def available_scanners(cls) -> Dict[str, str]:
        """Map of scanner name -> description."""
        return {name: scanner_cls().get_description() for name, scanner_cls in cls.SCANNER_REGISTRY.items()}

    def _init_scanners(self) -> None:
        """Initialize enabled scanners."""
        enabled_scanners = self.scanner_config.get('enabled_scanners') or self.config.DEFAULT_SCANNERS

        for scanner_name in enabled_scanners:
            if scanner_name in self.SCANNER_REGISTRY:
                scanner_class = self.SCANNER_REGISTRY[scanner_name]
                scanner = scanner_class(self.scanner_config.get(scanner_name, {}))
                self.scanners.append(scanner)
                self.logger.debug(f"Initialized scanner: {scanner_name}")
            else:
                self.logger.warning(f"Unknown scanner: {scanner_name}")

    def cancel(self) -> None:
        """Request cancellation of a running analysis (checked between files)."""
        self._cancelled = True

    def analyze(
        self,
        web_url: Optional[str] = None,
        progress: Optional[ProgressCallback] = None
    ) -> ScanResult:
        """
        Run full security analysis.

        Args:
            web_url: Optional localhost URL for web scanning
            progress: Optional callback(message, current, total)

        Returns:
            ScanResult with all findings
        """
        start_time = time.time()
        self._cancelled = False
        self.logger.info(f"Starting analysis of {self.project_path}")

        self.scan_result = ScanResult(project_path=self.project_path)
        self._file_contents: Dict[Path, List[str]] = {}
        self._suppressed = 0

        try:
            self._scan_files(progress)
        except Exception as e:
            self.logger.error(f"File scanning error: {e}")
            self.scan_result.add_error(f"File scanning failed: {e}")

        if web_url and not self._cancelled:
            if progress:
                progress(f"Scanning {web_url}...", 0, 0)
            self._scan_web(web_url)

        self._post_process()
        self.scan_result.complete_scan()

        score_result = self.score_engine.calculate(self.scan_result.vulnerabilities)
        self.scan_result.metadata['score'] = {
            'score': score_result.score,
            'risk_level': score_result.risk_level,
            'grade': score_result.grade,
            'breakdown': score_result.breakdown,
            'recommendations': score_result.recommendations,
        }
        self.scan_result.metadata['tool_version'] = self.config.APP_VERSION
        self.scan_result.metadata['scanners_enabled'] = [s.get_name() for s in self.scanners]
        self.scan_result.metadata['files_skipped'] = self.file_loader.files_skipped
        self.scan_result.metadata['cancelled'] = self._cancelled

        elapsed = time.time() - start_time
        self.logger.info(f"Analysis complete in {elapsed:.2f}s - {len(self.scan_result.vulnerabilities)} findings")

        return self.scan_result

    def _scan_files(self, progress: Optional[ProgressCallback]) -> None:
        """Scan all project files."""
        total = self.file_loader.count_files() if progress else 0

        def on_file(index: int, path: Path) -> None:
            if progress:
                progress(f"Scanning {path.relative_to(self.project_path).as_posix()}", index, total)

        for file_path, content in self.file_loader.load_files(on_file):
            if self._cancelled:
                self.scan_result.add_error("Scan cancelled by user")
                break

            self.scan_result.files_scanned += 1
            language = self.file_loader.get_file_language(file_path)

            context = ScanContext(
                project_path=self.project_path,
                file_path=file_path,
                file_content=content,
                language=language,
                config=self.scanner_config
            )

            lines: Optional[List[str]] = None
            file_findings: List[Vulnerability] = []
            for scanner in self.scanners:
                if not scanner.is_enabled() or not scanner.can_scan_file(file_path):
                    continue

                try:
                    vulnerabilities = scanner.scan(context)
                except Exception as e:
                    self.logger.error(f"Scanner {scanner.get_name()} failed on {file_path}: {e}")
                    self.scan_result.add_error(f"{scanner.get_name()} on {file_path.name}: {e}")
                    continue

                if scanner.get_name() not in self.scan_result.scanners_used:
                    self.scan_result.scanners_used.append(scanner.get_name())

                if vulnerabilities and lines is None:
                    lines = content.splitlines()
                    self._file_contents[file_path] = lines

                for vuln in vulnerabilities:
                    if self._is_suppressed(vuln, lines or []):
                        self._suppressed += 1
                        continue
                    file_findings.append(vuln)

            # A secret found by one scanner may appear in another finding's context lines
            for vuln in redact_secrets(file_findings, remove=True):
                self.scan_result.add_vulnerability(vuln)

        for error in self.file_loader.errors:
            self.scan_result.add_error(error)

    @staticmethod
    def _is_suppressed(vuln: Vulnerability, lines: List[str]) -> bool:
        """Honour '# securemysite: ignore' / '// nosec' on the line or the line above."""
        if not vuln.line_number or not lines or vuln.line_number > len(lines):
            return False
        idx = vuln.line_number - 1
        if SUPPRESS_RE.search(lines[idx]):
            return True
        if idx > 0 and SUPPRESS_NEXT_RE.search(lines[idx - 1]):
            return True
        return False

    def _scan_web(self, url: str) -> None:
        """Scan web application at URL."""
        self.logger.info(f"Scanning web application: {url}")

        web_scanner = next((s for s in self.scanners if s.get_name() == 'web_scanner'), None)
        if not web_scanner:
            web_scanner = WebScanner(self.scanner_config.get('web_scanner', {}))

        context = ScanContext(
            project_path=self.project_path,
            config={**self.scanner_config.get('web_scanner', {}), 'url': url}
        )

        try:
            for vuln in web_scanner.scan(context):
                self.scan_result.add_vulnerability(vuln)
            if 'web_scanner' not in self.scan_result.scanners_used:
                self.scan_result.scanners_used.append('web_scanner')
        except Exception as e:
            self.logger.error(f"Web scanner failed: {e}")
            self.scan_result.add_error(f"Web scan: {e}")

    # ------------------------------------------------------------------ post-processing

    def _relative(self, path: Optional[Path]) -> Optional[str]:
        if not path:
            return None
        try:
            return Path(path).resolve().relative_to(self.project_path).as_posix()
        except (ValueError, OSError):
            return Path(path).as_posix()

    def fingerprint(self, vuln: Vulnerability) -> str:
        """
        Stable identifier for a finding that survives unrelated edits (line shifts):
        relative path + title + content of the flagged line.
        """
        line_text = ''
        lines = self._file_contents.get(vuln.file_path) if vuln.file_path else None
        if lines and vuln.line_number and vuln.line_number <= len(lines):
            line_text = ' '.join(lines[vuln.line_number - 1].split())
        elif not vuln.file_path:
            line_text = vuln.code_snippet or ''
        raw = f"{self._relative(vuln.file_path) or ''}|{vuln.title}|{line_text}"
        return hashlib.sha256(raw.encode('utf-8', errors='replace')).hexdigest()[:20]

    def _post_process(self) -> None:
        """De-duplicate, filter, baseline-compare and sort findings."""
        result = self.scan_result

        # Annotate
        for vuln in result.vulnerabilities:
            vuln.metadata['relative_path'] = self._relative(vuln.file_path)
            vuln.metadata['fingerprint'] = self.fingerprint(vuln)

        # De-duplicate across scanners: same file + line + CWE (or title) -> keep most severe
        best: Dict[tuple, Vulnerability] = {}
        order: List[tuple] = []
        for vuln in result.vulnerabilities:
            # Distinct advisories for the same dependency line are separate findings
            key = (str(vuln.file_path), vuln.line_number, vuln.cwe_id or vuln.title, vuln.metadata.get('cve'))
            if vuln.file_path is None:
                key = (None, vuln.title, vuln.code_snippet)
            current = best.get(key)
            if current is None:
                best[key] = vuln
                order.append(key)
            elif vuln.severity.value < current.severity.value:
                best[key] = vuln
        duplicates = len(result.vulnerabilities) - len(best)
        vulns = [best[k] for k in order]

        # Minimum severity filter
        min_sev = self.scanner_config.get('min_severity')
        filtered_out = 0
        if min_sev:
            threshold = Severity[str(min_sev).upper()].value
            before = len(vulns)
            vulns = [v for v in vulns if v.severity.value <= threshold]
            filtered_out = before - len(vulns)

        # Baseline comparison
        baseline_hidden = 0
        baseline_path = self.scanner_config.get('baseline')
        if baseline_path:
            known = self._load_baseline(Path(baseline_path))
            before = len(vulns)
            vulns = [v for v in vulns if v.metadata['fingerprint'] not in known]
            baseline_hidden = before - len(vulns)

        vulns.sort(key=lambda v: (
            v.severity.value,
            v.metadata.get('relative_path') or '~',
            v.line_number or 0,
            v.title,
        ))
        result.vulnerabilities = vulns
        result.metadata.update({
            'duplicates_removed': duplicates,
            'suppressed': self._suppressed,
            'filtered_by_severity': filtered_out,
            'baseline_hidden': baseline_hidden,
        })

    def _load_baseline(self, path: Path) -> Set[str]:
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError) as e:
            self.scan_result.add_error(f"Could not read baseline {path}: {e}")
            return set()
        return {
            v.get('metadata', {}).get('fingerprint')
            for v in data.get('vulnerabilities', [])
            if v.get('metadata', {}).get('fingerprint')
        }

    # ------------------------------------------------------------------ queries / export

    def get_score(self) -> Optional[Dict[str, Any]]:
        """Get security score if analysis complete."""
        if not self.scan_result:
            return None
        return self.scan_result.metadata.get('score')

    def get_vulnerabilities_by_severity(self) -> Dict[str, List[Vulnerability]]:
        """Group vulnerabilities by severity."""
        if not self.scan_result:
            return {}
        return {
            sev.name: self.scan_result.get_vulnerabilities_by_severity(sev)
            for sev in Severity
        }

    def export_results(self, format_type: str = 'json') -> str:
        """
        Export scan results to string.

        Args:
            format_type: json, html, markdown, sarif or csv
        """
        if not self.scan_result:
            raise RuntimeError("No scan results to export")
        from core.reporter import export
        return export(self.scan_result, format_type)
