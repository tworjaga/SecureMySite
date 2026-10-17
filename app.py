"""Application controller for SecureMySite."""

import os
import sys
import logging
from pathlib import Path
from typing import Optional, List

from core.config import Config, APP_VERSION
from models.scan_result import ScanResult
from models.vulnerability import Severity


def setup_logging(verbose: bool = False, cli: bool = False) -> logging.Logger:
    """
    Setup application logging.

    Logs go to stderr so stdout stays clean for reports ("-o -").
    In CLI mode only warnings are shown unless verbose is set.
    """
    if verbose:
        level = logging.DEBUG
    elif cli:
        level = logging.WARNING
    else:
        level = logging.INFO

    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler(sys.stderr)],
        force=True,
    )
    return logging.getLogger('SecureMySite')


class _Style:
    """Tiny ANSI color helper (disabled when not a TTY or NO_COLOR is set)."""

    CODES = {
        'CRITICAL': '\033[1;91m', 'HIGH': '\033[38;5;208m', 'MEDIUM': '\033[93m', 'LOW': '\033[96m',
        'bold': '\033[1m', 'dim': '\033[2m', 'green': '\033[92m', 'reset': '\033[0m',
    }

    def __init__(self, enabled: bool):
        self.enabled = enabled and sys.stdout.isatty() and 'NO_COLOR' not in os.environ
        if self.enabled and os.name == 'nt':
            os.system('')  # enable VT processing on Windows terminals

    def __call__(self, text: str, style: str) -> str:
        if not self.enabled:
            return text
        return f"{self.CODES.get(style, '')}{text}{self.CODES['reset']}"


class Application:
    """
    Application controller.

    Manages application lifecycle and coordinates between CLI and GUI modes.
    """

    def __init__(self):
        self.config = Config()
        self.logger = logging.getLogger(__name__)
        self.qt_app = None
        self.main_window = None

    def run_gui(self) -> int:
        """Run GUI mode."""
        # Imported lazily so the CLI works on machines without Qt (e.g. CI)
        from PyQt6.QtWidgets import QApplication
        from PyQt6.QtCore import Qt
        from gui.main_window import MainWindow

        self.logger.info("Starting GUI mode")

        QApplication.setHighDpiScaleFactorRoundingPolicy(
            Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
        )

        self.qt_app = QApplication(sys.argv)
        self.qt_app.setApplicationName(Config.GUI_WINDOW_TITLE)
        self.qt_app.setApplicationVersion(APP_VERSION)
        self.qt_app.setOrganizationName("SecureMySite")

        self.main_window = MainWindow()
        self.main_window.show()

        return self.qt_app.exec()

    def run_cli(
        self,
        project_path: Path,
        url: Optional[str] = None,
        export_format: Optional[str] = None,
        export_path: Optional[str] = None,
        generate_prompt: bool = False,
        fail_on: Optional[str] = None,
        min_severity: Optional[str] = None,
        baseline: Optional[Path] = None,
        excludes: Optional[List[str]] = None,
        scanners: Optional[List[str]] = None,
        online: bool = False,
        quiet: bool = False,
        color: bool = True,
    ) -> int:
        """
        Run CLI mode.

        Returns:
            Exit code (see main.py epilog)
        """
        from core.engine import AnalysisEngine

        self.logger.info(f"Starting CLI scan of {project_path}")
        style = _Style(color)
        to_stdout = export_path == '-'

        scanner_config = {
            'exclude': excludes or [],
            'min_severity': min_severity,
            'baseline': str(baseline) if baseline else None,
            'dependency_scanner': {'online': online},
        }
        if scanners:
            scanner_config['enabled_scanners'] = scanners

        try:
            engine = AnalysisEngine(project_path, scanner_config=scanner_config)
            result = engine.analyze(url)
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            print(f"Error: {e}", file=sys.stderr)
            return 3

        # When the report goes to stdout, the human summary goes to stderr
        out = sys.stderr if to_stdout else sys.stdout
        if quiet:
            self._print_summary_line(result, style, out)
        else:
            self._display_cli_results(result, style, out)

        if export_format and export_path:
            if not self._export_results(result, export_format, export_path):
                return 3

        if generate_prompt:
            self._generate_prompt(result, out)

        return self._get_exit_code(result, fail_on)

    def _print_summary_line(self, result: ScanResult, style: _Style, out) -> None:
        score = result.metadata.get('score', {})
        counts = ' '.join(
            style(f"{sev.name[0]}:{len(result.get_vulnerabilities_by_severity(sev))}", sev.name) for sev in Severity
        )
        print(f"SecureMySite: score {score.get('score')}/100 ({score.get('grade')}) | {counts} | "
              f"{result.files_scanned} files", file=out)

    def _display_cli_results(self, result: ScanResult, style: _Style, out) -> None:
        """Display results in CLI format."""
        score = result.metadata.get('score', {})
        meta = result.metadata

        print("\n" + "=" * 64, file=out)
        print(style("SECURITY ANALYSIS RESULTS", 'bold'), file=out)
        print("=" * 64, file=out)
        if meta.get('scan_type') == 'domain':
            print(f"Domain:        {meta.get('target')}", file=out)
        else:
            print(f"Project:       {result.project_path}", file=out)
        print(f"Score:         {style(str(score.get('score')), 'bold')}/100  "
              f"Grade {score.get('grade')}  ({score.get('risk_level')})", file=out)
        if meta.get('scan_type') != 'domain':
            print(f"Files scanned: {result.files_scanned}  ({meta.get('files_skipped', 0)} skipped)", file=out)
        print(f"Duration:      {result.get_duration_seconds():.1f}s", file=out)
        extras = []
        if meta.get('suppressed'):
            extras.append(f"{meta['suppressed']} suppressed inline")
        if meta.get('baseline_hidden'):
            extras.append(f"{meta['baseline_hidden']} in baseline")
        if meta.get('filtered_by_severity'):
            extras.append(f"{meta['filtered_by_severity']} below min severity")
        if extras:
            print(f"Hidden:        {', '.join(extras)}", file=out)
        print("-" * 64, file=out)
        for sev in Severity:
            count = len(result.get_vulnerabilities_by_severity(sev))
            print(f"  {style(f'{sev.name:<9}', sev.name)} {count}", file=out)
        print("=" * 64, file=out)

        if result.vulnerabilities:
            print(style("\nFINDINGS:", 'bold'), file=out)
            limit = 25
            for vuln in result.vulnerabilities[:limit]:
                location = vuln.metadata.get('relative_path') or vuln.metadata.get('url') or 'web'
                if vuln.line_number and vuln.file_path:
                    location += f":{vuln.line_number}"
                print(f"  {style(f'[{vuln.severity.name}]', vuln.severity.name)} {vuln.title}", file=out)
                print(style(f"      {location}", 'dim'), file=out)
                print(f"      Fix: {vuln.remediation}", file=out)
            if len(result.vulnerabilities) > limit:
                print(style(f"\n  ... and {len(result.vulnerabilities) - limit} more (export a report for the full list)",
                            'dim'), file=out)
        else:
            print(style("\nNo issues found.", 'green'), file=out)

        if score.get('recommendations'):
            print(style("\nRECOMMENDATIONS:", 'bold'), file=out)
            for rec in score['recommendations']:
                print(f"  - {rec}", file=out)

        if result.errors:
            print(style(f"\n{len(result.errors)} scan warning(s); run with -v for details.", 'dim'), file=out)

    def run_domain(
        self,
        domain: str,
        active: bool = False,
        export_format: Optional[str] = None,
        export_path: Optional[str] = None,
        generate_prompt: bool = False,
        fail_on: Optional[str] = None,
        min_severity: Optional[str] = None,
        quiet: bool = False,
        color: bool = True,
    ) -> int:
        """Run an online domain scan from the CLI."""
        from scanners.domain_scanner import DomainScanner

        style = _Style(color)
        out = sys.stderr if export_path == '-' else sys.stdout
        if not quiet:
            print(style(f"Scanning {domain} (online: DNS-over-HTTPS, RDAP, TLS, HTTPS)...", 'dim'), file=out)

        def report(msg, i, n):
            print(style(f"  [{i}/{n}] {msg}", 'dim'), file=out)

        try:
            result = DomainScanner(active=active).scan(domain, progress=None if quiet else report)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            return 3

        if min_severity:
            threshold = Severity[min_severity.upper()].value
            result.vulnerabilities = [v for v in result.vulnerabilities if v.severity.value <= threshold]

        if quiet:
            self._print_summary_line(result, style, out)
        else:
            self._display_cli_results(result, style, out)
            self._display_domain_profile(result, style, out)

        if export_format and export_path and not self._export_results(result, export_format, export_path):
            return 3
        if generate_prompt:
            self._generate_prompt(result, out)
        return self._get_exit_code(result, fail_on)

    def _display_domain_profile(self, result: ScanResult, style: _Style, out) -> None:
        p = result.metadata.get('domain_profile', {})
        tls = p.get('tls') or {}
        if tls.get('verified'):
            tls_text = (f"{tls.get('version', '-')}, certificate by {tls.get('issuer') or '?'}, "
                        f"{tls.get('expires_in_days', '?')} days left")
        else:
            tls_text = tls.get('verify_error') or tls.get('error') or 'unavailable'
        expires = p.get('expires')
        rows = [
            ('IPv4', ', '.join(p.get('ipv4') or []) or '-'),
            ('CDN / WAF', p.get('cdn') or 'none detected'),
            ('Nameservers', ', '.join(p.get('nameservers') or []) or '-'),
            ('DNSSEC', p.get('dnssec', '-')),
            ('SPF', p.get('spf') or 'missing'),
            ('DMARC', p.get('dmarc') or 'missing'),
            ('Registrar', p.get('registrar') or '-'),
            ('Expires', f"{expires} ({p.get('expires_in_days', '?')} days)" if expires else '-'),
            ('TLS', tls_text),
        ]
        print(style("\nDOMAIN PROFILE:", 'bold'), file=out)
        for key, value in rows:
            print(f"  {key:<12} {value}", file=out)

    def _export_results(self, result: ScanResult, format_type: str, path: str) -> bool:
        """Export results to file (or stdout for '-')."""
        try:
            from core.reporter import export
            content = export(result, format_type)
            if path == '-':
                sys.stdout.write(content)
                sys.stdout.flush()
            else:
                Path(path).write_text(content, encoding='utf-8')
                print(f"\nExported {format_type} report to: {path}", file=sys.stderr)
            return True
        except Exception as e:
            self.logger.error(f"Export failed: {e}")
            print(f"Export error: {e}", file=sys.stderr)
            return False

    def _generate_prompt(self, result: ScanResult, out) -> None:
        """Generate and display AI fix prompt."""
        from prompt_engine.prompt_builder import PromptBuilder

        prompt = PromptBuilder(result).build_prompt()
        print("\n" + "=" * 64, file=out)
        print("AI FIX PROMPT", file=out)
        print("=" * 64, file=out)
        print(prompt, file=out)
        print("=" * 64, file=out)

    def _get_exit_code(self, result: ScanResult, fail_on: Optional[str] = None) -> int:
        """
        Exit code based on findings.

        Default: 2 if critical, 1 if high, else 0.
        With fail_on: 1 if any finding at/above that severity, else 0.
        """
        if fail_on:
            if fail_on == 'none':
                return 0
            threshold = Severity[fail_on.upper()].value
            return 1 if any(v.severity.value <= threshold for v in result.vulnerabilities) else 0

        if result.get_critical_count() > 0:
            return 2
        if result.get_high_count() > 0:
            return 1
        return 0


def create_app() -> Application:
    """Factory function to create application instance."""
    return Application()
