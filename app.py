"""Application controller for SecureMySite."""

import sys
import logging
from pathlib import Path
from typing import Optional, List

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt

from gui.main_window import MainWindow
from core.engine import AnalysisEngine
from core.config import Config
from models.scan_result import ScanResult


def setup_logging(verbose: bool = False) -> logging.Logger:
    """
    Setup application logging.
    
    Args:
        verbose: Enable debug logging
        
    Returns:
        Logger instance
    """
    level = logging.DEBUG if verbose else logging.INFO
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    return logging.getLogger('SecureMySite')


class Application:
    """
    Application controller.
    
    Manages application lifecycle and coordinates between CLI and GUI modes.
    """
    
    def __init__(self):
        self.config = Config()
        self.logger = logging.getLogger(__name__)
        self.qt_app: Optional[QApplication] = None
        self.main_window: Optional[MainWindow] = None
    
    def run_gui(self) -> int:
        """
        Run GUI mode.
        
        Returns:
            Exit code
        """
        self.logger.info("Starting GUI mode")
        
        # Enable high DPI support
        QApplication.setHighDpiScaleFactorRoundingPolicy(
            Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
        )
        
        # Create Qt application
        self.qt_app = QApplication(sys.argv)
        self.qt_app.setApplicationName(Config.GUI_WINDOW_TITLE)
        self.qt_app.setApplicationVersion("1.0.0")
        self.qt_app.setOrganizationName("SecureMySite")
        
        # Create and show main window
        self.main_window = MainWindow()
        self.main_window.show()
        
        # Run event loop
        return self.qt_app.exec()
    
    def run_cli(
        self,
        project_path: Path,
        url: Optional[str] = None,
        export_format: Optional[str] = None,
        export_path: Optional[Path] = None,
        generate_prompt: bool = False
    ) -> int:
        """
        Run CLI mode.
        
        Args:
            project_path: Path to project to scan
            url: Optional localhost URL for web scanning
            export_format: Export format (json, html, markdown)
            export_path: Path for export file
            generate_prompt: Generate AI fix prompt
            
        Returns:
            Exit code
        """
        self.logger.info(f"Starting CLI scan of {project_path}")
        
        try:
            # Run analysis
            engine = AnalysisEngine(project_path)
            result = engine.analyze(url)
            
            # Display results
            self._display_cli_results(result)
            
            # Export if requested
            if export_format and export_path:
                self._export_results(engine, result, export_format, export_path)
            
            # Generate prompt if requested
            if generate_prompt:
                self._generate_prompt(result)
            
            # Return exit code based on severity
            return self._get_exit_code(result)
            
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            print(f"Error: {e}", file=sys.stderr)
            return 1
    
    def _display_cli_results(self, result: ScanResult) -> None:
        """Display results in CLI format."""
        from scoring.score_engine import ScoreEngine
        
        score_engine = ScoreEngine()
        score_result = score_engine.calculate(result.vulnerabilities)
        
        print("\n" + "=" * 60)
        print("SECURITY ANALYSIS RESULTS")
        print("=" * 60)
        print(f"Project: {result.project_path}")
        print(f"Score: {score_result.score}/100 ({score_result.risk_level})")
        print(f"Grade: {score_result.grade}")
        print(f"Files Scanned: {result.files_scanned}")
        print(f"Duration: {result.get_duration_seconds():.1f}s")
        print("-" * 60)
        print("VULNERABILITIES:")
        print(f"  Critical: {result.get_critical_count()}")
        print(f"  High: {result.get_high_count()}")
        print(f"  Medium: {result.get_medium_count()}")
        print(f"  Low: {result.get_low_count()}")
        print("=" * 60)
        
        if score_result.recommendations:
            print("\nRECOMMENDATIONS:")
            for rec in score_result.recommendations:
                print(f"  - {rec}")
        
        if result.vulnerabilities:
            print("\nTOP ISSUES:")
            for vuln in result.vulnerabilities[:5]:
                print(f"  [{vuln.severity.name}] {vuln.title}")
                print(f"    Location: {vuln.get_location_string()}")
                print(f"    Fix: {vuln.remediation[:80]}...")
                print()
    
    def _export_results(
        self,
        engine: AnalysisEngine,
        result: ScanResult,
        format_type: str,
        path: Path
    ) -> None:
        """Export results to file."""
        try:
            content = engine.export_results(format_type)
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"\nExported results to: {path}")
        except Exception as e:
            self.logger.error(f"Export failed: {e}")
            print(f"Export error: {e}", file=sys.stderr)
    
    def _generate_prompt(self, result: ScanResult) -> None:
        """Generate and display AI fix prompt."""
        from prompt_engine.prompt_builder import PromptBuilder
        
        builder = PromptBuilder(result)
        prompt = builder.build_prompt()
        
        print("\n" + "=" * 60)
        print("AI FIX PROMPT")
        print("=" * 60)
        print(prompt)
        print("=" * 60)
    
    def _get_exit_code(self, result: ScanResult) -> int:
        """
        Get exit code based on scan results.
        
        Returns:
            0 if no critical/high issues, 1 otherwise
        """
        critical = result.get_critical_count()
        high = result.get_high_count()
        
        if critical > 0:
            return 2  # Critical issues found
        elif high > 0:
            return 1  # High severity issues found
        else:
            return 0  # No serious issues


def create_app() -> Application:
    """Factory function to create application instance."""
    return Application()
