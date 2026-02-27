"""Central analysis orchestrator for SecureMySite."""

import time
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any, Type
from concurrent.futures import ThreadPoolExecutor, as_completed

from models.vulnerability import Vulnerability
from models.scan_result import ScanResult
from scanners.base_scanner import BaseScanner, ScanContext
from scanners.python_sast import PythonSASTScanner
from scanners.js_scanner import JavaScriptScanner
from scanners.config_scanner import ConfigScanner
from scanners.dependency_scanner import DependencyScanner
from scanners.web_scanner import WebScanner
from scoring.score_engine import ScoreEngine
from core.file_loader import FileLoader
from core.config import Config


class AnalysisEngine:
    """
    Central analysis orchestrator.
    
    Coordinates file loading, scanner execution, and result aggregation.
    """
    
    # Registry of available scanners
    SCANNER_REGISTRY: Dict[str, Type[BaseScanner]] = {
        'python_sast': PythonSASTScanner,
        'javascript_scanner': JavaScriptScanner,
        'config_scanner': ConfigScanner,
        'dependency_scanner': DependencyScanner,
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
            scanner_config: Optional scanner-specific configuration
        """
        self.project_path = Path(project_path)
        self.config = config or Config()
        self.scanner_config = scanner_config or {}
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.file_loader = FileLoader(self.project_path, self.config)
        self.score_engine = ScoreEngine()
        
        # Initialize scanners
        self.scanners: List[BaseScanner] = []
        self._init_scanners()
        
        # Results
        self.scan_result: Optional[ScanResult] = None
    
    def _init_scanners(self) -> None:
        """Initialize enabled scanners."""
        enabled_scanners = self.scanner_config.get(
            'enabled_scanners',
            self.config.DEFAULT_SCANNERS
        )
        
        for scanner_name in enabled_scanners:
            if scanner_name in self.SCANNER_REGISTRY:
                scanner_class = self.SCANNER_REGISTRY[scanner_name]
                scanner = scanner_class(self.scanner_config.get(scanner_name, {}))
                self.scanners.append(scanner)
                self.logger.info(f"Initialized scanner: {scanner_name}")
            else:
                self.logger.warning(f"Unknown scanner: {scanner_name}")
    
    def analyze(self, web_url: Optional[str] = None) -> ScanResult:
        """
        Run full security analysis.
        
        Args:
            web_url: Optional localhost URL for web scanning
            
        Returns:
            ScanResult with all findings
        """
        start_time = time.time()
        self.logger.info(f"Starting analysis of {self.project_path}")
        
        # Initialize result
        self.scan_result = ScanResult(project_path=self.project_path)
        
        # Load and scan files
        try:
            self._scan_files()
        except Exception as e:
            self.logger.error(f"File scanning error: {e}")
            self.scan_result.add_error(f"File scanning failed: {e}")
        
        # Web scan if URL provided
        if web_url:
            self._scan_web(web_url)
        
        # Complete scan
        self.scan_result.complete_scan()
        
        # Calculate score
        score_result = self.score_engine.calculate(self.scan_result.vulnerabilities)
        self.scan_result.metadata['score'] = score_result.to_dict() if hasattr(score_result, 'to_dict') else {
            'score': score_result.score,
            'risk_level': score_result.risk_level,
            'grade': score_result.grade,
            'breakdown': score_result.breakdown,
        }
        
        elapsed = time.time() - start_time
        self.logger.info(f"Analysis complete in {elapsed:.2f}s")
        self.logger.info(f"Found {len(self.scan_result.vulnerabilities)} vulnerabilities")
        
        return self.scan_result
    
    def _scan_files(self) -> None:
        """Scan all project files."""
        self.logger.info("Scanning files...")
        
        # Load files and run scanners
        for file_path, content in self.file_loader.load_files():
            # Update statistics
            self.scan_result.files_scanned += 1
            
            # Determine language
            language = self.file_loader.get_file_language(file_path)
            
            # Create scan context
            context = ScanContext(
                project_path=self.project_path,
                file_path=file_path,
                file_content=content,
                language=language,
                config=self.scanner_config
            )
            
            # Run applicable scanners
            for scanner in self.scanners:
                if not scanner.is_enabled():
                    continue
                
                if not scanner.can_scan_file(file_path):
                    continue
                
                try:
                    vulnerabilities = scanner.scan(context)
                    for vuln in vulnerabilities:
                        self.scan_result.add_vulnerability(vuln)
                    
                    # Track scanner usage
                    if vulnerabilities and scanner.get_name() not in self.scan_result.scanners_used:
                        self.scan_result.scanners_used.append(scanner.get_name())
                        
                except Exception as e:
                    self.logger.error(f"Scanner {scanner.get_name()} failed on {file_path}: {e}")
                    self.scan_result.add_error(f"{scanner.get_name()}: {e}")
        
        # Add file loader errors
        for error in self.file_loader.errors:
            self.scan_result.add_error(error)
    
    def _scan_web(self, url: str) -> None:
        """Scan web application at URL."""
        self.logger.info(f"Scanning web application: {url}")
        
        # Find web scanner
        web_scanner = None
        for scanner in self.scanners:
            if scanner.get_name() == 'web_scanner':
                web_scanner = scanner
                break
        
        if not web_scanner:
            # Add web scanner dynamically
            web_scanner = WebScanner(self.scanner_config.get('web_scanner', {}))
        
        # Create context with URL
        context = ScanContext(
            project_path=self.project_path,
            config={**self.scanner_config, 'url': url}
        )
        
        try:
            vulnerabilities = web_scanner.scan(context)
            for vuln in vulnerabilities:
                self.scan_result.add_vulnerability(vuln)
            
            if vulnerabilities and 'web_scanner' not in self.scan_result.scanners_used:
                self.scan_result.scanners_used.append('web_scanner')
                
        except Exception as e:
            self.logger.error(f"Web scanner failed: {e}")
            self.scan_result.add_error(f"Web scan: {e}")
    
    def get_score(self) -> Optional[Dict[str, Any]]:
        """Get security score if analysis complete."""
        if not self.scan_result:
            return None
        
        score_result = self.score_engine.calculate(self.scan_result.vulnerabilities)
        return {
            'score': score_result.score,
            'risk_level': score_result.risk_level,
            'grade': score_result.grade,
            'breakdown': score_result.breakdown,
            'recommendations': score_result.recommendations,
        }
    
    def get_vulnerabilities_by_severity(self) -> Dict[str, List[Vulnerability]]:
        """Group vulnerabilities by severity."""
        if not self.scan_result:
            return {}
        
        from models.vulnerability import Severity
        
        return {
            'CRITICAL': self.scan_result.get_vulnerabilities_by_severity(Severity.CRITICAL),
            'HIGH': self.scan_result.get_vulnerabilities_by_severity(Severity.HIGH),
            'MEDIUM': self.scan_result.get_vulnerabilities_by_severity(Severity.MEDIUM),
            'LOW': self.scan_result.get_vulnerabilities_by_severity(Severity.LOW),
        }
    
    def export_results(self, format_type: str = 'json') -> str:
        """
        Export scan results to string.
        
        Args:
            format_type: Export format (json, html, markdown)
            
        Returns:
            Exported results as string
        """
        if not self.scan_result:
            raise RuntimeError("No scan results to export")
        
        if format_type == 'json':
            import json
            return json.dumps(self.scan_result.to_dict(), indent=2)
        
        elif format_type == 'html':
            return self._export_html()
        
        elif format_type == 'markdown':
            return self._export_markdown()
        
        else:
            raise ValueError(f"Unsupported export format: {format_type}")
    
    def _export_html(self) -> str:
        """Export results as HTML report."""
        score = self.get_score()
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Secure My Site - Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #1a1a1a; color: #fff; }}
        .header {{ background: #2d2d2d; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .score {{ font-size: 48px; font-weight: bold; color: {score.get('color', '#00d084') if score else '#00d084'}; }}
        .risk-level {{ font-size: 24px; color: #a0a0a0; }}
        .vulnerability {{ background: #2d2d2d; padding: 15px; margin: 10px 0; border-radius: 6px; border-left: 4px solid #ff4444; }}
        .severity-critical {{ border-color: #ff4444; }}
        .severity-high {{ border-color: #ff8800; }}
        .severity-medium {{ border-color: #ffcc00; }}
        .severity-low {{ border-color: #00ccff; }}
        .code {{ background: #1a1a1a; padding: 10px; border-radius: 4px; font-family: monospace; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Analysis Report</h1>
        <div class="score">Score: {score['score'] if score else 'N/A'}/100</div>
        <div class="risk-level">Risk Level: {score['risk_level'] if score else 'Unknown'}</div>
        <p>Project: {self.project_path}</p>
        <p>Files Scanned: {self.scan_result.files_scanned}</p>
        <p>Vulnerabilities: {len(self.scan_result.vulnerabilities)}</p>
    </div>
    
    <h2>Vulnerabilities</h2>
"""
        
        for vuln in self.scan_result.vulnerabilities:
            severity_class = f"severity-{vuln.severity.name.lower()}"
            html += f"""
    <div class="vulnerability {severity_class}">
        <h3>[{vuln.severity.name}] {vuln.title}</h3>
        <p><strong>Location:</strong> {vuln.get_location_string()}</p>
        <p><strong>Description:</strong> {vuln.description}</p>
        <p><strong>Remediation:</strong> {vuln.remediation}</p>
        {f'<div class="code"><pre>{vuln.code_snippet}</pre></div>' if vuln.code_snippet else ''}
    </div>
"""
        
        html += """
</body>
</html>
"""
        return html
    
    def _export_markdown(self) -> str:
        """Export results as Markdown report."""
        score = self.get_score()
        
        md = f"""# Security Analysis Report

## Summary

- **Score:** {score['score'] if score else 'N/A'}/100
- **Risk Level:** {score['risk_level'] if score else 'Unknown'}
- **Grade:** {score['grade'] if score else 'N/A'}
- **Project:** {self.project_path}
- **Files Scanned:** {self.scan_result.files_scanned}
- **Total Vulnerabilities:** {len(self.scan_result.vulnerabilities)}

## Breakdown

| Severity | Count |
|----------|-------|
| CRITICAL | {score['breakdown']['critical_count'] if score else 0} |
| HIGH | {score['breakdown']['high_count'] if score else 0} |
| MEDIUM | {score['breakdown']['medium_count'] if score else 0} |
| LOW | {score['breakdown']['low_count'] if score else 0} |

## Vulnerabilities

"""
        
        for vuln in self.scan_result.vulnerabilities:
            md += f"""
### [{vuln.severity.name}] {vuln.title}

**Location:** {vuln.get_location_string()}

**Description:** {vuln.description}

**Remediation:** {vuln.remediation}

"""
            if vuln.code_snippet:
                md += f"""**Code:**
```{vuln.code_snippet[:20]}
{vuln.code_snippet}
```

"""
        
        if score and score.get('recommendations'):
            md += "## Recommendations\n\n"
            for rec in score['recommendations']:
                md += f"- {rec}\n"
        
        return md
