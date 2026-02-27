"""Scan result container for SecureMySite."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

from .vulnerability import Vulnerability, Severity


@dataclass
class ScanResult:
    """
    Container for aggregate scan results.
    
    Attributes:
        project_path: Path to scanned project
        vulnerabilities: List of detected vulnerabilities
        scan_start_time: When scan started
        scan_end_time: When scan completed
        files_scanned: Number of files analyzed
        scanners_used: List of scanner names that ran
        errors: List of errors encountered during scan
        metadata: Additional scan metadata
    """
    project_path: Path
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    scan_start_time: datetime = field(default_factory=datetime.now)
    scan_end_time: Optional[datetime] = None
    files_scanned: int = 0
    scanners_used: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_vulnerability(self, vulnerability: Vulnerability) -> None:
        """Add a vulnerability to results."""
        self.vulnerabilities.append(vulnerability)
    
    def add_error(self, error: str) -> None:
        """Add an error message."""
        self.errors.append(error)
    
    def complete_scan(self) -> None:
        """Mark scan as complete."""
        self.scan_end_time = datetime.now()
    
    def get_duration_seconds(self) -> float:
        """Get scan duration in seconds."""
        if not self.scan_end_time:
            return 0.0
        return (self.scan_end_time - self.scan_start_time).total_seconds()
    
    def get_vulnerabilities_by_severity(self, severity: Severity) -> List[Vulnerability]:
        """Get vulnerabilities filtered by severity."""
        return [v for v in self.vulnerabilities if v.severity == severity]
    
    def get_critical_count(self) -> int:
        """Count critical vulnerabilities."""
        return len(self.get_vulnerabilities_by_severity(Severity.CRITICAL))
    
    def get_high_count(self) -> int:
        """Count high severity vulnerabilities."""
        return len(self.get_vulnerabilities_by_severity(Severity.HIGH))
    
    def get_medium_count(self) -> int:
        """Count medium severity vulnerabilities."""
        return len(self.get_vulnerabilities_by_severity(Severity.MEDIUM))
    
    def get_low_count(self) -> int:
        """Count low severity vulnerabilities."""
        return len(self.get_vulnerabilities_by_severity(Severity.LOW))
    
    def get_unique_vulnerabilities(self) -> List[Vulnerability]:
        """Get deduplicated list of vulnerabilities."""
        seen = set()
        unique = []
        for vuln in self.vulnerabilities:
            key = (str(vuln.file_path), vuln.line_number, vuln.title)
            if key not in seen:
                seen.add(key)
                unique.append(vuln)
        return unique
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            'project_path': str(self.project_path),
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'scan_start_time': self.scan_start_time.isoformat(),
            'scan_end_time': self.scan_end_time.isoformat() if self.scan_end_time else None,
            'files_scanned': self.files_scanned,
            'scanners_used': self.scanners_used,
            'errors': self.errors,
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanResult':
        """Create ScanResult from dictionary."""
        result = cls(
            project_path=Path(data['project_path']),
            vulnerabilities=[Vulnerability.from_dict(v) for v in data.get('vulnerabilities', [])],
            scan_start_time=datetime.fromisoformat(data['scan_start_time']),
            scan_end_time=datetime.fromisoformat(data['scan_end_time']) if data.get('scan_end_time') else None,
            files_scanned=data.get('files_scanned', 0),
            scanners_used=data.get('scanners_used', []),
            errors=data.get('errors', []),
            metadata=data.get('metadata', {})
        )
        return result
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics."""
        unique = self.get_unique_vulnerabilities()
        return {
            'total_vulnerabilities': len(unique),
            'critical': self.get_critical_count(),
            'high': self.get_high_count(),
            'medium': self.get_medium_count(),
            'low': self.get_low_count(),
            'files_scanned': self.files_scanned,
            'scanners_used': len(self.scanners_used),
            'errors': len(self.errors),
            'duration_seconds': self.get_duration_seconds()
        }
