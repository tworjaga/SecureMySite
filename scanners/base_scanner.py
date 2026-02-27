"""Abstract base class for all security scanners."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from pathlib import Path

from models.vulnerability import Vulnerability


@dataclass
class ScanContext:
    """
    Context object passed to scanners during analysis.
    
    Contains project information and scan configuration.
    """
    project_path: Path
    file_path: Optional[Path] = None
    file_content: Optional[str] = None
    language: Optional[str] = None
    config: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.config is None:
            self.config = {}
    
    def is_valid(self) -> bool:
        """Check if context has required information."""
        return self.project_path is not None


class BaseScanner(ABC):
    """
    Abstract base class for all security scanners.
    
    All scanners must implement:
    - get_name(): Return scanner identifier
    - get_description(): Return human-readable description
    - scan(): Perform analysis and return vulnerabilities
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize scanner with optional configuration.
        
        Args:
            config: Scanner-specific configuration options
        """
        self.config = config or {}
        self._enabled = self.config.get('enabled', True)
        self._weight = self.config.get('weight', 1.0)
    
    @abstractmethod
    def get_name(self) -> str:
        """Return unique scanner identifier."""
        pass
    
    @abstractmethod
    def get_description(self) -> str:
        """Return human-readable scanner description."""
        pass
    
    @abstractmethod
    def scan(self, context: ScanContext) -> List[Vulnerability]:
        """
        Perform security analysis.
        
        Args:
            context: ScanContext with project/file information
            
        Returns:
            List of detected vulnerabilities
        """
        pass
    
    def is_enabled(self) -> bool:
        """Check if scanner is enabled."""
        return self._enabled
    
    def set_enabled(self, enabled: bool) -> None:
        """Enable or disable scanner."""
        self._enabled = enabled
    
    def get_weight(self) -> float:
        """Get scanner weight for scoring."""
        return self._weight
    
    def set_weight(self, weight: float) -> None:
        """Set scanner weight."""
        self._weight = max(0.0, min(2.0, weight))
    
    def get_supported_languages(self) -> List[str]:
        """
        Return list of languages this scanner supports.
        
        Override in subclass to specify supported languages.
        """
        return []
    
    def can_scan_file(self, file_path: Path) -> bool:
        """
        Check if this scanner can analyze a specific file.
        
        Args:
            file_path: Path to file to check
            
        Returns:
            True if scanner can analyze this file type
        """
        if not file_path:
            return False
        
        # Check file extension against supported languages
        ext = file_path.suffix.lower()
        lang_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.jsx': 'javascript',
            '.ts': 'typescript',
            '.tsx': 'typescript',
            '.html': 'html',
            '.htm': 'html',
            '.json': 'json',
            '.yaml': 'yaml',
            '.yml': 'yaml',
            '.toml': 'toml',
            '.ini': 'ini',
            '.cfg': 'config',
            '.env': 'env',
            '.txt': 'text',
        }
        
        language = lang_map.get(ext)
        if language:
            return language in self.get_supported_languages()
        
        return False
    
    def extract_code_snippet(
        self,
        content: str,
        line_number: int,
        context_lines: int = 2
    ) -> str:
        """
        Extract code snippet around specific line.
        
        Args:
            content: Full file content
            line_number: Target line number (1-indexed)
            context_lines: Number of lines before and after
            
        Returns:
            Code snippet as string
        """
        lines = content.split('\n')
        if not lines or line_number < 1 or line_number > len(lines):
            return ""
        
        # Convert to 0-indexed
        target_idx = line_number - 1
        
        # Calculate range
        start_idx = max(0, target_idx - context_lines)
        end_idx = min(len(lines), target_idx + context_lines + 1)
        
        # Extract lines
        snippet_lines = lines[start_idx:end_idx]
        
        # Add line numbers
        numbered_lines = []
        for i, line in enumerate(snippet_lines, start=start_idx + 1):
            prefix = ">>> " if i == line_number else "    "
            numbered_lines.append(f"{prefix}{i:4d}: {line}")
        
        return '\n'.join(numbered_lines)
    
    def create_vulnerability(
        self,
        title: str,
        description: str,
        severity,
        category,
        line_number: Optional[int] = None,
        code_snippet: Optional[str] = None,
        remediation: Optional[str] = None,
        cwe_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Vulnerability:
        """
        Create a Vulnerability object with scanner source preset.
        
        Args:
            title: Vulnerability title
            description: Detailed description
            severity: Severity level
            category: Category
            line_number: Line where issue occurs
            code_snippet: Affected code
            remediation: Fix instructions
            cwe_id: CWE identifier
            metadata: Additional data
            
        Returns:
            Configured Vulnerability instance
        """
        from models.vulnerability import Vulnerability
        
        return Vulnerability(
            title=title,
            description=description,
            severity=severity,
            category=category,
            file_path=None,  # Set by caller
            line_number=line_number,
            code_snippet=code_snippet,
            remediation=remediation or "Review and fix the identified issue",
            cwe_id=cwe_id,
            scanner_source=self.get_name(),
            metadata=metadata or {}
        )
    
    def log_debug(self, message: str) -> None:
        """Log debug message if debug mode enabled."""
        if self.config.get('debug', False):
            print(f"[{self.get_name()}] DEBUG: {message}")
    
    def log_error(self, message: str) -> None:
        """Log error message."""
        print(f"[{self.get_name()}] ERROR: {message}")
