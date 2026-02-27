"""SecureMySite data models."""
from .vulnerability import Vulnerability, Severity, Category
from .scan_result import ScanResult

__all__ = ['Vulnerability', 'Severity', 'Category', 'ScanResult']
