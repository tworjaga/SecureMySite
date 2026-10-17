"""Input validation functions."""

import ipaddress
import re
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlparse


def validate_project_path(path: str) -> Tuple[bool, Optional[str]]:
    """
    Validate project path.
    
    Args:
        path: Path to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not path or not path.strip():
        return False, "Path is required"
    
    try:
        p = Path(path)

        
        if not p.exists():
            return False, f"Path does not exist: {path}"
        
        if not p.is_dir():
            return False, f"Path is not a directory: {path}"
        
        # Check if readable
        try:
            next(p.iterdir())
        except PermissionError:
            return False, f"Permission denied: {path}"
        except StopIteration:
            # Empty directory is valid
            pass
        
        return True, None
        
    except Exception as e:
        return False, f"Invalid path: {e}"


def is_local_hostname(hostname: Optional[str]) -> bool:
    """True for loopback addresses, 'localhost', *.localhost and mDNS *.local names."""
    if not hostname:
        return False
    hostname = hostname.strip('[]').rstrip('.').lower()
    if hostname == 'localhost' or hostname.endswith('.localhost') or hostname.endswith('.local'):
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


_LABEL_RE = re.compile(r'^(?!-)[a-z0-9-]{1,63}(?<!-)$')


def normalize_domain(text: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Turn user input ("https://Example.com/path", "www.example.com.") into a hostname.

    Returns:
        (hostname, None) on success, (None, error message) otherwise
    """
    raw = (text or '').strip()
    if not raw:
        return None, "Enter a domain, e.g. example.com"
    if '://' not in raw:
        raw = 'https://' + raw
    try:
        host = urlparse(raw).hostname
    except ValueError as e:
        return None, f"Invalid domain: {e}"
    if not host:
        return None, "Enter a domain, e.g. example.com"
    host = host.rstrip('.').lower()
    try:
        ipaddress.ip_address(host)
        return None, "Enter a domain name rather than an IP address"
    except ValueError:
        pass
    if is_local_hostname(host):
        return None, "Local hosts are scanned with the local URL option, not the domain scan"
    try:
        host = host.encode('idna').decode('ascii')
    except UnicodeError:
        return None, f"Invalid internationalized domain: {host}"
    labels = host.split('.')
    if len(labels) < 2 or len(host) > 253 or not all(_LABEL_RE.match(label) for label in labels):
        return None, f"Not a valid domain name: {host}"
    if labels[-1].isdigit():
        return None, f"Not a valid domain name: {host}"
    return host, None


def validate_url(url: str, allow_localhost_only: bool = True) -> Tuple[bool, Optional[str]]:
    """
    Validate URL format and optionally restrict to localhost.
    
    Args:
        url: URL to validate
        allow_localhost_only: If True, only allow localhost/127.0.0.1
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not url or not url.strip():
        return False, "URL is required"
    
    try:
        parsed = urlparse(url)
        
        # Check scheme
        if not parsed.scheme:
            return False, "URL missing scheme (http:// or https://)"

        
        if parsed.scheme not in ('http', 'https'):
            return False, f"Invalid scheme: {parsed.scheme}. Use http:// or https://"
        
        # Check hostname
        if not parsed.hostname:
            return False, "URL missing hostname"
        
        if allow_localhost_only and not is_local_hostname(parsed.hostname):
            return False, f"Only localhost, 127.0.0.0/8, ::1 and *.localhost / *.local allowed. Got: {parsed.hostname}"

        # Accessing .port raises ValueError for out-of-range ports
        _ = parsed.port
        
        return True, None
        
    except Exception as e:
        return False, f"Invalid URL: {e}"


def is_valid_extension(filename: str, allowed_extensions: Optional[set] = None) -> bool:
    """
    Check if file has valid extension.
    
    Args:
        filename: Filename to check
        allowed_extensions: Set of allowed extensions (with dot)
        
    Returns:
        True if extension is valid
    """
    if allowed_extensions is None:
        from core.config import Config
        allowed_extensions = set(Config.SUPPORTED_EXTENSIONS.keys())
    
    ext = Path(filename).suffix.lower()
    return ext in allowed_extensions


def validate_email(email: str) -> bool:
    """
    Validate email address format.
    
    Args:
        email: Email to validate
        
    Returns:
        True if valid format
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_filename(filename: str) -> Tuple[bool, Optional[str]]:
    """
    Validate filename for safe usage.
    
    Args:
        filename: Filename to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not filename:
        return False, "Filename cannot be empty"
    
    # Check for dangerous characters
    dangerous = ['<', '>', ':', '"', '/', '\\', '|', '?', '*']
    for char in dangerous:
        if char in filename:
            return False, f"Filename contains invalid character: {char}"
    
    # Check for reserved names (Windows)
    reserved = [
        'CON', 'PRN', 'AUX', 'NUL',
        'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
        'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9',
    ]
    name_upper = Path(filename).stem.upper()
    if name_upper in reserved:
        return False, f"Filename is reserved: {filename}"
    
    # Check length
    if len(filename) > 255:
        return False, "Filename too long (max 255 characters)"
    
    return True, None


def validate_scan_config(config: dict) -> Tuple[bool, Optional[str]]:
    """
    Validate scan configuration.
    
    Args:
        config: Configuration dictionary
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    # Check enabled_scanners
    if 'enabled_scanners' in config:
        scanners = config['enabled_scanners']
        if not isinstance(scanners, list):
            return False, "enabled_scanners must be a list"
        
        valid_scanners = {
            'python_sast',
            'javascript_scanner',
            'config_scanner',
            'dependency_scanner',
            'web_scanner',
        }
        
        for scanner in scanners:
            if scanner not in valid_scanners:
                return False, f"Unknown scanner: {scanner}"
    
    # Check web URL if provided
    if 'url' in config:
        is_valid, error = validate_url(config['url'])
        if not is_valid:
            return False, f"Invalid URL in config: {error}"
    
    return True, None


def is_safe_path(path: str, base_path: str) -> bool:
    """
    Check if path is within base_path (prevents path traversal).
    
    Args:
        path: Path to check
        base_path: Base directory that path should be within
        
    Returns:
        True if path is safe
    """
    try:
        # Resolve both paths
        resolved_path = Path(path).resolve()
        resolved_base = Path(base_path).resolve()
        
        # Check if path starts with base
        return str(resolved_path).startswith(str(resolved_base))
    except Exception:
        return False


def validate_port(port: int) -> bool:
    """Validate port number."""
    return isinstance(port, int) and 1 <= port <= 65535


def validate_timeout(timeout: int, max_timeout: int = 3600) -> bool:
    """Validate timeout value."""
    return isinstance(timeout, int) and 0 < timeout <= max_timeout
