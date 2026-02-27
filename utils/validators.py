"""Input validation functions."""

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


def validate_url(url: str, allow_localhost_only: bool = True) -> Tuple[bool, Optional[str]]:
    """
    Validate URL format and optionally restrict to localhost.
    
    Args:
        url: URL to validate
        allow_localhost_only: If True, only allow localhost/127.0.0.1
        
    Returns:
        Tuple of (is_valid, error_message)
    """
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
        
        if allow_localhost_only:
            # Only allow localhost variants
            allowed_hosts = [
                'localhost',
                '127.0.0.1',
                '::1',
            ]
            
            hostname = parsed.hostname
            
            if hostname not in allowed_hosts and not hostname.startswith('127.'):
                if not hostname.endswith('.local'):
                    return False, f"Only localhost, 127.0.0.1, and *.local allowed. Got: {hostname}"
        
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
