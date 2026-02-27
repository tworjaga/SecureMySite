"""Helper utility functions."""

import re
from pathlib import Path
from typing import Optional


def format_size(size_bytes: int) -> str:
    """
    Format byte size to human readable string.
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"


def truncate_string(text: str, max_length: int, suffix: str = "...") -> str:
    """
    Truncate string to maximum length.
    
    Args:
        text: Input string
        max_length: Maximum length
        suffix: Suffix to add if truncated
        
    Returns:
        Truncated string
    """
    if len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for safe file system usage.
    
    Removes or replaces dangerous characters.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    # Replace dangerous characters
    sanitized = re.sub(r'[<>:\"/\\|?*]', '_', filename)
    
    # Remove control characters
    sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', sanitized)
    
    # Trim whitespace
    sanitized = sanitized.strip()
    
    # Ensure not empty
    if not sanitized:
        sanitized = "unnamed"
    
    # Limit length
    if len(sanitized) > 255:
        name, ext = Path(sanitized).stem, Path(sanitized).suffix
        sanitized = name[:255 - len(ext)] + ext
    
    return sanitized


def get_line_count(content: str) -> int:
    """Count lines in content."""
    return content.count('\n') + 1


def get_file_extension(filename: str) -> str:
    """Get lowercase file extension."""
    return Path(filename).suffix.lower()


def is_text_file(file_path: Path) -> bool:
    """
    Check if file is a text file.
    
    Reads first 1024 bytes and checks for null bytes.
    """
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
            return b'\x00' not in chunk
    except Exception:
        return False


def pluralize(count: int, singular: str, plural: Optional[str] = None) -> str:
    """
    Return singular or plural form based on count.
    
    Args:
        count: Number to check
        singular: Singular form
        plural: Optional plural form (defaults to singular + 's')
        
    Returns:
        Appropriate form
    """
    if count == 1:
        return f"{count} {singular}"
    
    if plural is None:
        plural = singular + 's'
    
    return f"{count} {plural}"


def format_duration(seconds: float) -> str:
    """
    Format duration in seconds to human readable string.
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Formatted string
    """
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    elif seconds < 60:
        return f"{seconds:.1f} s"
    elif seconds < 3600:
        minutes = int(seconds / 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds / 3600)
        minutes = int((seconds % 3600) / 60)
        return f"{hours}h {minutes}m"


def mask_sensitive_data(text: str, patterns: Optional[list] = None) -> str:
    """
    Mask potentially sensitive data in text.
    
    Args:
        text: Input text
        patterns: Optional list of regex patterns to mask
        
    Returns:
        Masked text
    """
    if patterns is None:
        # Default patterns for common secrets
        patterns = [
            (r'(password|secret|key|token)\s*[=:]\s*["\'][^"\']+["\']', r'\\1=***'),
            (r'[a-zA-Z0-9_-]*_API_KEY["\']?\s*[=:]\s*["\'][a-zA-Z0-9]{20,}["\']', 'API_KEY=***'),
            (r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----.*?-----END', '***PRIVATE KEY***'),
        ]
    
    masked = text
    for pattern, replacement in patterns:
        masked = re.sub(pattern, replacement, masked, flags=re.IGNORECASE | re.DOTALL)
    
    return masked


def calculate_percentage(part: int, total: int) -> float:
    """Calculate percentage safely."""
    if total == 0:
        return 0.0
    return (part / total) * 100


def chunk_list(lst: list, chunk_size: int):
    """Split list into chunks."""
    for i in range(0, len(lst), chunk_size):
        yield lst[i:i + chunk_size]


def safe_json_dumps(obj, **kwargs) -> str:
    """Safely dump object to JSON string."""
    import json
    from datetime import datetime
    
    def default_serializer(o):
        if isinstance(o, datetime):
            return o.isoformat()
        if isinstance(o, Path):
            return str(o)
        raise TypeError(f"Object of type {type(o)} is not JSON serializable")
    
    return json.dumps(obj, default=default_serializer, **kwargs)
