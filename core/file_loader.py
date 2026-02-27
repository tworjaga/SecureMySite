"""Safe file loader with path traversal prevention."""

import os
import fnmatch
from pathlib import Path
from typing import List, Optional, Iterator, Tuple
import logging

from core.config import Config


class FileLoader:
    """
    Safe file loader with security constraints.
    
    Features:
    - Path traversal prevention
    - File size limits
    - Project size limits
    - Binary file detection
    - Exclusion pattern matching
    """
    
    def __init__(self, project_path: Path, config: Optional[Config] = None):
        """
        Initialize file loader.
        
        Args:
            project_path: Root path of project to scan
            config: Optional configuration override
        """
        self.project_path = Path(project_path).resolve()
        self.config = config or Config()
        self.logger = logging.getLogger(__name__)
        
        # Validate project path exists
        if not self.project_path.exists():
            raise FileNotFoundError(f"Project path does not exist: {project_path}")
        
        if not self.project_path.is_dir():
            raise NotADirectoryError(f"Project path is not a directory: {project_path}")
        
        # Track statistics
        self.files_scanned = 0
        self.files_skipped = 0
        self.total_size = 0
        self.errors: List[str] = []
    
    def load_files(self) -> Iterator[Tuple[Path, str]]:
        """
        Safely load all files in project.
        
        Yields:
            Tuple of (file_path, file_content)
        
        Raises:
            RuntimeError: If project size exceeds limit
        """
        project_size = self._calculate_project_size()
        
        if project_size > self.config.MAX_PROJECT_SIZE_BYTES:
            raise RuntimeError(
                f"Project size ({project_size / 1024 / 1024:.1f}MB) exceeds "
                f"maximum allowed ({self.config.MAX_PROJECT_SIZE_BYTES / 1024 / 1024:.1f}MB)"
            )
        
        file_count = 0
        
        for file_path in self._walk_files():
            # Check file count limit
            file_count += 1
            if file_count > self.config.MAX_FILES_TO_SCAN:
                self.logger.warning(f"Reached maximum file count limit: {self.config.MAX_FILES_TO_SCAN}")
                self.errors.append(f"Scan limited to {self.config.MAX_FILES_TO_SCAN} files")
                break
            
            # Check if file should be excluded
            if self._should_exclude(file_path):
                self.files_skipped += 1
                continue
            
            # Validate file is within project directory (path traversal check)
            if not self._is_within_project(file_path):
                self.logger.warning(f"Skipping file outside project: {file_path}")
                self.files_skipped += 1
                continue
            
            # Check file size
            try:
                file_size = file_path.stat().st_size
                if file_size > self.config.MAX_FILE_SIZE_BYTES:
                    self.logger.warning(f"Skipping large file: {file_path} ({file_size / 1024 / 1024:.1f}MB)")
                    self.errors.append(f"Skipped large file: {file_path.name}")
                    self.files_skipped += 1
                    continue
                
                self.total_size += file_size
            except OSError as e:
                self.logger.error(f"Cannot stat file {file_path}: {e}")
                self.errors.append(f"Cannot access file: {file_path.name}")
                continue
            
            # Check if binary
            if self._is_binary(file_path):
                self.logger.debug(f"Skipping binary file: {file_path}")
                self.files_skipped += 1
                continue
            
            # Read file content
            try:
                content = self._read_file(file_path)
                if content is not None:
                    self.files_scanned += 1
                    yield file_path, content
            except Exception as e:
                self.logger.error(f"Error reading file {file_path}: {e}")
                self.errors.append(f"Error reading: {file_path.name}")
    
    def _walk_files(self) -> Iterator[Path]:
        """Walk project directory yielding file paths."""
        try:
            for root, dirs, files in os.walk(self.project_path):
                # Filter out excluded directories
                dirs[:] = [
                    d for d in dirs 
                    if not self._should_exclude_dir(Path(root) / d)
                ]
                
                for filename in files:
                    yield Path(root) / filename
        except PermissionError as e:
            self.logger.error(f"Permission denied accessing directory: {e}")
            self.errors.append(f"Permission denied: {e}")
    
    def _should_exclude(self, file_path: Path) -> bool:
        """Check if file should be excluded."""
        # Check against exclude patterns
        relative_path = file_path.relative_to(self.project_path)
        path_str = str(relative_path)
        
        if self.config.should_exclude(path_str):
            return True
        
        # Check extension
        ext = file_path.suffix.lower()
        if ext and not self.config.is_supported_extension(ext):
            # Allow files with no extension (like .env)
            if ext:
                return True
        
        return False
    
    def _should_exclude_dir(self, dir_path: Path) -> bool:
        """Check if directory should be excluded."""
        relative_path = dir_path.relative_to(self.project_path)
        path_str = str(relative_path)
        
        # Check directory name against patterns
        for pattern in self.config.EXCLUDE_PATTERNS:
            if fnmatch.fnmatch(path_str, pattern):
                return True
            if fnmatch.fnmatch(dir_path.name, pattern):
                return True
        
        return False
    
    def _is_within_project(self, file_path: Path) -> bool:
        """
        Check if file is within project directory.
        
        Prevents path traversal attacks.
        """
        try:
            resolved_path = file_path.resolve()
            return str(resolved_path).startswith(str(self.project_path))
        except Exception:
            return False
    
    def _is_binary(self, file_path: Path) -> bool:
        """
        Check if file is binary.
        
        Reads first 1024 bytes and checks for null bytes.
        """
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                return b'\x00' in chunk
        except Exception:
            return True
    
    def _read_file(self, file_path: Path) -> Optional[str]:
        """
        Read file content as text.
        
        Tries multiple encodings.
        """
        encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
        
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    return f.read()
            except UnicodeDecodeError:
                continue
            except Exception as e:
                self.logger.error(f"Error reading {file_path} with {encoding}: {e}")
                return None
        
        return None
    
    def _calculate_project_size(self) -> int:
        """Calculate total size of project in bytes."""
        total_size = 0
        
        try:
            for root, dirs, files in os.walk(self.project_path):
                # Skip excluded directories
                dirs[:] = [
                    d for d in dirs 
                    if not self._should_exclude_dir(Path(root) / d)
                ]
                
                for filename in files:
                    file_path = Path(root) / filename
                    try:
                        total_size += file_path.stat().st_size
                    except OSError:
                        pass
        except Exception as e:
            self.logger.error(f"Error calculating project size: {e}")
        
        return total_size
    
    def get_statistics(self) -> dict:
        """Get loading statistics."""
        return {
            'files_scanned': self.files_scanned,
            'files_skipped': self.files_skipped,
            'total_size_bytes': self.total_size,
            'total_size_mb': self.total_size / 1024 / 1024,
            'errors': self.errors,
        }
    
    def get_file_language(self, file_path: Path) -> Optional[str]:
        """Get programming language for file based on extension."""
        ext = file_path.suffix.lower()
        return self.config.SUPPORTED_EXTENSIONS.get(ext)
