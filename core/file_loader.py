"""Safe file loader with path traversal prevention."""

import os
import fnmatch
from pathlib import Path
from typing import List, Optional, Iterator, Tuple, Callable
import logging

from core.config import Config


IGNORE_FILE_NAME = '.securemysiteignore'


class FileLoader:
    """
    Safe file loader with security constraints.

    Features:
    - Path traversal prevention
    - File size limits
    - Project size limits
    - Binary file detection
    - Exclusion pattern matching (built-in + .securemysiteignore)
    """

    def __init__(
        self,
        project_path: Path,
        config: Optional[Config] = None,
        extra_excludes: Optional[List[str]] = None
    ):
        """
        Initialize file loader.

        Args:
            project_path: Root path of project to scan
            config: Optional configuration override
            extra_excludes: Additional glob patterns (relative paths) to skip
        """
        self.project_path = Path(project_path).resolve()
        self.config = config or Config()
        self.logger = logging.getLogger(__name__)

        # Validate project path exists
        if not self.project_path.exists():
            raise FileNotFoundError(f"Project path does not exist: {project_path}")

        if not self.project_path.is_dir():
            raise NotADirectoryError(f"Project path is not a directory: {project_path}")

        # User-defined ignore globs
        self.ignore_patterns: List[str] = list(extra_excludes or [])
        self.ignore_patterns.extend(self._load_ignore_file())

        # Track statistics
        self.files_scanned = 0
        self.files_skipped = 0
        self.total_size = 0
        self.errors: List[str] = []

    def _load_ignore_file(self) -> List[str]:
        """Load glob patterns from .securemysiteignore (gitignore-like, one per line)."""
        ignore_file = self.project_path / IGNORE_FILE_NAME
        if not ignore_file.is_file():
            return []

        patterns = []
        try:
            for line in ignore_file.read_text(encoding='utf-8', errors='replace').splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    patterns.append(line.replace('\\', '/').rstrip('/'))
        except OSError as e:
            self.logger.warning(f"Could not read {IGNORE_FILE_NAME}: {e}")
        return patterns

    def _matches_ignore(self, rel_path: str) -> bool:
        """Check a project-relative POSIX path against user ignore globs."""
        if not self.ignore_patterns:
            return False
        name = rel_path.rsplit('/', 1)[-1]
        for pattern in self.ignore_patterns:
            anchored = pattern.lstrip('/')
            if (
                fnmatch.fnmatch(rel_path, anchored)
                or rel_path.startswith(anchored + '/')
                or ('/' not in pattern and fnmatch.fnmatch(name, pattern))
            ):
                return True
        return False

    def count_files(self) -> int:
        """Count candidate files (for progress reporting)."""
        return sum(1 for f in self._walk_files() if not self._should_exclude(f))

    def load_files(
        self,
        progress_callback: Optional[Callable[[int, Path], None]] = None
    ) -> Iterator[Tuple[Path, str]]:
        """
        Safely load all files in project.

        Args:
            progress_callback: Optional callable(index, path) invoked per file

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
            # Check if file should be excluded
            if self._should_exclude(file_path):
                self.files_skipped += 1
                continue

            # Check file count limit
            file_count += 1
            if file_count > self.config.MAX_FILES_TO_SCAN:
                self.logger.warning(f"Reached maximum file count limit: {self.config.MAX_FILES_TO_SCAN}")
                self.errors.append(f"Scan limited to {self.config.MAX_FILES_TO_SCAN} files")
                break

            if progress_callback:
                progress_callback(file_count, file_path)

            # Validate file is within project directory (path traversal / symlink check)
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
        def on_error(err: OSError) -> None:
            self.logger.error(f"Cannot access directory: {err}")
            self.errors.append(f"Permission denied: {err.filename}")

        for root, dirs, files in os.walk(self.project_path, onerror=on_error):
            # Filter out excluded directories (sorted for deterministic output)
            dirs[:] = sorted(
                d for d in dirs
                if not self._should_exclude_dir(Path(root) / d)
            )

            for filename in sorted(files):
                yield Path(root) / filename

    def _relative_posix(self, path: Path) -> str:
        return path.relative_to(self.project_path).as_posix()

    def _should_exclude(self, file_path: Path) -> bool:
        """Check if file should be excluded."""
        rel = self._relative_posix(file_path)

        if self.config.should_exclude(rel):
            return True

        if file_path.name == IGNORE_FILE_NAME or self._matches_ignore(rel):
            return True

        # Only scan file types we understand (Dockerfile, .env.* etc. included)
        return self.config.get_language(file_path.name) is None

    def _should_exclude_dir(self, dir_path: Path) -> bool:
        """Check if directory should be excluded."""
        if self.config.is_excluded_dir_name(dir_path.name):
            return True

        rel = self._relative_posix(dir_path)
        if self.config.should_exclude(rel + '/x') or self._matches_ignore(rel):
            return True

        # Any Python virtualenv, whatever it is called (.env, .venv-3.12, ...)
        if (dir_path / 'pyvenv.cfg').is_file():
            return True

        return False

    def _is_within_project(self, file_path: Path) -> bool:
        """
        Check if file is within project directory.

        Prevents path traversal attacks via symlinks.
        """
        try:
            return file_path.resolve().is_relative_to(self.project_path)
        except (OSError, RuntimeError):
            return False

    def _is_binary(self, file_path: Path) -> bool:
        """
        Check if file is binary.

        Reads first 8KB and checks for null bytes.
        """
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(8192)
                return b'\x00' in chunk
        except OSError:
            return True

    def _read_file(self, file_path: Path) -> Optional[str]:
        """
        Read file content as text.

        Tries UTF-8 (with BOM handling) first, then falls back to cp1252/latin-1.
        """
        try:
            raw = file_path.read_bytes()
        except OSError as e:
            self.logger.error(f"Error reading {file_path}: {e}")
            return None

        for encoding in ('utf-8-sig', 'cp1252'):
            try:
                return raw.decode(encoding)
            except UnicodeDecodeError:
                continue
        # latin-1 never fails
        return raw.decode('latin-1')

    def _calculate_project_size(self) -> int:
        """Calculate total size of scannable files in bytes."""
        total_size = 0

        for file_path in self._walk_files():
            try:
                total_size += file_path.stat().st_size
            except OSError:
                pass

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
        """Get programming language for file based on its name/extension."""
        return self.config.get_language(file_path.name)
