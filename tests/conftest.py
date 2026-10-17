"""Shared pytest fixtures."""

import os
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# GUI tests run headless
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

SAMPLE_PROJECT = ROOT / "tests" / "sample_vulnerable_project"


@pytest.fixture
def sample_project() -> Path:
    return SAMPLE_PROJECT


@pytest.fixture
def make_project(tmp_path):
    """Create a project from a {relative_path: content} mapping."""
    def _make(files: dict) -> Path:
        for rel, content in files.items():
            path = tmp_path / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(textwrap.dedent(content).lstrip("\n"), encoding="utf-8")
        return tmp_path
    return _make


def scan_file(scanner, project: Path, rel: str):
    """Run a single scanner over one file of a project."""
    from scanners.base_scanner import ScanContext
    path = project / rel
    return scanner.scan(ScanContext(
        project_path=project,
        file_path=path,
        file_content=path.read_text(encoding="utf-8"),
    ))


def titles(vulns):
    return [v.title for v in vulns]
