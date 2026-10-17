"""Web scanner against a real local server, and the command-line interface."""

import json
import subprocess
import sys
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

import pytest

from scanners.base_scanner import ScanContext
from scanners.web_scanner import WebScanner
from tests.conftest import ROOT, titles


class _Handler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def end_headers(self):
        if self.path == "/":
            self.send_header("Set-Cookie", "sessionid=abc; Path=/")
            origin = self.headers.get("Origin")
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
        super().end_headers()


@pytest.fixture
def local_site(make_project):
    root = make_project({
        "index.html": "<h1>hello</h1>",
        ".env": "SECRET=1\n",
        ".git/config": "[core]\n\tbare = false\n",
    })
    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(_Handler, directory=str(root)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/"
    server.shutdown()


def test_web_scanner_live(local_site, tmp_path):
    vulns = WebScanner().scan(ScanContext(project_path=tmp_path, config={"url": local_site}))
    found = titles(vulns)
    assert "Missing Content Security Policy" in found
    assert "Exposed Sensitive Endpoint: /.env" in found
    assert "Exposed Sensitive Endpoint: /.git/config" in found
    assert "Sensitive Cookie Missing HttpOnly: sessionid" in found
    cors = next(v for v in vulns if v.title == "CORS Reflects Arbitrary Origin")
    assert cors.severity.name == "CRITICAL"


def test_web_scanner_refuses_remote_hosts(tmp_path):
    vulns = WebScanner().scan(ScanContext(project_path=tmp_path, config={"url": "http://example.com"}))
    assert titles(vulns) == ["Invalid URL for Web Scan"]


def _cli(*args):
    return subprocess.run(
        [sys.executable, str(ROOT / "main.py"), *args],
        capture_output=True, text=True, cwd=ROOT, timeout=120,
    )


def test_cli_exit_codes(sample_project, make_project):
    assert _cli(str(sample_project), "-q").returncode == 2
    clean = make_project({"app.py": "print('hi')\n"})
    assert _cli(str(clean), "-q").returncode == 0
    assert _cli(str(sample_project), "-q", "--fail-on", "none").returncode == 0
    assert _cli(str(sample_project), "-q", "--scanners", "javascript_scanner", "--fail-on", "critical").returncode == 1
    assert _cli("does-not-exist").returncode == 3


def test_cli_json_to_stdout(sample_project):
    proc = _cli(str(sample_project), "-q", "-e", "json", "-o", "-")
    data = json.loads(proc.stdout)
    assert data["summary"]["total_vulnerabilities"] == len(data["vulnerabilities"]) > 0


def test_cli_infers_format_from_extension(sample_project, tmp_path):
    out = tmp_path / "report.sarif"
    _cli(str(sample_project), "-q", "-o", str(out))
    assert json.loads(out.read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_cli_list_scanners():
    proc = _cli("--list-scanners")
    assert proc.returncode == 0
    for name in ("python_sast", "secrets_scanner", "iac_scanner", "html_scanner", "web_scanner"):
        assert name in proc.stdout


def test_cli_domain_guard_rails(sample_project):
    assert _cli("--domain", "example.com", "--active").returncode == 3          # needs --authorized
    assert _cli("--domain", "localhost").returncode == 3                         # local hosts refused
    assert _cli(str(sample_project), "--domain", "example.com").returncode == 3  # one mode at a time
    assert _cli(str(sample_project), "--active").returncode == 3                 # --active is domain-only
