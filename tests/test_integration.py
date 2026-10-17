"""End-to-end tests against the sample vulnerable project."""

from core.engine import AnalysisEngine
from models.vulnerability import Severity


def test_sample_project_detects_known_issues(sample_project):
    result = AnalysisEngine(sample_project).analyze()
    found = {(v.metadata["relative_path"], v.line_number, v.title) for v in result.vulnerabilities}

    expected = {
        ("app.py", 8, "Debug Mode Enabled"),
        ("app.py", 9, "Hardcoded Secret Key"),
        ("app.py", 18, "SQL Injection"),
        ("app.py", 26, "Command Injection via os.system()"),
        ("app.py", 34, "Server-Side Template Injection"),
        ("app.py", 41, "Dynamic Code Execution"),
        ("app.py", 45, "Flask Debug Mode"),
        ("static/app.js", 6, "DOM XSS via innerHTML"),
        ("static/app.js", 16, "Code Injection via eval()"),
        ("static/app.js", 21, "Sensitive Token in Web Storage"),
    }
    missing = expected - found
    assert not missing, f"missing findings: {missing}"

    deps = [v for v in result.vulnerabilities if v.scanner_source == "dependency_scanner"]
    assert {v.metadata["package"] for v in deps} >= {"django", "flask", "pyyaml", "pillow"}
    # Several advisories on one requirement line must not be collapsed by de-duplication
    django_cves = {v.metadata["cve"] for v in deps if v.metadata["package"] == "django"}
    assert django_cves == {"CVE-2021-31542", "CVE-2021-35042"}


def test_results_sorted_and_scored(sample_project):
    result = AnalysisEngine(sample_project).analyze()
    severities = [v.severity.value for v in result.vulnerabilities]
    assert severities == sorted(severities)
    score = result.metadata["score"]
    assert score["grade"] == "F"
    assert score["breakdown"]["critical_count"] == result.get_critical_count()
    assert result.files_scanned == 3
    assert not result.errors


def test_no_duplicate_findings(sample_project):
    result = AnalysisEngine(sample_project).analyze()
    keys = [(str(v.file_path), v.line_number, v.cwe_id or v.title, v.metadata.get("cve"))
            for v in result.vulnerabilities]
    assert len(keys) == len(set(keys))


def test_secrets_are_masked_everywhere(sample_project):
    result = AnalysisEngine(sample_project).analyze()
    blob = " ".join((v.code_snippet or "") + str(v.metadata) for v in result.vulnerabilities)
    assert "sk_test_FAKEKEY1234567890ABCDEFGHIJKLMNO" not in blob
    assert "hardcoded-secret-key-12345" not in blob
    assert any(v.severity == Severity.CRITICAL for v in result.vulnerabilities)
