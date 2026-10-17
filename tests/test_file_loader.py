"""Engine features (suppression, baseline, filtering), scoring and report formats."""

import csv
import io
import json

from core.engine import AnalysisEngine
from core import reporter
from models.vulnerability import Vulnerability, Severity, Category
from scoring.score_engine import ScoreEngine
from utils.validators import validate_url


def test_inline_suppression(make_project):
    project = make_project({"app.py": '''
        eval(a)  # securemysite: ignore
        # securemysite: ignore-next-line
        eval(b)
        eval(c)  # nosec
        eval(d)
    '''})
    result = AnalysisEngine(project).analyze()
    assert [v.line_number for v in result.vulnerabilities] == [5]
    assert result.metadata["suppressed"] == 3


def test_min_severity_filter(sample_project):
    result = AnalysisEngine(sample_project, scanner_config={"min_severity": "critical"}).analyze()
    assert result.vulnerabilities
    assert all(v.severity == Severity.CRITICAL for v in result.vulnerabilities)
    assert result.metadata["filtered_by_severity"] > 0


def test_baseline_hides_known_findings(make_project, tmp_path):
    project = make_project({"app.py": "eval(a)\n"})
    engine = AnalysisEngine(project)
    engine.analyze()
    baseline = tmp_path / "baseline.json"
    baseline.write_text(engine.export_results("json"), encoding="utf-8")

    # Insert lines above: fingerprints are line-number independent
    (project / "app.py").write_text("import os\n\neval(a)\nexec(b)\n", encoding="utf-8")
    result = AnalysisEngine(project, scanner_config={"baseline": str(baseline)}).analyze()
    assert [v.line_number for v in result.vulnerabilities] == [4]
    assert result.metadata["baseline_hidden"] == 1


def test_scanner_selection(sample_project):
    result = AnalysisEngine(sample_project, scanner_config={"enabled_scanners": ["javascript_scanner"]}).analyze()
    assert {v.scanner_source for v in result.vulnerabilities} == {"javascript_scanner"}


def test_cancel_stops_scan(sample_project):
    engine = AnalysisEngine(sample_project)
    engine.analyze(progress=lambda *a: engine.cancel())
    assert engine.scan_result.metadata["cancelled"]


# ----------------------------------------------------------------- scoring

_counter = iter(range(10**6))


def _vuln(severity):
    return Vulnerability(title=f"finding-{next(_counter)}", description="d", severity=severity,
                         category=Category.INJECTION, remediation="r", scanner_source="s")


def test_score_caps_keep_progress_visible():
    engine = ScoreEngine()
    many_low = [_vuln(Severity.LOW) for _ in range(50)]
    assert engine.calculate(many_low).score == 90
    one_critical = engine.calculate([_vuln(Severity.CRITICAL)])
    assert one_critical.score <= 49
    assert engine.calculate([]).score == 100


# ----------------------------------------------------------------- reports

def _xss_result(make_project):
    project = make_project({"x.js": "el.innerHTML = '<img src=x onerror=alert(1)>' + location.hash;\n"})
    return AnalysisEngine(project).analyze()


def test_html_report_escapes_content(make_project):
    html = reporter.to_html(_xss_result(make_project))
    assert "<img src=x onerror" not in html
    assert "&lt;img src=x onerror" in html


def test_sarif_structure(sample_project):
    result = AnalysisEngine(sample_project).analyze()
    sarif = json.loads(reporter.to_sarif(result))
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert len(run["results"]) == len(result.vulnerabilities)
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for res in run["results"]:
        assert res["ruleId"] in rule_ids
        loc = res["locations"][0]["physicalLocation"]
        assert not loc["artifactLocation"]["uri"].startswith(("C:", "/"))


def test_csv_and_markdown(sample_project):
    result = AnalysisEngine(sample_project).analyze()
    rows = list(csv.DictReader(io.StringIO(reporter.to_csv(result))))
    assert len(rows) == len(result.vulnerabilities)
    assert rows[0]["severity"] == "CRITICAL"
    md = reporter.to_markdown(result)
    assert md.startswith("# Security Analysis Report")
    json.loads(reporter.to_json(result))


# ----------------------------------------------------------------- validators

def test_localhost_validation_blocks_lookalikes():
    assert validate_url("http://localhost:3000")[0]
    assert validate_url("http://127.0.0.5")[0]
    assert validate_url("http://[::1]:8080")[0]
    assert validate_url("http://app.localhost")[0]
    assert not validate_url("http://127.evil.com")[0]
    assert not validate_url("http://localhost.evil.com")[0]
    assert not validate_url("http://example.com")[0]
    assert not validate_url("file:///etc/passwd")[0]
