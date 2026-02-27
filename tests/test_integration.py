"""Integration test for SecureMySite."""

from pathlib import Path
from core.engine import AnalysisEngine

def test_sample_project():
    """Test analysis of sample vulnerable project."""
    project_path = Path('tests/sample_vulnerable_project')
    
    print(f"Analyzing: {project_path.absolute()}")
    print("-" * 50)
    
    engine = AnalysisEngine(project_path)
    result = engine.analyze()
    
    score_data = result.metadata.get('score', {})
    score = score_data.get('score', 'N/A')
    risk_level = score_data.get('risk_level', 'Unknown')
    
    print(f"Security Score: {score}/100")
    print(f"Risk Level: {risk_level}")
    print(f"Files Scanned: {result.files_scanned}")
    print(f"Total Vulnerabilities: {len(result.vulnerabilities)}")
    print("-" * 50)
    print("Top Findings:")
    
    for vuln in result.vulnerabilities[:10]:
        print(f"  [{vuln.severity.name}] {vuln.title}")
        if vuln.file_path:
            print(f"    Location: {vuln.get_location_string()}")
    
    print("-" * 50)
    print("Scanners Used:", result.scanners_used)
    
    if result.errors:
        print("Errors:", result.errors)

if __name__ == '__main__':
    test_sample_project()
