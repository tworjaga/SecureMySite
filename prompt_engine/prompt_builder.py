"""AI fix prompt generator for SecureMySite."""

from typing import List, Dict, Any, Optional
from pathlib import Path

from models.vulnerability import Vulnerability, Severity
from models.scan_result import ScanResult
from scoring.score_engine import ScoreEngine


class PromptBuilder:
    """
    Generates structured prompts for AI security fix generation.
    
    Creates comprehensive prompts that can be used with ChatGPT, Claude,
    or other AI assistants to generate secure code fixes.
    """
    
    def __init__(self, scan_result: ScanResult):
        """
        Initialize prompt builder.
        
        Args:
            scan_result: Scan results to include in prompt
        """
        self.scan_result = scan_result
        self.score_engine = ScoreEngine()
    
    def build_prompt(self, include_code: bool = True) -> str:
        """
        Build comprehensive AI fix prompt.
        
        Args:
            include_code: Whether to include code snippets
            
        Returns:
            Formatted prompt string
        """
        score_result = self.score_engine.calculate(self.scan_result.vulnerabilities)
        
        sections = [
            self._build_header(),
            self._build_context(score_result),
            self._build_summary(),
            self._build_critical_issues(include_code),
            self._build_high_issues(include_code),
            self._build_medium_issues(include_code),
            self._build_low_issues(include_code),
            self._build_requirements(),
            self._build_deliverable(),
        ]
        
        return '\n\n'.join(sections)
    
    def _build_header(self) -> str:
        """Build prompt header."""
        return """## SECURITY ANALYSIS - AI FIX REQUEST

You are a senior security engineer tasked with fixing vulnerabilities in a web application.
Analyze the security issues below and provide production-ready secure code fixes."""
    
    def _build_context(self, score_result) -> str:
        """Build context section."""
        summary = self.scan_result.get_summary()
        
        return f"""## CONTEXT

**Project:** {self.scan_result.project_path}
**Security Score:** {score_result.score}/100 ({score_result.risk_level})
**Grade:** {score_result.grade}
**Total Issues:** {summary['total_vulnerabilities']} (Critical: {summary['critical']}, High: {summary['high']}, Medium: {summary['medium']}, Low: {summary['low']})
**Files Scanned:** {summary['files_scanned']}
**Scan Duration:** {summary['duration_seconds']:.1f}s"""
    
    def _build_summary(self) -> str:
        """Build executive summary."""
        score_result = self.score_engine.calculate(self.scan_result.vulnerabilities)
        
        summary_lines = ["## EXECUTIVE SUMMARY", ""]
        
        if score_result.recommendations:
            summary_lines.append("**Priority Actions:**")
            for i, rec in enumerate(score_result.recommendations[:3], 1):
                summary_lines.append(f"{i}. {rec}")
            summary_lines.append("")
        
        # Group by category
        from models.vulnerability import Category
        category_counts: Dict[str, int] = {}
        for vuln in self.scan_result.vulnerabilities:
            cat = vuln.category.name
            category_counts[cat] = category_counts.get(cat, 0) + 1
        
        if category_counts:
            summary_lines.append("**Vulnerability Categories:**")
            for cat, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
                summary_lines.append(f"- {cat}: {count} issues")
            summary_lines.append("")
        
        return '\n'.join(summary_lines)
    
    def _build_critical_issues(self, include_code: bool) -> str:
        """Build critical issues section."""
        from models.vulnerability import Severity
        
        critical = self.scan_result.get_vulnerabilities_by_severity(Severity.CRITICAL)
        if not critical:
            return ""
        
        sections = ["## CRITICAL ISSUES (Fix Immediately)", ""]
        
        for i, vuln in enumerate(critical, 1):
            sections.append(self._format_vulnerability(vuln, i, include_code))
            sections.append("")
        
        return '\n'.join(sections)
    
    def _build_high_issues(self, include_code: bool) -> str:
        """Build high severity issues section."""
        from models.vulnerability import Severity
        
        high = self.scan_result.get_vulnerabilities_by_severity(Severity.HIGH)
        if not high:
            return ""
        
        sections = ["## HIGH SEVERITY ISSUES", ""]
        
        for i, vuln in enumerate(high, 1):
            sections.append(self._format_vulnerability(vuln, i, include_code))
            sections.append("")
        
        return '\n'.join(sections)
    
    def _build_medium_issues(self, include_code: bool) -> str:
        """Build medium severity issues section."""
        from models.vulnerability import Severity
        
        medium = self.scan_result.get_vulnerabilities_by_severity(Severity.MEDIUM)
        if not medium:
            return ""
        
        sections = ["## MEDIUM SEVERITY ISSUES", ""]
        
        for i, vuln in enumerate(medium, 1):
            sections.append(self._format_vulnerability(vuln, i, include_code))
            sections.append("")
        
        return '\n'.join(sections)
    
    def _build_low_issues(self, include_code: bool) -> str:
        """Build low severity issues section."""
        from models.vulnerability import Severity
        
        low = self.scan_result.get_vulnerabilities_by_severity(Severity.LOW)
        if not low:
            return ""
        
        sections = ["## LOW SEVERITY ISSUES", ""]
        
        for i, vuln in enumerate(low, 1):
            sections.append(self._format_vulnerability(vuln, i, include_code))
            sections.append("")
        
        return '\n'.join(sections)
    
    def _format_vulnerability(self, vuln: Vulnerability, index: int, include_code: bool) -> str:
        """Format single vulnerability for prompt."""
        lines = [
            f"### {index}. {vuln.title}",
            "",
            f"**Severity:** {vuln.severity.name}",
            f"**Category:** {vuln.category.name}",
            f"**Location:** {vuln.get_location_string()}",
        ]
        
        if vuln.cwe_id:
            lines.append(f"**CWE:** {vuln.cwe_id}")
        
        lines.extend([
            "",
            f"**Problem:** {vuln.description}",
            "",
            f"**Required Fix:** {vuln.remediation}",
        ])
        
        if include_code and vuln.code_snippet:
            lines.extend([
                "",
                "**Current Code:**",
                f"```{self._get_language(vuln.file_path)}",
                vuln.code_snippet,
                "```",
            ])
        
        return '\n'.join(lines)
    
    def _get_language(self, file_path: Optional[Path]) -> str:
        """Get language identifier for code block."""
        if not file_path:
            return "text"
        
        ext_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.jsx': 'jsx',
            '.ts': 'typescript',
            '.tsx': 'tsx',
            '.html': 'html',
            '.css': 'css',
            '.json': 'json',
            '.yaml': 'yaml',
            '.yml': 'yaml',
            '.sql': 'sql',
            '.sh': 'bash',
            '.md': 'markdown',
        }
        
        return ext_map.get(file_path.suffix.lower(), 'text')
    
    def _build_requirements(self) -> str:
        """Build secure code requirements section."""
        return """## SECURE CODE REQUIREMENTS

When rewriting code, ensure:

- [ ] All user inputs are validated and sanitized
- [ ] No dynamic code execution (eval, exec, Function constructor)
- [ ] Parameterized queries for all database operations
- [ ] Secrets loaded from environment variables, never hardcoded
- [ ] Security headers implemented (CSP, X-Frame-Options, etc.)
- [ ] Debug mode disabled in production
- [ ] Proper error handling without information leakage
- [ ] Secure randomness for cryptographic operations
- [ ] Path traversal prevention for file operations
- [ ] HTTPS enforcement for all communications"""
    
    def _build_deliverable(self) -> str:
        """Build final deliverable section."""
        return """## FINAL DELIVERABLE

Provide production-ready, secure code that:

1. **Maintains Original Functionality** - All features work as before
2. **Implements All Security Fixes** - Every vulnerability addressed
3. **Includes Security Comments** - Brief explanations of changes
4. **Follows Best Practices** - PEP 8, ESLint, or language standards
5. **Passes Security Review** - No new vulnerabilities introduced

**Output Format:**

For each file that needs changes:
```
### FILE: [path/to/file.py]

**Changes Made:**
- [List of specific security fixes]

**Secure Code:**
```python
[Complete, production-ready code]
```
```"""
    
    def build_quick_fix_prompt(self, vulnerability: Vulnerability) -> str:
        """
        Build focused prompt for single vulnerability fix.
        
        Args:
            vulnerability: Single vulnerability to fix
            
        Returns:
            Focused prompt string
        """
        return f"""## QUICK SECURITY FIX

**Issue:** {vulnerability.title}
**Severity:** {vulnerability.severity.name}
**Location:** {vulnerability.get_location_string()}

**Problem:**
{vulnerability.description}

**Current Code:**
```{self._get_language(vulnerability.file_path)}
{vulnerability.code_snippet or 'N/A'}
```

**Required Fix:**
{vulnerability.remediation}

Provide the secure replacement code that fixes this vulnerability while maintaining functionality."""
    
    def build_summary_prompt(self) -> str:
        """Build executive summary prompt."""
        score_result = self.score_engine.calculate(self.scan_result.vulnerabilities)
        summary = self.scan_result.get_summary()
        
        return f"""## SECURITY ANALYSIS SUMMARY

**Project:** {self.scan_result.project_path}
**Overall Score:** {score_result.score}/100 ({score_result.risk_level})
**Grade:** {score_result.grade}

**Findings:**
- Total Vulnerabilities: {summary['total_vulnerabilities']}
- Critical: {summary['critical']}
- High: {summary['high']}
- Medium: {summary['medium']}
- Low: {summary['low']}

**Top Recommendations:**
{chr(10).join(f"- {rec}" for rec in score_result.recommendations[:5])}

**Next Steps:**
1. Address all CRITICAL issues immediately
2. Fix HIGH severity issues before production
3. Schedule MEDIUM issues for next sprint
4. Address LOW issues as part of maintenance"""
    
    def export_to_file(self, filepath: Path, include_code: bool = True) -> None:
        """
        Export prompt to file.
        
        Args:
            filepath: Path to save prompt
            include_code: Whether to include code snippets
        """
        prompt = self.build_prompt(include_code)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(prompt)
    
    def get_prompt_stats(self) -> Dict[str, Any]:
        """Get statistics about the generated prompt."""
        prompt = self.build_prompt()
        
        return {
            'total_length': len(prompt),
            'line_count': prompt.count('\n') + 1,
            'vulnerabilities_included': len(self.scan_result.vulnerabilities),
            'estimated_tokens': len(prompt) // 4,  # Rough estimate
        }
