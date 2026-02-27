"""AI fix prompt generator for SecureMySite."""

from typing import List, Dict, Any, Optional, Set
from pathlib import Path
from collections import defaultdict

from models.vulnerability import Vulnerability, Severity, Category
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
            self._build_executive_summary(),
            self._build_vulnerability_analysis(include_code),
            self._build_file_specific_fixes(include_code),
            self._build_requirements(),
            self._build_deliverable(),
        ]
        
        return '\n\n'.join(filter(None, sections))
    
    def _build_header(self) -> str:
        """Build prompt header."""
        return """# SECURITY ANALYSIS - AI FIX REQUEST

You are a senior security engineer with 20+ years of experience. Your task is to analyze the security vulnerabilities below and provide production-ready secure code fixes.

## YOUR ROLE
- Analyze each vulnerability with precision
- Provide complete, working code replacements
- Explain the security rationale for each change
- Ensure no functionality is broken in the process"""
    
    def _build_context(self, score_result) -> str:
        """Build context section."""
        summary = self.scan_result.get_summary()
        
        return f"""## PROJECT CONTEXT

| Metric | Value |
|--------|-------|
| **Project Path** | `{self.scan_result.project_path}` |
| **Security Score** | {score_result.score}/100 ({score_result.risk_level}) |
| **Grade** | {score_result.grade} |
| **Total Issues** | {summary['total_vulnerabilities']} |
| **Critical** | {summary['critical']} |
| **High** | {summary['high']} |
| **Medium** | {summary['medium']} |
| **Low** | {summary['low']} |
| **Files Scanned** | {summary['files_scanned']} |
| **Scan Duration** | {summary['duration_seconds']:.1f}s"""
    
    def _build_executive_summary(self) -> str:
        """Build executive summary with actionable insights."""
        score_result = self.score_engine.calculate(self.scan_result.vulnerabilities)
        
        lines = ["## EXECUTIVE SUMMARY", ""]
        
        # Risk assessment
        if score_result.score < 20:
            lines.append("**CRITICAL RISK ASSESSMENT:** This codebase has severe security vulnerabilities that must be addressed immediately before any production deployment. Multiple attack vectors exist including remote code execution and data exposure.")
        elif score_result.score < 40:
            lines.append("**HIGH RISK ASSESSMENT:** Significant security issues present. Immediate remediation required before production use.")
        elif score_result.score < 60:
            lines.append("**MODERATE RISK ASSESSMENT:** Security concerns identified that should be addressed in the next development cycle.")
        elif score_result.score < 80:
            lines.append("**LOW RISK ASSESSMENT:** Minor security improvements recommended. Overall security posture is acceptable.")
        else:
            lines.append("**SAFE ASSESSMENT:** No significant security issues detected. Continue following security best practices.")
        
        lines.append("")
        
        # Priority actions
        if score_result.recommendations:
            lines.append("### Priority Actions")
            for i, rec in enumerate(score_result.recommendations[:5], 1):
                lines.append(f"{i}. {rec}")
            lines.append("")
        
        # Category breakdown
        category_counts: Dict[str, int] = defaultdict(int)
        for vuln in self.scan_result.vulnerabilities:
            category_counts[vuln.category.name] += 1
        
        if category_counts:
            lines.append("### Vulnerability Breakdown by Category")
            for cat, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"- **{cat}:** {count} issue(s)")
            lines.append("")
        
        return '\n'.join(lines)
    
    def _build_vulnerability_analysis(self, include_code: bool) -> str:
        """Build detailed vulnerability analysis grouped by severity."""
        sections = []
        
        # Group vulnerabilities by severity
        by_severity = {
            Severity.CRITICAL: [],
            Severity.HIGH: [],
            Severity.MEDIUM: [],
            Severity.LOW: []
        }
        
        for vuln in self.scan_result.vulnerabilities:
            by_severity[vuln.severity].append(vuln)
        
        # Build sections for each severity level
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        severity_headers = {
            Severity.CRITICAL: "## CRITICAL VULNERABILITIES (Immediate Action Required)",
            Severity.HIGH: "## HIGH SEVERITY VULNERABILITIES (Fix Before Production)",
            Severity.MEDIUM: "## MEDIUM SEVERITY VULNERABILITIES (Address Soon)",
            Severity.LOW: "## LOW SEVERITY VULNERABILITIES (Maintenance Items)"
        }
        
        for severity in severity_order:
            vulns = by_severity[severity]
            if not vulns:
                continue
            
            sections.append(severity_headers[severity])
            sections.append("")
            
            for i, vuln in enumerate(vulns, 1):
                sections.append(self._format_vulnerability_detail(vuln, i, include_code))
                sections.append("")
        
        return '\n'.join(sections)
    
    def _format_vulnerability_detail(self, vuln: Vulnerability, index: int, include_code: bool) -> str:
        """Format detailed vulnerability information."""
        lines = [
            f"### {index}. {vuln.title}",
            "",
            f"**Severity:** {vuln.severity.name}",
            f"**Category:** {vuln.category.name}",
            f"**Location:** `{vuln.get_location_string()}`",
        ]
        
        if vuln.cwe_id:
            lines.append(f"**CWE Reference:** [{vuln.cwe_id}](https://cwe.mitre.org/data/definitions/{vuln.cwe_id.replace('CWE-', '')}.html)")
        
        lines.extend([
            "",
            "**Security Impact:**",
            f"{vuln.description}",
            "",
            "**Required Fix:**",
            f"{vuln.remediation}",
        ])
        
        if include_code and vuln.code_snippet:
            language = self._get_language(vuln.file_path)
            lines.extend([
                "",
                "**Vulnerable Code:**",
                f"```{language}",
                vuln.code_snippet,
                "```",
                "",
                "**Secure Replacement:**",
                f"```{language}",
                "[Provide the complete, secure replacement code here]",
                "```",
            ])
        
        return '\n'.join(lines)
    
    def _build_file_specific_fixes(self, include_code: bool) -> str:
        """Build file-by-file fix instructions."""
        # Group vulnerabilities by file
        by_file: Dict[Path, List[Vulnerability]] = defaultdict(list)
        for vuln in self.scan_result.vulnerabilities:
            if vuln.file_path:
                by_file[vuln.file_path].append(vuln)
        
        if not by_file:
            return ""
        
        sections = ["## FILE-BY-FILE SECURITY FIXES", ""]
        
        for file_path, vulns in sorted(by_file.items(), key=lambda x: len(x[1]), reverse=True):
            sections.append(f"### File: `{file_path}`")
            sections.append("")
            sections.append(f"**Issues Found:** {len(vulns)}")
            sections.append("")
            
            # List issues in this file
            for vuln in vulns:
                sections.append(f"- [{vuln.severity.name}] {vuln.title} (line {vuln.line_number or 'N/A'})")
            
            sections.append("")
            
            if include_code:
                # Provide consolidated fix for this file
                sections.append("**Consolidated Secure Version:**")
                sections.append(f"```{self._get_language(file_path)}")
                sections.append("[Provide the complete, secure version of this file]")
                sections.append("```")
                sections.append("")
        
        return '\n'.join(sections)
    
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
        return """## MANDATORY SECURITY REQUIREMENTS

All code changes MUST satisfy these requirements:

### Input Validation
- [ ] All user inputs validated using whitelist approach
- [ ] Type checking enforced for all external data
- [ ] Maximum length limits applied to string inputs
- [ ] Numeric inputs bounded to expected ranges

### Code Execution Prevention
- [ ] No use of `eval()`, `exec()`, or `Function()` constructor
- [ ] No dynamic code generation from user input
- [ ] No `pickle.loads()` or unsafe deserialization
- [ ] No `yaml.load()` without SafeLoader

### Database Security
- [ ] Parameterized queries used exclusively (no string concatenation)
- [ ] ORM used where available
- [ ] No SQL keywords in user-controlled input

### Secret Management
- [ ] No hardcoded credentials, API keys, or passwords
- [ ] Environment variables used for all secrets
- [ ] `.env` files excluded from version control
- [ ] Key management service used for production secrets

### Web Security Headers
- [ ] Content-Security-Policy implemented
- [ ] X-Frame-Options set to DENY or SAMEORIGIN
- [ ] X-Content-Type-Options: nosniff
- [ ] Strict-Transport-Security for HTTPS

### Configuration
- [ ] DEBUG mode disabled in production
- [ ] Detailed error messages hidden from users
- [ ] Secure cookie flags (HttpOnly, Secure, SameSite)
- [ ] HTTPS enforcement

### Cryptography
- [ ] SHA-256 or stronger for hashing (no MD5/SHA1)
- [ ] `secrets` module used for security randomness
- [ ] Proper key derivation for password hashing (bcrypt/Argon2)
- [ ] TLS 1.2+ for all communications"""
    
    def _build_deliverable(self) -> str:
        """Build final deliverable section."""
        return """## DELIVERABLE SPECIFICATION

Provide your response in the following format:

### 1. Executive Summary
Brief overview of changes made and security improvements achieved.

### 2. File-by-File Changes

For each modified file, provide:

```
### FILE: [relative/path/to/file.ext]

**Changes Summary:**
- Line X: [What was changed and why]
- Line Y: [What was changed and why]

**Complete Secure Code:**
```[language]
[Full file content - not just snippets]
```

**Security Rationale:**
Explanation of how the changes address the vulnerabilities.
```

### 3. Verification Checklist

Confirm that:
- [ ] All CRITICAL vulnerabilities fixed
- [ ] All HIGH vulnerabilities fixed
- [ ] No functionality broken
- [ ] Code follows language style guidelines
- [ ] Security requirements met
- [ ] No new vulnerabilities introduced

### 4. Testing Recommendations

Suggest specific test cases to verify:
- Security fixes work correctly
- Functionality preserved
- Edge cases handled safely"""
    
    def build_quick_fix_prompt(self, vulnerability: Vulnerability) -> str:
        """
        Build focused prompt for single vulnerability fix.
        
        Args:
            vulnerability: Single vulnerability to fix
            
        Returns:
            Focused prompt string
        """
        return f"""# SINGLE VULNERABILITY FIX

## Issue Details

| Field | Value |
|-------|-------|
| **Title** | {vulnerability.title} |
| **Severity** | {vulnerability.severity.name} |
| **Category** | {vulnerability.category.name} |
| **Location** | `{vulnerability.get_location_string()}` |
| **CWE** | {vulnerability.cwe_id or 'N/A'} |

## Problem Description

{vulnerability.description}

## Current Code

```{self._get_language(vulnerability.file_path)}
{vulnerability.code_snippet or 'Code snippet not available'}
```

## Required Fix

{vulnerability.remediation}

## Your Task

Provide the complete, secure replacement code that:
1. Fixes the vulnerability completely
2. Maintains all original functionality
3. Follows security best practices
4. Includes brief security comments explaining changes

## Output Format

```
### SECURE REPLACEMENT

```[language]
[Complete secure code here]
```

### EXPLANATION

[Explain what was changed and why it fixes the vulnerability]
```"""
    
    def build_summary_prompt(self) -> str:
        """Build executive summary prompt."""
        score_result = self.score_engine.calculate(self.scan_result.vulnerabilities)
        summary = self.scan_result.get_summary()
        
        # Get top files with issues
        by_file: Dict[str, int] = defaultdict(int)
        for vuln in self.scan_result.vulnerabilities:
            if vuln.file_path:
                by_file[str(vuln.file_path)] += 1
        
        top_files = sorted(by_file.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return f"""# SECURITY ANALYSIS SUMMARY

## Overview

| Metric | Value |
|--------|-------|
| **Project** | `{self.scan_result.project_path}` |
| **Security Score** | {score_result.score}/100 |
| **Risk Level** | {score_result.risk_level} |
| **Grade** | {score_result.grade} |
| **Total Issues** | {summary['total_vulnerabilities']} |

## Severity Distribution

- **Critical:** {summary['critical']} (Immediate action required)
- **High:** {summary['high']} (Fix before production)
- **Medium:** {summary['medium']} (Address in next sprint)
- **Low:** {summary['low']} (Maintenance backlog)

## Most Affected Files

{chr(10).join(f"{i+1}. `{file}` - {count} issue(s)" for i, (file, count) in enumerate(top_files))}

## Key Recommendations

{chr(10).join(f"{i+1}. {rec}" for i, rec in enumerate(score_result.recommendations[:5]))}

## Next Steps

1. **Immediate (24 hours):** Address all CRITICAL vulnerabilities
2. **Short-term (1 week):** Fix all HIGH severity issues
3. **Medium-term (1 month):** Resolve MEDIUM priority items
4. **Ongoing:** Monitor and address LOW priority items"""
    
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
            'estimated_tokens': len(prompt) // 4,
            'severity_breakdown': {
                'critical': len(self.scan_result.get_vulnerabilities_by_severity(Severity.CRITICAL)),
                'high': len(self.scan_result.get_vulnerabilities_by_severity(Severity.HIGH)),
                'medium': len(self.scan_result.get_vulnerabilities_by_severity(Severity.MEDIUM)),
                'low': len(self.scan_result.get_vulnerabilities_by_severity(Severity.LOW)),
            }
        }
