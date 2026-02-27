"""Security score calculation engine for SecureMySite."""

from typing import List, Dict, Any, Tuple
from dataclasses import dataclass

from models.vulnerability import Vulnerability, Severity


@dataclass
class ScoreResult:
    """Result of security score calculation."""
    score: int
    risk_level: str
    grade: str
    breakdown: Dict[str, Any]
    recommendations: List[str]


class ScoreEngine:
    """
    Calculates security scores based on vulnerability findings.
    
    Base score starts at 100 and deducts points based on severity.
    """
    
    BASE_SCORE = 100
    MIN_SCORE = 0
    
    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 15,
        Severity.HIGH: 10,
        Severity.MEDIUM: 5,
        Severity.LOW: 2
    }
    
    RISK_LEVELS: List[Tuple[int, int, str, str]] = [
        (80, 100, "Safe", "A+"),
        (75, 79, "Safe", "A"),
        (70, 74, "Moderate", "A-"),
        (65, 69, "Moderate", "B+"),
        (60, 64, "Moderate", "B"),
        (55, 59, "Moderate", "B-"),
        (50, 54, "High Risk", "C+"),
        (45, 49, "High Risk", "C"),
        (40, 44, "High Risk", "C-"),
        (35, 39, "Critical Risk", "D+"),
        (30, 34, "Critical Risk", "D"),
        (25, 29, "Critical Risk", "D-"),
        (0, 24, "Critical Risk", "F"),
    ]
    
    def __init__(self):
        self.weights = self.SEVERITY_WEIGHTS
    
    def calculate(self, vulnerabilities: List[Vulnerability]) -> ScoreResult:
        """
        Calculate security score from list of vulnerabilities.
        
        Args:
            vulnerabilities: List of detected vulnerabilities
            
        Returns:
            ScoreResult with score, risk level, grade, and breakdown
        """
        # Deduplicate vulnerabilities
        unique_vulns = self._deduplicate(vulnerabilities)
        
        # Count by severity
        critical_count = len([v for v in unique_vulns if v.severity == Severity.CRITICAL])
        high_count = len([v for v in unique_vulns if v.severity == Severity.HIGH])
        medium_count = len([v for v in unique_vulns if v.severity == Severity.MEDIUM])
        low_count = len([v for v in unique_vulns if v.severity == Severity.LOW])
        
        # Calculate deductions
        critical_deduction = critical_count * self.weights[Severity.CRITICAL]
        high_deduction = high_count * self.weights[Severity.HIGH]
        medium_deduction = medium_count * self.weights[Severity.MEDIUM]
        low_deduction = low_count * self.weights[Severity.LOW]
        
        total_deduction = critical_deduction + high_deduction + medium_deduction + low_deduction
        
        # Calculate final score
        raw_score = self.BASE_SCORE - total_deduction
        final_score = max(self.MIN_SCORE, min(self.BASE_SCORE, raw_score))
        
        # Determine risk level and grade
        risk_level, grade = self._get_risk_level_and_grade(final_score)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            critical_count, high_count, medium_count, low_count, unique_vulns
        )
        
        breakdown = {
            'critical_count': critical_count,
            'high_count': high_count,
            'medium_count': medium_count,
            'low_count': low_count,
            'total_vulnerabilities': len(unique_vulns),
            'critical_deduction': critical_deduction,
            'high_deduction': high_deduction,
            'medium_deduction': medium_deduction,
            'low_deduction': low_deduction,
            'total_deduction': total_deduction,
            'base_score': self.BASE_SCORE,
            'raw_score': raw_score
        }
        
        return ScoreResult(
            score=final_score,
            risk_level=risk_level,
            grade=grade,
            breakdown=breakdown,
            recommendations=recommendations
        )
    
    def _deduplicate(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Remove duplicate vulnerabilities based on file+line+title."""
        seen = set()
        unique = []
        for vuln in vulnerabilities:
            key = (str(vuln.file_path), vuln.line_number, vuln.title)
            if key not in seen:
                seen.add(key)
                unique.append(vuln)
        return unique
    
    def _get_risk_level_and_grade(self, score: int) -> Tuple[str, str]:
        """Determine risk level and letter grade from score."""
        for min_score, max_score, risk, grade in self.RISK_LEVELS:
            if min_score <= score <= max_score:
                return risk, grade
        return "Critical Risk", "F"
    
    def _generate_recommendations(
        self,
        critical: int,
        high: int,
        medium: int,
        low: int,
        vulnerabilities: List[Vulnerability]
    ) -> List[str]:
        """Generate prioritized security recommendations."""
        recommendations = []
        
        if critical > 0:
            recommendations.append(
                f"CRITICAL: Address {critical} critical vulnerabilities immediately. "
                "These pose severe security risks including RCE and data exposure."
            )
        
        if high > 0:
            recommendations.append(
                f"HIGH: Fix {high} high severity issues before production deployment. "
                "Focus on XSS prevention and secure configuration."
            )
        
        if medium > 0:
            recommendations.append(
                f"MEDIUM: Review and fix {medium} medium severity issues. "
                "Implement security headers and input validation."
            )
        
        if low > 0:
            recommendations.append(
                f"LOW: Address {low} low severity issues as part of regular maintenance. "
                "Follow security best practices."
            )
        
        # Add specific recommendations based on vulnerability types
        categories = set()
        for vuln in vulnerabilities:
            categories.add(vuln.category)
        
        if any(v.category.name == 'INJECTION' for v in vulnerabilities):
            recommendations.append(
                "Implement parameterized queries and input validation to prevent injection attacks."
            )
        
        if any(v.category.name == 'EXPOSURE' for v in vulnerabilities):
            recommendations.append(
                "Audit all hardcoded credentials and move them to environment variables or secure vaults."
            )
        
        if any(v.category.name == 'CONFIGURATION' for v in vulnerabilities):
            recommendations.append(
                "Review security configuration. Disable debug mode and implement proper security headers."
            )
        
        if not recommendations:
            recommendations.append("No vulnerabilities detected. Continue following security best practices.")
        
        return recommendations
    
    def get_score_color(self, score: int) -> str:
        """Get color code for score display."""
        if score >= 80:
            return '#00d084'  # Green
        elif score >= 60:
            return '#ffcc00'  # Yellow
        elif score >= 40:
            return '#ff8800'  # Orange
        else:
            return '#ff4444'  # Red
    
    def get_score_description(self, score: int) -> str:
        """Get human-readable description of score."""
        if score >= 80:
            return "Good security posture with minor or no issues"
        elif score >= 60:
            return "Moderate risk - address high severity issues"
        elif score >= 40:
            return "High risk - multiple security concerns require attention"
        else:
            return "Critical risk - immediate action required"
    
    def calculate_category_score(
        self,
        vulnerabilities: List[Vulnerability]
    ) -> Dict[str, Any]:
        """Calculate scores broken down by category."""
        categories = {}
        
        for vuln in vulnerabilities:
            cat_name = vuln.category.name
            if cat_name not in categories:
                categories[cat_name] = {
                    'count': 0,
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0
                }
            
            categories[cat_name]['count'] += 1
            severity_key = vuln.severity.name.lower()
            categories[cat_name][severity_key] += 1
        
        return categories
