"""Severity classification rules for SecureMySite."""

from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
import re

from models.vulnerability import Severity, Category


@dataclass
class SeverityRule:
    """Rule for classifying vulnerability severity."""
    name: str
    pattern: str
    severity: Severity
    category: Category
    description: str
    remediation: str
    cwe_id: Optional[str] = None
    flags: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.flags is None:
            self.flags = {}
    
    def matches(self, content: str) -> bool:
        """Check if content matches this rule's pattern."""
        try:
            return bool(re.search(self.pattern, content, re.IGNORECASE))
        except re.error:
            return False


# CRITICAL severity rules
CRITICAL_RULES: List[SeverityRule] = [
    SeverityRule(
        name="eval_dynamic_input",
        pattern=r'\beval\s*\(',
        severity=Severity.CRITICAL,
        category=Category.INJECTION,
        description="Dynamic code execution via eval() with potentially untrusted input",
        remediation="Replace eval() with safer alternatives like ast.literal_eval() for literals, or implement proper input validation",
        cwe_id="CWE-95",
        flags={'languages': ['python', 'javascript']}
    ),
    SeverityRule(
        name="exec_dynamic_input",
        pattern=r'\bexec\s*\(',
        severity=Severity.CRITICAL,
        category=Category.INJECTION,
        description="Dynamic code execution via exec() with potentially untrusted input",
        remediation="Avoid exec() entirely. Use safer code patterns or configuration files instead",
        cwe_id="CWE-95",
        flags={'languages': ['python']}
    ),
    SeverityRule(
        name="subprocess_shell_true",
        pattern=r'subprocess\..*shell\s*=\s*True',
        severity=Severity.CRITICAL,
        category=Category.INJECTION,
        description="Shell command injection risk via subprocess with shell=True",
        remediation="Use shell=False and pass command as list. Validate all inputs with shlex.quote() if shell required",
        cwe_id="CWE-78",
        flags={'languages': ['python']}
    ),
    SeverityRule(
        name="os_system_user_input",
        pattern=r'os\.system\s*\([^)]*[\+\%]',
        severity=Severity.CRITICAL,
        category=Category.INJECTION,
        description="Command injection via os.system() with user input concatenation",
        remediation="Use subprocess with shell=False and proper argument passing. Never concatenate user input",
        cwe_id="CWE-78",
        flags={'languages': ['python']}
    ),
    SeverityRule(
        name="sql_string_concatenation",
        pattern=r'(?:execute|cursor\.execute|\.query)\s*\(\s*["\'][^"\']*%s|f["\'][^"\']*\{',
        severity=Severity.CRITICAL,
        category=Category.INJECTION,
        description="SQL injection via string concatenation or f-strings in queries",
        remediation="Use parameterized queries with placeholders. Never concatenate user input into SQL",
        cwe_id="CWE-89",
        flags={'languages': ['python']}
    ),
    SeverityRule(
        name="hardcoded_password",
        pattern=r'(?:password|passwd|pwd|secret|api_key|apikey|token)\s*=\s*["\'][^"\']{8,}["\']',
        severity=Severity.CRITICAL,
        category=Category.EXPOSURE,
        description="Hardcoded credential detected in source code",
        remediation="Load credentials from environment variables or secure vaults. Use python-dotenv or similar",
        cwe_id="CWE-798",
        flags={'languages': ['python', 'javascript']}
    ),
    SeverityRule(
        name="debug_mode_production",
        pattern=r'DEBUG\s*=\s*True',
        severity=Severity.CRITICAL,
        category=Category.CONFIGURATION,
        description="Debug mode enabled - exposes sensitive information and enables code execution",
        remediation="Set DEBUG = False in production. Use environment variables to control debug mode",
        cwe_id="CWE-489",
        flags={'languages': ['python']}
    ),
    SeverityRule(
        name="pickle_loads",
        pattern=r'pickle\.loads?',
        severity=Severity.CRITICAL,
        category=Category.INJECTION,
        description="Unsafe deserialization via pickle - can lead to remote code execution",
        remediation="Use safe serialization formats like JSON. If pickle required, implement cryptographic signing",
        cwe_id="CWE-502",
        flags={'languages': ['python']}
    ),
    SeverityRule(
        name="yaml_load_unsafe",
        pattern=r'yaml\.load\s*\([^)]*\)(?!.*Loader)',
        severity=Severity.CRITICAL,
        category=Category.INJECTION,
        description="Unsafe YAML loading without explicit Loader - arbitrary code execution risk",
        remediation="Use yaml.safe_load() or specify Loader=yaml.SafeLoader explicitly",
        cwe_id="CWE-502",
        flags={'languages': ['python']}
    ),
    SeverityRule(
        name="open_cors_wildcard",
        pattern=r'CORS\s*\([^)]*resources\s*=\s*.*\*[^)]*\)',
        severity=Severity.CRITICAL,
        category=Category.CONFIGURATION,
        description="Overly permissive CORS allowing any origin to access resources",
        remediation="Specify exact allowed origins. Never use wildcard with credentials enabled",
        cwe_id="CWE-942",
        flags={'languages': ['python']}
    ),
    SeverityRule(
        name="flask_debug_true",
        pattern=r'app\.run\s*\([^)]*debug\s*=\s*True',
        severity=Severity.CRITICAL,
        category=Category.CONFIGURATION,
        description="Flask debug mode enabled - exposes Werkzeug debugger with PIN",
        remediation="Remove debug=True before deployment. Use FLASK_ENV=production",
        cwe_id="CWE-489",
        flags={'languages': ['python']}
    ),
]

# HIGH severity rules
HIGH_RULES: List[SeverityRule] = [
    SeverityRule(
        name="innerhtml_assignment",
        pattern=r'\.innerHTML\s*=',
        severity=Severity.HIGH,
        category=Category.INJECTION,
        description="Unsafe innerHTML assignment - potential DOM XSS vulnerability",
        remediation="Use textContent for plain text or implement DOMPurify sanitization",
        cwe_id="CWE-79",
        flags={'languages': ['javascript']}
    ),
    SeverityRule(
        name="document_write",
        pattern=r'document\.write\s*\(',
        severity=Severity.HIGH,
        category=Category.INJECTION,
        description="Dangerous document.write() usage - XSS risk",
        remediation="Use modern DOM manipulation methods. Avoid document.write() entirely",
        cwe_id="CWE-79",
        flags={'languages': ['javascript']}
    ),
    SeverityRule(
        name="eval_javascript",
        pattern=r'\beval\s*\(',
        severity=Severity.HIGH,
        category=Category.INJECTION,
        description="eval() usage in JavaScript - code injection risk",
        remediation="Use JSON.parse() for JSON data. Avoid eval() for any user input",
        cwe_id="CWE-95",
        flags={'languages': ['javascript']}
    ),
    SeverityRule(
        name="localstorage_token",
        pattern=r'localStorage\.(?:setItem|\.)\s*\([^)]*token',
        severity=Severity.HIGH,
        category=Category.EXPOSURE,
        description="Sensitive token stored in localStorage - accessible to XSS",
        remediation="Store tokens in httpOnly cookies or use secure session storage",
        cwe_id="CWE-522",
        flags={'languages': ['javascript']}
    ),
    SeverityRule(
        name="exposed_api_key_js",
        pattern=r'[\'"]?(?:api[_-]?key|apikey)[\'"]?\s*[:=]\s*[\'"]\w{20,}[\'"]',
        severity=Severity.HIGH,
        category=Category.EXPOSURE,
        description="API key exposed in client-side JavaScript",
        remediation="Move API calls to server-side. Never expose keys in frontend code",
        cwe_id="CWE-798",
        flags={'languages': ['javascript']}
    ),
    SeverityRule(
        name="wildcard_cors_header",
        pattern=r'Access-Control-Allow-Origin.*\*',
        severity=Severity.HIGH,
        category=Category.CONFIGURATION,
        description="Open CORS policy allowing any origin",
        remediation="Specify allowed origins explicitly. Remove wildcard in production",
        cwe_id="CWE-942",
        flags={'languages': ['python', 'javascript']}
    ),
    SeverityRule(
        name="missing_csp_header",
        pattern=r'(?i)(?!.*content-security-policy)',
        severity=Severity.HIGH,
        category=Category.CONFIGURATION,
        description="Content Security Policy header missing",
        remediation="Implement strict CSP headers to prevent XSS and data injection",
        cwe_id="CWE-693",
        flags={'check_type': 'header_missing'}
    ),
    SeverityRule(
        name="missing_xframe_options",
        pattern=r'(?i)(?!.*x-frame-options)',
        severity=Severity.HIGH,
        category=Category.CONFIGURATION,
        description="X-Frame-Options header missing - clickjacking risk",
        remediation="Add X-Frame-Options: DENY or SAMEORIGIN header",
        cwe_id="CWE-1021",
        flags={'check_type': 'header_missing'}
    ),
    SeverityRule(
        name="insecure_random",
        pattern=r'random\.(?:choice|shuffle|randint)',
        severity=Severity.HIGH,
        category=Category.CRYPTOGRAPHY,
        description="Insecure randomness used for security context",
        remediation="Use secrets module for security-sensitive randomness",
        cwe_id="CWE-338",
        flags={'languages': ['python']}
    ),
    SeverityRule(
        name="path_traversal",
        pattern=r'open\s*\(\s*[^)]*\+',
        severity=Severity.HIGH,
        category=Category.INJECTION,
        description="Potential path traversal via user input in file path",
        remediation="Validate and sanitize file paths. Use pathlib with strict validation",
        cwe_id="CWE-22",
        flags={'languages': ['python']}
    ),
    SeverityRule(
        name="md5_hash_usage",
        pattern=r'hashlib\.md5|md5\s*\(',
        severity=Severity.HIGH,
        category=Category.CRYPTOGRAPHY,
        description="MD5 hash algorithm used - cryptographically broken",
        remediation="Use SHA-256 or stronger for hashing. Use bcrypt/Argon2 for passwords",
        cwe_id="CWE-328",
        flags={'languages': ['python']}
    ),
    SeverityRule(
        name="sha1_hash_usage",
        pattern=r'hashlib\.sha1|sha1\s*\(',
        severity=Severity.HIGH,
        category=Category.CRYPTOGRAPHY,
        description="SHA1 hash algorithm used - cryptographically weak",
        remediation="Use SHA-256 or stronger hash algorithms",
        cwe_id="CWE-328",
        flags={'languages': ['python']}
    ),
]

# MEDIUM severity rules
MEDIUM_RULES: List[SeverityRule] = [
    SeverityRule(
        name="missing_xcontent_type",
        pattern=r'(?i)(?!.*x-content-type-options)',
        severity=Severity.MEDIUM,
        category=Category.CONFIGURATION,
        description="X-Content-Type-Options header missing",
        remediation="Add X-Content-Type-Options: nosniff header",
        cwe_id="CWE-693",
        flags={'check_type': 'header_missing'}
    ),
    SeverityRule(
        name="missing_referrer_policy",
        pattern=r'(?i)(?!.*referrer-policy)',
        severity=Severity.MEDIUM,
        category=Category.CONFIGURATION,
        description="Referrer-Policy header missing",
        remediation="Add Referrer-Policy: strict-origin-when-cross-origin",
        cwe_id="CWE-693",
        flags={'check_type': 'header_missing'}
    ),
    SeverityRule(
        name="verbose_error_messages",
        pattern=r'(?:app\.debug|DEBUG\s*=\s*True|traceback\.print_exc)',
        severity=Severity.MEDIUM,
        category=Category.CONFIGURATION,
        description="Verbose error messages may expose sensitive information",
        remediation="Disable debug mode. Log errors internally, show generic messages to users",
        cwe_id="CWE-209",
        flags={'languages': ['python']}
    ),
    SeverityRule(
        name="insecure_cookie_flags",
        pattern=r'(?:Set-Cookie|cookie).*[^;]\s*$',
        severity=Severity.MEDIUM,
        category=Category.CONFIGURATION,
        description="Cookie missing Secure or HttpOnly flags",
        remediation="Add Secure, HttpOnly, and SameSite=Strict flags to all cookies",
        cwe_id="CWE-614",
        flags={'check_type': 'cookie_analysis'}
    ),
    SeverityRule(
        name="inline_event_handler",
        pattern=r'on\w+\s*=',
        severity=Severity.MEDIUM,
        category=Category.INJECTION,
        description="Inline event handler - potential XSS vector",
        remediation="Use addEventListener() instead of inline handlers",
        cwe_id="CWE-79",
        flags={'languages': ['html', 'javascript']}
    ),
    SeverityRule(
        name="jsonp_usage",
        pattern=r'callback\s*=',
        severity=Severity.MEDIUM,
        category=Category.INJECTION,
        description="JSONP callback parameter - injection risk",
        remediation="Use CORS instead of JSONP. Validate callback names strictly",
        cwe_id="CWE-942",
        flags={'languages': ['javascript']}
    ),
    SeverityRule(
        name="disabled_cert_validation",
        pattern=r'verify\s*=\s*False|verify_ssl\s*=\s*False',
        severity=Severity.MEDIUM,
        category=Category.TRANSPORT,
        description="SSL certificate validation disabled",
        remediation="Never disable certificate validation in production",
        cwe_id="CWE-295",
        flags={'languages': ['python']}
    ),
]

# LOW severity rules
LOW_RULES: List[SeverityRule] = [
    SeverityRule(
        name="missing_xxss_protection",
        pattern=r'(?i)(?!.*x-xss-protection)',
        severity=Severity.LOW,
        category=Category.CONFIGURATION,
        description="X-XSS-Protection header missing",
        remediation="Add X-XSS-Protection: 1; mode=block (or use CSP instead)",
        cwe_id="CWE-693",
        flags={'check_type': 'header_missing'}
    ),
    SeverityRule(
        name="todo_security_comment",
        pattern=r'#\s*(?:TODO|FIXME|XXX).*?(?:security|vuln|fix|patch)',
        severity=Severity.LOW,
        category=Category.CONFIGURATION,
        description="Security-related TODO/FIXME comment found",
        remediation="Address security TODOs before production deployment",
        cwe_id=None,
        flags={'languages': ['python', 'javascript']}
    ),
    SeverityRule(
        name="weak_cipher_config",
        pattern=r'(?:DES|RC4|3DES|MD5)',
        severity=Severity.LOW,
        category=Category.CRYPTOGRAPHY,
        description="Weak cipher or hash algorithm referenced",
        remediation="Use AES-256-GCM and SHA-256 or stronger algorithms",
        cwe_id="CWE-326",
        flags={'languages': ['python', 'javascript']}
    ),
    SeverityRule(
        name="missing_integrity_check",
        pattern=r'<script[^>]*src\s*=\s*["\']https?://',
        severity=Severity.LOW,
        category=Category.CONFIGURATION,
        description="External script without integrity attribute",
        remediation="Add SRI integrity attribute to external resources",
        cwe_id="CWE-353",
        flags={'languages': ['html']}
    ),
]

# Combined rules dictionary
SEVERITY_RULES: Dict[Severity, List[SeverityRule]] = {
    Severity.CRITICAL: CRITICAL_RULES,
    Severity.HIGH: HIGH_RULES,
    Severity.MEDIUM: MEDIUM_RULES,
    Severity.LOW: LOW_RULES,
}


class SeverityClassifier:
    """Classifies code content based on severity rules."""
    
    def __init__(self):
        self.rules = SEVERITY_RULES
    
    def classify(self, content: str, language: str = None) -> List[Tuple[SeverityRule, re.Match]]:
        """
        Classify content against all rules.
        
        Returns list of tuples (rule, match) for all matching rules.
        """
        matches = []
        
        for severity, rules in self.rules.items():
            for rule in rules:
                # Skip if language filter doesn't match
                if language and 'languages' in rule.flags:
                    if language.lower() not in [l.lower() for l in rule.flags['languages']]:
                        continue
                
                # Skip header missing checks for content classification
                if rule.flags.get('check_type') == 'header_missing':
                    continue
                
                if rule.matches(content):
                    match = re.search(rule.pattern, content, re.IGNORECASE)
                    if match:
                        matches.append((rule, match))
        
        return matches
    
    def get_rule_by_name(self, name: str) -> Optional[SeverityRule]:
        """Get a specific rule by name."""
        for rules in self.rules.values():
            for rule in rules:
                if rule.name == name:
                    return rule
        return None
    
    def get_rules_by_category(self, category: Category) -> List[SeverityRule]:
        """Get all rules for a specific category."""
        result = []
        for rules in self.rules.values():
            for rule in rules:
                if rule.category == category:
                    result.append(rule)
        return result
    
    def get_rules_by_severity(self, severity: Severity) -> List[SeverityRule]:
        """Get all rules for a specific severity level."""
        return self.rules.get(severity, [])
