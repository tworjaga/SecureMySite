"""Provider-specific secret / credential detection across all text files."""

import math
import re
from typing import List, Dict, Any

from models.vulnerability import Vulnerability, Severity, Category
from scanners.base_scanner import BaseScanner, ScanContext, redact_secrets


def shannon_entropy(value: str) -> float:
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(value)
    return -sum(c / length * math.log2(c / length) for c in counts.values())


class SecretsScanner(BaseScanner):
    """
    Detects well-known credential formats (cloud keys, API tokens, private keys)
    in every scanned text file. Matches are always masked in the report.
    """

    RULES: Dict[str, Dict[str, Any]] = {
        'private_key': {
            'pattern': r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----',
            'title': 'Private Key',
            'severity': Severity.CRITICAL,
        },
        'aws_access_key': {
            'pattern': r'(?<![A-Z0-9])(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}(?![A-Z0-9])',
            'title': 'AWS Access Key ID',
            'severity': Severity.CRITICAL,
        },
        'github_token': {
            'pattern': r'\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b',
            'title': 'GitHub Token',
            'severity': Severity.CRITICAL,
        },
        'gitlab_token': {
            'pattern': r'\bglpat-[A-Za-z0-9_\-]{20,}\b',
            'title': 'GitLab Personal Access Token',
            'severity': Severity.CRITICAL,
        },
        'slack_token': {
            'pattern': r'\bxox[abposr]-[A-Za-z0-9-]{10,}\b',
            'title': 'Slack Token',
            'severity': Severity.CRITICAL,
        },
        'slack_webhook': {
            'pattern': r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}',
            'title': 'Slack Webhook URL',
            'severity': Severity.HIGH,
        },
        'discord_webhook': {
            'pattern': r'https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]{50,}',
            'title': 'Discord Webhook URL',
            'severity': Severity.HIGH,
        },
        'stripe_live_key': {
            'pattern': r'\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b',
            'title': 'Stripe Live Secret Key',
            'severity': Severity.CRITICAL,
        },
        'stripe_test_key': {
            'pattern': r'\b(?:sk|rk)_test_[A-Za-z0-9]{20,}\b',
            'title': 'Stripe Test Secret Key',
            'severity': Severity.LOW,
        },
        'google_api_key': {
            'pattern': r'\bAIza[0-9A-Za-z_\-]{35}\b',
            'title': 'Google API Key',
            'severity': Severity.HIGH,
        },
        'openai_key': {
            'pattern': r'\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}\b|\bsk-(?:proj|svcacct)-[A-Za-z0-9_\-]{40,}\b',
            'title': 'OpenAI API Key',
            'severity': Severity.CRITICAL,
        },
        'anthropic_key': {
            'pattern': r'\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,}\b',
            'title': 'Anthropic API Key',
            'severity': Severity.CRITICAL,
        },
        'huggingface_token': {
            'pattern': r'\bhf_[A-Za-z0-9]{34,}\b',
            'title': 'Hugging Face Token',
            'severity': Severity.HIGH,
        },
        'sendgrid_key': {
            'pattern': r'\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b',
            'title': 'SendGrid API Key',
            'severity': Severity.CRITICAL,
        },
        'twilio_key': {
            'pattern': r'\bSK[0-9a-f]{32}\b',
            'title': 'Twilio API Key',
            'severity': Severity.HIGH,
        },
        'npm_token': {
            'pattern': r'\bnpm_[A-Za-z0-9]{36}\b',
            'title': 'npm Access Token',
            'severity': Severity.CRITICAL,
        },
        'pypi_token': {
            'pattern': r'\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b',
            'title': 'PyPI API Token',
            'severity': Severity.CRITICAL,
        },
        'telegram_bot_token': {
            'pattern': r'\b\d{8,10}:AA[0-9A-Za-z_\-]{33}\b',
            'title': 'Telegram Bot Token',
            'severity': Severity.HIGH,
        },
        'mailgun_key': {
            'pattern': r'\bkey-[0-9a-z]{32}\b',
            'title': 'Mailgun API Key',
            'severity': Severity.HIGH,
        },
        'azure_storage_key': {
            'pattern': r'AccountKey=[A-Za-z0-9+/]{86}==',
            'title': 'Azure Storage Account Key',
            'severity': Severity.CRITICAL,
        },
        'supabase_service_key': {
            'pattern': r'\bsb_secret_[A-Za-z0-9_\-]{20,}\b',
            'title': 'Supabase Secret Key',
            'severity': Severity.CRITICAL,
        },
        'jwt': {
            'pattern': r'\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b',
            'title': 'Hardcoded JSON Web Token',
            'severity': Severity.MEDIUM,
            'min_entropy': 3.5,
        },
        'basic_auth_url': {
            'pattern': r'\bhttps?://[^\s:/@"\']{2,}:[^\s:/@"\']{3,}@[^\s/"\']+',
            'title': 'Credentials Embedded in URL',
            'severity': Severity.HIGH,
        },
    }

    # Lockfiles contain integrity hashes that look random; skip them
    SKIP_FILES = {'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'poetry.lock', 'pipfile.lock', 'composer.lock'}

    def get_name(self) -> str:
        return "secrets_scanner"

    def get_description(self) -> str:
        return "Secret detection (cloud keys, API tokens, private keys, webhooks) across all files"

    def get_supported_languages(self) -> List[str]:
        return ['python', 'javascript', 'typescript', 'html', 'json', 'yaml', 'toml', 'ini', 'config',
                'env', 'text', 'dockerfile']

    def can_scan_file(self, file_path) -> bool:
        if file_path and file_path.name.lower() in self.SKIP_FILES:
            return False
        return super().can_scan_file(file_path)

    def scan(self, context: ScanContext) -> List[Vulnerability]:
        if not context.file_path or not context.file_content:
            return []

        vulnerabilities = []
        content = context.file_content

        for rule_name, rule in self.RULES.items():
            for match in re.finditer(rule['pattern'], content):
                secret = match.group(0)
                if rule.get('min_entropy') and shannon_entropy(secret) < rule['min_entropy']:
                    continue
                if rule_name == 'basic_auth_url' and re.search(r'://[^:]+:(?:\$\{|\{\{|%\(|<|password@|pass@|\*+@)', secret):
                    continue

                info = {
                    'title': f"Exposed Secret: {rule['title']}",
                    'description': f"A {rule['title']} was found in this file. Anyone who can read the code "
                                   "(repository, build artefacts or browser bundle) can use it.",
                    'severity': rule['severity'],
                    'category': Category.EXPOSURE,
                    'remediation': f"Revoke and rotate this {rule['title']} now, remove it from the code and git "
                                   "history (git filter-repo / BFG), and load it from an environment variable "
                                   "or secrets manager instead.",
                    'cwe': 'CWE-798',
                }
                vuln = self.finding_from_match(context, match, info, rule_name, mask_match=True)
                vuln.metadata['secret_type'] = rule['title']
                vulnerabilities.append(vuln)

        vulnerabilities.sort(key=lambda v: (v.line_number or 0, v.column_start or 0))
        return redact_secrets(vulnerabilities)
