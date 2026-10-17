"""Infrastructure-as-code scanner: Dockerfile, docker-compose and GitHub Actions workflows."""

import re
from pathlib import Path
from typing import List, Optional

from models.vulnerability import Vulnerability, Severity, Category
from scanners.base_scanner import BaseScanner, ScanContext, mask_secret, redact_secrets, SECRET_KEY


SECRET_NAME = r'[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_KEY|ACCESS_KEY)[A-Z0-9_]*'
DB_PORTS = {'5432': 'PostgreSQL', '3306': 'MySQL', '6379': 'Redis', '27017': 'MongoDB', '9200': 'Elasticsearch',
            '11211': 'Memcached', '5984': 'CouchDB'}


class IaCScanner(BaseScanner):
    """
    Scans container and CI configuration.

    Dockerfile: running as root, unpinned/latest base images, ADD from URLs, secrets in ENV/ARG,
                curl | sh, chmod 777, COPY . without .dockerignore
    docker-compose: privileged containers, docker.sock mounts, host networking, database ports
                    published on all interfaces
    GitHub Actions: script injection via ${{ github.event.* }}, pull_request_target with PR checkout,
                    write-all permissions, unpinned third-party actions
    """

    def get_name(self) -> str:
        return "iac_scanner"

    def get_description(self) -> str:
        return "Infrastructure scanner (Dockerfile, docker-compose, GitHub Actions)"

    def get_supported_languages(self) -> List[str]:
        return ['dockerfile', 'yaml']

    @staticmethod
    def _kind(file_path: Path) -> Optional[str]:
        name = file_path.name.lower()
        if name in ('dockerfile', 'containerfile') or name.startswith('dockerfile.') or name.endswith('.dockerfile'):
            return 'dockerfile'
        if re.fullmatch(r'(?:docker-)?compose(?:[.\w-]*)?\.ya?ml', name):
            return 'compose'
        parts = [p.lower() for p in file_path.parts]
        if name.endswith(('.yml', '.yaml')) and len(parts) >= 3 and parts[-3:-1] == ['.github', 'workflows']:
            return 'workflow'
        return None

    def can_scan_file(self, file_path: Path) -> bool:
        return bool(file_path) and self._kind(file_path) is not None

    def scan(self, context: ScanContext) -> List[Vulnerability]:
        if not context.file_path or context.file_content is None:
            return []
        kind = self._kind(context.file_path)
        if kind == 'dockerfile':
            return redact_secrets(self._scan_dockerfile(context))
        if kind == 'compose':
            return self._scan_compose(context)
        if kind == 'workflow':
            return self._scan_workflow(context)
        return []

    # ------------------------------------------------------------------ helpers

    def _make(self, context: ScanContext, line: int, title: str, description: str, severity: Severity,
              category: Category, remediation: str, cwe: Optional[str], rule: str,
              secret: Optional[str] = None) -> Vulnerability:
        snippet = self.extract_code_snippet(context.file_content, line)
        metadata = {'rule': rule}
        if secret:
            snippet = snippet.replace(secret, mask_secret(secret))
            metadata[SECRET_KEY] = secret
        return Vulnerability(
            title=title,
            description=description,
            severity=severity,
            category=category,
            file_path=context.file_path,
            line_number=line,
            code_snippet=snippet,
            remediation=remediation,
            cwe_id=cwe,
            scanner_source=self.get_name(),
            metadata=metadata,
        )

    @staticmethod
    def _logical_lines(content: str):
        """Yield (line_number, text) with backslash continuations joined."""
        buffer, start = '', 0
        for i, line in enumerate(content.splitlines(), 1):
            if not buffer:
                start = i
            stripped = line.rstrip()
            if stripped.endswith('\\'):
                buffer += stripped[:-1] + ' '
                continue
            buffer += stripped
            yield start, buffer
            buffer = ''
        if buffer:
            yield start, buffer

    # ------------------------------------------------------------------ Dockerfile

    def _scan_dockerfile(self, context: ScanContext) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        last_user: Optional[str] = None
        from_line = 1
        stages = 0

        for line_no, text in self._logical_lines(context.file_content):
            stripped = text.strip()
            if not stripped or stripped.startswith('#'):
                continue
            instr, _, args = stripped.partition(' ')
            instr = instr.upper()
            args = args.strip()

            if instr == 'FROM':
                stages += 1
                from_line = line_no
                last_user = None
                image = args.split()[0] if args else ''
                if image.lower() != 'scratch' and not image.startswith('$') and '@sha256:' not in image:
                    name_part = image.rsplit('/', 1)[-1]
                    if ':' not in name_part or name_part.endswith(':latest'):
                        vulns.append(self._make(
                            context, line_no, 'Unpinned Base Image',
                            f'Base image "{image}" uses the implicit/explicit latest tag; builds are not reproducible '
                            'and may pull in unexpected changes',
                            Severity.LOW, Category.CONFIGURATION,
                            'Pin a specific version tag (ideally with an @sha256 digest).', 'CWE-1357', 'docker_latest'))

            elif instr == 'USER':
                last_user = args.split()[0] if args else None

            elif instr == 'ADD' and re.search(r'https?://', args):
                vulns.append(self._make(
                    context, line_no, 'ADD Downloads Remote File',
                    'ADD with a URL downloads content without integrity verification',
                    Severity.MEDIUM, Category.CONFIGURATION,
                    'Use RUN curl -fsSL ... && echo "<sha256>  file" | sha256sum -c, or COPY a vetted file.',
                    'CWE-494', 'docker_add_url'))

            elif instr in ('ENV', 'ARG'):
                for m in re.finditer(r'\b(' + SECRET_NAME + r')\s*[= ]\s*["\']?([^\s"\'$]{4,})', args, re.IGNORECASE):
                    vulns.append(self._make(
                        context, line_no, f'Secret in Dockerfile {instr}',
                        f'{m.group(1)} is set in the image via {instr}; it is stored in the image layers and visible '
                        'with docker history',
                        Severity.HIGH, Category.EXPOSURE,
                        'Use BuildKit secrets (RUN --mount=type=secret) or inject at runtime via environment.',
                        'CWE-798', 'docker_secret_env', secret=m.group(2)))

            elif instr == 'RUN':
                if re.search(r'(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b', args):
                    vulns.append(self._make(
                        context, line_no, 'Remote Script Piped to Shell',
                        'A script is downloaded and executed without verification',
                        Severity.MEDIUM, Category.CONFIGURATION,
                        'Download to a file, verify its checksum/signature, then execute.', 'CWE-494', 'curl_pipe_sh'))
                if re.search(r'chmod\s+(?:-R\s+)?0?777\b', args):
                    vulns.append(self._make(
                        context, line_no, 'World-Writable Permissions',
                        'chmod 777 makes files writable by every user in the container',
                        Severity.MEDIUM, Category.CONFIGURATION,
                        'Grant the minimum permissions needed (e.g. 755 / 644) to the app user only.', 'CWE-732', 'chmod_777'))
                if re.search(r'\bsudo\b', args):
                    vulns.append(self._make(
                        context, line_no, 'sudo Used in Dockerfile',
                        'sudo in images is unnecessary and widens privilege escalation paths',
                        Severity.LOW, Category.CONFIGURATION,
                        'Run root-only steps before switching USER, and do not install sudo.', 'CWE-250', 'docker_sudo'))

            elif instr in ('COPY', 'ADD') and re.match(r'(?:--\S+\s+)*\.\s+', args):
                project_root = Path(context.project_path)
                dockerignore = context.file_path.parent / '.dockerignore'
                if not dockerignore.exists() and not (project_root / '.dockerignore').exists():
                    vulns.append(self._make(
                        context, line_no, 'COPY . Without .dockerignore',
                        'The whole build context (including .env, .git and local secrets) is copied into the image',
                        Severity.MEDIUM, Category.EXPOSURE,
                        'Add a .dockerignore excluding .git, .env*, node_modules, venvs and credentials.',
                        'CWE-538', 'docker_no_dockerignore'))

            elif instr == 'EXPOSE' and re.search(r'\b22\b', args):
                vulns.append(self._make(
                    context, line_no, 'SSH Port Exposed',
                    'Port 22 is exposed; containers should not run an SSH daemon',
                    Severity.LOW, Category.CONFIGURATION,
                    'Remove sshd and use docker exec / kubectl exec for debugging.', 'CWE-284', 'docker_ssh'))

        if stages and (last_user is None or last_user in ('root', '0', '0:0')):
            vulns.append(self._make(
                context, from_line, 'Container Runs as Root',
                'The final image stage has no non-root USER, so the application runs as root',
                Severity.MEDIUM, Category.CONFIGURATION,
                'Create an unprivileged user and add "USER appuser" before CMD/ENTRYPOINT.', 'CWE-250', 'docker_root'))
        return vulns

    # ------------------------------------------------------------------ docker-compose

    def _scan_compose(self, context: ScanContext) -> List[Vulnerability]:
        vulns = []
        lines = context.file_content.splitlines()
        for i, line in enumerate(lines, 1):
            text = line.split('#', 1)[0]
            if re.search(r'^\s*privileged\s*:\s*true\b', text, re.IGNORECASE):
                vulns.append(self._make(
                    context, i, 'Privileged Container',
                    'privileged: true gives the container full access to the host kernel and devices',
                    Severity.HIGH, Category.CONFIGURATION,
                    'Remove privileged mode; grant specific capabilities with cap_add if truly needed.', 'CWE-250',
                    'compose_privileged'))
            if '/var/run/docker.sock' in text:
                vulns.append(self._make(
                    context, i, 'Docker Socket Mounted',
                    'Mounting docker.sock lets the container control the Docker daemon (root on the host)',
                    Severity.HIGH, Category.CONFIGURATION,
                    'Avoid mounting the Docker socket, or use a restricted socket proxy.', 'CWE-250', 'compose_docker_sock'))
            if re.search(r'^\s*network_mode\s*:\s*["\']?host', text):
                vulns.append(self._make(
                    context, i, 'Host Networking Enabled',
                    'network_mode: host removes network isolation between the container and the host',
                    Severity.MEDIUM, Category.CONFIGURATION,
                    'Use the default bridge network and publish only required ports.', 'CWE-668', 'compose_host_net'))
            port = re.search(r'^\s*-\s*["\']?(?:(0\.0\.0\.0):)?(\d+):(\d+)', text)
            if port and port.group(1) != '127.0.0.1' and port.group(3) in DB_PORTS:
                vulns.append(self._make(
                    context, i, f'{DB_PORTS[port.group(3)]} Port Published',
                    f'The {DB_PORTS[port.group(3)]} port is published on all host interfaces',
                    Severity.MEDIUM, Category.EXPOSURE,
                    'Do not publish database ports, or bind them to 127.0.0.1 (e.g. "127.0.0.1:5432:5432").',
                    'CWE-668', 'compose_db_port'))
        return vulns

    # ------------------------------------------------------------------ GitHub Actions

    def _scan_workflow(self, context: ScanContext) -> List[Vulnerability]:
        vulns = []
        content = context.file_content
        lines = content.splitlines()
        uses_prt = re.search(r'^\s*pull_request_target\s*:|on:\s*\[?[^\]\n]*pull_request_target', content, re.MULTILINE)

        in_run = False
        run_indent = 0
        for i, line in enumerate(lines, 1):
            indent = len(line) - len(line.lstrip())
            run_match = re.match(r'^\s*(?:-\s*)?run\s*:\s*(.*)$', line)
            if run_match:
                in_run = True
                run_indent = indent
                body = run_match.group(1)
            elif in_run and (indent > run_indent or not line.strip()):
                body = line
            else:
                in_run = False
                body = ''

            if body and re.search(
                r'\$\{\{\s*github\.(?:event\.(?:issue|pull_request|comment|review|review_comment|discussion|head_commit|pages|commits)[^}]*'
                r'(?:title|body|message|name|label|ref|email|default_branch)|head_ref)[^}]*\}\}', body):
                vulns.append(self._make(
                    context, i, 'GitHub Actions Script Injection',
                    'Attacker-controlled event data is interpolated directly into a shell script',
                    Severity.HIGH, Category.INJECTION,
                    'Pass the value through an environment variable (env: TITLE: ${{ ... }}) and use "$TITLE" in the script.',
                    'CWE-78', 'gha_script_injection'))

            if uses_prt and re.search(r'ref\s*:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)', line):
                vulns.append(self._make(
                    context, i, 'pull_request_target Checks Out Untrusted Code',
                    'Workflow runs with repository secrets on pull_request_target and checks out the PR head - '
                    'a malicious PR can steal secrets',
                    Severity.CRITICAL, Category.CONFIGURATION,
                    'Use the pull_request event for untrusted code, or never check out / execute PR code here.',
                    'CWE-829', 'gha_prt_checkout'))

            if re.search(r'^\s*permissions\s*:\s*write-all\b', line):
                vulns.append(self._make(
                    context, i, 'Workflow Has write-all Permissions',
                    'The GITHUB_TOKEN can write to every scope',
                    Severity.MEDIUM, Category.AUTHENTICATION,
                    'Declare minimal permissions (e.g. permissions: contents: read).', 'CWE-250', 'gha_write_all'))

            uses = re.match(r'^\s*(?:-\s*)?uses\s*:\s*["\']?([\w.-]+/[\w./-]+)@([\w.\-/]+)', line)
            if uses:
                owner = uses.group(1).split('/')[0].lower()
                ref = uses.group(2)
                if owner not in ('actions', 'github') and not re.fullmatch(r'[0-9a-f]{40}', ref):
                    vulns.append(self._make(
                        context, i, 'Third-Party Action Not Pinned to Commit',
                        f'{uses.group(1)}@{ref} is referenced by a mutable tag/branch; a compromised tag runs in your CI',
                        Severity.LOW, Category.DEPENDENCY,
                        'Pin third-party actions to a full commit SHA (and let Dependabot update it).', 'CWE-829',
                        'gha_unpinned_action'))
        return vulns
