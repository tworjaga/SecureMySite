"""Unit tests for the individual scanners."""

from scanners.python_sast import PythonSASTScanner
from scanners.js_scanner import JavaScriptScanner
from scanners.config_scanner import ConfigScanner
from scanners.dependency_scanner import DependencyScanner
from scanners.secrets_scanner import SecretsScanner
from scanners.html_scanner import HTMLScanner
from scanners.iac_scanner import IaCScanner
from models.vulnerability import Severity

from tests.conftest import scan_file, titles


# ----------------------------------------------------------------- Python

def test_python_sql_injection_via_variable(make_project):
    project = make_project({"db.py": '''
        def get(cur, name):
            q = "SELECT * FROM users WHERE name = '%s'" % name
            cur.execute(q)
            cur.execute(f"DELETE FROM t WHERE id = {name}")
            cur.execute("SELECT * FROM users WHERE name = ?", (name,))
    '''})
    vulns = scan_file(PythonSASTScanner(), project, "db.py")
    assert [v.line_number for v in vulns if v.title == "SQL Injection"] == [3, 4]


def test_python_ignores_comments_and_constants(make_project):
    project = make_project({"ok.py": '''
        # eval(user_input) would be bad here
        import subprocess
        value = eval("1 + 1")
        subprocess.run(["ls", "-l"])
        password = os.environ["PASSWORD"]
        api_key = "changeme"
        HELP = "Remove @csrf_exempt, never pass verify=False, avoid ALLOWED_HOSTS = ['*']"
        doc = f"use hashlib.md5( only with usedforsecurity=False {x}"
    '''})
    assert scan_file(PythonSASTScanner(), project, "ok.py") == []


def test_python_command_injection_and_secrets(make_project):
    project = make_project({"app.py": '''
        import os, subprocess, pickle, yaml
        os.system("ping " + host)
        subprocess.call(cmd, shell=True)
        data = pickle.loads(blob)
        cfg = yaml.load(text)
        safe = yaml.load(text, Loader=yaml.SafeLoader)
        app.config["SECRET_KEY"] = "s3cr3t-value-123"
        token = random.choice(chars) + "x"
    '''})
    found = titles(scan_file(PythonSASTScanner(), project, "app.py"))
    assert "Command Injection via os.system()" in found
    assert "Shell Command Injection" in found
    assert "Unsafe Deserialization" in found
    assert found.count("Unsafe YAML Loading") == 1
    assert "Hardcoded Secret Key" in found
    assert "Insecure Randomness" in found


def test_python_syntax_error_falls_back_to_regex(make_project):
    project = make_project({"broken.py": "def x(:\n    eval(data)\n"})
    assert "Dynamic Code Execution" in titles(scan_file(PythonSASTScanner(), project, "broken.py"))


# ----------------------------------------------------------------- JavaScript

def test_js_no_false_positive_on_on_prefixed_names(make_project):
    project = make_project({"a.js": '''
        const option = 1;
        let connection = db();
        el.textContent = userInput;
        el.innerHTML = '';
    '''})
    assert scan_file(JavaScriptScanner(), project, "a.js") == []


def test_js_detects_modern_sinks(make_project):
    project = make_project({"a.jsx": '''
        <div dangerouslySetInnerHTML={{ __html: comment }} />
        db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)
        app.use(cors())
        https.request({ rejectUnauthorized: false })
        res.send("Hello " + req.query.name)
        // eval(commented)
    '''})
    found = titles(scan_file(JavaScriptScanner(), project, "a.jsx"))
    assert "XSS via dangerouslySetInnerHTML" in found
    assert "SQL Injection" in found
    assert "Open CORS Policy" in found
    assert "TLS Certificate Validation Disabled" in found
    assert "Reflected XSS" in found
    assert "Code Injection via eval()" not in found


def test_js_secrets_masked(make_project):
    project = make_project({"k.js": "const apiKey = 'abcdefghijklmnopqrstuvwxyz123456';\n"})
    vulns = scan_file(JavaScriptScanner(), project, "k.js")
    assert vulns and "abcdefghijklmnopqrstuvwxyz123456" not in vulns[0].code_snippet


# ----------------------------------------------------------------- Config

def test_config_env_unquoted_values_and_placeholders(make_project):
    project = make_project({
        ".env": "DEBUG=true\nSECRET_KEY=abc123def456ghi\nDB_PASSWORD=hunter22\nAPI_KEY=${API_KEY}\n",
        ".env.example": "SECRET_KEY=changeme\n",
    })
    vulns = scan_file(ConfigScanner(), project, ".env")
    found = titles(vulns)
    assert "Sensitive File Exposed: .env" in found
    assert "Hardcoded Secret" in found
    assert "Database Credentials in Config" in found
    assert "API Key Exposed" not in found
    assert all("abc123def456ghi" not in (v.code_snippet or "") for v in vulns)
    assert not ConfigScanner().can_scan_file(project / "settings.py")
    assert scan_file(ConfigScanner(), project, ".env.example") == []


def test_config_gitignored_env_is_low(make_project):
    project = make_project({".gitignore": ".env\n", ".env": "X=1\n"})
    vulns = scan_file(ConfigScanner(), project, ".env")
    assert vulns[0].severity == Severity.LOW


def test_config_json_secret_line_number(make_project):
    project = make_project({"config.json": '{\n  "name": "x",\n  "db": {"password": "realpassw0rd!"}\n}\n'})
    vulns = scan_file(ConfigScanner(), project, "config.json")
    assert [(v.title, v.line_number) for v in vulns] == [("Secret in JSON Config: password", 3)]


# ----------------------------------------------------------------- Dependencies

def test_dependency_version_matching(make_project):
    project = make_project({"requirements.txt": "django==3.0.0\nrequests==2.32.3\nflask\n"})
    vulns = scan_file(DependencyScanner(), project, "requirements.txt")
    packages = {v.metadata.get("package") for v in vulns}
    assert "django" in packages
    assert "requests" not in packages
    assert "flask" not in packages  # unpinned: no version, no CVE match ...
    assert "Unpinned Dependencies" in titles(vulns)  # ... but flagged as unpinned
    django = next(v for v in vulns if v.metadata.get("package") == "django")
    assert django.metadata["fixed_version"]
    assert django.line_number == 1


def test_dependency_specifier_semantics():
    scanner = DependencyScanner()
    assert scanner._version_affected("1.2.5", ["<1.2.6"])
    assert not scanner._version_affected("1.2.6", ["<1.2.6"])
    assert scanner._version_affected("3.1.5", [">=3.1,<3.1.8"])
    assert not scanner._version_affected("3.2.0", [">=3.1,<3.1.8"])
    assert scanner._version_affected("2.0", ["<=2.0"])


def test_package_lock_is_authoritative(make_project):
    project = make_project({
        "package.json": '{"dependencies": {"minimist": "^1.2.0"}}',
        "package-lock.json": '{"lockfileVersion": 3, "packages": {"": {}, '
                             '"node_modules/minimist": {"version": "1.2.8"}}}',
    })
    assert scan_file(DependencyScanner(), project, "package.json") == []
    assert scan_file(DependencyScanner(), project, "package-lock.json") == []


def test_pyproject_dependencies(make_project):
    project = make_project({"pyproject.toml": '[project]\nname = "x"\ndependencies = ["pyyaml==3.13"]\n'})
    vulns = scan_file(DependencyScanner(), project, "pyproject.toml")
    assert any(v.metadata.get("package") == "pyyaml" for v in vulns)


# ----------------------------------------------------------------- Secrets

def test_secrets_provider_tokens(make_project):
    project = make_project({"deploy.sh.txt": (
        "AWS=AKIAIOSFODNN7EXAMPLE\n"
        "GH=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
    )})
    vulns = scan_file(SecretsScanner(), project, "deploy.sh.txt")
    assert [v.metadata["secret_type"] for v in vulns] == ["AWS Access Key ID", "GitHub Token", "Private Key"]
    assert all("AKIAIOSFODNN7EXAMPLE" not in (v.code_snippet or "") for v in vulns)


def test_short_secrets_fully_masked():
    from scanners.base_scanner import mask_secret
    assert mask_secret("Sup3rS3cret") == "********"
    token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    assert mask_secret(token).startswith("ghp_")
    assert "abcdefghijklmnop" not in mask_secret(token)


def test_short_password_in_connection_string_not_leaked(make_project):
    project = make_project({".env": "DATABASE_URL=postgres://app:Sup3rS3cret@db:5432/app\n"})
    vulns = scan_file(ConfigScanner(), project, ".env")
    blob = " ".join((v.code_snippet or "") + str(v.metadata.get("match", "")) for v in vulns)
    assert "Sup3" not in blob


def test_secrets_skip_lockfiles(make_project):
    project = make_project({"package-lock.json": '{"x": "AKIAIOSFODNN7EXAMPLE"}'})
    assert not SecretsScanner().can_scan_file(project / "package-lock.json")


# ----------------------------------------------------------------- HTML

def test_html_scanner(make_project):
    project = make_project({"templates/index.html": '''
        <html>
        <script src="https://cdn.example.com/lib.js"></script>
        <script src="http://cdn.example.com/old.js"></script>
        <a href="https://other.example" target="_blank">x</a>
        <form method="get"><input type="password" name="pw"></form>
        <div>{{ comment|safe }}</div>
        <button onclick="go()">go</button>
        <script>
          document.getElementById('o').innerHTML = location.hash;
        </script>
        </html>
    '''})
    vulns = scan_file(HTMLScanner(), project, "templates/index.html")
    found = titles(vulns)
    for expected in ("Third-Party Script Without SRI", "Script Loaded over HTTP",
                     'target="_blank" Without rel="noopener"', "Password Sent in URL",
                     "Unescaped Template Output (|safe)", "Inline Event Handlers", "DOM XSS via innerHTML"):
        assert expected in found, expected
    xss = next(v for v in vulns if v.title == "DOM XSS via innerHTML")
    assert xss.line_number == 9


# ----------------------------------------------------------------- IaC

def test_dockerfile_checks(make_project):
    project = make_project({"Dockerfile": '''
        FROM python:latest
        ENV API_KEY=supersecretvalue
        ADD https://example.com/x.tar.gz /tmp/
        RUN curl -fsSL https://get.example.com | sh
        COPY . /app
        CMD ["python", "app.py"]
    '''})
    found = titles(scan_file(IaCScanner(), project, "Dockerfile"))
    for expected in ("Unpinned Base Image", "Secret in Dockerfile ENV", "ADD Downloads Remote File",
                     "Remote Script Piped to Shell", "COPY . Without .dockerignore", "Container Runs as Root"):
        assert expected in found, expected


def test_dockerfile_non_root_ok(make_project):
    project = make_project({"Dockerfile": "FROM python:3.12-slim\nUSER app\n", ".dockerignore": ".env\n"})
    assert scan_file(IaCScanner(), project, "Dockerfile") == []


def test_compose_and_workflow(make_project):
    project = make_project({
        "docker-compose.yml": '''
            services:
              db:
                image: postgres:16
                ports:
                  - "5432:5432"
              agent:
                privileged: true
                volumes:
                  - /var/run/docker.sock:/var/run/docker.sock
        ''',
        ".github/workflows/ci.yml": '''
            on: pull_request_target
            permissions: write-all
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                    with:
                      ref: ${{ github.event.pull_request.head.sha }}
                  - uses: some/action@v1
                  - run: echo "${{ github.event.pull_request.title }}"
        ''',
    })
    compose = titles(scan_file(IaCScanner(), project, "docker-compose.yml"))
    assert {"PostgreSQL Port Published", "Privileged Container", "Docker Socket Mounted"} <= set(compose)
    workflow = titles(scan_file(IaCScanner(), project, ".github/workflows/ci.yml"))
    assert {"GitHub Actions Script Injection", "pull_request_target Checks Out Untrusted Code",
            "Workflow Has write-all Permissions", "Third-Party Action Not Pinned to Commit"} <= set(workflow)
