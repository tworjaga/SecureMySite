"""File discovery and exclusion rules."""

from core.config import Config
from core.file_loader import FileLoader


def loaded(project):
    return sorted(p.relative_to(project).as_posix() for p, _ in FileLoader(project).load_files())


def test_substring_names_are_not_excluded(make_project):
    project = make_project({
        "layout.py": "x = 1",
        "checkout.js": "let a = 1",
        "website/app.py": "x = 1",
        "src/environment.py": "x = 1",
        "about.txt": "hello",
    })
    assert loaded(project) == ["about.txt", "checkout.js", "layout.py", "src/environment.py", "website/app.py"]


def test_dependency_and_build_dirs_excluded(make_project):
    project = make_project({
        "node_modules/lib/index.js": "eval(x)",
        "dist/bundle.js": "eval(x)",
        "__pycache__/x.py": "",
        "src/main.py": "x = 1",
    })
    assert loaded(project) == ["src/main.py"]


def test_env_files_and_dockerfile_are_scanned(make_project):
    project = make_project({
        ".env": "SECRET=1",
        ".env.production": "SECRET=1",
        "Dockerfile": "FROM python",
        "image.png": "not really",
    })
    assert loaded(project) == [".env", ".env.production", "Dockerfile"]


def test_virtualenv_detected_by_pyvenv_cfg(make_project):
    project = make_project({
        "myenv/pyvenv.cfg": "home = x",
        "myenv/lib/site.py": "eval(x)",
        "app.py": "x = 1",
    })
    assert loaded(project) == ["app.py"]


def test_securemysiteignore(make_project):
    project = make_project({
        ".securemysiteignore": "# comment\nlegacy/\n*.min.js\n",
        "legacy/old.py": "eval(x)",
        "static/lib.min.js": "eval(x)",
        "static/app.js": "x",
    })
    assert loaded(project) == ["static/app.js"]


def test_extra_excludes(make_project):
    project = make_project({"migrations/0001.py": "x", "app.py": "x"})
    files = [p.name for p, _ in FileLoader(project, extra_excludes=["migrations/*"]).load_files()]
    assert files == ["app.py"]


def test_config_language_resolution():
    assert Config.get_language(".env.local") == "env"
    assert Config.get_language("Dockerfile") == "dockerfile"
    assert Config.get_language("index.html") == "html"
    assert Config.get_language("page.jinja2") == "html"
    assert Config.get_language("photo.png") is None
