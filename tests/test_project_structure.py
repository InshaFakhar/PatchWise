"""Phase 3 structural tests.

These tests do not test PatchWise features (none exist yet). They check that:
  1. the project skeleton is complete,
  2. secrets are protected (TB-01),
  3. the ranking engine stays independent of the LLM (TB-02, Proposal Section 8).
"""

import ast
import importlib
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "patchwise"

EXPECTED_DIRS = [
    "config", "data/synthetic", "data/snapshots", "docs", "eval", "tests",
    "deploy", "patchwise/db", "patchwise/ingest", "patchwise/ranking",
    "patchwise/explain", "patchwise/review", "patchwise/export", "patchwise/web",
]
EXPECTED_FILES = [
    "README.md", "LICENSE", ".gitignore", ".env.example", "requirements.txt",
    "requirements-dev.txt", "pytest.ini", "config/settings.yaml",
    "config/scoring_config.yaml", "patchwise/services.py", "patchwise/cli.py",
]
SUBPACKAGES = ["db", "ingest", "ranking", "explain", "review", "export", "web"]

# Top-level names of LLM client libraries. Only patchwise/explain may use them.
LLM_LIBRARIES = {"google", "groq", "openai", "anthropic"}


# ---------- helper functions ----------

def collect_imports(py_file):
    """Return every imported module name in a Python file (without running it)."""
    tree = ast.parse(Path(py_file).read_text(encoding="utf-8"))
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            base = "." * node.level + (node.module or "")
            if node.module is None:  # e.g. "from .. import explain"
                for alias in node.names:
                    found.append(base + alias.name)
            else:
                found.append(base)
    return found


def points_to_explain(name):
    """True if an import name refers to the patchwise.explain package."""
    parts = name.lstrip(".").split(".")
    return parts[0] == "explain" or parts[:2] == ["patchwise", "explain"]


def uses_llm_library(name):
    """True if an import name belongs to an LLM client library."""
    return name.lstrip(".").split(".")[0] in LLM_LIBRARIES


def violations_in_ranking(ranking_dir):
    """List forbidden imports found inside a ranking package folder."""
    problems = []
    for py_file in Path(ranking_dir).rglob("*.py"):
        for name in collect_imports(py_file):
            if points_to_explain(name) or uses_llm_library(name):
                problems.append(f"{py_file.name}: {name}")
    return problems


# ---------- skeleton tests ----------

def test_expected_directories_exist():
    missing = [d for d in EXPECTED_DIRS if not (ROOT / d).is_dir()]
    assert not missing, f"Missing directories: {missing}"


def test_expected_files_exist():
    missing = [f for f in EXPECTED_FILES if not (ROOT / f).is_file()]
    assert not missing, f"Missing files: {missing}"


def test_package_has_version():
    patchwise = importlib.import_module("patchwise")
    assert patchwise.__version__ == "0.1.0"


def test_every_package_folder_has_init_file():
    """Each backend folder must be a real package (have __init__.py)."""
    missing = [
        name for name in ["."] + SUBPACKAGES
        if not (PACKAGE / name / "__init__.py").is_file()
    ]
    assert not missing, f"Missing __init__.py in: {missing}"


def test_all_subpackages_are_importable():
    for name in SUBPACKAGES:
        importlib.import_module(f"patchwise.{name}")


def test_mit_license_present():
    text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert text.startswith("MIT License")


# ---------- secret-protection tests (TB-01) ----------

def test_gitignore_protects_secrets_and_database():
    lines = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert ".env" in lines
    assert "*.db" in lines


def test_env_example_contains_no_real_keys():
    for line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        if name.endswith("_API_KEY") or name.endswith("SECRET_KEY"):
            assert value == "", f"{name} must be empty in .env.example"


# ---------- architecture-rule tests (TB-02) ----------

def test_ranking_package_is_independent_of_llm():
    problems = violations_in_ranking(PACKAGE / "ranking")
    assert not problems, f"Ranking must not use the LLM layer: {problems}"


def test_llm_libraries_are_used_only_inside_explain():
    problems = []
    for py_file in PACKAGE.rglob("*.py"):
        if "explain" in py_file.relative_to(PACKAGE).parts:
            continue
        for name in collect_imports(py_file):
            if uses_llm_library(name):
                problems.append(f"{py_file.relative_to(ROOT)}: {name}")
    assert not problems, f"LLM libraries used outside explain/: {problems}"


def test_guard_really_detects_violations():
    """Proves the independence guard is not vacuously passing on empty folders."""
    bad_examples = [
        "from patchwise.explain import something\n",
        "from ..explain import something\n",
        "from .. import explain\n",
        "import groq\n",
        "from google import generativeai\n",
    ]

    for code in bad_examples:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "bad.py").write_text(code, encoding="utf-8")
            assert violations_in_ranking(tmp), f"Guard missed: {code!r}"

    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "good.py").write_text("import math\nfrom pathlib import Path\n")
        assert not violations_in_ranking(tmp)