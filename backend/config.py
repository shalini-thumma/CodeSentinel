"""Thresholds and environment settings.

Change a limit here rather than inside a detector. The README describes
what each value does so the scoring and scan bounds stay explainable.
"""

from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT_DIR = ROOT / "reports"
SEMGREP_RULES = ROOT / "rules" / "semgrep.yml"

try:
    from dotenv import load_dotenv

    load_dotenv(ROOT / ".env")
except ImportError:
    pass

# Directories that are dependencies, build output, or tooling caches.
IGNORE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".next",
    ".nuxt",
    "node_modules",
    "bower_components",
    "venv",
    ".venv",
    "env",
    "dist",
    "build",
    "__pycache__",
    "site-packages",
    "dist-packages",
    "coverage",
    "htmlcov",
    "vendor",
    "target",
    "out",
    "bin",
    "obj",
}

SKIP_FILE_NAMES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "cargo.lock",
    "composer.lock",
    "gemfile.lock",
    ".ds_store",
}

# Safety bounds. Large inputs are rejected or truncated instead of scanned forever.
MAX_REPO_BYTES = 80 * 1024 * 1024
MAX_FILES = 2500
MAX_FILE_BYTES = 400_000
CLONE_TIMEOUT_SECONDS = 90
EXTERNAL_TOOL_TIMEOUT_SECONDS = 120
MAX_FINDINGS_PER_RULE = 40
MAX_LINE_LENGTH = 2000

# Duplicate and complexity heuristics.
DUPLICATE_WINDOW = 4
COMPLEXITY_THRESHOLD = 12

CODE_LANGUAGES = {
    "Python",
    "Java",
    "JavaScript",
    "TypeScript",
    "C",
    "C++",
    "Go",
    "Rust",
    "PHP",
    "Ruby",
    "C#",
    "Kotlin",
    "Swift",
    "Shell",
    "SQL",
}

# Penalty subtracted from a starting score of 100.
# Security findings weigh more because they are the primary risk signal.
SECURITY_WEIGHTS = {
    "critical": 18,
    "high": 10,
    "medium": 4,
    "low": 1,
    "informational": 0,
}
OTHER_WEIGHTS = {
    "critical": 8,
    "high": 4,
    "medium": 2,
    "low": 1,
    "informational": 0,
}

SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")


def llm_settings() -> tuple[str, str, str] | None:
    """Return (api_key, base_url, model) or None when AI review is off."""
    key = (os.getenv("CODESENTINEL_LLM_API_KEY") or os.getenv("OPENAI_API_KEY") or "").strip()
    if not key:
        return None
    base = (os.getenv("CODESENTINEL_LLM_BASE_URL") or "https://api.openai.com/v1").strip()
    model = (os.getenv("CODESENTINEL_LLM_MODEL") or "gpt-4o-mini").strip()
    return key, base, model
