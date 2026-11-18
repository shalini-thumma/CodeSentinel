"""Walk a project tree and decide which files are source code.

Detection is based on file extensions and names. It does not assume a
framework, a build system, or a particular folder layout.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from backend.config import CODE_LANGUAGES, IGNORE_DIRS, MAX_FILE_BYTES, MAX_FILES, SKIP_FILE_NAMES

EXT_LANGUAGE = {
    ".py": "Python",
    ".java": "Java",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".c": "C",
    ".h": "C",
    ".cpp": "C++",
    ".cc": "C++",
    ".cxx": "C++",
    ".hpp": "C++",
    ".hh": "C++",
    ".go": "Go",
    ".rs": "Rust",
    ".php": "PHP",
    ".rb": "Ruby",
    ".cs": "C#",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".swift": "Swift",
    ".sh": "Shell",
    ".bash": "Shell",
    ".sql": "SQL",
    ".json": "JSON",
    ".yml": "YAML",
    ".yaml": "YAML",
    ".toml": "Config",
    ".ini": "Config",
    ".cfg": "Config",
    ".conf": "Config",
    ".xml": "XML",
    ".html": "HTML",
    ".htm": "HTML",
    ".css": "CSS",
    ".md": "Markdown",
    ".txt": "Text",
    ".properties": "Config",
    ".gradle": "Build",
    ".env": "Config",
}

SPECIAL_NAMES = {
    "dockerfile": "Docker",
    "makefile": "Build",
    "jenkinsfile": "Groovy",
    "cmakelists.txt": "Build",
}


@dataclass
class SourceFile:
    relative: str
    language: str
    text: str
    lines: list[str]
    is_code: bool
    is_test: bool


@dataclass
class RepoSnapshot:
    root: Path
    files: list[SourceFile] = field(default_factory=list)
    languages: dict[str, int] = field(default_factory=dict)
    skipped: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    @property
    def file_count(self) -> int:
        return len(self.files)

    @property
    def scanned_code_files(self) -> int:
        return sum(1 for source in self.files if source.is_code)

    def code_files(self, *, include_tests: bool = True) -> list[SourceFile]:
        selected = []
        for source in self.files:
            if not source.is_code:
                continue
            if source.is_test and not include_tests:
                continue
            selected.append(source)
        return selected


def looks_like_test(relative: str) -> bool:
    path = Path(relative)
    if any(part.lower() in {"tests", "test", "__tests__"} for part in path.parts):
        return True
    name = path.name.lower()
    return (
        name.startswith("test_")
        or name.endswith("_test.py")
        or name.endswith(".spec.js")
        or name.endswith(".test.js")
        or name.endswith("_test.go")
    )


def classify_file(path: Path) -> str | None:
    name = path.name.lower()
    if name.startswith(".env"):
        return "Config"
    if name.startswith("readme"):
        return "Markdown"
    if name in SPECIAL_NAMES:
        return SPECIAL_NAMES[name]
    return EXT_LANGUAGE.get(path.suffix.lower())


def line_snippet(lines: list[str], line: int, radius: int = 2) -> str:
    if not lines or line < 1:
        return ""
    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    return "\n".join(f"{number}: {lines[number - 1].rstrip()}" for number in range(start, end + 1))


def _read_text(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:1024]:
        return None
    return data.decode("utf-8", errors="replace")


def inspect_repository(root: Path) -> RepoSnapshot:
    root = root.resolve()
    snapshot = RepoSnapshot(root=root)
    if not root.is_dir():
        snapshot.limitations.append("The path is not a directory.")
        return snapshot

    discovered: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(name for name in dirnames if name not in IGNORE_DIRS and not name.startswith("."))
        for name in sorted(filenames):
            if name.lower() in SKIP_FILE_NAMES:
                continue
            discovered.append(Path(dirpath) / name)

    truncated = False
    for path in discovered:
        language = classify_file(path)
        if language is None:
            continue
        relative = path.relative_to(root).as_posix()
        try:
            size = path.stat().st_size
        except OSError:
            snapshot.skipped.append(relative)
            continue
        if size > MAX_FILE_BYTES:
            snapshot.skipped.append(relative)
            continue
        text = _read_text(path)
        if text is None:
            snapshot.skipped.append(relative)
            continue
        if len(snapshot.files) >= MAX_FILES:
            truncated = True
            break
        source = SourceFile(
            relative=relative,
            language=language,
            text=text,
            lines=text.splitlines(),
            is_code=language in CODE_LANGUAGES,
            is_test=looks_like_test(relative),
        )
        snapshot.files.append(source)
        if source.is_code:
            snapshot.languages[language] = snapshot.languages.get(language, 0) + 1

    snapshot.languages = dict(sorted(snapshot.languages.items(), key=lambda item: (-item[1], item[0])))
    if truncated:
        snapshot.limitations.append(
            f"Only the first {MAX_FILES} text files were scanned. Results are partial."
        )
    if not snapshot.files:
        snapshot.limitations.append("No supported source or text files were found.")
    return snapshot
