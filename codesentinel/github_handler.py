"""Bounded, read-only ingestion for public GitHub repositories."""

from __future__ import annotations

import io
import json
import re
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from codesentinel.models import RepositoryInfo, RepositorySnapshot


MAX_ARCHIVE_BYTES = 20 * 1024 * 1024
MAX_TOTAL_RELEVANT_BYTES = 25 * 1024 * 1024
MAX_SOURCE_BYTES = 15 * 1024 * 1024
MAX_SOURCE_FILE_BYTES = 1024 * 1024
MAX_SOURCE_LINES = 250_000
MAX_SOURCE_FILE_LINES = 50_000
MAX_ANALYZED_FILES = 8000
MAX_API_RESPONSE_BYTES = 512 * 1024
IGNORED_DIRECTORIES = {
    ".git", ".hg", ".svn", "node_modules", "venv", ".venv", "env",
    "dist", "build", "__pycache__", ".mypy_cache", ".pytest_cache",
    "coverage", "vendor", "target", "out",
}

LANGUAGE_EXTENSIONS = {
    ".py": "Python", ".pyi": "Python", ".java": "Java", ".js": "JavaScript",
    ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".mts": "TypeScript",
    ".cts": "TypeScript", ".c": "C", ".h": "C/C++", ".cc": "C++",
    ".cpp": "C++", ".cxx": "C++", ".hpp": "C++", ".hh": "C++",
    ".cs": "C#", ".go": "Go", ".rs": "Rust", ".rb": "Ruby",
    ".php": "PHP", ".swift": "Swift", ".kt": "Kotlin", ".kts": "Kotlin",
    ".scala": "Scala", ".sh": "Shell", ".bash": "Shell", ".html": "HTML",
    ".css": "CSS", ".sql": "SQL", ".xml": "XML", ".yaml": "YAML",
    ".yml": "YAML", ".toml": "TOML", ".json": "JSON",
}
RELEVANT_FILENAMES = {
    "readme", "readme.md", "readme.rst", "dockerfile", "makefile",
    "pyproject.toml", "setup.py", "requirements.txt", "package.json",
    "go.mod", "cargo.toml", "pom.xml", "build.gradle", "composer.json",
    ".env.example", ".env.sample",
}
OWNER_OR_REPO = re.compile(r"^[A-Za-z0-9_.-]+$")
ALLOWED_REDIRECT_HOSTS = {"api.github.com", "codeload.github.com"}


class RepositoryError(ValueError):
    """An invalid, unavailable, or oversized repository input."""


class _GitHubRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        target = urlsplit(new_url)
        if target.scheme != "https" or target.hostname not in ALLOWED_REDIRECT_HOSTS:
            raise RepositoryError("GitHub returned an unexpected download redirect.")
        return super().redirect_request(request, response, code, message, headers, new_url)


def parse_github_url(repository_url: str) -> tuple[str, str]:
    """Accept only canonical public GitHub repository URLs."""
    if not isinstance(repository_url, str) or len(repository_url) > 500:
        raise RepositoryError("Enter a valid public GitHub repository URL.")
    parsed = urlsplit(repository_url.strip())
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.query
        or parsed.fragment
    ):
        raise RepositoryError("Use a public repository URL in the form https://github.com/owner/repository.")
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) != 2:
        raise RepositoryError("Use a repository URL, not a file, issue, or branch URL.")
    owner, name = parts
    if name.lower().endswith(".git"):
        name = name[:-4]
    if not OWNER_OR_REPO.fullmatch(owner) or not OWNER_OR_REPO.fullmatch(name):
        raise RepositoryError("The repository URL contains an invalid owner or repository name.")
    if owner in {".", ".."} or name in {".", ".."}:
        raise RepositoryError("The repository URL contains an invalid owner or repository name.")
    return owner, name


def _read_bounded(response, maximum: int) -> bytes:
    declared_size = response.headers.get("Content-Length")
    if declared_size:
        try:
            if int(declared_size) > maximum:
                raise RepositoryError("The repository archive exceeds the 20 MB download limit.")
        except ValueError:
            pass
    chunks = []
    total = 0
    while True:
        chunk = response.read(min(64 * 1024, maximum + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum:
            raise RepositoryError("The repository archive exceeds the 20 MB download limit.")
    return b"".join(chunks)


def _open_github(url: str, maximum: int) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "CodeSentinel/1.0", "Accept": "application/vnd.github+json"},
    )
    opener = urllib.request.build_opener(_GitHubRedirectHandler())
    with opener.open(request, timeout=15) as response:
        final_url = urlsplit(response.geturl())
        if final_url.scheme != "https" or final_url.hostname not in ALLOWED_REDIRECT_HOSTS:
            raise RepositoryError("GitHub returned an unexpected download location.")
        return _read_bounded(response, maximum)


def _is_relevant(path: str) -> bool:
    filename = PurePosixPath(path).name.lower()
    return PurePosixPath(path).suffix.lower() in LANGUAGE_EXTENSIONS or filename in RELEVANT_FILENAMES


def _is_source(path: str) -> bool:
    return PurePosixPath(path).suffix.lower() in LANGUAGE_EXTENSIONS


def inspect_zip(
    archive: bytes,
    owner: str,
    name: str,
    default_branch: str,
    repository_url: str,
) -> RepositorySnapshot:
    """Read text source and project metadata without extracting or executing files."""
    if len(archive) > MAX_ARCHIVE_BYTES:
        raise RepositoryError("The repository archive exceeds the 20 MB download limit.")
    files: dict[str, str] = {}
    language_counts: dict[str, int] = {}
    warnings: list[str] = []
    skipped_files = 0
    total_relevant_bytes = 0
    total_source_bytes = 0
    total_source_lines = 0
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
            for entry in zipped.infolist():
                if entry.is_dir():
                    continue
                raw_path = entry.filename
                if "\\" in raw_path or ":" in raw_path or raw_path.startswith("/"):
                    skipped_files += 1
                    continue
                path_parts = PurePosixPath(raw_path).parts
                if len(path_parts) < 2 or any(part in {"", ".", ".."} for part in path_parts):
                    skipped_files += 1
                    continue
                relative_parts = path_parts[1:]
                if any(part.lower() in IGNORED_DIRECTORIES for part in relative_parts[:-1]):
                    skipped_files += 1
                    continue
                relative_path = "/".join(relative_parts)
                if not _is_relevant(relative_path):
                    continue
                if entry.file_size > MAX_SOURCE_FILE_BYTES:
                    skipped_files += 1
                    warnings.append(f"Skipped oversized file: {relative_path}")
                    continue
                if total_relevant_bytes + entry.file_size > MAX_TOTAL_RELEVANT_BYTES:
                    skipped_files += 1
                    warnings.append(f"Skipped file after reaching the total analysis byte budget: {relative_path}")
                    continue
                if len(files) >= MAX_ANALYZED_FILES:
                    raise RepositoryError("The repository contains more than 8,000 relevant files.")
                if _is_source(relative_path) and total_source_bytes + entry.file_size > MAX_SOURCE_BYTES:
                    raise RepositoryError("The repository source exceeds the 15 MB analysis limit.")
                if relative_path in files:
                    skipped_files += 1
                    continue
                content_bytes = zipped.read(entry)
                total_relevant_bytes += len(content_bytes)
                if b"\x00" in content_bytes:
                    skipped_files += 1
                    continue
                source_line_count = content_bytes.count(b"\n") + int(
                    bool(content_bytes) and not content_bytes.endswith(b"\n")
                )
                if _is_source(relative_path) and (
                    source_line_count > MAX_SOURCE_FILE_LINES
                    or total_source_lines + source_line_count > MAX_SOURCE_LINES
                ):
                    skipped_files += 1
                    warnings.append(f"Skipped source file over the analysis line budget: {relative_path}")
                    continue
                content = content_bytes.decode("utf-8", errors="replace")
                files[relative_path] = content
                if _is_source(relative_path):
                    total_source_bytes += len(content_bytes)
                    total_source_lines += source_line_count
                    extension = PurePosixPath(relative_path).suffix.lower()
                    language = LANGUAGE_EXTENSIONS[extension]
                    language_counts[language] = language_counts.get(language, 0) + 1
    except RepositoryError:
        raise
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        raise RepositoryError("GitHub returned an unreadable repository archive.") from exc

    if not language_counts:
        raise RepositoryError("No supported source files or project metadata were found in this repository.")
    repository = RepositoryInfo(
        name=name,
        owner=owner,
        url=repository_url,
        default_branch=default_branch,
        languages=dict(sorted(language_counts.items(), key=lambda item: (-item[1], item[0]))),
        analyzed_files=len(files),
        skipped_files=skipped_files,
    )
    return RepositorySnapshot(repository=repository, files=files, warnings=warnings)


def download_repository(repository_url: str) -> RepositorySnapshot:
    """Download and inspect a public GitHub repository with strict resource bounds."""
    owner, name = parse_github_url(repository_url)
    api_url = f"https://api.github.com/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(name)}"
    try:
        metadata = json.loads(_open_github(api_url, MAX_API_RESPONSE_BYTES))
        default_branch = metadata.get("default_branch")
        if not isinstance(default_branch, str) or not default_branch:
            raise RepositoryError("GitHub did not provide a default branch for this repository.")
        archive_url = (
            f"https://codeload.github.com/{urllib.parse.quote(owner)}/{urllib.parse.quote(name)}"
            f"/zip/refs/heads/{urllib.parse.quote(default_branch, safe='')}"
        )
        archive = _open_github(archive_url, MAX_ARCHIVE_BYTES)
        return inspect_zip(archive, owner, name, default_branch, repository_url.strip())
    except RepositoryError:
        raise
    except urllib.error.HTTPError as exc:
        if exc.code in {403, 404}:
            raise RepositoryError("Repository is private, unavailable, or GitHub's unauthenticated API limit was reached.") from exc
        raise RepositoryError(f"GitHub could not provide this repository (HTTP {exc.code}).") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise RepositoryError("Could not reach GitHub or read its repository metadata. Try again shortly.") from exc
    except (KeyError, TypeError) as exc:
        raise RepositoryError("GitHub returned incomplete repository metadata.") from exc