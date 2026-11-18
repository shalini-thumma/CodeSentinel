"""Clone a public GitHub repository without accepting credentials or shell input.

The user string is parsed into an owner and a repository name. The clone URL
is rebuilt from those two pieces, and git is started with an argument list
rather than a shell command.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from backend.config import CLONE_TIMEOUT_SECONDS, MAX_REPO_BYTES
from backend.errors import InvalidRepositoryURL, RepositoryAccessError, RepositoryTooLarge

logger = logging.getLogger("codesentinel.github")

_IDENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$")


@dataclass
class CloneHandle:
    root: Path
    owner: str
    repo: str
    workspace: Path

    def cleanup(self) -> None:
        shutil.rmtree(self.workspace, ignore_errors=True)


def parse_github_url(url: str) -> tuple[str, str]:
    """Accept https://github.com/owner/repo and reject everything else."""
    if url is None or not str(url).strip():
        raise InvalidRepositoryURL("Enter a GitHub repository URL.")
    raw = str(url).strip()
    if any(char in raw for char in ("\n", "\r", "\x00", " ", "\\")):
        raise InvalidRepositoryURL("The URL contains unsupported characters.")
    if "@" in raw:
        raise InvalidRepositoryURL("URLs that contain credentials are not accepted.")

    parsed = urlparse(raw)
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com":
        raise InvalidRepositoryURL("Only public https://github.com/owner/repo URLs are supported.")
    if parsed.query or parsed.fragment:
        raise InvalidRepositoryURL("Use the repository root URL, without a branch, file, or query string.")

    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) != 2:
        raise InvalidRepositoryURL("Use the repository root, for example https://github.com/owner/repo.")

    owner, repo = parts
    if repo.endswith(".git"):
        repo = repo[: -len(".git")]
    if not _IDENT.match(owner) or not _IDENT.match(repo) or ".." in owner or ".." in repo:
        raise InvalidRepositoryURL("The owner or repository name contains unsupported characters.")
    return owner, repo


def build_clone_command(owner: str, repo: str, dest: Path) -> list[str]:
    url = f"https://github.com/{owner}/{repo}.git"
    return [
        "git",
        "-c",
        "protocol.file.allow=never",
        "clone",
        "--depth",
        "1",
        "--single-branch",
        "--no-tags",
        url,
        str(dest),
    ]


def _directory_size(path: Path) -> int:
    total = 0
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames[:] = [name for name in dirnames if name != ".git"]
        for name in filenames:
            try:
                total += (Path(dirpath) / name).stat().st_size
            except OSError:
                continue
    return total


def clone_repository(url: str) -> CloneHandle:
    """Shallow-clone a public repository into a temporary directory."""
    owner, repo = parse_github_url(url)
    if shutil.which("git") is None:
        raise RepositoryAccessError("Git is not installed or not on PATH.")

    workspace = Path(tempfile.mkdtemp(prefix="codesentinel_"))
    destination = workspace / repo
    command = build_clone_command(owner, repo, destination)
    logger.info("Cloning %s/%s", owner, repo)
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GCM_INTERACTIVE"] = "Never"
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=CLONE_TIMEOUT_SECONDS,
            env=env,
            check=False,
        )
    except subprocess.TimeoutExpired:
        shutil.rmtree(workspace, ignore_errors=True)
        raise RepositoryAccessError(
            "Cloning timed out. The repository may be too large or GitHub may be unreachable."
        ) from None
    except OSError:
        shutil.rmtree(workspace, ignore_errors=True)
        raise RepositoryAccessError("Git could not be started.") from None

    if completed.returncode != 0 or not destination.exists():
        shutil.rmtree(workspace, ignore_errors=True)
        message = (completed.stderr or completed.stdout or "").lower()
        if "not found" in message or "repository not found" in message:
            raise RepositoryAccessError(
                "Repository not found or not public. CodeSentinel only clones public HTTPS repositories."
            )
        if "could not resolve" in message or "unable to access" in message:
            raise RepositoryAccessError("Could not reach GitHub. Check the network connection and try again.")
        raise RepositoryAccessError("Git clone failed. The repository may be private, missing, or unavailable.")

    size = _directory_size(destination)
    if size > MAX_REPO_BYTES:
        shutil.rmtree(workspace, ignore_errors=True)
        raise RepositoryTooLarge(
            "The repository is larger than the 80 MB scan limit. Analyze a smaller project or a subfolder."
        )
    return CloneHandle(root=destination, owner=owner, repo=repo, workspace=workspace)
