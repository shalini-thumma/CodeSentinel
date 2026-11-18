from dataclasses import dataclass
from pathlib import PurePosixPath

from codesentinel.github_handler import LANGUAGE_EXTENSIONS
from codesentinel.models import RepositorySnapshot


@dataclass(frozen=True)
class ProjectInventory:
    source_files: dict[str, str]
    has_tests: bool
    has_documentation: bool
    has_dependency_manifest: bool
    has_configuration: bool


DEPENDENCY_FILES = {
    "requirements.txt", "pyproject.toml", "setup.py", "poetry.lock",
    "pipfile", "pipfile.lock", "package.json", "package-lock.json",
    "yarn.lock", "pnpm-lock.yaml", "pom.xml", "build.gradle",
    "build.gradle.kts", "go.mod", "cargo.toml", "composer.json",
}
CONFIGURATION_FILES = {
    ".env.example", ".env.sample", "dockerfile", "docker-compose.yml",
    "docker-compose.yaml", "pyproject.toml", "tsconfig.json", "pom.xml",
    "makefile", "webpack.config.js", "vite.config.js",
}


def build_inventory(snapshot: RepositorySnapshot) -> ProjectInventory:
    source_files = {
        path: content
        for path, content in snapshot.files.items()
        if PurePosixPath(path).suffix.lower() in LANGUAGE_EXTENSIONS
    }
    filenames = {PurePosixPath(path).name.lower() for path in snapshot.files}
    test_paths = [path.lower() for path in source_files]
    has_tests = any(
        "/test/" in f"/{path}/"
        or "/tests/" in f"/{path}/"
        or PurePosixPath(path).name.lower().startswith(("test_", "spec_"))
        or PurePosixPath(path).name.lower().endswith(("_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts"))
        for path in test_paths
    )
    has_documentation = any(
        PurePosixPath(path).name.lower() in {"readme", "readme.md", "readme.rst"}
        for path in snapshot.files
    )
    return ProjectInventory(
        source_files=source_files,
        has_tests=has_tests,
        has_documentation=has_documentation,
        has_dependency_manifest=bool(filenames & DEPENDENCY_FILES),
        has_configuration=bool(filenames & CONFIGURATION_FILES),
    )