"""Find unfinished edges around the code: unused names, missing handling, and missing project files.

Python names are resolved per file for imports and variables, and across the
whole tree for function calls, so a function used by a test is not called unused.
Placeholder functions are left to the gap detector.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

from backend.models import Finding, make_finding
from backend.python_ast import (
    decorator_names,
    is_abstract_function,
    is_placeholder_function,
    iter_functions,
    parse_module,
)
from backend.repository_analyzer import RepoSnapshot, SourceFile, line_snippet

STDLIB = set(getattr(sys, "stdlib_module_names", ())) | {"__future__"}
_DOC_LIMIT = 3

_PYTHON_DEP_FILES = {"requirements.txt", "pyproject.toml", "pipfile", "setup.py", "setup.cfg"}
_JS_DEP_FILES = {"package.json"}
_C_BUILD_FILES = {"makefile", "cmakelists.txt", "compile_commands.json", "meson.build"}
_CONFIG_FILES = {
    ".env.example",
    ".env.sample",
    ".env",
    "config.py",
    "settings.py",
    "pyproject.toml",
    "config.json",
    "config.yaml",
    "config.yml",
    "application.properties",
    "application.yml",
}


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    mapping: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            mapping[child] = node
    return mapping


def _inside(node: ast.AST, parents: dict[ast.AST, ast.AST], kinds: tuple[type, ...]) -> bool:
    current: ast.AST | None = node
    while current in parents:
        current = parents[current]
        if isinstance(current, kinds):
            return True
    return False


def _enclosing_function(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> ast.AST | None:
    current: ast.AST | None = node
    while current in parents:
        current = parents[current]
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current
    return None


def _risky_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name) and func.id in {"open", "urlopen"}:
        return True
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        owner = func.value.id
        if owner == "requests" and func.attr in {"get", "post", "put", "delete", "patch", "head", "request"}:
            return True
        if owner == "subprocess" and func.attr in {"run", "Popen", "call", "check_output", "check_call"}:
            return True
        if owner == "urllib" and func.attr == "request":
            return True
    return False


def _closes_resource(fn: ast.AST) -> bool:
    return any(isinstance(node, ast.Attribute) and node.attr == "close" for node in ast.walk(fn))


def _is_open_call(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open"


def _swallowed(handler: ast.ExceptHandler) -> bool:
    body = handler.body
    if len(body) != 1:
        return False
    statement = body[0]
    if isinstance(statement, ast.Pass):
        return True
    return isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant)


class _Usage(ast.NodeVisitor):
    def __init__(self) -> None:
        self.used: set[str] = set()
        self.imports: list[tuple[str, int, str]] = []
        self.assigned: list[tuple[str, int]] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            self.imports.append((local, node.lineno, alias.name.split(".")[0]))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module == "__future__" or node.level:
            return
        for alias in node.names:
            if alias.name == "*":
                continue
            local = alias.asname or alias.name
            root = (node.module or alias.name).split(".")[0]
            self.imports.append((local, node.lineno, root))

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load):
            self.used.add(node.id)
        elif isinstance(node.ctx, ast.Store):
            self.assigned.append((node.id, node.lineno))


def _local_modules(snapshot: RepoSnapshot) -> set[str]:
    names = set()
    root = snapshot.root
    for dirpath, dirnames, filenames in __import__("os").walk(root):
        dirnames[:] = [name for name in dirnames if not name.startswith(".")]
        for name in dirnames:
            names.add(name)
        for name in filenames:
            if name.endswith(".py"):
                names.add(Path(name).stem)
    return names


def _uses_environment(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id == "os" and node.attr in {"environ", "getenv"}:
                return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "getenv":
            return True
    return False


def _repo_finding(
    rule_id: str,
    severity: str,
    title: str,
    description: str,
    recommendation: str,
) -> Finding:
    return make_finding(
        rule_id=rule_id,
        category="loose_end",
        severity=severity,  # type: ignore[arg-type]
        title=title,
        description=description,
        file="(repository)",
        line=1,
        recommendation=recommendation,
    )


def _names_in(fn: ast.AST) -> tuple[set[str], list[tuple[str, int]]]:
    loads: set[str] = set()
    stores: list[tuple[str, int]] = []
    for node in ast.walk(fn):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node is not fn:
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            loads.add(node.id)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            stores.append((node.id, node.lineno))
    return loads, stores


def _unused_variables(tree: ast.AST, source: SourceFile) -> list[Finding]:
    """Flag stores that are never read in the same function or module scope.

    Nested functions are walked on their own so a name reused elsewhere does
    not hide a dead assignment.
    """
    findings: list[Finding] = []
    seen: set[tuple[int, str]] = set()

    def add(name: str, line: int) -> None:
        if name.startswith("_") or name.isupper() or (line, name) in seen:
            return
        seen.add((line, name))
        findings.append(
            make_finding(
                rule_id="unused-variable",
                category="loose_end",
                severity="low",
                title="Unused variable",
                description=f"`{name}` is assigned and never read in the same scope.",
                file=source.relative,
                line=line,
                recommendation="Remove the variable or use the value. A leading underscore marks an intentional discard.",
                snippet=line_snippet(source.lines, line),
            )
        )

    module_loads: set[str] = set()
    module_stores: list[tuple[str, int]] = []
    for statement in tree.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            loads, stores = _names_in(statement)
            for name, line in stores:
                if name not in loads:
                    add(name, line)
            continue
        for node in ast.walk(statement):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                module_loads.add(node.id)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                module_stores.append((node.id, node.lineno))
    for name, line in module_stores:
        if name not in module_loads:
            add(name, line)
    return findings


def _python_file_findings(source: SourceFile, all_used: set[str]) -> tuple[list[Finding], set[str], set[str]]:
    tree = parse_module(source.text)
    if tree is None:
        return [], set(), set()
    usage = _Usage()
    usage.visit(tree)
    findings: list[Finding] = []
    imported_roots: set[str] = set()

    if not source.is_test:
        seen_imports: set[str] = set()
        for local, line, root in usage.imports:
            imported_roots.add(root)
            if local in usage.used or local in seen_imports:
                continue
            seen_imports.add(local)
            findings.append(
                make_finding(
                    rule_id="unused-import",
                    category="loose_end",
                    severity="low",
                    title="Unused import",
                    description=f"`{local}` is imported and no later reference was found in this file.",
                    file=source.relative,
                    line=line,
                    recommendation="Remove the import, or use it. Unused imports hide the real dependencies of a file.",
                    snippet=line_snippet(source.lines, line),
                )
            )

        findings.extend(_unused_variables(tree, source))

        for fn, class_node in iter_functions(tree):
            if class_node is not None:
                continue
            name = fn.name
            if (
                is_placeholder_function(fn)
                or is_abstract_function(fn, class_node)
                or name in all_used
                or name.startswith("_")
                or name == "main"
                or decorator_names(fn)
            ):
                continue
            findings.append(
                make_finding(
                    rule_id="unused-function",
                    category="loose_end",
                    severity="low",
                    title="Unused function",
                    description=(
                        f"`{name}` is not referenced by name anywhere in the scanned Python files. "
                        "A framework may still call it dynamically, so this is a potential loose end."
                    ),
                    file=source.relative,
                    line=fn.lineno,
                    recommendation="Call the function from real code or tests, or delete it if the feature was abandoned.",
                    snippet=line_snippet(source.lines, fn.lineno),
                )
            )

        parents = _parents(tree)
        handled: set[int] = set()
        for node in ast.walk(tree):
            if _risky_call(node) and not _inside(node, parents, (ast.Try,)):
                fn = _enclosing_function(node, parents)
                key = fn.lineno if fn else node.lineno
                if key in handled:
                    continue
                handled.add(key)
                findings.append(
                    make_finding(
                        rule_id="missing-error-handling",
                        category="loose_end",
                        severity="medium",
                        title="Fallible call is not inside try",
                        description=(
                            "A file, network, or process call can fail, and no try statement encloses it. "
                            "The caller may still handle the error higher up."
                        ),
                        file=source.relative,
                        line=getattr(node, "lineno", 1),
                        recommendation="Handle the expected failures, or document why the exception should propagate.",
                        snippet=line_snippet(source.lines, getattr(node, "lineno", 1)),
                    )
                )
            if _is_open_call(node) and not _inside(node, parents, (ast.With, ast.AsyncWith)):
                fn = _enclosing_function(node, parents)
                if fn and _closes_resource(fn):
                    continue
                findings.append(
                    make_finding(
                        rule_id="unclosed-resource",
                        category="loose_end",
                        severity="medium",
                        title="Opened file is not used as a context manager",
                        description="open() is called outside a with statement, and no close() call was found in the same function.",
                        file=source.relative,
                        line=node.lineno,
                        recommendation="Use `with open(...) as handle:` so the file closes on success and on error.",
                        snippet=line_snippet(source.lines, node.lineno),
                    )
                )
            if isinstance(node, ast.ExceptHandler):
                bare = node.type is None
                if bare or _swallowed(node):
                    findings.append(
                        make_finding(
                            rule_id="swallowed-exception",
                            category="loose_end",
                            severity="medium",
                            title="Exception is swallowed" if not bare else "Bare except hides the failure",
                            description=(
                                "The handler catches every exception or discards it. "
                                "KeyboardInterrupt and real bugs can disappear with a bare except."
                            ),
                            file=source.relative,
                            line=node.lineno,
                            recommendation="Catch the specific error you can recover from, and log or re-raise anything else.",
                            snippet=line_snippet(source.lines, node.lineno),
                        )
                    )

        long_functions = 0
        for fn, _class_node in iter_functions(tree):
            if fn.end_lineno and fn.end_lineno - fn.lineno >= 40 and not ast.get_docstring(fn):
                if long_functions >= _DOC_LIMIT:
                    break
                long_functions += 1
                findings.append(
                    make_finding(
                        rule_id="missing-docstring",
                        category="loose_end",
                        severity="informational",
                        title="Long function has no docstring",
                        description=f"`{fn.name}` is long enough that a short description would help a reviewer.",
                        file=source.relative,
                        line=fn.lineno,
                        recommendation="Add a one- or two-line docstring that states the input and the result.",
                        snippet=line_snippet(source.lines, fn.lineno),
                    )
                )

    return findings, usage.used, imported_roots


def detect_loose_ends(snapshot: RepoSnapshot) -> list[Finding]:
    python_sources = [source for source in snapshot.files if source.language == "Python"]
    parsed: list[tuple[SourceFile, ast.AST | None]] = []
    all_used: set[str] = set()
    for source in python_sources:
        tree = parse_module(source.text)
        parsed.append((source, tree))
        if tree is None:
            continue
        usage = _Usage()
        usage.visit(tree)
        all_used |= usage.used

    findings: list[Finding] = []
    third_party: set[str] = set()
    local = _local_modules(snapshot)
    uses_env = False
    for source, tree in parsed:
        if tree is None and not source.is_test:
            findings.append(
                make_finding(
                    rule_id="syntax-error",
                    category="loose_end",
                    severity="medium",
                    title="Python file could not be parsed",
                    description="Syntax errors blocked unused-name and resource checks for this file.",
                    file=source.relative,
                    line=1,
                    recommendation="Fix the syntax error and scan again.",
                )
            )
            continue
        file_findings, _used, roots = _python_file_findings(source, all_used)
        findings.extend(file_findings)
        if tree is not None and _uses_environment(tree):
            uses_env = True
        for root in roots:
            if root not in STDLIB and root not in local:
                third_party.add(root)

    names = {Path(source.relative).name.lower() for source in snapshot.files}
    code_files = snapshot.code_files()
    if code_files and not any(source.is_test for source in snapshot.files):
        findings.append(
            _repo_finding(
                "missing-tests",
                "informational",
                "No tests were found",
                "The tree has source files and no test file or tests directory. Missing tests are a coverage gap, not a vulnerability.",
                "Add tests for the main behavior, especially input validation and error paths.",
            )
        )
    if not any(name.startswith("readme") for name in names):
        findings.append(
            _repo_finding(
                "missing-readme",
                "informational",
                "No README was found",
                "A repository without a README is difficult to install, run, or review.",
                "Add a README with the purpose of the project and how to run it.",
            )
        )
    if any(source.language == "Python" and source.is_code for source in snapshot.files):
        if third_party and not any(name in _PYTHON_DEP_FILES for name in names):
            listed = ", ".join(sorted(third_party))
            findings.append(
                _repo_finding(
                    "missing-dependency-file",
                    "medium",
                    "Third-party Python imports have no dependency file",
                    f"These imports do not look local or standard-library: {listed}. No requirements.txt or pyproject.toml was found.",
                    "Add a dependency file so another person can install the same libraries.",
                )
            )
    if any(source.language in {"JavaScript", "TypeScript"} for source in code_files) and not any(
        name in _JS_DEP_FILES for name in names
    ):
        findings.append(
            _repo_finding(
                "missing-package-json",
                "informational",
                "JavaScript files have no package.json",
                "Node projects normally declare dependencies and scripts in package.json. A small script may not need one.",
                "Add package.json if these files depend on external packages.",
            )
        )
    if any(source.language in {"C", "C++"} for source in code_files) and not any(name in _C_BUILD_FILES for name in names):
        findings.append(
            _repo_finding(
                "missing-build-file",
                "informational",
                "C or C++ files have no build file",
                "No Makefile, CMakeLists.txt, or compile_commands.json was found. The project may still build with a one-off command.",
                "Add a small build file so the compile flags are not tribal knowledge.",
            )
        )
    if uses_env and not any(name in _CONFIG_FILES for name in names):
        findings.append(
            _repo_finding(
                "missing-config-example",
                "informational",
                "Environment variables are used without an example config",
                "Code reads the environment, but there is no .env.example or config file showing the expected names.",
                "Add a .env.example with the variable names and dummy values, never real secrets.",
            )
        )
    return findings
