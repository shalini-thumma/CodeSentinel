"""Detect explicit markers and clearly incomplete implementations."""

from __future__ import annotations

import ast
import re
from pathlib import PurePosixPath

from codesentinel.models import Finding, Severity


TODO_MARKER = re.compile(r"\b(TODO|FIXME)\b", re.IGNORECASE)
NOT_IMPLEMENTED = re.compile(r"\bthrow\s+new\s+(?:Error|Exception)\s*\(\s*['\"]not implemented", re.I)


def _finding(rule_id, severity, title, path, line, explanation, recommendation):
    return Finding(
        rule_id=rule_id,
        category="gap",
        severity=severity,
        title=title,
        file=path,
        line=line,
        explanation=explanation,
        recommendation=recommendation,
        confidence="high",
    )


def _is_docstring(statement: ast.stmt) -> bool:
    return (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and isinstance(statement.value.value, str)
    )


def _function_is_intentional_stub(function: ast.FunctionDef | ast.AsyncFunctionDef, parents: dict) -> bool:
    for decorator in function.decorator_list:
        if isinstance(decorator, ast.Name) and decorator.id == "abstractmethod":
            return True
        if isinstance(decorator, ast.Attribute) and decorator.attr == "abstractmethod":
            return True
    parent = parents.get(function)
    while parent is not None:
        if isinstance(parent, ast.ClassDef):
            for base in parent.bases:
                if isinstance(base, ast.Name) and base.id == "Protocol":
                    return True
                if isinstance(base, ast.Attribute) and base.attr == "Protocol":
                    return True
            break
        parent = parents.get(parent)
    return False


def _python_gaps(path: str, content: str) -> list[Finding]:
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return []
    parents = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent

    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if _function_is_intentional_stub(node, parents):
            continue
        implementation = [statement for statement in node.body if not _is_docstring(statement)]
        if not implementation or all(
            isinstance(statement, ast.Pass)
            or isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant) and statement.value.value is Ellipsis
            for statement in implementation
        ):
            findings.append(_finding(
                "GAP-EMPTY-FUNCTION", Severity.MEDIUM, "Concrete function has no implementation",
                path, node.lineno,
                f"`{node.name}` contains only a docstring, pass, or ellipsis, so it does not perform its apparent work.",
                "Implement the function or remove it. If this is an intentional interface stub, mark it abstract or define it in a Protocol.",
            ))
            continue
        for child in ast.walk(node):
            if isinstance(child, ast.Raise) and isinstance(child.exc, ast.Call):
                called = child.exc.func
                if isinstance(called, ast.Name) and called.id == "NotImplementedError":
                    findings.append(_finding(
                        "GAP-NOT-IMPLEMENTED", Severity.MEDIUM, "Function explicitly reports it is not implemented",
                        path, child.lineno,
                        f"`{node.name}` raises NotImplementedError on this path.",
                        "Complete the behavior or leave the method abstract so callers cannot mistake it for a working implementation.",
                    ))
                    break
    return findings


def detect_gaps(files: dict[str, str]) -> list[Finding]:
    findings = []
    for path, content in files.items():
        for line_number, line in enumerate(content.splitlines(), start=1):
            marker = TODO_MARKER.search(line)
            if marker:
                findings.append(_finding(
                    f"GAP-{marker.group(1).upper()}", Severity.LOW,
                    f"{marker.group(1).upper()} marker remains", path, line_number,
                    "An explicit work marker is present; it may be intentional but should be reviewed before release.",
                    "Resolve the item, or link it to tracked work with an owner and rationale.",
                ))
            if NOT_IMPLEMENTED.search(line):
                findings.append(_finding(
                    "GAP-NOT-IMPLEMENTED", Severity.MEDIUM, "Implementation raises a not-implemented error",
                    path, line_number,
                    "This statement appears to be a placeholder implementation.",
                    "Implement the required behavior or make the unsupported state explicit in the API contract.",
                ))
        if PurePosixPath(path).suffix.lower() == ".py" and not path.lower().endswith(".pyi"):
            findings.extend(_python_gaps(path, content))
    unique = {}
    for finding in findings:
        unique.setdefault((finding.rule_id, finding.file, finding.line), finding)
    return list(unique.values())