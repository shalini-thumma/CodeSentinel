"""Find unfinished implementation that can be distinguished from abstract APIs.

Python is parsed with the ast module. Brace languages use a small scanner that
ignores strings, comments, classes, and control-flow blocks. A `pass` inside
an @abstractmethod is treated as intentional.
"""

from __future__ import annotations

import ast
import re

from backend.models import Finding, make_finding
from backend.python_ast import (
    is_abstract_function,
    is_placeholder_function,
    iter_functions,
    parse_module,
)
from backend.repository_analyzer import RepoSnapshot, SourceFile, line_snippet

_RETURN_NAME = re.compile(r"^(get|fetch|compute|calculate|load|read|parse|build|create)_")
_MARKER = re.compile(r"\b(TODO|FIXME|XXX|HACK)\b", re.IGNORECASE)
_MARKER_SEVERITY = {"FIXME": "medium", "TODO": "low", "XXX": "low", "HACK": "low"}
_CONTROL = re.compile(
    r"\b(if|else|for|foreach|while|switch|catch|try|do|class|struct|enum|namespace|interface)\b"
)
_FUNCTIONISH = re.compile(
    r"\b(function|func|void|int|char|bool|boolean|string|String|long|double|float|var|let|const|public|private|protected|static|async|def)\b|=>"
)
_BRACE_LANGUAGES = {"Java", "JavaScript", "TypeScript", "C", "C++", "C#", "PHP", "Go", "Kotlin", "Swift", "Rust"}


def _mask_non_code(text: str) -> str:
    """Replace comments and strings with spaces so braces inside them are ignored."""
    chars = list(text)
    index = 0
    length = len(chars)
    while index < length:
        char = chars[index]
        nxt = chars[index + 1] if index + 1 < length else ""
        if char == "/" and nxt == "/":
            while index < length and chars[index] != "\n":
                chars[index] = " "
                index += 1
            continue
        if char == "/" and nxt == "*":
            chars[index] = " "
            chars[index + 1] = " "
            index += 2
            while index < length - 1 and not (chars[index] == "*" and chars[index + 1] == "/"):
                if chars[index] != "\n":
                    chars[index] = " "
                index += 1
            if index < length:
                chars[index] = " "
            if index + 1 < length:
                chars[index + 1] = " "
            index += 2
            continue
        if char in {'"', "'", "`"}:
            quote = char
            chars[index] = " "
            index += 1
            while index < length:
                if chars[index] == "\\":
                    chars[index] = " "
                    if index + 1 < length and chars[index + 1] != "\n":
                        chars[index + 1] = " "
                        index += 2
                        continue
                if chars[index] == "\n" and quote != "`":
                    break
                if chars[index] == quote:
                    chars[index] = " "
                    index += 1
                    break
                if chars[index] != "\n":
                    chars[index] = " "
                index += 1
            continue
        index += 1
    return "".join(chars)


def _empty_brace_functions(source: SourceFile) -> list[Finding]:
    if source.language not in _BRACE_LANGUAGES:
        return []
    masked = _mask_non_code(source.text)
    findings: list[Finding] = []
    stack: list[int] = []
    reported: set[int] = set()
    for index, char in enumerate(masked):
        if char == "{":
            stack.append(index)
        elif char == "}" and stack:
            opening = stack.pop()
            body = source.text[opening + 1 : index]
            if body.strip() and not re.fullmatch(r"[\s/*-]*", body):
                continue
            previous_break = source.text.rfind("\n", 0, opening) 
            header_start = source.text.rfind("\n", 0, max(0, previous_break - 1))
            header = source.text[header_start + 1 : opening]
            if _CONTROL.search(header) or not _FUNCTIONISH.search(header):
                continue
            line = source.text.count("\n", 0, opening) + 1
            if line in reported:
                continue
            reported.add(line)
            findings.append(
                make_finding(
                    rule_id="empty-function",
                    category="gap",
                    severity="medium",
                    title="Empty or comment-only function",
                    description=(
                        "The function body has no executable statement. "
                        "Interface and abstract signatures without a body are not reported."
                    ),
                    file=source.relative,
                    line=line,
                    recommendation="Implement the function, or delete it if the feature is not part of this project.",
                    snippet=line_snippet(source.lines, line),
                )
            )
    return findings


def _segment(text: str, fn: ast.AST) -> str:
    segment = ast.get_source_segment(text, fn)
    return segment or ""


def _has_dynamic_sink(segment: str) -> bool:
    has_sink = bool(re.search(r"(?i)(\.execute\s*\(|os\.system\s*\(|os\.popen\s*\(|pickle\.loads?\s*\(|(?<![\w.])eval\s*\()", segment))
    dynamic = bool(re.search(r"(\+|f[\"']|\.format\s*\(|\$\{)", segment))
    return has_sink and dynamic


def _has_guard(fn: ast.AST) -> bool:
    return any(isinstance(node, (ast.If, ast.Assert)) for node in ast.walk(fn))


def _python_gaps(source: SourceFile) -> list[Finding]:
    tree = parse_module(source.text)
    if tree is None:
        return [
            make_finding(
                rule_id="syntax-error",
                category="gap",
                severity="medium",
                title="Python file could not be parsed",
                description="The file has a syntax error, so function-level gap checks were skipped for it.",
                file=source.relative,
                line=1,
                recommendation="Fix the syntax error and scan the file again.",
            )
        ]
    findings: list[Finding] = []
    for fn, class_node in iter_functions(tree):
        if is_abstract_function(fn, class_node):
            continue
        line = int(getattr(fn, "lineno", 1))
        name = getattr(fn, "name", "function")
        if is_placeholder_function(fn):
            findings.append(
                make_finding(
                    rule_id="empty-function",
                    category="gap",
                    severity="medium",
                    title="Placeholder or empty function",
                    description=(
                        f"`{name}` contains only a docstring, pass, ellipsis, or NotImplementedError. "
                        "It is not marked as an abstract method."
                    ),
                    file=source.relative,
                    line=line,
                    recommendation="Add the implementation or mark the method abstract if subclasses are expected to fill it in.",
                    snippet=line_snippet(source.lines, line),
                )
            )
            continue
        if _RETURN_NAME.match(name):
            has_return = any(isinstance(node, (ast.Return, ast.Yield, ast.YieldFrom)) for node in ast.walk(fn))
            has_raise = any(isinstance(node, ast.Raise) for node in ast.walk(fn))
            if not has_return and not has_raise:
                findings.append(
                    make_finding(
                        rule_id="missing-return",
                        category="gap",
                        severity="medium",
                        title="Function name implies a result, but nothing is returned",
                        description=(
                            f"`{name}` is named like a function that produces a value, and no return or raise was found. "
                            "This can be intentional if the name is historical."
                        ),
                        file=source.relative,
                        line=line,
                        recommendation="Return the computed value, or rename the function so it describes a side effect.",
                        snippet=line_snippet(source.lines, line),
                    )
                )
        segment = _segment(source.text, fn)
        if _has_dynamic_sink(segment) and not _has_guard(fn):
            findings.append(
                make_finding(
                    rule_id="missing-validation",
                    category="gap",
                    severity="medium",
                    title="No validation branch before a sensitive call",
                    description=(
                        f"`{name}` builds a dynamic command, query, or code string and has no if or assert. "
                        "A missing branch does not by itself prove the input is dangerous."
                    ),
                    file=source.relative,
                    line=line,
                    recommendation="Validate or allow-list the input before the call, and prefer parameterized APIs.",
                    snippet=line_snippet(source.lines, line),
                )
            )
    return findings


def _markers(source: SourceFile) -> list[Finding]:
    findings: list[Finding] = []
    for number, line in enumerate(source.lines, start=1):
        if len(line) > 500:
            continue
        match = _MARKER.search(line)
        if not match:
            continue
        kind = match.group(1).upper()
        findings.append(
            make_finding(
                rule_id="todo-marker",
                category="gap",
                severity=_MARKER_SEVERITY[kind],  # type: ignore[arg-type]
                title=f"{kind} marker",
                description=f"A {kind} comment marks work that is still open. It may be a real gap or a note to a future reader.",
                file=source.relative,
                line=number,
                recommendation="Finish the work or turn the marker into a tracked issue and remove the stale comment.",
                snippet=line_snippet(source.lines, number),
            )
        )
    return findings


def detect_gaps(snapshot: RepoSnapshot) -> list[Finding]:
    findings: list[Finding] = []
    for source in snapshot.code_files(include_tests=False):
        if source.language == "Python":
            findings.extend(_python_gaps(source))
        else:
            findings.extend(_empty_brace_functions(source))
        findings.extend(_markers(source))
    return findings
