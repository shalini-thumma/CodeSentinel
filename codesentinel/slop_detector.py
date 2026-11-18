"""Report measurable maintainability signals without guessing code authorship."""

from __future__ import annotations

import ast
import re
from collections import defaultdict
from pathlib import PurePosixPath

from codesentinel.github_handler import LANGUAGE_EXTENSIONS
from codesentinel.models import Finding, Severity


CODE_EXTENSIONS = {
    ".py", ".java", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
    ".mts", ".cts", ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp",
    ".hh", ".cs", ".go", ".rs", ".rb", ".php", ".swift", ".kt",
    ".kts", ".scala", ".sh", ".bash", ".sql",
}
IMPORT_LINE = re.compile(r"^\s*import\s+.+(?:\s+from\s+.+)?;?\s*$")
BLOCK_SIZE = 4


def _finding(rule_id, severity, title, path, line, explanation, recommendation):
    return Finding(
        rule_id=rule_id,
        category="slop",
        severity=severity,
        title=title,
        file=path,
        line=line,
        explanation=explanation,
        recommendation=recommendation,
        confidence="medium",
    )


def _duplicate_imports(path: str, content: str) -> list[Finding]:
    findings = []
    suffix = PurePosixPath(path).suffix.lower()
    if suffix == ".py":
        try:
            tree = ast.parse(content)
        except (SyntaxError, ValueError):
            return findings
        seen = set()
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
            normalized = ast.dump(node, include_attributes=False)
            if normalized in seen:
                findings.append(_finding(
                    "SLOP-DUPLICATE-IMPORT", Severity.LOW, "Duplicate import statement",
                    path, node.lineno, "The same import statement appears more than once in this file.",
                    "Keep one import and remove the duplicate.",
                ))
            seen.add(normalized)
    elif suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}:
        seen = set()
        for line_number, line in enumerate(content.splitlines(), start=1):
            normalized = line.strip()
            if IMPORT_LINE.match(normalized):
                if normalized in seen:
                    findings.append(_finding(
                        "SLOP-DUPLICATE-IMPORT", Severity.LOW, "Duplicate import statement",
                        path, line_number, "The same import statement appears more than once in this file.",
                        "Keep one import and remove the duplicate.",
                    ))
                seen.add(normalized)
    return findings


def _normalized_code_lines(content: str):
    normalized = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "/*", "*", "*/")):
            continue
        code = re.sub(r"\s+", " ", stripped).rstrip(";")
        if len(code) > 2 and any(character.isalnum() for character in code):
            normalized.append((line_number, code))
    return normalized


def _duplicate_blocks(files: dict[str, str]) -> list[Finding]:
    occurrences = defaultdict(list)
    for path, content in files.items():
        if PurePosixPath(path).suffix.lower() not in CODE_EXTENSIONS:
            continue
        lines = _normalized_code_lines(content)
        for index in range(len(lines) - BLOCK_SIZE + 1):
            block = tuple(code for _, code in lines[index:index + BLOCK_SIZE])
            if all(line.startswith(("import ", "from ")) for line in block):
                continue
            occurrences[block].append((path, lines[index][0]))

    findings = []
    reported_locations = set()
    for positions in occurrences.values():
        unique_positions = list(dict.fromkeys(positions))
        if len(unique_positions) < 2:
            continue
        original = unique_positions[0]
        for path, line in unique_positions[1:]:
            location = (path, line)
            if location in reported_locations:
                continue
            reported_locations.add(location)
            original_path, original_line = original
            findings.append(_finding(
                "SLOP-DUPLICATE-BLOCK", Severity.MEDIUM, "Repeated block of code",
                path, line,
                f"Four consecutive non-comment code lines repeat at `{original_path}:{original_line}`. Exact repetition may be intentional, but changes can drift between copies.",
                "Consider extracting shared behavior into a helper, or keep the copies synchronized if they intentionally differ by context.",
            ))
    return findings


def _python_complexity(path: str, content: str) -> list[Finding]:
    if PurePosixPath(path).suffix.lower() != ".py":
        return []
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return []
    findings = []
    branches = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler)
    comprehensions = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
    for function in (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
        complexity = 1
        for node in ast.walk(function):
            if isinstance(node, branches) or isinstance(node, ast.IfExp):
                complexity += 1
            elif isinstance(node, ast.BoolOp):
                complexity += max(0, len(node.values) - 1)
            elif isinstance(node, comprehensions):
                complexity += sum(1 + len(generator.ifs) for generator in node.generators)
        if complexity > 10:
            findings.append(_finding(
                "SLOP-HIGH-COMPLEXITY", Severity.MEDIUM, "Function has high branch complexity",
                path, function.lineno,
                f"`{function.name}` has an estimated cyclomatic complexity of {complexity}, making its paths harder to review and test.",
                "Split independent decisions into small helpers and add tests for each branch.",
            ))
    return findings


def detect_slop(files: dict[str, str]) -> list[Finding]:
    findings = _duplicate_blocks(files)
    for path, content in files.items():
        if PurePosixPath(path).suffix.lower() in LANGUAGE_EXTENSIONS:
            findings.extend(_duplicate_imports(path, content))
            findings.extend(_python_complexity(path, content))
    unique = {}
    for finding in findings:
        unique.setdefault((finding.rule_id, finding.file, finding.line), finding)
    return list(unique.values())