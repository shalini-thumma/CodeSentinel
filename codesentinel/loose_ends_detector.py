"""Find actionable maintenance gaps with deliberately conservative rules."""

from __future__ import annotations

import ast

from codesentinel.models import Finding, RepositorySnapshot, Severity
from codesentinel.repository_analyzer import ProjectInventory


def _finding(rule_id, severity, title, path, line, explanation, recommendation):
    return Finding(
        rule_id=rule_id,
        category="loose_end",
        severity=severity,
        title=title,
        file=path,
        line=line,
        explanation=explanation,
        recommendation=recommendation,
        confidence="medium",
    )


def _assigned_names(target: ast.expr) -> list[ast.Name]:
    if isinstance(target, ast.Name):
        return [target]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [name for element in target.elts for name in _assigned_names(element)]
    return []


def _python_loose_ends(path: str, content: str) -> list[Finding]:
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return []
    findings = []
    loaded_names = {
        node.id for node in ast.walk(tree)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
    }
    seen_imports = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if isinstance(node, ast.ImportFrom) and node.module == "__future__":
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                bound_name = alias.asname or (alias.name.split(".", 1)[0] if isinstance(node, ast.Import) else alias.name)
                key = (bound_name, node.lineno)
                if key in seen_imports:
                    continue
                seen_imports.add(key)
                if bound_name not in loaded_names:
                    findings.append(_finding(
                        "LOOSE-UNUSED-IMPORT", Severity.LOW, "Imported name is not referenced",
                        path, node.lineno,
                        f"`{bound_name}` is imported but no matching name reference was found in this Python file.",
                        "Remove the import if it is not needed, or verify dynamic/plugin usage that static analysis cannot see.",
                    ))
        elif isinstance(node, ast.ExceptHandler) and not node.type:
            findings.append(_finding(
                "LOOSE-BARE-EXCEPT", Severity.MEDIUM, "Bare exception handler catches every exception",
                path, node.lineno,
                "This handler catches exceptions including process-control exceptions, which can hide failures or prevent shutdown.",
                "Catch the specific expected exception types and handle or re-raise unexpected failures.",
            ))

    for function in (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
        function_nodes = list(ast.walk(function))
        function_loads = {
            node.id for node in function_nodes
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
        }
        for node in function_nodes:
            targets = []
            if isinstance(node, ast.Assign):
                targets = [name for target in node.targets for name in _assigned_names(target)]
            elif isinstance(node, ast.AnnAssign):
                targets = _assigned_names(node.target)
            elif isinstance(node, ast.NamedExpr):
                targets = _assigned_names(node.target)
            for target in targets:
                if target.id != "_" and not target.id.startswith("_") and target.id not in function_loads:
                    findings.append(_finding(
                        "LOOSE-UNUSED-VARIABLE", Severity.LOW, "Assigned local is never read",
                        path, target.lineno,
                        f"`{target.id}` is assigned in `{function.name}` but no read of that name was found in the function.",
                        "Remove the assignment or use the value; confirm the name is not consumed through dynamic reflection.",
                    ))
    return findings


def detect_loose_ends(snapshot: RepositorySnapshot, inventory: ProjectInventory) -> list[Finding]:
    findings = []
    for path, content in inventory.source_files.items():
        if path.lower().endswith(".py") and not path.lower().endswith(".pyi"):
            findings.extend(_python_loose_ends(path, content))

    if inventory.source_files and not inventory.has_tests:
        findings.append(_finding(
            "LOOSE-NO-TEST-FILES", Severity.INFORMATIONAL, "No recognizable test files found",
            "(repository)", None,
            "The repository inventory did not find files or directories with common test naming. This does not measure test coverage or quality.",
            "Add tests for critical behavior and security-sensitive paths, or verify that the project uses a different test naming convention.",
        ))
    if inventory.source_files and not inventory.has_documentation:
        findings.append(_finding(
            "LOOSE-NO-README", Severity.INFORMATIONAL, "No README detected",
            "(repository)", None,
            "No common README filename was found in the scanned repository files.",
            "Add a short README covering setup, configuration, and how to run tests.",
        ))
    if inventory.source_files and not inventory.has_dependency_manifest:
        findings.append(_finding(
            "LOOSE-NO-DEPENDENCY-MANIFEST", Severity.INFORMATIONAL, "No dependency manifest detected",
            "(repository)", None,
            "No common dependency manifest was found. This may be appropriate for a project that uses only standard libraries or another dependency workflow.",
            "Document dependency installation or add the manifest used by the project if dependencies are required.",
        ))
    unique = {}
    for finding in findings:
        unique.setdefault((finding.rule_id, finding.file, finding.line), finding)
    return list(unique.values())