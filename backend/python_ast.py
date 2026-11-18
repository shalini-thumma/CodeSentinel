"""Small Python AST helpers shared by the detectors.

Each detector still decides what a finding means. This module only answers
structural questions: is the function abstract, empty, or highly branched?
"""

from __future__ import annotations

import ast


def parse_module(text: str) -> ast.AST | None:
    try:
        return ast.parse(text)
    except SyntaxError:
        return None


def expr_name(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return expr_name(node.func)
    return ""


def decorator_names(fn: ast.AST) -> list[str]:
    names = []
    for decorator in getattr(fn, "decorator_list", []):
        name = expr_name(decorator)
        if name:
            names.append(name)
    return names


def class_is_abstract(node: ast.ClassDef) -> bool:
    return any(expr_name(base) in {"ABC", "ABCMeta"} for base in node.bases)


def _meaningful_body(fn: ast.AST) -> list[ast.stmt]:
    body = list(getattr(fn, "body", []))
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    return body


def _is_ellipsis(stmt: ast.stmt) -> bool:
    return isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is Ellipsis


def _is_not_implemented(stmt: ast.stmt) -> bool:
    if not isinstance(stmt, ast.Raise):
        return False
    return expr_name(stmt.exc) == "NotImplementedError"


def _is_placeholder_return(stmt: ast.stmt) -> bool:
    if not isinstance(stmt, ast.Return) or not isinstance(stmt.value, ast.Constant):
        return False
    if not isinstance(stmt.value.value, str):
        return False
    text = stmt.value.value.lower()
    return any(word in text for word in ("not implemented", "todo", "placeholder", "fixme"))


def is_placeholder_function(fn: ast.AST) -> bool:
    """True when the function has no real implementation."""
    statements = _meaningful_body(fn)
    if not statements:
        return True
    if all(isinstance(stmt, ast.Pass) or _is_ellipsis(stmt) for stmt in statements):
        return True
    if len(statements) == 1 and (_is_not_implemented(statements[0]) or _is_placeholder_return(statements[0])):
        return True
    return False


def is_abstract_function(fn: ast.AST, class_node: ast.ClassDef | None) -> bool:
    """Intentional abstract methods are not unfinished business logic."""
    names = set(decorator_names(fn))
    if "abstractmethod" in names or "abstractproperty" in names:
        return True
    if class_node and class_is_abstract(class_node) and any(_is_not_implemented(stmt) for stmt in _meaningful_body(fn)):
        return True
    return False


def iter_functions(tree: ast.AST) -> list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, ast.ClassDef | None]]:
    found: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, ast.ClassDef | None]] = []

    class Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.stack: list[ast.ClassDef] = []

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            self.stack.append(node)
            self.generic_visit(node)
            self.stack.pop()

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            found.append((node, self.stack[-1] if self.stack else None))
            self.generic_visit(node)

        visit_AsyncFunctionDef = visit_FunctionDef

    Visitor().visit(tree)
    return found


def branch_complexity(fn: ast.AST) -> int:
    """Simplified McCabe-style count: 1 plus each branch or boolean join."""
    score = 1
    for node in ast.walk(fn):
        if isinstance(
            node,
            (
                ast.If,
                ast.For,
                ast.AsyncFor,
                ast.While,
                ast.ExceptHandler,
                ast.With,
                ast.AsyncWith,
                ast.Assert,
                ast.IfExp,
                ast.ListComp,
                ast.SetComp,
                ast.DictComp,
                ast.GeneratorExp,
            ),
        ):
            score += 1
        elif isinstance(node, ast.BoolOp):
            score += max(0, len(node.values) - 1)
    return score
