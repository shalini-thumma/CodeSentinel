"""Find potential security issues without executing the project.

Built-in checks are regular expressions over source lines, so they work for
every language we can read. Bandit and Semgrep are optional extras: when they
are installed they add findings, and when they are missing the scan continues.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
from dataclasses import dataclass

from backend.config import (
    EXTERNAL_TOOL_TIMEOUT_SECONDS,
    MAX_LINE_LENGTH,
    SEMGREP_RULES,
)
from backend.models import Finding, ToolStatus, make_finding
from backend.repository_analyzer import RepoSnapshot, line_snippet

logger = logging.getLogger("codesentinel.security")

_SQL = r"(?:select|insert|update|delete|drop|union)"
_SECRET_NAME = r"(?:api[_-]?key|apikey|secret|password|passwd|token|access[_-]?key|private[_-]?key)"

PLACEHOLDERS = {
    "changeme",
    "password",
    "secret",
    "your_password",
    "your-password",
    "your_api_key",
    "your-api-key",
    "placeholder",
    "example",
    "todo",
    "fixme",
    "none",
    "null",
    "undefined",
    "test",
    "testing",
    "xxxxxxxx",
    "12345678",
}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    description: str
    recommendation: str
    pattern: re.Pattern[str]
    languages: frozenset[str] | None = None
    dynamic_critical: bool = False


def _rule(
    rule_id: str,
    title: str,
    severity: str,
    description: str,
    recommendation: str,
    pattern: str,
    languages: set[str] | None = None,
    dynamic_critical: bool = False,
) -> Rule:
    return Rule(
        rule_id=rule_id,
        title=title,
        severity=severity,
        description=description,
        recommendation=recommendation,
        pattern=re.compile(pattern),
        languages=frozenset(languages) if languages else None,
        dynamic_critical=dynamic_critical,
    )


RULES: tuple[Rule, ...] = (
    _rule(
        "sql-injection",
        "Potential SQL injection",
        "high",
        "A SQL string appears to be built with interpolation, concatenation, or formatting. "
        "This is a potential injection risk, not confirmation that the database is reachable.",
        "Use a parameterized query and pass user values separately from the SQL text.",
        rf"(?i)(?:f[\"'].{{0,200}}\b{_SQL}\b.{{0,200}}\{{"
        rf"|[\"'].{{0,200}}\b{_SQL}\b.{{0,200}}[\"']\s*(?:\+|%|\.format\s*\()"
        rf"|\b{_SQL}\b.{{0,80}}\$\{{)",
    ),
    _rule(
        "command-injection",
        "Potential command injection",
        "high",
        "A shell or process API is invoked. If the command includes external input, "
        "an attacker may be able to run extra commands. Reachability was not proven.",
        "Pass arguments as a list, avoid shell=True, and do not build command strings from input.",
        r"(?i)(?:os\.system\s*\(|os\.popen\s*\(|subprocess\.(?:run|Popen|call|check_output|check_call|getoutput|getstatusoutput)\s*\([^)\n]*shell\s*=\s*True|(?<![\w.])exec\s*\([^)\n]*\+|Runtime\.getRuntime\(\)\.exec\s*\()",
        dynamic_critical=True,
    ),
    _rule(
        "code-execution",
        "Potential dynamic code execution",
        "high",
        "eval or exec can run code that is assembled at runtime. This is unsafe when the input is not fully trusted.",
        "Remove eval/exec or replace it with a parser that only accepts the values you expect.",
        r"(?i)(?<![\w.])(?:eval|exec)\s*\(",
        {"Python", "JavaScript", "TypeScript", "PHP", "Ruby"},
    ),
    _rule(
        "unsafe-deserialization",
        "Potential unsafe deserialization",
        "high",
        "pickle, marshal, or unsafe YAML loading can execute data while reading it. "
        "This is a potential risk if the data comes from outside the process.",
        "Prefer JSON or another format that does not reconstruct objects. Use yaml.safe_load for YAML.",
        r"(?i)(?:pickle\.loads?\s*\(|marshal\.loads?\s*\(|yaml\.load\s*\()",
        {"Python"},
    ),
    _rule(
        "xss",
        "Potential cross-site scripting sink",
        "medium",
        "HTML is being written from a string. If that string includes user input, a browser may run it as script.",
        "Insert text with a safe text API, or escape untrusted data before writing HTML.",
        r"(?i)(?:\.innerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML)",
        {"JavaScript", "TypeScript", "HTML"},
    ),
    _rule(
        "unsafe-memory",
        "Potential unsafe memory operation",
        "high",
        "strcpy, strcat, gets, or sprintf does not enforce the destination size. "
        "This is a potential buffer overflow if the source is larger than the buffer.",
        "Use a bounded alternative such as snprintf or a language container that tracks length.",
        r"(?i)\b(?:strcpy|strcat|gets|sprintf)\s*\(",
        {"C", "C++"},
    ),
    _rule(
        "insecure-config",
        "Potential insecure configuration",
        "medium",
        "A debug server, wildcard host list, or disabled TLS check was found. "
        "These settings are risky if they ship outside a local sandbox.",
        "Disable debug mode, name the allowed hosts, and keep TLS verification on.",
        r"(?i)(?:\.run\([^)\n]*debug\s*=\s*True|ALLOWED_HOSTS\s*=\s*\[\s*[\"']\*[\"']\s*\]|allow_origins\s*=\s*\[\s*[\"']\*[\"']\s*\]|verify\s*=\s*False)",
    ),
    _rule(
        "weak-auth",
        "Potential weak authentication check",
        "medium",
        "A password is compared with a source literal, or a token check appears to disable verification. "
        "This may be a demo stub rather than a real login, so it is marked as potential.",
        "Store a salted hash, compare hashes with a constant-time function, and verify token signatures.",
        r"(?i)(?:\bpassword\b\s*==\s*[\"'][^\"']{4,}[\"']|algorithms\s*=\s*\[[^\]]*none|jwt\.decode\([^)\n]*verify\s*=\s*False)",
    ),
)

_SECRET_ASSIGNMENT = re.compile(
    rf"(?i)\b{_SECRET_NAME}\b\s*=(?!=)\s*([\"'])([^\"']+)\1"
)
_TOKEN_RULES = (
    ("secret-token", "critical", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "Potential private key in source"),
    ("secret-token", "high", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "Potential cloud access key"),
    ("secret-token", "high", re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}"), "Potential payment API key"),
    ("secret-token", "high", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"), "Potential source-control token"),
    ("secret-token", "high", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), "Potential chat token"),
)


def _is_placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    if len(lowered) < 8 or lowered in PLACEHOLDERS:
        return True
    if any(word in lowered for word in ("placeholder", "example", "changeme", "your_", "your-", "insert", "replace", "xxx", "<", ">")):
        return True
    return len(set(lowered)) == 1


def _dynamic_line(line: str) -> bool:
    return bool(re.search(r"(\+|f[\"']|\.format\s*\(|%s|\$\{)", line))


def _append(
    findings: list[Finding],
    *,
    rule_id: str,
    severity: str,
    title: str,
    description: str,
    recommendation: str,
    source_file: str,
    source_lines: list[str],
    line: int,
    tool: str = "codesentinel",
) -> None:
    findings.append(
        make_finding(
            rule_id=rule_id,
            category="security",
            severity=severity,  # type: ignore[arg-type]
            title=title,
            description=description,
            file=source_file,
            line=line,
            recommendation=recommendation,
            snippet=line_snippet(source_lines, line),
            tool=tool,
        )
    )


def _scan_text(snapshot_file_relative: str, language: str, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for number, line in enumerate(lines, start=1):
        if len(line) > MAX_LINE_LENGTH:
            continue
        secret_hit = False
        for rule_id, severity, pattern, title in _TOKEN_RULES:
            if pattern.search(line):
                secret_hit = True
                _append(
                    findings,
                    rule_id=rule_id,
                    severity=severity,
                    title=title,
                    description=(
                        "The line matches a known credential format. The value may be an example, "
                        "so this is a potential exposure rather than a confirmed live secret."
                    ),
                    recommendation="Remove the secret, rotate it if it was real, and load it from the environment.",
                    source_file=snapshot_file_relative,
                    source_lines=lines,
                    line=number,
                )
                break
        assignment = _SECRET_ASSIGNMENT.search(line)
        if assignment and not secret_hit:
            value = assignment.group(2)
            if not _is_placeholder(value):
                _append(
                    findings,
                    rule_id="hardcoded-secret",
                    severity="high",
                    title="Potential hardcoded secret",
                    description=(
                        "A credential-like name is assigned a string literal. "
                        "This is a potential hardcoded secret, not proof that the value is live."
                    ),
                    recommendation="Read the value from an environment variable or a secret manager and rotate anything already committed.",
                    source_file=snapshot_file_relative,
                    source_lines=lines,
                    line=number,
                )
        for rule in RULES:
            if rule.languages is not None and language not in rule.languages:
                continue
            if not rule.pattern.search(line):
                continue
            severity = rule.severity
            title = rule.title
            if rule.dynamic_critical and _dynamic_line(line):
                severity = "critical"
                title = "Potential command injection"
            elif rule.dynamic_critical:
                severity = "medium"
                title = "Use of a shell command API"
            _append(
                findings,
                rule_id=rule.rule_id,
                severity=severity,
                title=title,
                description=rule.description,
                recommendation=rule.recommendation,
                source_file=snapshot_file_relative,
                source_lines=lines,
                line=number,
            )
    return findings


def _relative(root, filename: str) -> str:
    from pathlib import Path

    path = Path(filename)
    try:
        if path.is_absolute():
            return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name
    return path.as_posix()


def _run_bandit(snapshot: RepoSnapshot) -> tuple[list[Finding], ToolStatus]:
    executable = shutil.which("bandit")
    if executable is None:
        return [], ToolStatus(
            name="bandit",
            ran=False,
            detail="Bandit is not installed. Built-in Python checks still ran.",
        )
    try:
        completed = subprocess.run(
            [
                executable,
                "-r",
                str(snapshot.root),
                "-f",
                "json",
                "-q",
                "-x",
                "./.git,./node_modules,./venv,./.venv,./dist,./build,./__pycache__",
            ],
            capture_output=True,
            text=True,
            timeout=EXTERNAL_TOOL_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return [], ToolStatus(name="bandit", ran=False, detail="Bandit did not finish. Built-in checks still ran.")
    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError:
        return [], ToolStatus(name="bandit", ran=False, detail="Bandit did not return JSON. Built-in checks still ran.")

    findings: list[Finding] = []
    for item in payload.get("results", []):
        level = str(item.get("issue_severity", "LOW")).upper()
        confidence = str(item.get("issue_confidence", "MEDIUM")).upper()
        severity = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(level, "low")
        if confidence == "LOW" and severity == "high":
            severity = "medium"
        test_id = item.get("test_id", "bandit")
        text = str(item.get("issue_text", "Bandit reported a potential issue."))
        more = item.get("more_info") or ""
        relative = _relative(snapshot.root, str(item.get("filename", "")))
        line = int(item.get("line_number") or 1)
        findings.append(
            make_finding(
                rule_id=f"bandit-{test_id}",
                category="security",
                severity=severity,  # type: ignore[arg-type]
                title=f"Bandit {test_id}: potential issue",
                description=f"Reported by Bandit. {text} This is a static-analysis signal, not a confirmed exploit.",
                file=relative,
                line=line,
                recommendation=f"Review Bandit test {test_id} and change the flagged pattern. {more}".strip(),
                tool="bandit",
            )
        )
    return findings, ToolStatus(name="bandit", ran=True, detail=f"Bandit finished and produced {len(findings)} raw result(s).")


def _run_semgrep(snapshot: RepoSnapshot) -> tuple[list[Finding], ToolStatus]:
    executable = shutil.which("semgrep")
    if executable is None:
        return [], ToolStatus(
            name="semgrep",
            ran=False,
            detail="Semgrep is not installed. Built-in checks still ran.",
        )
    if not SEMGREP_RULES.exists():
        return [], ToolStatus(name="semgrep", ran=False, detail="The Semgrep rule file is missing.")
    try:
        completed = subprocess.run(
            [
                executable,
                "scan",
                "--config",
                str(SEMGREP_RULES),
                "--json",
                "--quiet",
                "--metrics=off",
                "--disable-version-check",
                str(snapshot.root),
            ],
            capture_output=True,
            text=True,
            timeout=EXTERNAL_TOOL_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return [], ToolStatus(name="semgrep", ran=False, detail="Semgrep did not finish. Built-in checks still ran.")
    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError:
        return [], ToolStatus(name="semgrep", ran=False, detail="Semgrep did not return JSON. Built-in checks still ran.")

    severity_map = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    findings: list[Finding] = []
    for item in payload.get("results", []):
        extra = item.get("extra") or {}
        start = (item.get("start") or {}).get("line") or 1
        severity = severity_map.get(str(extra.get("severity", "WARNING")).upper(), "medium")
        relative = _relative(snapshot.root, str(item.get("path", "")))
        check_id = str(item.get("check_id", "semgrep"))
        message = str(extra.get("message", "Semgrep reported a potential issue."))
        findings.append(
            make_finding(
                rule_id=f"semgrep-{check_id}",
                category="security",
                severity=severity,  # type: ignore[arg-type]
                title="Semgrep potential issue",
                description=f"Reported by Semgrep ({check_id}). {message} This is not a confirmed exploit.",
                file=relative,
                line=int(start),
                recommendation="Inspect the flagged line and apply the safer pattern described by the Semgrep rule.",
                tool="semgrep",
            )
        )
    return findings, ToolStatus(name="semgrep", ran=True, detail=f"Semgrep finished and produced {len(findings)} raw result(s).")


def scan_security(snapshot: RepoSnapshot, *, use_external_tools: bool = True) -> tuple[list[Finding], list[ToolStatus]]:
    findings: list[Finding] = []
    for source in snapshot.files:
        findings.extend(_scan_text(source.relative, source.language, source.lines))

    deduped: list[Finding] = []
    seen: set[tuple[str, str, int]] = set()
    for finding in findings:
        key = (finding.rule_id, finding.file, finding.line)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    findings = deduped

    tools = [ToolStatus(name="codesentinel-rules", ran=True, detail="Built-in secret and vulnerability patterns ran.")]
    if not use_external_tools:
        tools.append(ToolStatus(name="bandit", ran=False, detail="Skipped by configuration."))
        tools.append(ToolStatus(name="semgrep", ran=False, detail="Skipped by configuration."))
        return findings, tools

    covered = {(item.file, item.line) for item in findings}
    for runner in (_run_bandit, _run_semgrep):
        extra, status = runner(snapshot)
        added = 0
        for item in extra:
            if (item.file, item.line) in covered:
                continue
            findings.append(item)
            covered.add((item.file, item.line))
            added += 1
        if status.ran:
            status = ToolStatus(name=status.name, ran=True, detail=f"{status.detail} {added} were added after de-duplication.")
        tools.append(status)
        logger.info("%s: %s", status.name, status.detail)
    return findings, tools
