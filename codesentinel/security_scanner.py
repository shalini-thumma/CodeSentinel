"""Conservative, read-only security checks for common source patterns."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path, PurePosixPath

from codesentinel.models import Finding, Severity


SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?:[A-Za-z0-9]+[_-])*(?:api[_-]?key|access[_-]?token|auth[_-]?token|"
    r"client[_-]?secret|password|passwd|secret[_-]?key|private[_-]?key)\b"
    r"\s*[:=]\s*['\"]([^'\"\r\n]{8,})['\"]"
)
PLACEHOLDER_VALUES = {
    "changeme", "change_me", "your_api_key", "your_key_here", "example",
    "placeholder", "password", "secret", "none", "null", "<redacted>",
}
SECRET_PATTERNS = (
    ("SEC-AWS-KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "Potential AWS access key"),
    ("SEC-GITHUB-TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "Potential GitHub token"),
    ("SEC-PRIVATE-KEY", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "Private key material"),
)
INJECTION_PATTERNS = (
    ("SEC-SQL-FSTRING", re.compile(r"\b(?:execute|executemany|query)\s*\(\s*f[\"']", re.I), "Potential SQL injection through an interpolated query"),
    ("SEC-SQL-CONCAT", re.compile(r"\b(?:execute|executemany|query)\s*\([^\n)]*[\"'][^\"']*[\"']\s*\+\s*[A-Za-z_]", re.I), "Potential SQL injection through query string concatenation"),
    ("SEC-SQL-TEMPLATE", re.compile(r"\.(?:query|execute)\s*\(\s*`[^`]*\$\{", re.I), "Potential SQL injection through a templated query"),
    ("SEC-COMMAND-SHELL", re.compile(r"\b(?:os\.system|os\.popen)\s*\("), "Potential command injection through a shell command"),
    ("SEC-SHELL-TRUE", re.compile(r"\bshell\s*=\s*True\b"), "Potential command injection: subprocess uses a shell"),
)
UNSAFE_PATTERNS = (
    ("SEC-EVAL", re.compile(r"\b(?:eval|exec)\s*\("), Severity.HIGH, "Dynamic code execution can run untrusted input"),
    ("SEC-PICKLE", re.compile(r"\bpickle\.loads?\s*\("), Severity.HIGH, "Deserializing untrusted pickle data can execute code"),
    ("SEC-YAML-LOAD", re.compile(r"\byaml\.load\s*\("), Severity.MEDIUM, "Unsafe YAML loading may construct arbitrary Python objects"),
    ("SEC-TLS-VERIFY", re.compile(r"\bverify\s*=\s*False\b"), Severity.MEDIUM, "TLS certificate verification is disabled"),
    ("SEC-INNERHTML", re.compile(r"\.innerHTML\s*="), Severity.MEDIUM, "Untrusted HTML assignment can create a cross-site scripting risk"),
    ("SEC-WEAK-HASH", re.compile(r"\b(?:md5|sha1)\s*\("), Severity.LOW, "MD5 or SHA-1 is unsuitable for security-sensitive hashing"),
    ("SEC-DEBUG", re.compile(r"\bDEBUG\s*=\s*True\b"), Severity.MEDIUM, "Debug mode appears enabled in source configuration"),
)
PLACEHOLDER_RE = re.compile(r"(?i)^(?:\$\{[^}]+\}|<[^>]+>|your[_ -].*|example.*|test[_ -].*|\*+)$")


def _finding(rule_id, severity, title, path, line, explanation, recommendation, confidence="medium"):
    return Finding(
        rule_id=rule_id,
        category="security",
        severity=severity,
        title=title,
        file=path,
        line=line,
        explanation=explanation,
        recommendation=recommendation,
        confidence=confidence,
    )


def _secret_findings(path: str, line_number: int, line: str) -> list[Finding]:
    findings = []
    assignment = SECRET_ASSIGNMENT.search(line)
    if assignment:
        normalized = assignment.group(1).strip().lower()
        if normalized not in PLACEHOLDER_VALUES and not PLACEHOLDER_RE.match(normalized):
            findings.append(_finding(
                "SEC-HARDCODED-SECRET", Severity.HIGH, "Potential hardcoded credential", path, line_number,
                "A value assigned to a credential-like setting appears to be a literal secret. The value is omitted from this report.",
                "Move the value to a secret manager or environment variable, rotate it if real, and avoid committing credentials.",
            ))
    for rule_id, pattern, title in SECRET_PATTERNS:
        if pattern.search(line):
            findings.append(_finding(
                rule_id, Severity.CRITICAL if rule_id == "SEC-PRIVATE-KEY" else Severity.HIGH,
                title, path, line_number,
                "A known secret-like format was found. This is a potential exposed credential and should be verified without sharing its value.",
                "Remove the material from source control, rotate or revoke it if real, and load secrets from a managed secret store.",
                "high",
            ))
    return findings


def _static_findings(files: dict[str, str]) -> list[Finding]:
    findings = []
    for path, content in files.items():
        for line_number, line in enumerate(content.splitlines(), start=1):
            findings.extend(_secret_findings(path, line_number, line))
            for rule_id, pattern, title in INJECTION_PATTERNS:
                if pattern.search(line):
                    findings.append(_finding(
                        rule_id, Severity.HIGH, title, path, line_number,
                        "This source pattern may combine an externally influenced value with a sensitive operation. Data flow is not proven by this check.",
                        "Use parameterized queries for database access. For processes, pass an argument list with shell execution disabled and validate inputs.",
                    ))
            for rule_id, pattern, severity, explanation in UNSAFE_PATTERNS:
                if pattern.search(line):
                    findings.append(_finding(
                        rule_id, severity, explanation.split(".")[0], path, line_number,
                        f"{explanation}. Context and input trust are not established by this pattern check.",
                        "Review the data source and use a safe, allowlisted alternative appropriate to this operation.",
                    ))
    return findings


def _bandit_findings(files: dict[str, str]) -> list[Finding]:
    executable = shutil.which("bandit")
    python_files = {path: text for path, text in files.items() if PurePosixPath(path).suffix.lower() == ".py"}
    if not executable or not python_files:
        return []
    try:
        with tempfile.TemporaryDirectory(prefix="codesentinel-bandit-") as temporary_dir:
            root = Path(temporary_dir)
            for relative_path, text in python_files.items():
                target = root.joinpath(*PurePosixPath(relative_path).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text, encoding="utf-8")
            result = subprocess.run(
                [executable, "-q", "-r", str(root), "-f", "json"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        payload = json.loads(result.stdout or "{}")
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return []

    findings = []
    severity_map = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
    for issue in payload.get("results", []):
        raw_path = str(issue.get("filename", "")).replace("\\", "/")
        try:
            relative_path = Path(raw_path).resolve().relative_to(root.resolve()).as_posix()
        except (OSError, ValueError):
            continue
        findings.append(_finding(
            f"BANDIT-{issue.get('test_id', 'UNKNOWN')}",
            severity_map.get(str(issue.get("issue_severity", "LOW")).upper(), Severity.LOW),
            str(issue.get("issue_text", "Bandit security finding"))[:160],
            relative_path,
            issue.get("line_number"),
            f"Bandit reported: {str(issue.get('issue_text', 'Potential security issue'))[:500]}",
            "Review the reported call and use a safer API or validate and constrain its input.",
            str(issue.get("issue_confidence", "MEDIUM")).lower(),
        ))
    return findings


def scan_security(files: dict[str, str]) -> list[Finding]:
    """Run built-in pattern checks and Bandit when its CLI is installed."""
    findings = _static_findings(files)
    findings.extend(_bandit_findings(files))
    unique = {}
    for finding in findings:
        key = (finding.rule_id, finding.file, finding.line)
        unique.setdefault(key, finding)
    return list(unique.values())