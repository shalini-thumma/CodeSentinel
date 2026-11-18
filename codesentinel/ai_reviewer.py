"""Optional OpenAI-compatible review of existing findings and redacted excerpts."""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request

from codesentinel.models import Finding


MAX_REVIEW_FINDINGS = 30
MAX_TOTAL_EXCERPT_CHARS = 24000
SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?:[A-Za-z0-9]+[_-])*(?:api[_-]?key|access[_-]?token|auth[_-]?token|"
    r"client[_-]?secret|password|passwd|secret[_-]?key|private[_-]?key)\b"
    r"\s*[:=]\s*(['\"])[^'\"\r\n]*\1"
)
SECRET_LITERAL = re.compile(
    r"(?i)\b(?:[A-Za-z0-9]+[_-])*(?:api[_-]?key|access[_-]?token|auth[_-]?token|"
    r"client[_-]?secret|password|passwd|secret[_-]?key|private[_-]?key)\b"
    r"\s*[:=]\s*(['\"])([^'\"\r\n]{8,})\1"
)
SECRET_TOKEN = re.compile(r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,})\b")
PRIVATE_KEY_START = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
PRIVATE_KEY_END = re.compile(r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")


def redact_snippet(text: str) -> str:
    """Remove common credential forms before any optional external request."""
    output = []
    inside_private_key = False
    for line in text.splitlines():
        if inside_private_key:
            if PRIVATE_KEY_END.search(line):
                inside_private_key = False
            output.append("[private key material redacted]")
            continue
        if PRIVATE_KEY_START.search(line):
            inside_private_key = not bool(PRIVATE_KEY_END.search(line))
            output.append("[private key material redacted]")
            continue
        line = SECRET_ASSIGNMENT.sub("credential assignment=[REDACTED]", line)
        line = SECRET_TOKEN.sub("[REDACTED_TOKEN]", line)
        output.append(line)
    return "\n".join(output)


def _known_secret_values(files: dict[str, str]) -> set[str]:
    values = set()
    for content in files.values():
        for line in content.splitlines():
            match = SECRET_LITERAL.search(line)
            if match:
                values.add(match.group(2))
            values.update(SECRET_TOKEN.findall(line))
    return values


def _redact_review_text(text: str, secret_values: set[str]) -> str:
    for value in sorted(secret_values, key=len, reverse=True):
        text = text.replace(value, "[REDACTED_SECRET]")
    return redact_snippet(text)


def _review_payload(files: dict[str, str], findings: list[Finding]) -> tuple[list[dict], int]:
    reviews = []
    total_chars = 0
    for index, finding in enumerate(findings[:MAX_REVIEW_FINDINGS], start=1):
        source = files.get(finding.file, "")
        lines = source.splitlines()
        if finding.line and 1 <= finding.line <= len(lines):
            start = max(0, finding.line - 3)
            end = min(len(lines), finding.line + 2)
            excerpt = "\n".join(f"{number + 1}: {lines[number]}" for number in range(start, end))
            excerpt = redact_snippet(excerpt)[:1600]
        else:
            excerpt = ""
        remaining = MAX_TOTAL_EXCERPT_CHARS - total_chars
        excerpt = excerpt[:max(0, remaining)]
        total_chars += len(excerpt)
        reviews.append({
            "id": f"F{index}",
            "category": finding.category,
            "rule_id": finding.rule_id,
            "severity": finding.severity.value,
            "title": finding.title,
            "file": finding.file,
            "line": finding.line,
            "static_explanation": finding.explanation,
            "static_recommendation": finding.recommendation,
            "redacted_excerpt": excerpt,
        })
    return reviews, total_chars


def review_findings(files: dict[str, str], findings: list[Finding]):
    """Return revised text for existing findings only; fail closed to static results."""
    api_key = os.getenv("CODESENTINEL_AI_API_KEY", "").strip()
    if not api_key or not findings:
        return findings, False, None

    base_url = os.getenv("CODESENTINEL_AI_BASE_URL", "https://api.openai.com/v1").strip().rstrip("/")
    parsed_base = urllib.parse.urlsplit(base_url)
    local_http = parsed_base.scheme == "http" and parsed_base.hostname in {"localhost", "127.0.0.1", "::1"}
    if not parsed_base.hostname or (parsed_base.scheme != "https" and not local_http):
        return findings, False, "AI review was skipped because its configured endpoint is not HTTPS."

    entries, _ = _review_payload(files, findings)
    secret_values = _known_secret_values(files)
    request_body = {
        "model": os.getenv("CODESENTINEL_AI_MODEL", "gpt-4o-mini"),
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
        "messages": [
            {
                "role": "system",
                "content": (
                    "Review only the supplied static findings. Do not add, remove, or change severity of findings. "
                    "Improve explanations and fixes only when supported by the excerpt. Identify overlap by returned IDs. "
                    "Return JSON: {reviews:[{id, explanation, recommendation, related:[ids]}]}. "
                    "Do not repeat any credential-like material. If evidence is insufficient, keep the static text unchanged."
                ),
            },
            {"role": "user", "content": json.dumps(entries, ensure_ascii=True)},
        ],
    }
    request = urllib.request.Request(
        f"{base_url}/chat/completions",
        data=json.dumps(request_body).encode("utf-8"),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            response_body = json.loads(response.read(256 * 1024))
        message = response_body["choices"][0]["message"]["content"]
        result = json.loads(message)
        review_map = {entry["id"]: entry for entry in result.get("reviews", []) if isinstance(entry, dict)}
        valid_ids = {entry["id"] for entry in entries}
        reviewed = []
        for index, finding in enumerate(findings, start=1):
            review = review_map.get(f"F{index}")
            if not review:
                reviewed.append(finding)
                continue
            update = {}
            explanation = review.get("explanation")
            recommendation = review.get("recommendation")
            related = review.get("related", [])
            if isinstance(explanation, str) and explanation.strip():
                update["explanation"] = _redact_review_text(explanation[:1200], secret_values)
            if isinstance(recommendation, str) and recommendation.strip():
                update["recommendation"] = _redact_review_text(recommendation[:1200], secret_values)
            if isinstance(related, list):
                update["related_findings"] = [item for item in related if item in valid_ids and item != f"F{index}"][:10]
            reviewed.append(finding.model_copy(update=update) if update else finding)
        return reviewed, True, None
    except (OSError, TimeoutError, urllib.error.URLError, urllib.error.HTTPError, KeyError, TypeError, ValueError):
        return findings, False, "AI review was unavailable; static findings are retained."