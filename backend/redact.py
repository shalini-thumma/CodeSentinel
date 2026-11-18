"""Remove credential-shaped text before it is stored, shown, or sent to an LLM."""

from __future__ import annotations

import re

_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|apikey|secret|password|passwd|token|access[_-]?key|private[_-]?key)\b"
    r"(\s*[:=]{1,2}\s*)(['\"])[^'\"]{4,}(\3)"
)
_AWS = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_STRIPE = re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{8,}")
_GITHUB = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}")
_SLACK = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")


def redact(text: str) -> str:
    if not text:
        return text
    text = _PRIVATE_KEY.sub("***PRIVATE KEY REDACTED***", text)
    text = _AWS.sub("AKIA***REDACTED***", text)
    text = _STRIPE.sub("sk_***REDACTED***", text)
    text = _GITHUB.sub("gh***REDACTED***", text)
    text = _SLACK.sub("xox***REDACTED***", text)
    text = _ASSIGNMENT.sub(r"\1\2\3***REDACTED***\4", text)
    return text
