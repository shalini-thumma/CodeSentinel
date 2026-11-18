"""Shared data objects passed between modules and returned by the API."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "informational"]
Category = Literal["security", "slop", "gap", "loose_end"]
Confidence = Literal["potential", "likely"]


class Finding(BaseModel):
    """One potential issue. `confidence` is never treated as proof of exploitability."""

    id: str = ""
    rule_id: str
    category: Category
    severity: Severity
    title: str
    description: str
    file: str
    line: int
    recommendation: str
    tool: str = "codesentinel"
    confidence: Confidence = "potential"
    code_snippet: str = ""
    end_line: int | None = None


class ToolStatus(BaseModel):
    name: str
    ran: bool
    detail: str


class Overlap(BaseModel):
    file: str
    line: int
    finding_ids: list[str]
    titles: list[str]


class AnalysisReport(BaseModel):
    repo_url: str
    repo_name: str
    analyzed_at: str
    duration_seconds: float
    languages: dict[str, int]
    file_count: int
    scanned_code_files: int
    health_score: int = Field(ge=0, le=100)
    health_explanation: str
    severity_summary: dict[str, int]
    category_summary: dict[str, int]
    findings: list[Finding]
    overlaps: list[Overlap]
    ai_summary: str
    ai_used: bool
    ai_note: str
    tools: list[ToolStatus]
    limitations: list[str]
    json_report_path: str | None = None
    html_report_path: str | None = None


class AnalyzeRequest(BaseModel):
    url: str
    use_external_tools: bool = True
    use_llm: bool = True


def make_finding(
    *,
    rule_id: str,
    category: Category,
    severity: Severity,
    title: str,
    description: str,
    file: str,
    line: int,
    recommendation: str,
    snippet: str = "",
    tool: str = "codesentinel",
    confidence: Confidence = "potential",
    end_line: int | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        category=category,
        severity=severity,
        title=title,
        description=description,
        file=file,
        line=line,
        recommendation=recommendation,
        code_snippet=snippet,
        tool=tool,
        confidence=confidence,
        end_line=end_line,
    )
