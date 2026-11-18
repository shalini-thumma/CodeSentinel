from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    category: str
    severity: Severity
    title: str
    file: str
    line: int | None = None
    explanation: str
    recommendation: str
    confidence: str = "medium"
    evidence: str | None = None
    related_findings: list[str] = Field(default_factory=list)


class RepositoryInfo(BaseModel):
    name: str
    owner: str
    url: str
    default_branch: str
    languages: dict[str, int] = Field(default_factory=dict)
    analyzed_files: int = 0
    skipped_files: int = 0


class RepositorySnapshot(BaseModel):
    repository: RepositoryInfo
    files: dict[str, str]
    warnings: list[str] = Field(default_factory=list)


class AnalysisReport(BaseModel):
    repository: RepositoryInfo
    findings: list[Finding] = Field(default_factory=list)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    health_score: int = 100
    score_explanation: str = ""
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ai_reviewed: bool = False
    warnings: list[str] = Field(default_factory=list)