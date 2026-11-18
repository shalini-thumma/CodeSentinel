"""Deterministic report assembly and safe HTML serialization."""

from __future__ import annotations

import html
import json

from codesentinel.models import AnalysisReport, Finding, RepositorySnapshot, Severity


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFORMATIONAL: 4,
}
SCORE_PENALTIES = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 12,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFORMATIONAL: 0,
}


def build_report(
    snapshot: RepositorySnapshot,
    findings: list[Finding],
    ai_reviewed: bool = False,
    warnings: list[str] | None = None,
) -> AnalysisReport:
    ordered = sorted(findings, key=lambda finding: (
        SEVERITY_ORDER[finding.severity], finding.file.lower(), finding.line or 0, finding.rule_id
    ))
    severity_counts = {severity.value: sum(f.severity == severity for f in ordered) for severity in Severity}
    penalty = min(100, sum(SCORE_PENALTIES[finding.severity] for finding in ordered))
    score = 100 - penalty
    return AnalysisReport(
        repository=snapshot.repository,
        findings=ordered,
        severity_counts=severity_counts,
        health_score=score,
        score_explanation=(
            "Heuristic: starts at 100 and subtracts fixed points per detected finding "
            "(Critical 25, High 12, Medium 5, Low 2, Informational 0), capped at 0. "
            "This is a triage aid, not a security certification or proof of code quality."
        ),
        ai_reviewed=ai_reviewed,
        warnings=list(snapshot.warnings) + (warnings or []),
    )


def json_report(report: AnalysisReport) -> str:
    return json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=True)


def html_report(report: AnalysisReport) -> str:
    counts = "".join(
        f"<li><strong>{html.escape(severity)}</strong><span>{count}</span></li>"
        for severity, count in report.severity_counts.items()
    )
    rows = []
    for finding in report.findings:
        rows.append(
            "<article class=\"finding\">"
            f"<div class=\"meta\"><span>{html.escape(finding.severity.value)}</span>"
            f"<span>{html.escape(finding.category)}</span><code>{html.escape(finding.rule_id)}</code></div>"
            f"<h2>{html.escape(finding.title)}</h2>"
            f"<p class=\"location\">{html.escape(finding.file)}{':' + str(finding.line) if finding.line else ''}</p>"
            f"<p>{html.escape(finding.explanation)}</p>"
            f"<p><strong>Suggested fix:</strong> {html.escape(finding.recommendation)}</p>"
            "</article>"
        )
    if not rows:
        rows.append("<p>No findings were detected by the configured static checks.</p>")
    warnings = "".join(f"<li>{html.escape(warning)}</li>" for warning in report.warnings)
    languages = ", ".join(f"{html.escape(name)} ({count} files)" for name, count in report.repository.languages.items()) or "Not detected"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>CodeSentinel report: {html.escape(report.repository.owner)}/{html.escape(report.repository.name)}</title>
<style>
:root {{ color-scheme: light; --ink: #152c2b; --muted: #58706d; --paper: #f3f6f2; --line: #d7e1dc; --accent: #087f72; --lime: #d8f36a; }}
* {{ box-sizing: border-box; }} body {{ margin: 0; background: var(--paper); color: var(--ink); font: 16px/1.55 Georgia, serif; }}
main {{ max-width: 1000px; margin: auto; padding: 48px 24px; }} header {{ border-bottom: 1px solid var(--line); padding-bottom: 24px; }}
.brand {{ font: 700 13px/1.2 Arial, sans-serif; letter-spacing: 0; color: var(--accent); text-transform: uppercase; }}
h1 {{ font-size: 34px; margin: 12px 0; overflow-wrap: anywhere; }} .summary {{ display: flex; flex-wrap: wrap; gap: 24px; align-items: center; }}
.score {{ background: var(--lime); border-radius: 6px; padding: 10px 16px; font: 700 24px Arial, sans-serif; }}
section {{ margin: 28px 0; }} ul {{ padding-left: 20px; }} .counts {{ display: flex; flex-wrap: wrap; gap: 12px 28px; list-style: none; padding: 0; }}
.counts li {{ display: flex; gap: 12px; min-width: 135px; justify-content: space-between; border-bottom: 1px solid var(--line); }}
.finding {{ padding: 20px 0; border-top: 1px solid var(--line); }} .meta {{ display: flex; gap: 10px; align-items: center; flex-wrap: wrap; font: 700 12px Arial, sans-serif; text-transform: uppercase; color: var(--accent); }}
.meta code {{ color: var(--muted); }} h2 {{ font: 700 20px Arial, sans-serif; margin: 10px 0 2px; }} .location {{ color: var(--muted); font: 13px Arial, sans-serif; overflow-wrap: anywhere; }}
footer {{ margin-top: 38px; border-top: 1px solid var(--line); padding-top: 18px; color: var(--muted); font-size: 14px; }}
</style></head><body><main>
<header><div class="brand">CodeSentinel / Static Audit</div><h1>{html.escape(report.repository.owner)}/{html.escape(report.repository.name)}</h1>
<div class="summary"><div class="score">Health {report.health_score}/100</div><div>{html.escape(report.repository.url)}</div></div>
<p>Branch: {html.escape(report.repository.default_branch)} · Files analyzed: {report.repository.analyzed_files} · Languages: {languages}</p></header>
<section><h2>Severity summary</h2><ul class="counts">{counts}</ul><p>{html.escape(report.score_explanation)}</p></section>
<section><h2>Findings ({len(report.findings)})</h2>{''.join(rows)}</section>
{f'<section><h2>Analysis notes</h2><ul>{warnings}</ul></section>' if warnings else ''}
<footer>Generated by CodeSentinel · {report.generated_at.isoformat()} · Static checks can miss issues and produce false positives; verify each finding.</footer>
</main></body></html>"""