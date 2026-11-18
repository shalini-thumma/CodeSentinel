from codesentinel.ai_reviewer import review_findings
from codesentinel.gap_detector import detect_gaps
from codesentinel.loose_ends_detector import detect_loose_ends
from codesentinel.models import AnalysisReport, RepositorySnapshot
from codesentinel.report_generator import build_report
from codesentinel.repository_analyzer import build_inventory
from codesentinel.security_scanner import scan_security
from codesentinel.slop_detector import detect_slop


def analyze_snapshot(snapshot: RepositorySnapshot) -> AnalysisReport:
    inventory = build_inventory(snapshot)
    source_files = inventory.source_files
    findings = []
    findings.extend(scan_security(source_files))
    findings.extend(detect_slop(source_files))
    findings.extend(detect_gaps(source_files))
    findings.extend(detect_loose_ends(snapshot, inventory))
    findings, ai_reviewed, ai_warning = review_findings(source_files, findings)
    warnings = [ai_warning] if ai_warning else []
    return build_report(snapshot, findings, ai_reviewed=ai_reviewed, warnings=warnings)