"""scoring.py — turn a list of Findings into a 0-100 authentication score."""

from auditor.core import Finding


def score(findings: list[Finding], start: int = 100) -> int:
    total = start
    for f in findings:
        if not f.passed:
            total -= f.severity.value
    return max(0, total)


def grade(points: int) -> str:
    return ("Strong" if points >= 85 else
            "Fair"   if points >= 60 else
            "Weak"   if points >= 35 else "Critical")
