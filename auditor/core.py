"""
core.py — the shared vocabulary for the auditor.

Every check returns a `Finding`. Scoring, the AI layer, and the report all
read `Finding`s. Settling this one shape first means every other module has a
fixed contract to build against.
"""

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    """How bad a finding is. The number is the weight scoring subtracts."""
    CRITICAL = 25
    HIGH = 15
    MEDIUM = 8
    LOW = 3
    INFO = 0        # noted, but costs no points


@dataclass
class Finding:
    """
    One result from one check. Fill every field — the report is only as good
    as what goes in here, so 'evidence' and 'recommendation' matter as much as
    the pass/fail.
    """
    category: str          # e.g. "Password Policy"
    test_performed: str    # what the check actually did, in one sentence
    passed: bool           # did the app behave securely?
    severity: Severity     # use INFO when passed=True
    finding: str           # what was observed
    evidence: str = ""     # the proof: a response snippet, a header, a log line
    recommendation: str = ""           # how to fix it
    ai_explanation: str = field(default="", repr=False)  # filled by ai_report

    def as_dict(self) -> dict:
        """Flat dict for scoring, reporting, and the AI prompt."""
        return {
            "category": self.category,
            "test_performed": self.test_performed,
            "passed": self.passed,
            "severity": self.severity.name,
            "finding": self.finding,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }
