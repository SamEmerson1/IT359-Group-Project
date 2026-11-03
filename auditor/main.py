"""
main.py — CLI entry point for the auditor.

    python -m auditor.main --target http://127.0.0.1:5000 --out report.html

Runs every check against the target, adds a plain-language explanation to each
finding, scores the result, writes an HTML report, and prints a summary table.
"""

import argparse
import sys

from auditor.checks import ALL_CHECKS
from auditor import ai_report, report
from auditor.scoring import score, grade


def run_audit(target: str):
    findings = []
    for check in ALL_CHECKS:
        try:
            f = check.run(target)
        except Exception as e:  # one broken check shouldn't sink the whole scan
            from auditor.core import Finding, Severity
            f = Finding(
                category=getattr(check, "__name__", "unknown"),
                test_performed="Check raised an error.",
                passed=False, severity=Severity.INFO,
                finding=f"The check could not run: {e}",
                evidence="", recommendation="Debug this check module.")
        f.ai_explanation = ai_report.explain(f)
        findings.append(f)
    return findings


def print_summary(findings):
    print(f"\n{'CATEGORY':<28}{'RESULT':<10}SEVERITY")
    print("-" * 50)
    for f in findings:
        result = "PASS" if f.passed else "FAIL"
        print(f"{f.category:<28}{result:<10}{f.severity.name}")
    pts = score(findings)
    print("-" * 50)
    print(f"Authentication security score: {pts}/100 ({grade(pts)})\n")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Authentication security auditor")
    ap.add_argument("--target", required=True, help="URL of OUR target app")
    ap.add_argument("--out", default="report.html", help="output HTML report path")
    args = ap.parse_args(argv)

    print(f"Auditing {args.target} ...")
    findings = run_audit(args.target)

    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(report.render_html(findings))

    print_summary(findings)
    print(f"Full report written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
