"""
ai_report.py — the AI layer (OpenAI backend).

Design rule: the AI *explains*, it does not *measure*. The checks produce the
facts (the Finding); we send those structured facts to the model and ask only
for a plain-language explanation and fix. If the key is missing or the call
fails for any reason, each finding falls back to a solid template, so the tool
always completes a scan.

SETUP (one time):
    pip install openai
    set your API key in the environment:
        macOS/Linux:   export OPENAI_API_KEY="sk-..."
        Windows (PS):  setx OPENAI_API_KEY "sk-..."     (then reopen the shell)

Cost: only FAILED findings are sent to the model — at most 7 short prompts per
scan — so a few dollars of gpt-4o-mini credit lasts a very long time. Passing
checks and the hardened-mode demo make zero API calls.
"""

import os
from auditor.core import Finding

MODEL = "gpt-4o-mini"   # cheap and capable; swap if your group prefers another

PROMPT = (
    "You are writing a security report for a non-expert reader. Using ONLY the "
    "finding below as fact, write 2-3 sentences: what the problem is, why it "
    "matters, and the concrete fix. Do not invent anything beyond the data.\n\n"
    "Finding: {data}"
)


def explain(finding: Finding) -> str:
    """Return a plain-language explanation for one finding."""
    if finding.passed:
        # Passing checks don't need an AI paragraph (and don't spend tokens).
        return finding.finding
    try:
        return _call_llm(PROMPT.format(data=finding.as_dict()))
    except Exception:
        return _template(finding)


def _call_llm(prompt: str) -> str:
    """Call OpenAI. Raises on any problem so explain() falls back to _template."""
    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY is not set")
    from openai import OpenAI          # lazy import: the tool still runs if the
    client = OpenAI()                  # package isn't installed (uses fallback)
    resp = client.chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system",
             "content": "You are a security engineer writing clear, accurate "
                        "remediation notes for a non-expert. Use only the facts given."},
            {"role": "user", "content": prompt},
        ],
        temperature=0.2,
        max_tokens=180,
    )
    return resp.choices[0].message.content.strip()


def _template(finding: Finding) -> str:
    """Readable fallback built from the structured finding — no API needed."""
    impact = {
        "CRITICAL": "This is a critical weakness that could directly expose accounts.",
        "HIGH": "This is a high-severity weakness that meaningfully weakens account security.",
        "MEDIUM": "This is a moderate weakness that makes attacks easier.",
        "LOW": "This is a minor weakness worth tidying up.",
    }.get(finding.severity.name, "")
    return f"{finding.finding} {impact} How to fix it: {finding.recommendation}"
