"""Fast pattern-based detection layer. Returns findings with matched spans."""

import base64
import binascii
import re
from dataclasses import dataclass


@dataclass
class Finding:
    rule_id: str
    score: float
    reason: str
    text: str  # matched span (used for highlighting and sanitizing)


OVERRIDE = re.compile(
    r"\b(ignore|disregard|forget|override)\b[^.\n]{0,30}\b(previous|prior|above|earlier|all|your|the)\b[^.\n]{0,20}"
    r"\b(instructions?|rules|prompts?|guidelines|directives)\b"
    r"|\byou are now\b|\bnew system prompt\b|\bsystem override\b|\bdeveloper mode\b"
    r"|\bdo not (tell|inform|mention (this )?to) the user\b|\bwithout (telling|informing|asking) the user\b",
    re.IGNORECASE,
)
AI_ADDRESSED = re.compile(
    r"\b(ai|assistant|agent|llm|chatbot)\b[^.\n]{0,40}\b(must|should|need to|are required to|now)\b"
    r"|\b(attention|note|instruction)s?\s+(to|for)\s+(the\s+)?(ai|assistant|agent)\b",
    re.IGNORECASE,
)
ROLE_TOKENS = re.compile(r"<\|im_start\|>|<\|im_end\|>|<\|system\|>|\[/?INST\]|<<SYS>>|^\s*#{2,}\s*system\b", re.IGNORECASE | re.MULTILINE)
TOOL_NAMES = re.compile(r"\b(send_email|transfer_funds|read_file|fetch_url|read_inbox)\b")
ZERO_WIDTH = re.compile("[​-‏‪-‮⁠-⁤﻿]")
BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
MD_IMAGE_WITH_QUERY = re.compile(r"!\[[^\]]*\]\((https?://[^)\s]+\?[^)\s]+)\)")


def _matches(pattern: re.Pattern[str], text: str, rule_id: str, score: float, reason: str) -> list[Finding]:
    return [Finding(rule_id, score, reason, m.group(0)) for m in pattern.finditer(text)]


def _instruction_findings(text: str) -> list[Finding]:
    return (
        _matches(OVERRIDE, text, "heur.override_phrase", 0.6, "Instruction-override phrase")
        + _matches(AI_ADDRESSED, text, "heur.addresses_ai", 0.5, "Text addresses the AI assistant directly")
        + _matches(ROLE_TOKENS, text, "heur.role_token", 0.7, "Fake chat-template / role token")
        + _matches(TOOL_NAMES, text, "heur.tool_name", 0.5, "Content names an agent tool")
    )


def scan(text: str, hidden_segments: list[str] | None = None) -> list[Finding]:
    findings = _instruction_findings(text)

    if ZERO_WIDTH.search(text):
        findings.append(Finding("heur.zero_width", 0.5, "Invisible zero-width / bidi characters", ""))
        stripped = ZERO_WIDTH.sub("", text)
        for f in _instruction_findings(stripped):
            if f.text and f.text not in text:  # only visible once the invisible chars are removed
                findings.append(Finding("heur.obfuscated_instruction", 0.9, f"Obfuscated: {f.reason}", f.text))

    for seg in hidden_segments or []:
        inner = _instruction_findings(seg)
        if inner:
            findings.append(Finding("heur.hidden_instruction", 0.95, "Instructions hidden in invisible HTML", seg))
        elif len(seg) >= 20:
            findings.append(Finding("heur.hidden_text", 0.3, "Hidden HTML text", seg))

    for m in BASE64_BLOB.finditer(text):
        try:
            decoded = base64.b64decode(m.group(0), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            continue
        if _instruction_findings(decoded):
            findings.append(Finding("heur.base64_instruction", 0.9, f"Base64 blob decodes to instructions: {decoded[:60]!r}", m.group(0)))

    findings += _matches(MD_IMAGE_WITH_QUERY, text, "heur.md_image_exfil", 0.7, "Markdown image with query-string URL (exfil pattern)")
    return findings


def combined_score(findings: list[Finding]) -> float:
    """Max finding score, nudged up a little for each extra distinct rule that fired."""
    if not findings:
        return 0.0
    distinct = len({f.rule_id for f in findings})
    return min(1.0, max(f.score for f in findings) + 0.1 * (distinct - 1))
