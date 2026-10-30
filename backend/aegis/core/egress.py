"""Outbound data checks: canary tokens, secrets, PII, and data smuggled in URLs."""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote, urlparse

from aegis.config import WORKSPACE_DIR
from aegis.core.policy import Decision, domain_matches, email_domain

SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "egress.secret.api_key": re.compile(r"\bsk-[A-Za-z0-9-]{16,}\b"),
    "egress.secret.aws_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "egress.secret.private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "egress.secret.assignment": re.compile(r"\b[A-Z_]*(PASSWORD|SECRET|TOKEN|API_KEY)\s*=\s*\S+"),
}
EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(\.[\w-]+)+\b")
PHONE = re.compile(r"(?<!\w)\+?\d[\d\s().-]{8,}\d\b")
LONG_QUERY_VALUE = 24


def load_canaries(secrets_file: Path = WORKSPACE_DIR / "secrets.env") -> list[str]:
    """Every value in secrets.env is a canary: it must never leave the sandbox."""
    if not secrets_file.exists():
        return []
    values = []
    for line in secrets_file.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            value = line.split("=", 1)[1].strip()
            if len(value) >= 8:
                values.append(value)
    return values


@dataclass
class EgressChecker:
    allow_domains: list[str]
    canaries: list[str] = field(default_factory=load_canaries)

    def destination(self, tool: str, args: dict[str, Any]) -> str:
        if tool == "send_email":
            return email_domain(str(args.get("to", "")))
        if tool == "fetch_url":
            return urlparse(str(args.get("url", ""))).hostname or ""
        return ""

    def check(self, tool: str, args: dict[str, Any]) -> Decision:
        payload = "\n".join(str(v) for v in args.values())
        decoded = unquote(payload)
        dest = self.destination(tool, args)
        external = not domain_matches(dest, self.allow_domains) if dest else True
        hits: list[tuple[str, str]] = []

        for canary in self.canaries:
            if canary in payload or canary in decoded:
                hits.append(("egress.canary", f"Canary token {canary[:10]}… found in outbound {tool} (destination: {dest or 'unknown'})"))

        if external:
            for rule_id, pattern in SECRET_PATTERNS.items():
                if pattern.search(decoded):
                    hits.append((rule_id, f"Secret-like value ({rule_id.rsplit('.', 1)[-1]}) sent to external destination {dest}"))
            body_text = decoded if tool != "send_email" else f"{args.get('subject', '')}\n{args.get('body', '')}"
            if EMAIL.search(body_text) or PHONE.search(body_text):
                hits.append(("egress.pii", f"PII (email/phone) sent to non-allowlisted destination {dest}"))
            if tool == "fetch_url":
                for key, value in parse_qsl(urlparse(str(args.get("url", ""))).query):
                    if len(value) >= LONG_QUERY_VALUE:
                        hits.append(("egress.url_data", f"URL query parameter '{key}' carries {len(value)} chars of data to {dest}"))

        if hits:
            severity = 1.0 if any(r == "egress.canary" for r, _ in hits) else 0.85
            return Decision(verdict="DENY", risk_score=severity, reasons=[r for _, r in hits], rule_ids=sorted({r for r, _ in hits}))
        return Decision(verdict="ALLOW", risk_score=0.0, reasons=["No sensitive data in outbound payload"], rule_ids=[])
