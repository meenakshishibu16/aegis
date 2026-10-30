"""YAML policy: models, hot-reloading loader, and the rule engine.

Evaluation order: tool permitted -> argument constraints -> rate limit -> taint rule.
"""

import fnmatch
import re
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, Field

Risk = Literal["low", "medium", "high"]
RISK_SCORE: dict[str, float] = {"low": 0.1, "medium": 0.5, "high": 0.9}


class ToolRule(BaseModel):
    allowed: bool = True
    risk: Risk = "low"
    if_tainted: Literal["allow", "deny"] = "allow"
    rate_limit: int | None = None              # max calls per session
    path_allow: list[str] = Field(default_factory=list)
    path_deny: list[str] = Field(default_factory=list)
    recipient_domains: list[str] | None = None  # allowlist for send_email "to"
    url_domains: list[str] | None = None        # allowlist for fetch_url "url"
    max_amount: float | None = None
    arg_regex: dict[str, str] = Field(default_factory=dict)  # arg name -> pattern the value must fully match


class Policy(BaseModel):
    agent_id: str
    trusted_files: list[str] = Field(default_factory=list)
    egress_allow_domains: list[str] = Field(default_factory=list)
    tools: dict[str, ToolRule]


class Decision(BaseModel):
    verdict: Literal["ALLOW", "DENY"]
    risk_score: float
    reasons: list[str] = Field(default_factory=list)
    rule_ids: list[str] = Field(default_factory=list)


def domain_matches(host: str, allowed: list[str]) -> bool:
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in allowed)


def email_domain(address: str) -> str:
    return address.rsplit("@", 1)[-1].strip().strip(">").lower() if "@" in address else ""


class PolicyStore:
    """Loads policy.yaml and reloads it when the file changes on disk."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._mtime = 0.0
        self._policy: Policy | None = None

    def get(self) -> Policy:
        mtime = self.path.stat().st_mtime
        if self._policy is None or mtime != self._mtime:
            self._policy = Policy.model_validate(yaml.safe_load(self.path.read_text(encoding="utf-8")))
            self._mtime = mtime
        return self._policy


def evaluate(policy: Policy, tool: str, args: dict[str, Any], call_count: int, tainted: bool) -> Decision:
    """`call_count` is how many times this tool already ran in the session."""
    rule = policy.tools.get(tool)
    if rule is None or not rule.allowed:
        return Decision(verdict="DENY", risk_score=1.0, reasons=[f"Tool '{tool}' is not permitted by policy"], rule_ids=[f"{tool}.allowed"])

    risk = RISK_SCORE[rule.risk]
    deny: list[tuple[str, str]] = []  # (rule_id, reason)

    path = str(args.get("path", ""))
    if path and rule.path_deny and any(fnmatch.fnmatch(path, g) for g in rule.path_deny):
        deny.append((f"{tool}.path_deny", f"Path '{path}' matches a denied pattern"))
    if path and rule.path_allow and not any(fnmatch.fnmatch(path, g) for g in rule.path_allow):
        deny.append((f"{tool}.path_allow", f"Path '{path}' is outside the allowed paths"))

    if rule.recipient_domains is not None and "to" in args:
        recipients = [r.strip() for r in str(args["to"]).replace(";", ",").split(",") if r.strip()]
        bad = [r for r in recipients if not domain_matches(email_domain(r), rule.recipient_domains)]
        if bad:
            deny.append((f"{tool}.recipient_domains", f"Recipient(s) {', '.join(bad)} not in allowed domains {rule.recipient_domains}"))

    if rule.url_domains is not None and "url" in args:
        host = urlparse(str(args["url"])).hostname or ""
        if not domain_matches(host, rule.url_domains):
            deny.append((f"{tool}.url_domains", f"URL host '{host}' not in allowed domains {rule.url_domains}"))

    if rule.max_amount is not None and "amount" in args:
        try:
            amount = float(args["amount"])
        except (TypeError, ValueError):
            amount = float("inf")
        if amount > rule.max_amount:
            deny.append((f"{tool}.max_amount", f"Amount {args['amount']} exceeds limit {rule.max_amount}"))

    for arg, pattern in rule.arg_regex.items():
        if arg in args and not re.fullmatch(pattern, str(args[arg])):
            deny.append((f"{tool}.arg_regex.{arg}", f"Argument '{arg}' does not match required pattern"))

    if rule.rate_limit is not None and call_count >= rule.rate_limit:
        deny.append((f"{tool}.rate_limit", f"Rate limit reached ({rule.rate_limit} calls per session)"))

    if tainted and rule.if_tainted == "deny":
        deny.append((f"{tool}.if_tainted", f"High-risk tool '{tool}' blocked: session is tainted by untrusted content"))

    if deny:
        return Decision(verdict="DENY", risk_score=max(risk, 0.8), reasons=[r for _, r in deny], rule_ids=[i for i, _ in deny])
    return Decision(verdict="ALLOW", risk_score=risk + (0.1 if tainted else 0.0), reasons=["Permitted by policy"], rule_ids=[f"{tool}.allowed"])
