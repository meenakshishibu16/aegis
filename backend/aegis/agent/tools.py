"""Mock tools. Nothing here touches the real network, mail, or money.

State for each run lives in its own directory (outbox.json, ledger.json,
fetch_log.json, file_log.json) so scenarios can check what happened.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from aegis.config import SITES_DIR, WORKSPACE_DIR
from aegis.core.detector.extract import html_to_text

LOCAL_TLD = ".test"  # only these hosts are served, from simulator/attack_server/<host>/


@dataclass
class ToolContext:
    run_dir: Path
    inbox_path: Path
    workspace: Path = WORKSPACE_DIR
    sites_dir: Path = SITES_DIR

    def __post_init__(self) -> None:
        self.run_dir.mkdir(parents=True, exist_ok=True)

    def append(self, name: str, entry: dict[str, Any]) -> None:
        path = self.run_dir / f"{name}.json"
        items = self.load(name)
        items.append(entry)
        path.write_text(json.dumps(items, indent=2), encoding="utf-8")

    def load(self, name: str) -> list[dict[str, Any]]:
        path = self.run_dir / f"{name}.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else []


@dataclass
class ToolResult:
    text: str                      # what the agent sees
    source: str | None = None      # provenance: "web" | "email" | "file" | None (no external content)
    raw: str | None = None         # raw content for inspection (e.g. HTML with hidden elements)
    content_type: str = "text"     # "text" | "html"
    ref: str = ""                  # file path / URL, used for taint decisions


def read_file(ctx: ToolContext, path: str) -> ToolResult:
    target = (ctx.workspace / path).resolve()
    if not target.is_relative_to(ctx.workspace.resolve()) or not target.is_file():
        return ToolResult(f"Error: file not found: {path}")
    ctx.append("file_log", {"path": path})
    return ToolResult(target.read_text(encoding="utf-8"), source="file", ref=path)


def read_inbox(ctx: ToolContext) -> ToolResult:
    emails = json.loads(ctx.inbox_path.read_text(encoding="utf-8"))
    lines = [
        f"--- Email {i + 1} ---\nFrom: {e['from']}\nSubject: {e['subject']}\n\n{e['body']}"
        for i, e in enumerate(emails)
    ]
    return ToolResult("\n\n".join(lines), source="email", ref="inbox")


def send_email(ctx: ToolContext, to: str, subject: str, body: str) -> ToolResult:
    ctx.append("outbox", {"to": to, "subject": subject, "body": body})
    return ToolResult(f"Email sent to {to}.")


def fetch_url(ctx: ToolContext, url: str) -> ToolResult:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    ctx.append("fetch_log", {"url": url})
    if not host.endswith(LOCAL_TLD):
        return ToolResult(f"Error: network access disabled for {host or url}.")
    page = parsed.path.lstrip("/") or "index.html"
    target = (ctx.sites_dir / host / page).resolve()
    if not target.is_relative_to(ctx.sites_dir.resolve()) or not target.is_file():
        return ToolResult(f"HTTP 404: {url}", source="web", ref=url)
    html = target.read_text(encoding="utf-8")
    # A naive scraper: get_text() keeps hidden elements, which is what makes
    # hidden-text injection work against unprotected agents.
    return ToolResult(html_to_text(html).full_text, source="web", raw=html, content_type="html", ref=url)


def transfer_funds(ctx: ToolContext, to_account: str, amount: float) -> ToolResult:
    ctx.append("ledger", {"to_account": to_account, "amount": float(amount)})
    return ToolResult(f"Transferred {amount} to {to_account}.")


TOOLS: dict[str, Callable[..., ToolResult]] = {
    "read_file": read_file,
    "read_inbox": read_inbox,
    "send_email": send_email,
    "fetch_url": fetch_url,
    "transfer_funds": transfer_funds,
}

OUTBOUND_TOOLS = {"send_email", "fetch_url"}


def _spec(name: str, description: str, params: dict[str, tuple[str, str]]) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": {k: {"type": t, "description": d} for k, (t, d) in params.items()},
                "required": list(params),
            },
        },
    }


TOOL_SPECS: list[dict[str, Any]] = [
    _spec("read_file", "Read a file from the user's workspace.", {"path": ("string", "Relative file path, e.g. notes.md")}),
    _spec("read_inbox", "Read all emails in the user's inbox.", {}),
    _spec("send_email", "Send an email.", {
        "to": ("string", "Recipient email address"),
        "subject": ("string", "Subject line"),
        "body": ("string", "Email body"),
    }),
    _spec("fetch_url", "Fetch a web page and return its text.", {"url": ("string", "Full URL")}),
    _spec("transfer_funds", "Transfer money from the user's account.", {
        "to_account": ("string", "Destination account id"),
        "amount": ("number", "Amount in USD"),
    }),
]


def execute(ctx: ToolContext, name: str, args: dict[str, Any]) -> ToolResult:
    fn = TOOLS.get(name)
    if fn is None:
        return ToolResult(f"Error: unknown tool {name}")
    try:
        return fn(ctx, **args)
    except (TypeError, ValueError) as exc:
        return ToolResult(f"Error: bad arguments for {name}: {exc}")
