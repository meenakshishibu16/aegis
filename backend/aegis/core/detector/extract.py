"""Text extraction from HTML that keeps hidden content visible to the scanner."""

import re
from dataclasses import dataclass, field

from bs4 import BeautifulSoup, Comment

HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*[01](px|pt)?\b|opacity\s*:\s*0(\.0+)?\b"
    r"|color\s*:\s*(#fff(fff)?|white)\b",
    re.IGNORECASE,
)


@dataclass
class Extracted:
    full_text: str                                  # visible + hidden text (what a naive scraper sees)
    visible_text: str
    hidden_segments: list[str] = field(default_factory=list)


def _clean(text: str) -> str:
    return re.sub(r"\n\s*\n+", "\n\n", re.sub(r"[ \t]+", " ", text)).strip()


def html_to_text(html: str) -> Extracted:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style"]):
        tag.decompose()

    hidden: list[str] = []
    for comment in soup.find_all(string=lambda s: isinstance(s, Comment)):
        if comment.strip():
            hidden.append(_clean(str(comment)))
        comment.extract()

    full_text = _clean(soup.get_text("\n"))

    hidden_tags = [t for t in soup.find_all(True) if t.has_attr("hidden") or HIDDEN_STYLE.search(t.get("style", ""))]
    for tag in hidden_tags:
        text = _clean(tag.get_text(" "))
        if text:
            hidden.append(text)
    for tag in hidden_tags:
        tag.decompose()

    if hidden:
        full_text = full_text + "\n\n" + "\n".join(h for h in hidden if h not in full_text)
    return Extracted(full_text=full_text.strip(), visible_text=_clean(soup.get_text("\n")), hidden_segments=hidden)
