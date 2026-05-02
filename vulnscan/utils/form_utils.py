from __future__ import annotations

from urllib.parse import urljoin

from bs4 import BeautifulSoup

_SKIP_TYPES = frozenset({"submit", "button", "image", "reset", "file"})
_PASSTHROUGH_TYPES = frozenset({"hidden", "checkbox", "radio"})


def extract_forms(html: str, base_url: str) -> list[dict]:
    """
    Parse all HTML forms into dicts with keys:
      action   : absolute submission URL
      method   : "GET" or "POST"
      inputs   : {name: default_value} for ALL named fields (for CSRF tokens etc.)
      injectable: [name, ...] — fields we should inject payloads into
    """
    soup = BeautifulSoup(html, "lxml")
    forms: list[dict] = []

    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip()
        method = (form.get("method") or "get").strip().upper()
        if method not in ("GET", "POST"):
            method = "GET"
        action_url = urljoin(base_url, action) if action else base_url

        all_inputs: dict[str, str] = {}
        injectable: list[str] = []

        for tag in form.find_all(["input", "textarea", "select"]):
            name = (tag.get("name") or "").strip()
            if not name:
                continue
            tag_type = (tag.get("type") or "text").lower()
            if tag_type in _SKIP_TYPES:
                continue
            value = (tag.get("value") or "")
            all_inputs[name] = value
            if tag_type not in _PASSTHROUGH_TYPES:
                injectable.append(name)

        if injectable:
            forms.append({
                "action": action_url,
                "method": method,
                "inputs": all_inputs,
                "injectable": injectable,
            })

    return forms
