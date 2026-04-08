from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs, urlencode


# Extensions to skip during crawling
SKIP_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico",
        ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".pdf", ".zip", ".tar", ".gz", ".mp4", ".mp3",
        ".webp", ".avif",
    }
)


def normalize_url(url: str, base: str | None = None) -> str | None:
    """
    Normalize a URL: resolve relative URLs against base, drop fragments,
    ensure scheme is http or https.
    Returns None if the URL should be skipped.
    """
    if base:
        url = urljoin(base, url)

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        return None

    # Drop fragment
    normalized = urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        parsed.query,
        "",  # no fragment
    ))

    # Skip binary/static assets
    path_lower = parsed.path.lower()
    for ext in SKIP_EXTENSIONS:
        if path_lower.endswith(ext):
            return None

    return normalized


def same_origin(url_a: str, url_b: str) -> bool:
    """Return True if both URLs share the same scheme+host+port."""
    a, b = urlparse(url_a), urlparse(url_b)
    return a.scheme == b.scheme and a.netloc == b.netloc


def extract_params(url: str) -> dict[str, list[str]]:
    """Return query-string parameters as {name: [value, ...]}."""
    parsed = urlparse(url)
    return parse_qs(parsed.query, keep_blank_values=True)


def inject_param(url: str, param: str, value: str) -> str:
    """Return a new URL with `param` set to `value` in the query string."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    new_query = urlencode(params, doseq=True)
    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        "",
    ))


def is_valid_http_url(url: str) -> bool:
    """Validate that a URL is a safe, well-formed http/https URL."""
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def get_base_url(url: str) -> str:
    """Return scheme://host (no path/query)."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"
