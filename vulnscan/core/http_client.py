from __future__ import annotations

import ssl
from typing import Any

import httpx


def build_client(
    proxy_url: str | None = None,
    verify_ssl: bool = True,
    timeout: float = 10.0,
    follow_redirects: bool = True,
) -> httpx.AsyncClient:
    """
    Build a hardened httpx AsyncClient with optional proxy support.
    Never use the requests library — it blocks the event loop.
    """
    ssl_context: ssl.SSLContext | bool
    if not verify_ssl:
        ssl_context = False
    else:
        ssl_context = ssl.create_default_context()

    limits = httpx.Limits(
        max_connections=200,
        max_keepalive_connections=50,
        keepalive_expiry=30,
    )

    client_kwargs: dict[str, Any] = {
        "verify": ssl_context,
        "timeout": httpx.Timeout(timeout, connect=5.0),
        "limits": limits,
        "follow_redirects": follow_redirects,
        "http2": True,
        "headers": {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
        },
    }

    # httpx >= 0.24 uses `proxy` (singular) instead of `proxies`
    if proxy_url:
        client_kwargs["proxy"] = proxy_url

    return httpx.AsyncClient(**client_kwargs)
