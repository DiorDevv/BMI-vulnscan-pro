from __future__ import annotations

import base64
from http.cookiejar import CookieJar
from typing import Any


class SessionManager:
    """Manages cookies, auth headers, and custom headers for the scan session."""

    def __init__(
        self,
        cookies_str: str | None = None,
        auth: str | None = None,
        extra_headers: list[str] | None = None,
    ) -> None:
        self._cookies: dict[str, str] = {}
        self._auth_header: str | None = None
        self._extra_headers: dict[str, str] = {}

        if cookies_str:
            self._parse_cookies(cookies_str)
        if auth:
            self._parse_auth(auth)
        if extra_headers:
            for h in extra_headers:
                self._parse_header(h)

    def _parse_cookies(self, cookies_str: str) -> None:
        for part in cookies_str.split(";"):
            part = part.strip()
            if "=" in part:
                name, _, value = part.partition("=")
                self._cookies[name.strip()] = value.strip()

    def _parse_auth(self, auth: str) -> None:
        if ":" in auth:
            encoded = base64.b64encode(auth.encode()).decode()
            self._auth_header = f"Basic {encoded}"

    def _parse_header(self, header_str: str) -> None:
        if ": " in header_str:
            name, _, value = header_str.partition(": ")
            name_stripped = name.strip()
            # Never log auth-related headers
            if name_stripped.lower() not in ("authorization", "cookie"):
                self._extra_headers[name_stripped] = value.strip()
            else:
                self._extra_headers[name_stripped] = value.strip()

    @property
    def cookies(self) -> dict[str, str]:
        return dict(self._cookies)

    @property
    def headers(self) -> dict[str, str]:
        hdrs: dict[str, str] = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
        }
        if self._auth_header:
            hdrs["Authorization"] = self._auth_header
        hdrs.update(self._extra_headers)
        return hdrs

    def merge_headers(self, extra: dict[str, str]) -> dict[str, str]:
        merged = self.headers
        merged.update(extra)
        return merged

    # Ensure credentials never appear in repr/str
    def __repr__(self) -> str:
        return f"SessionManager(cookies={list(self._cookies.keys())}, auth={'set' if self._auth_header else 'none'})"
