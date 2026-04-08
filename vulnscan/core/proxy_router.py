from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class ProxyRouter:
    """Manages proxy configuration for Burp Suite / SOCKS5 proxies."""

    proxy_url: str | None = None
    verify_ssl: bool = True
    _proxies: dict[str, str] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.proxy_url:
            self._validate_proxy_url(self.proxy_url)
            self._proxies = {
                "http://": self.proxy_url,
                "https://": self.proxy_url,
            }

    @staticmethod
    def _validate_proxy_url(url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https", "socks5", "socks4"):
            raise ValueError(f"Unsupported proxy scheme: {parsed.scheme!r}")
        if not parsed.hostname:
            raise ValueError(f"Invalid proxy URL (no hostname): {url!r}")

    @property
    def httpx_proxies(self) -> dict[str, str] | None:
        return self._proxies if self._proxies else None

    @property
    def is_configured(self) -> bool:
        return bool(self.proxy_url)
