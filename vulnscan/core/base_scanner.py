from __future__ import annotations

import ssl
from abc import ABC, abstractmethod
from typing import Any

import httpx
import structlog

from ..models.finding import Finding
from ..utils.url_utils import inject_param
from .http_client import build_client
from .payload_engine import PayloadEngine
from .proxy_router import ProxyRouter
from .rate_limiter import RateLimiter
from .session_manager import SessionManager

logger = structlog.get_logger(__name__)


class BaseScanner(ABC):
    """Abstract base class that all scanner modules inherit from."""

    def __init__(
        self,
        session: SessionManager,
        rate_limiter: RateLimiter,
        proxy_router: ProxyRouter,
        payload_engine: PayloadEngine,
        config: dict[str, Any] | None = None,
    ) -> None:
        self.session = session
        self.rate_limiter = rate_limiter
        self.proxy_router = proxy_router
        self.payload_engine = payload_engine
        self.config: dict[str, Any] = config or {}
        self._client: httpx.AsyncClient | None = None
        self._request_count: int = 0

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = build_client(
                proxy_url=self.proxy_router.proxy_url,
                verify_ssl=self.config.get("verify_ssl", True),
                timeout=float(self.config.get("timeout", 10)),
                follow_redirects=self.config.get("follow_redirects", True),
            )
        return self._client

    async def _request(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> httpx.Response:
        """
        Rate-limited, session-aware HTTP request with structured error logging.
        Raises httpx exceptions so callers can decide how to handle them.
        """
        await self.rate_limiter.acquire()
        client = await self._get_client()

        # Merge session headers/cookies without overriding caller-supplied values
        headers = self.session.headers.copy()
        caller_headers = kwargs.pop("headers", {})
        headers.update(caller_headers)

        # Cookies are merged into headers to avoid the per-request cookies deprecation
        merged_cookies: dict[str, str] = {}
        merged_cookies.update(self.session.cookies)
        caller_cookies: dict[str, str] = kwargs.pop("cookies", {})
        merged_cookies.update(caller_cookies)
        if merged_cookies:
            cookie_header = "; ".join(f"{k}={v}" for k, v in merged_cookies.items())
            headers.setdefault("Cookie", cookie_header)

        log = logger.bind(method=method, url=url, module=self.__class__.__name__)

        try:
            resp = await client.request(
                method,
                url,
                headers=headers,
                **kwargs,
            )
            self._request_count += 1
            log.debug("http_response", status=resp.status_code, size=len(resp.content))
            return resp
        except httpx.TimeoutException as exc:
            log.warning("request_timeout", error=str(exc))
            raise
        except httpx.ConnectError as exc:
            log.warning("connect_error", error=str(exc))
            raise
        except ssl.SSLError as exc:
            log.warning("ssl_error", error=str(exc))
            raise
        except UnicodeDecodeError as exc:
            log.warning("unicode_error", error=str(exc))
            raise

    async def _confirm_finding(self, finding: Finding) -> bool:
        """
        Re-send the exploit payload to confirm the finding is real.
        Returns True if the evidence pattern is still present.
        """
        if not finding.payload or not finding.parameter:
            return True  # cannot confirm without payload context

        try:
            # inject_param replaces the param value instead of appending it
            confirm_url = inject_param(finding.url, finding.parameter, finding.payload)
            resp = await self._request("GET", confirm_url)
            body = resp.text[:5000]
            confirmed = finding.evidence[:50] in body or finding.payload in body
            if not confirmed:
                logger.info(
                    "finding_not_confirmed",
                    finding_id=finding.id,
                    url=finding.url,
                )
            return confirmed
        except Exception:
            # If confirmation request fails, keep the finding (conservative)
            return True

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def __aenter__(self) -> "BaseScanner":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    @abstractmethod
    async def scan(self, url: str) -> list[Finding]:
        """Run the module's scan against the given URL. Must be overridden."""
        ...
