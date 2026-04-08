from __future__ import annotations

import asyncio
import re
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx
import structlog
from bs4 import BeautifulSoup

from .url_utils import normalize_url, same_origin

logger = structlog.get_logger(__name__)

ROBOTS_DISALLOW_RE = re.compile(r"^Disallow:\s*(.+)$", re.MULTILINE)

MAX_URLS = 500


@dataclass
class FormInput:
    name: str
    input_type: str = "text"
    value: str = ""


@dataclass
class Form:
    action: str
    method: str
    inputs: list[FormInput] = field(default_factory=list)


@dataclass
class CrawlResult:
    urls: set[str] = field(default_factory=set)
    forms: list[Form] = field(default_factory=list)
    params: dict[str, list[str]] = field(default_factory=dict)  # url → list of param names


class AsyncCrawler:
    """BFS async crawler, same-origin only, depth ≤ 3, max 500 URLs."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        max_depth: int = 3,
        ignore_robots: bool = False,
        exclude_pattern: str | None = None,
    ) -> None:
        self._client = client
        self._max_depth = max_depth
        self._ignore_robots = ignore_robots
        self._exclude_re = re.compile(exclude_pattern) if exclude_pattern else None
        self._disallowed: list[str] = []

    async def _fetch_robots(self, base_url: str) -> None:
        robots_url = urljoin(base_url, "/robots.txt")
        try:
            resp = await self._client.get(robots_url, timeout=5)
            if resp.status_code == 200:
                for match in ROBOTS_DISALLOW_RE.finditer(resp.text):
                    self._disallowed.append(match.group(1).strip())
        except Exception:
            pass  # robots.txt is optional

    def _is_allowed(self, url: str) -> bool:
        if self._ignore_robots:
            return True
        parsed = urlparse(url)
        path = parsed.path
        for disallowed in self._disallowed:
            if path.startswith(disallowed):
                return False
        return True

    def _is_excluded(self, url: str) -> bool:
        if self._exclude_re and self._exclude_re.search(url):
            return True
        return False

    def _extract_links(self, html: str, base_url: str, origin: str) -> list[str]:
        soup = BeautifulSoup(html, "lxml")
        links: list[str] = []
        for tag in soup.find_all(["a", "link"], href=True):
            href = tag.get("href", "")
            if isinstance(href, list):
                href = href[0] if href else ""
            normalized = normalize_url(str(href), base=base_url)
            if normalized and same_origin(normalized, origin):
                links.append(normalized)
        # Also check script src for JS files that may add forms
        for tag in soup.find_all("script", src=True):
            src = tag.get("src", "")
            if isinstance(src, list):
                src = src[0] if src else ""
            normalized = normalize_url(str(src), base=base_url)
            if normalized and same_origin(normalized, origin):
                links.append(normalized)
        return links

    def _extract_forms(self, html: str, base_url: str) -> list[Form]:
        soup = BeautifulSoup(html, "lxml")
        forms: list[Form] = []
        for form_tag in soup.find_all("form"):
            action = form_tag.get("action", base_url)
            if isinstance(action, list):
                action = action[0] if action else base_url
            action = urljoin(base_url, str(action))
            method = str(form_tag.get("method", "GET")).upper()
            inputs: list[FormInput] = []
            for inp in form_tag.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                if isinstance(name, list):
                    name = name[0] if name else ""
                inp_type = inp.get("type", "text")
                if isinstance(inp_type, list):
                    inp_type = inp_type[0] if inp_type else "text"
                value = inp.get("value", "")
                if isinstance(value, list):
                    value = value[0] if value else ""
                inputs.append(FormInput(name=str(name), input_type=str(inp_type), value=str(value)))
            forms.append(Form(action=action, method=method, inputs=inputs))
        return forms

    def _extract_query_params(self, url: str) -> list[str]:
        parsed = urlparse(url)
        if not parsed.query:
            return []
        params: list[str] = []
        for part in parsed.query.split("&"):
            if "=" in part:
                params.append(part.split("=", 1)[0])
        return params

    async def crawl(self, start_url: str) -> CrawlResult:
        result = CrawlResult()
        origin = start_url

        if not self._ignore_robots:
            await self._fetch_robots(start_url)

        # BFS queue: (url, depth)
        queue: deque[tuple[str, int]] = deque([(start_url, 0)])
        visited: set[str] = set()

        while queue and len(result.urls) < MAX_URLS:
            url, depth = queue.popleft()

            if url in visited:
                continue
            if not self._is_allowed(url):
                continue
            if self._is_excluded(url):
                continue

            visited.add(url)

            try:
                resp = await self._client.get(url, timeout=10)
                if resp.status_code not in (200, 301, 302, 403):
                    continue

                content_type = resp.headers.get("content-type", "")
                if "html" not in content_type and "text" not in content_type:
                    continue

                result.urls.add(url)

                # Extract query params
                qparams = self._extract_query_params(url)
                if qparams:
                    result.params[url] = qparams

                if depth < self._max_depth:
                    links = self._extract_links(resp.text, url, origin)
                    for link in links:
                        if link not in visited and len(result.urls) < MAX_URLS:
                            queue.append((link, depth + 1))

                forms = self._extract_forms(resp.text, url)
                result.forms.extend(forms)

            except Exception as exc:
                logger.warning("crawl_error", url=url, error=str(exc))

        logger.info(
            "crawl_complete",
            start=start_url,
            urls_found=len(result.urls),
            forms_found=len(result.forms),
        )
        return result
