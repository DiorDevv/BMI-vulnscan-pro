"""Async crawler tests."""
from __future__ import annotations

import pytest
import httpx
import respx

from vulnscan.utils.crawler import AsyncCrawler


HOME_HTML = """
<html>
<body>
  <a href="/about">About</a>
  <a href="/products?id=1">Products</a>
  <a href="https://external.com/link">External</a>
  <form action="/search" method="GET">
    <input name="q" type="text">
    <input name="category" type="hidden" value="all">
  </form>
</body>
</html>
"""

ABOUT_HTML = """
<html>
<body>
  <a href="/contact">Contact</a>
</body>
</html>
"""


@pytest.mark.asyncio
async def test_crawl_discovers_links() -> None:
    """Crawler must discover same-origin links."""
    with respx.MockRouter(assert_all_called=False) as mock:
        mock.get("http://crawltest.local/").mock(
            return_value=httpx.Response(200, text=HOME_HTML,
                                         headers={"content-type": "text/html"})
        )
        mock.get("http://crawltest.local/about").mock(
            return_value=httpx.Response(200, text=ABOUT_HTML,
                                         headers={"content-type": "text/html"})
        )
        mock.get("http://crawltest.local/products").mock(
            return_value=httpx.Response(200, text="<html>products</html>",
                                         headers={"content-type": "text/html"})
        )
        mock.get("http://crawltest.local/contact").mock(
            return_value=httpx.Response(200, text="<html>contact</html>",
                                         headers={"content-type": "text/html"})
        )
        mock.get("http://crawltest.local/robots.txt").mock(
            return_value=httpx.Response(404, text="")
        )

        async with httpx.AsyncClient(follow_redirects=True) as client:
            crawler = AsyncCrawler(client=client, max_depth=2, ignore_robots=True)
            result = await crawler.crawl("http://crawltest.local/")

    assert "http://crawltest.local/" in result.urls
    assert "http://crawltest.local/about" in result.urls
    # External links must NOT be included
    assert "https://external.com/link" not in result.urls


@pytest.mark.asyncio
async def test_crawl_extracts_forms() -> None:
    """Crawler must extract form fields."""
    with respx.MockRouter(assert_all_called=False) as mock:
        mock.get("http://formtest.local/").mock(
            return_value=httpx.Response(200, text=HOME_HTML,
                                         headers={"content-type": "text/html"})
        )
        mock.get("http://formtest.local/robots.txt").mock(
            return_value=httpx.Response(404, text="")
        )

        async with httpx.AsyncClient(follow_redirects=True) as client:
            crawler = AsyncCrawler(client=client, ignore_robots=True)
            result = await crawler.crawl("http://formtest.local/")

    assert len(result.forms) >= 1
    form = result.forms[0]
    input_names = [i.name for i in form.inputs]
    assert "q" in input_names


@pytest.mark.asyncio
async def test_crawl_extracts_query_params() -> None:
    """Crawler must extract query parameter names from discovered URLs."""
    with respx.MockRouter(assert_all_called=False) as mock:
        mock.get("http://paramtest.local/").mock(
            return_value=httpx.Response(200, text=HOME_HTML,
                                         headers={"content-type": "text/html"})
        )
        mock.get("http://paramtest.local/products").mock(
            return_value=httpx.Response(200, text="<html>products</html>",
                                         headers={"content-type": "text/html"})
        )
        mock.get("http://paramtest.local/robots.txt").mock(
            return_value=httpx.Response(404, text="")
        )

        async with httpx.AsyncClient(follow_redirects=True) as client:
            crawler = AsyncCrawler(client=client, ignore_robots=True)
            result = await crawler.crawl("http://paramtest.local/")

    # /products?id=1 should have 'id' as a param
    param_urls = {url: params for url, params in result.params.items()}
    product_params = next(
        (params for url, params in param_urls.items() if "products" in url),
        None,
    )
    assert product_params is not None
    assert "id" in product_params


@pytest.mark.asyncio
async def test_crawl_respects_max_depth() -> None:
    """Crawler must stop at max_depth=1."""
    level0 = '<html><a href="/level1">L1</a></html>'
    level1 = '<html><a href="/level2">L2</a></html>'
    level2 = '<html><p>deep</p></html>'

    with respx.MockRouter(assert_all_called=False) as mock:
        mock.get("http://depthtest.local/").mock(
            return_value=httpx.Response(200, text=level0,
                                         headers={"content-type": "text/html"})
        )
        mock.get("http://depthtest.local/level1").mock(
            return_value=httpx.Response(200, text=level1,
                                         headers={"content-type": "text/html"})
        )
        mock.get("http://depthtest.local/level2").mock(
            return_value=httpx.Response(200, text=level2,
                                         headers={"content-type": "text/html"})
        )
        mock.get("http://depthtest.local/robots.txt").mock(
            return_value=httpx.Response(404, text="")
        )

        async with httpx.AsyncClient(follow_redirects=True) as client:
            crawler = AsyncCrawler(client=client, max_depth=1, ignore_robots=True)
            result = await crawler.crawl("http://depthtest.local/")

    assert "http://depthtest.local/" in result.urls
    assert "http://depthtest.local/level1" in result.urls
    assert "http://depthtest.local/level2" not in result.urls
