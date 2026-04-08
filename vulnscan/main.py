"""
VulnScan Pro — CLI entrypoint and scan orchestrator.

AUTHORIZED USE ONLY: This tool is for legitimate penetration testing
and security audits where explicit written permission has been obtained.
"""

from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import click
import structlog
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from .core.http_client import build_client
from .core.payload_engine import PayloadEngine
from .core.proxy_router import ProxyRouter
from .core.rate_limiter import RateLimiter
from .core.session_manager import SessionManager
from .models.enums import ScanStatus, Severity
from .models.finding import Finding
from .models.scan_result import ScanResult
from .modules.cors_checker import CORSChecker
from .modules.dir_bruteforce import DirBruteforcer
from .modules.header_analyzer import HeaderAnalyzer
from .modules.open_redirect import OpenRedirectScanner
from .modules.port_scanner import PortScanner
from .modules.sql_injection import SQLiScanner
from .modules.ssl_analyzer import SSLAnalyzer
from .modules.xss_scanner import XSSScanner
from .reporting.html_reporter import HTMLReporter
from .reporting.json_reporter import JSONReporter
from .storage.db import Database
from .utils.crawler import AsyncCrawler
from .utils.logger import configure_logging
from .utils.url_utils import get_base_url, is_valid_http_url

console = Console(stderr=True)
logger = structlog.get_logger(__name__)

SEV_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold orange1",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold green",
    Severity.INFO: "bold blue",
}

# ── Scan configuration dataclass ──────────────────────────────────────────────

class ScanConfig:
    def __init__(
        self,
        target: str,
        scan_profile: str = "quick",
        modules: list[str] | None = None,
        threads: int = 30,
        rps: float = 10.0,
        timeout: int = 10,
        depth: int = 3,
        output: str | None = None,
        fmt: str = "html",
        proxy: str | None = None,
        cookies: str | None = None,
        headers: list[str] | None = None,
        auth: str | None = None,
        ignore_ssl: bool = False,
        ignore_robots: bool = False,
        exclude: str | None = None,
        notify_slack: str | None = None,
        verbose: bool = False,
    ) -> None:
        self.target = target
        self.scan_profile = scan_profile
        self.modules = modules or []
        self.threads = min(threads, 100)
        self.rps = rps
        self.timeout = timeout
        self.depth = depth
        self.output = output
        self.fmt = fmt
        self.proxy = proxy
        self.cookies = cookies
        self.headers = headers or []
        self.auth = auth
        self.ignore_ssl = ignore_ssl
        self.ignore_robots = ignore_robots
        self.exclude = exclude
        self.notify_slack = notify_slack
        self.verbose = verbose


# ── Orchestrator ──────────────────────────────────────────────────────────────

async def run_scan(config: ScanConfig, event_cb=None) -> ScanResult:
    """
    Run a full vulnerability scan.

    Args:
        config:    Scan configuration.
        event_cb:  Optional async callback ``async def cb(event: dict) -> None``
                   called for every progress event.  Used by the web UI to
                   stream real-time updates to the browser via SSE.
    """

    async def emit(event_type: str, **kwargs: Any) -> None:
        if event_cb is not None:
            try:
                await event_cb({"type": event_type, **kwargs})
            except Exception:
                pass  # Never let telemetry crash the scan

    result = ScanResult(
        target=config.target,
        scan_profile=config.scan_profile,
        status=ScanStatus.RUNNING,
    )

    session = SessionManager(
        cookies_str=config.cookies,
        auth=config.auth,
        extra_headers=config.headers,
    )
    proxy_router = ProxyRouter(proxy_url=config.proxy, verify_ssl=not config.ignore_ssl)
    rate_limiter = RateLimiter(rps=config.rps)
    payload_engine = PayloadEngine()

    scanner_config: dict[str, Any] = {
        "verify_ssl": not config.ignore_ssl,
        "timeout": config.timeout,
        "follow_redirects": True,
    }

    def make_scanner(cls: type) -> Any:
        return cls(
            session=session,
            rate_limiter=rate_limiter,
            proxy_router=proxy_router,
            payload_engine=payload_engine,
            config=scanner_config,
        )

    all_findings: list[Finding] = []
    base_url = get_base_url(config.target)

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.fields[found]} found"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )

    with progress:

        # ── Phase 1: Recon ────────────────────────────────────────────────────
        console.print("\n[bold cyan]Phase 1 — Recon[/]\n")
        await emit("phase", name="recon", message="Phase 1 — Recon")

        ssl_task = progress.add_task("[cyan]SSL Analysis", total=1, found=0)
        await emit("module_start", module="ssl", message="SSL Analysis …")
        ssl_scanner = make_scanner(SSLAnalyzer)
        ssl_findings = await ssl_scanner.scan(config.target)
        all_findings.extend(ssl_findings)
        progress.update(ssl_task, advance=1, found=len(ssl_findings))
        result.modules_run.append("ssl")
        await emit(
            "module_done",
            module="ssl",
            findings=len(ssl_findings),
            message=f"SSL Analysis: {len(ssl_findings)} finding(s)",
        )

        hdr_task = progress.add_task("[cyan]Header Analysis", total=1, found=0)
        await emit("module_start", module="headers", message="Header Analysis …")
        hdr_scanner = make_scanner(HeaderAnalyzer)
        hdr_findings = await hdr_scanner.scan(config.target)
        all_findings.extend(hdr_findings)
        progress.update(hdr_task, advance=1, found=len(hdr_findings))
        result.modules_run.append("headers")
        await emit(
            "module_done",
            module="headers",
            findings=len(hdr_findings),
            message=f"Header Analysis: {len(hdr_findings)} finding(s)",
        )

        port_task = progress.add_task("[cyan]Port Scan", total=1, found=0)
        if config.scan_profile != "stealth":
            await emit("module_start", module="ports", message="Port Scan …")
            port_scanner = make_scanner(PortScanner)
            port_findings = await port_scanner.scan(config.target)
            all_findings.extend(port_findings)
            progress.update(port_task, advance=1, found=len(port_findings))
            result.modules_run.append("ports")
            await emit(
                "module_done",
                module="ports",
                findings=len(port_findings),
                message=f"Port Scan: {len(port_findings)} finding(s)",
            )
        else:
            progress.update(port_task, advance=1, found=0)
            await emit("module_skip", module="ports", message="Port Scan: skipped (stealth mode)")

        # Crawl target
        crawl_task = progress.add_task("[cyan]Crawler", total=1, found=0)
        await emit("module_start", module="crawl", message="Crawling target …")
        async with build_client(
            proxy_url=config.proxy,
            verify_ssl=not config.ignore_ssl,
            timeout=float(config.timeout),
        ) as http_client:
            crawler = AsyncCrawler(
                client=http_client,
                max_depth=config.depth,
                ignore_robots=config.ignore_robots,
                exclude_pattern=config.exclude,
            )
            crawl_result = await crawler.crawl(config.target)
        progress.update(crawl_task, advance=1, found=len(crawl_result.urls))
        await emit(
            "module_done",
            module="crawl",
            findings=len(crawl_result.urls),
            message=f"Crawler: {len(crawl_result.urls)} URL(s) discovered",
        )

        # ── Phase 2: Active scanning ──────────────────────────────────────────
        if config.scan_profile != "quick":
            console.print("\n[bold cyan]Phase 2 — Active Scanning[/]\n")
            await emit("phase", name="active", message="Phase 2 — Active Scanning")

            active_modules = config.modules or ["sqli", "xss", "dirs", "cors", "redirect"]

            # URLs with params → SQLi + XSS + redirect
            if crawl_result.params:
                total_urls = len(crawl_result.params)
                active_task = progress.add_task(
                    "[yellow]Active scan (URLs)", total=total_urls, found=0
                )
                await emit(
                    "module_start",
                    module="active",
                    message=f"Active scan: {total_urls} parameterised URL(s) …",
                )
                for url_with_params in crawl_result.params:
                    tasks: list[Any] = []
                    if "sqli" in active_modules:
                        tasks.append(make_scanner(SQLiScanner).scan(url_with_params))
                    if "xss" in active_modules:
                        tasks.append(make_scanner(XSSScanner).scan(url_with_params))
                    if "redirect" in active_modules:
                        tasks.append(make_scanner(OpenRedirectScanner).scan(url_with_params))

                    if tasks:
                        gathered = await asyncio.gather(*tasks, return_exceptions=True)
                        for r in gathered:
                            if isinstance(r, list):
                                all_findings.extend(r)
                    progress.update(active_task, advance=1, found=len(all_findings))

                await emit(
                    "module_done",
                    module="active",
                    findings=len(all_findings),
                    message=f"Active scan: {len(all_findings)} finding(s) so far",
                )

            # CORS check on base URL
            if "cors" in active_modules:
                cors_task = progress.add_task("[yellow]CORS Check", total=1, found=0)
                await emit("module_start", module="cors", message="CORS Misconfiguration check …")
                cors_scanner = make_scanner(CORSChecker)
                cors_findings = await cors_scanner.scan(config.target)
                all_findings.extend(cors_findings)
                progress.update(cors_task, advance=1, found=len(cors_findings))
                result.modules_run.append("cors")
                await emit(
                    "module_done",
                    module="cors",
                    findings=len(cors_findings),
                    message=f"CORS Check: {len(cors_findings)} finding(s)",
                )

            # Directory bruteforce
            if "dirs" in active_modules:
                dir_task = progress.add_task("[yellow]Dir Bruteforce", total=1, found=0)
                await emit("module_start", module="dirs", message="Directory bruteforce …")
                dir_scanner = make_scanner(DirBruteforcer)
                dir_findings = await dir_scanner.scan(base_url)
                all_findings.extend(dir_findings)
                progress.update(dir_task, advance=1, found=len(dir_findings))
                result.modules_run.append("dirs")
                await emit(
                    "module_done",
                    module="dirs",
                    findings=len(dir_findings),
                    message=f"Dir Bruteforce: {len(dir_findings)} finding(s)",
                )

        else:
            # Quick scan: just headers + SSL + top 10 dirs
            console.print("\n[bold cyan]Phase 2 — Quick Dir Check[/]\n")
            await emit("phase", name="quick_dirs", message="Phase 2 — Quick Directory Check")
            dir_task = progress.add_task("[yellow]Top Dirs", total=1, found=0)
            await emit("module_start", module="dirs", message="Top directory check …")
            dir_scanner = make_scanner(DirBruteforcer)
            dir_findings = await dir_scanner.scan(base_url)
            all_findings.extend(dir_findings)
            progress.update(dir_task, advance=1, found=len(dir_findings))
            result.modules_run.append("dirs")
            await emit(
                "module_done",
                module="dirs",
                findings=len(dir_findings),
                message=f"Dir Check: {len(dir_findings)} finding(s)",
            )

        # ── Phase 3: Dedup + FP reduction ────────────────────────────────────
        console.print("\n[bold cyan]Phase 3 — Dedup & FP Reduction[/]\n")
        await emit("phase", name="dedup", message="Phase 3 — Dedup & False-Positive Reduction")

        seen: set[tuple[str, str, str | None]] = set()
        unique_findings: list[Finding] = []
        for f in all_findings:
            key = (f.vuln_type.value, f.url, f.parameter)
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        for f in unique_findings:
            result.add_finding(f)

        result.finish(ScanStatus.DONE)

    await emit(
        "summary",
        risk_score=result.risk_score,
        severity_counts=result.severity_counts,
        duration=result.duration_seconds,
        modules=result.modules_run,
        total_findings=len(result.findings),
        message=(
            f"Scan complete — Risk {result.risk_score}/100 | "
            f"{len(result.findings)} finding(s) | "
            f"{result.duration_seconds:.1f}s"
        ),
    )

    return result


# ── Rich summary panel ────────────────────────────────────────────────────────

def _print_summary(result: ScanResult) -> None:
    sc = result.severity_counts
    score = result.risk_score
    risk_label = (
        "CRITICAL" if score >= 75
        else "HIGH" if score >= 50
        else "MEDIUM" if score >= 25
        else "LOW"
    )
    bar_filled = int(score / 10)
    bar = "█" * bar_filled + "░" * (10 - bar_filled)

    summary = Table.grid(padding=(0, 1))
    summary.add_column()
    summary.add_row(
        f"[bold cyan]VulnScan Pro[/] · {result.target} · "
        f"[dim]{result.duration_seconds:.1f}s[/]"
    )
    summary.add_row(
        f"Risk Score: [bold]{score}/100[/]  {bar}  "
        f"[{'bold red' if score >= 75 else 'bold orange1' if score >= 50 else 'bold yellow'}]{risk_label}[/]"
    )
    summary.add_row("")
    summary.add_row(
        f"[bold red]CRITICAL[/] {'█' * max(1, sc['critical'])}  {sc['critical']}    "
        f"[bold orange1]HIGH[/] {'█' * max(1, sc['high'])}  {sc['high']}    "
        f"[bold yellow]MEDIUM[/] {'█' * max(1, sc['medium'])}  {sc['medium']}    "
        f"[bold green]LOW[/] {'█' * max(1, sc['low'])}  {sc['low']}    "
        f"[bold blue]INFO[/] {'█' * max(1, sc['info'])}  {sc['info']}"
    )

    console.print()
    console.print(Panel(summary, title="Scan Complete", border_style="cyan"))


# ── Reporting helpers ─────────────────────────────────────────────────────────

def _generate_reports(result: ScanResult, config: ScanConfig) -> list[Path]:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base_name = config.output or f"report_{timestamp}"
    reports: list[Path] = []

    fmt = config.fmt
    html_reporter = HTMLReporter()
    json_reporter = JSONReporter()

    if fmt in ("html", "all"):
        p = html_reporter.generate(result, f"{base_name}.html")
        reports.append(p)
        console.print(f"[green]HTML report:[/] {p}")

    if fmt in ("json", "all"):
        p = json_reporter.generate_json(result, f"{base_name}.json")
        reports.append(p)
        console.print(f"[green]JSON report:[/] {p}")

    if fmt in ("csv", "all"):
        p = json_reporter.generate_csv(result, f"{base_name}.csv")
        reports.append(p)
        console.print(f"[green]CSV report:[/]  {p}")

    return reports


async def _notify_slack(webhook_url: str, result: ScanResult) -> None:
    """Send a Slack notification summary."""
    import httpx
    sc = result.severity_counts
    text = (
        f":shield: *VulnScan Pro* finished scanning `{result.target}`\n"
        f"Risk: *{result.risk_score}/100* | "
        f"Critical: {sc['critical']} | High: {sc['high']} | "
        f"Medium: {sc['medium']} | Low: {sc['low']}"
    )
    try:
        async with httpx.AsyncClient() as client:
            await client.post(webhook_url, json={"text": text}, timeout=10)
    except Exception as exc:
        logger.warning("slack_notify_failed", error=str(exc))


# ── Click CLI ─────────────────────────────────────────────────────────────────

@click.command()
@click.option("--web", is_flag=True, default=False,
              help="Launch the browser-based Web UI instead of CLI scanning")
@click.option("--port", default=8719, show_default=True,
              type=int, help="Port for the Web UI (used with --web)")
@click.option("--target", default=None, help="Target URL (must start with http/https)")
@click.option("--scan", "scan_profile", default="quick",
              type=click.Choice(["quick", "full", "stealth"]),
              show_default=True, help="Scan profile")
@click.option("--modules", default=None,
              help="Comma-separated: sqli,xss,headers,ssl,dirs,cors,redirect")
@click.option("--threads", default=30, show_default=True,
              type=click.IntRange(1, 100), help="Concurrent workers")
@click.option("--rps", default=10.0, show_default=True,
              type=float, help="Requests per second")
@click.option("--timeout", default=10, show_default=True,
              type=int, help="Per-request timeout (seconds)")
@click.option("--depth", default=3, show_default=True,
              type=int, help="Crawler depth")
@click.option("--output", default=None, help="Output file base path")
@click.option("--format", "fmt", default="html",
              type=click.Choice(["html", "json", "csv", "all"]),
              show_default=True, help="Report format")
@click.option("--proxy", default=None, help="Proxy URL (e.g. http://127.0.0.1:8080)")
@click.option("--cookies", default=None, help="Cookies: 'name=value; name2=value2'")
@click.option("--headers", multiple=True, help="Extra headers: 'Name: Value' (repeatable)")
@click.option("--auth", default=None, help="HTTP Basic auth: 'user:pass'")
@click.option("--ignore-ssl", is_flag=True, default=False, help="Skip SSL verification")
@click.option("--ignore-robots", is_flag=True, default=False, help="Ignore robots.txt")
@click.option("--exclude", default=None, help="Skip URLs matching this regex")
@click.option("--notify-slack", default=None, help="Slack webhook URL for alerts")
@click.option("--verbose", is_flag=True, default=False, help="Verbose output")
def cli(
    web: bool,
    port: int,
    target: str | None,
    scan_profile: str,
    modules: str | None,
    threads: int,
    rps: float,
    timeout: int,
    depth: int,
    output: str | None,
    fmt: str,
    proxy: str | None,
    cookies: str | None,
    headers: tuple[str, ...],
    auth: str | None,
    ignore_ssl: bool,
    ignore_robots: bool,
    exclude: str | None,
    notify_slack: str | None,
    verbose: bool,
) -> None:
    """
    VulnScan Pro — authorized web vulnerability scanner.

    \b
    Examples:
      vulnscan --web                                        # Launch Web UI
      vulnscan --target https://example.com                 # Quick CLI scan
      vulnscan --target https://example.com --scan full --format all
      vulnscan --target https://example.com --proxy http://127.0.0.1:8080
    """
    # ── Web UI mode ───────────────────────────────────────────────────────────
    if web:
        from .web.app import start_server
        start_server(port=port, open_browser=True)
        return

    configure_logging(verbose=verbose)

    # Validate target URL (security: reject non-http URLs)
    if not target:
        console.print(
            "[bold red]Error:[/] --target is required when not using --web\n"
            "  Run [bold]vulnscan --web[/] to use the browser UI"
        )
        sys.exit(1)

    if not is_valid_http_url(target):
        console.print(
            f"[bold red]Error:[/] Invalid target URL: {target!r}\n"
            "Target must start with http:// or https://"
        )
        sys.exit(1)

    # Stealth profile: lower RPS
    if scan_profile == "stealth" and rps == 10.0:
        rps = 1.0

    module_list = [m.strip() for m in modules.split(",")] if modules else []

    config = ScanConfig(
        target=target,
        scan_profile=scan_profile,
        modules=module_list,
        threads=threads,
        rps=rps,
        timeout=timeout,
        depth=depth,
        output=output,
        fmt=fmt,
        proxy=proxy,
        cookies=cookies,
        headers=list(headers),
        auth=auth,
        ignore_ssl=ignore_ssl,
        ignore_robots=ignore_robots,
        exclude=exclude,
        notify_slack=notify_slack,
        verbose=verbose,
    )

    console.print(
        Panel(
            f"[bold cyan]VulnScan Pro v1.0.0[/]\n"
            f"Target:  [bold]{target}[/]\n"
            f"Profile: [bold]{scan_profile}[/]  |  "
            f"RPS: {rps}  |  Threads: {threads}  |  Timeout: {timeout}s\n"
            f"[dim]For authorized security testing only.[/]",
            border_style="cyan",
        )
    )

    try:
        result = asyncio.run(_main_async(config))
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/]")
        sys.exit(130)

    _print_summary(result)
    _generate_reports(result, config)

    if notify_slack:
        asyncio.run(_notify_slack(notify_slack, result))

    # Exit code: non-zero if critical/high findings
    sc = result.severity_counts
    if sc["critical"] > 0 or sc["high"] > 0:
        sys.exit(2)


async def _main_async(config: ScanConfig) -> ScanResult:
    db = Database()
    await db.connect()
    try:
        result = await run_scan(config)
        await db.save_scan(result)
        return result
    except Exception as exc:
        logger.exception("scan_failed", error=str(exc))
        raise
    finally:
        await db.close()


if __name__ == "__main__":
    cli()
