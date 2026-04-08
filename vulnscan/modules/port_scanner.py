from __future__ import annotations

import asyncio
from urllib.parse import urlparse

import structlog

from ..core.base_scanner import BaseScanner
from ..models.enums import Severity, VulnType
from ..models.finding import Finding

logger = structlog.get_logger(__name__)

TOP_20_PORTS: list[tuple[int, str]] = [
    (21, "FTP"),
    (22, "SSH"),
    (23, "Telnet"),
    (25, "SMTP"),
    (53, "DNS"),
    (80, "HTTP"),
    (110, "POP3"),
    (135, "MSRPC"),
    (139, "NetBIOS"),
    (143, "IMAP"),
    (443, "HTTPS"),
    (445, "SMB"),
    (993, "IMAPS"),
    (995, "POP3S"),
    (1723, "PPTP"),
    (3306, "MySQL"),
    (3389, "RDP"),
    (5900, "VNC"),
    (8080, "HTTP-Alt"),
    (8443, "HTTPS-Alt"),
]

RISKY_PORTS: frozenset[int] = frozenset({21, 23, 135, 139, 445, 1723, 3306, 3389, 5900})


async def _check_port(host: str, port: int, timeout: float = 3.0) -> bool:
    """Return True if the port is open."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except (OSError, asyncio.TimeoutError):
        return False


class PortScanner(BaseScanner):
    """Async TCP port scanner for the top 20 common ports."""

    async def scan(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(url)
        host = parsed.hostname

        if not host:
            return findings

        timeout = float(self.config.get("port_timeout", 3.0))

        tasks = [
            self._scan_port(url, host, port, service, timeout)
            for port, service in TOP_20_PORTS
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Finding):
                findings.append(result)

        logger.info(
            "port_scan_complete",
            host=host,
            open_ports=len(findings),
        )
        return findings

    async def _scan_port(
        self, url: str, host: str, port: int, service: str, timeout: float
    ) -> Finding | None:
        is_open = await _check_port(host, port, timeout)
        if not is_open:
            return None

        is_risky = port in RISKY_PORTS
        severity = Severity.HIGH if is_risky else Severity.INFO

        return Finding(
            vuln_type=VulnType.OPEN_PORT,
            severity=severity,
            url=url,
            evidence=f"Port {port}/{service} is open on {host}",
            cvss_score=7.5 if is_risky else 0.0,
            cwe_id="CWE-200",
            owasp_ref="A05:2021",
            remediation=(
                f"Close port {port} ({service}) if not required, "
                "or restrict access via firewall rules."
            ),
        )
