"""
VulnScan Pro — FastAPI Web Server.

Provides a browser UI with real-time SSE streaming of scan progress.
AUTHORIZED USE ONLY.
"""
from __future__ import annotations

import asyncio
import json
import os
import threading
import time
import uuid
import webbrowser
from pathlib import Path
from typing import Any, AsyncGenerator

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from ..main import ScanConfig, run_scan
from ..storage.db import Database
from ..utils.logger import configure_logging
from ..utils.url_utils import is_valid_http_url
from .telegram import TelegramNotifier

BASE_DIR = Path(__file__).parent

# ── In-memory scan state ──────────────────────────────────────────────────────
# scan_id → asyncio.Queue of SSE events
_active_queues: dict[str, asyncio.Queue[Any]] = {}
# scan_id → {"status": ..., "result": ..., "error": ...}
_scan_store: dict[str, dict[str, Any]] = {}

# ── Contact rate limiting (IP → list of timestamps) ──────────────────────────
_contact_timestamps: dict[str, list[float]] = {}
_CONTACT_LIMIT = 3      # max xabarlar
_CONTACT_WINDOW = 3600  # 1 soat (sekund)

# ── Telegram notifier (singleton) ────────────────────────────────────────────
_telegram = TelegramNotifier()

# ── App setup ─────────────────────────────────────────────────────────────────
app = FastAPI(
    title="VulnScan Pro",
    description="Authorized web vulnerability scanner with browser UI",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def home(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request=request, name="home.html")


@app.get("/scan", response_class=HTMLResponse)
async def scan_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request=request, name="index.html")


@app.get("/services", response_class=HTMLResponse)
async def services_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request=request, name="services.html")


@app.get("/about", response_class=HTMLResponse)
async def about_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request=request, name="about.html")


@app.get("/contact", response_class=HTMLResponse)
async def contact_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request=request, name="contact.html")


class ScanRequest(BaseModel):
    url: str
    profile: str = "quick"
    ignore_ssl: bool = False
    ignore_robots: bool = False


@app.post("/api/scan")
async def start_scan(req: ScanRequest) -> JSONResponse:
    if not is_valid_http_url(req.url):
        return JSONResponse(
            {"error": "Invalid URL — must start with http:// or https://"},
            status_code=400,
        )

    scan_id = uuid.uuid4().hex
    queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=2000)
    _active_queues[scan_id] = queue
    _scan_store[scan_id] = {
        "status": "running",
        "result": None,
        "error": None,
        "url": req.url,
        "profile": req.profile,
    }

    asyncio.create_task(
        _scan_task(scan_id, req.url, req.profile, req.ignore_ssl, req.ignore_robots)
    )
    return JSONResponse({"scan_id": scan_id})


@app.get("/api/scan/{scan_id}/stream")
async def stream_scan(scan_id: str) -> StreamingResponse:
    """SSE endpoint — streams real-time scan events to the browser."""

    # If scan is already done, replay the final event immediately
    state = _scan_store.get(scan_id)
    if state and state["status"] == "done":
        async def _replay() -> AsyncGenerator[str, None]:
            payload = json.dumps({"type": "done", "result": state["result"]}, default=str)
            yield f"data: {payload}\n\n"
            yield 'data: {"type":"stream_end"}\n\n'
        return StreamingResponse(_replay(), media_type="text/event-stream")

    if scan_id not in _active_queues:
        async def _not_found() -> AsyncGenerator[str, None]:
            yield 'data: {"type":"error","message":"Scan not found"}\n\n'
        return StreamingResponse(_not_found(), media_type="text/event-stream")

    queue = _active_queues[scan_id]

    async def _event_stream() -> AsyncGenerator[str, None]:
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=25.0)
            except asyncio.TimeoutError:
                yield 'data: {"type":"ping"}\n\n'
                continue

            if event is None:  # sentinel — scan finished
                yield 'data: {"type":"stream_end"}\n\n'
                break

            yield f"data: {json.dumps(event, default=str)}\n\n"

    return StreamingResponse(
        _event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/scan/{scan_id}")
async def get_scan_status(scan_id: str) -> JSONResponse:
    if scan_id in _scan_store:
        return JSONResponse(_scan_store[scan_id])
    return JSONResponse({"error": "Not found"}, status_code=404)


@app.get("/api/history")
async def scan_history() -> JSONResponse:
    """Return the last 20 scans from the database."""
    db = Database()
    await db.connect()
    try:
        rows = await db.list_recent_scans(limit=20)
        return JSONResponse({"scans": rows})
    finally:
        await db.close()


class ContactRequest(BaseModel):
    name: str
    email: str
    subject: str
    message: str
    url: str | None = None


@app.post("/api/contact")
async def send_contact(req: ContactRequest, request: Request) -> JSONResponse:
    # ── Validatsiya ──────────────────────────────────────────────────────────
    if len(req.name.strip()) < 2:
        return JSONResponse({"error": "Ism kamida 2 harf bo'lishi kerak"}, status_code=422)
    if "@" not in req.email or "." not in req.email.split("@")[-1]:
        return JSONResponse({"error": "Email manzil noto'g'ri"}, status_code=422)
    if req.subject not in ("bug", "feature", "security", "help", "report", "other"):
        return JSONResponse({"error": "Noto'g'ri mavzu"}, status_code=422)
    if len(req.message.strip()) < 20:
        return JSONResponse({"error": "Xabar kamida 20 belgi bo'lishi kerak"}, status_code=422)

    # ── Rate limit (IP bo'yicha) ─────────────────────────────────────────────
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    timestamps = _contact_timestamps.get(client_ip, [])
    # Eski yozuvlarni tozalash
    timestamps = [t for t in timestamps if now - t < _CONTACT_WINDOW]
    if len(timestamps) >= _CONTACT_LIMIT:
        wait = int(_CONTACT_WINDOW - (now - timestamps[0]))
        return JSONResponse(
            {"error": f"Juda ko'p urinish. {wait // 60} daqiqadan so'ng qayta urinib ko'ring."},
            status_code=429,
        )
    timestamps.append(now)
    _contact_timestamps[client_ip] = timestamps

    # ── Telegram bildirishnoma ───────────────────────────────────────────────
    sent = await _telegram.notify_contact(
        name=req.name.strip(),
        email=req.email.strip(),
        subject=req.subject,
        message=req.message.strip(),
        url=req.url.strip() if req.url else None,
        ip=client_ip,
    )

    return JSONResponse({
        "ok": True,
        "telegram": sent,
        "message": "Xabaringiz muvaffaqiyatli yuborildi!",
    })


@app.get("/health")
async def health_check() -> JSONResponse:
    """Health check endpoint — used by Render and UptimeRobot to keep the service alive."""
    return JSONResponse({"status": "ok", "service": "VulnScan Pro"})


# ── Background scan task ──────────────────────────────────────────────────────

async def _scan_task(
    scan_id: str,
    url: str,
    profile: str,
    ignore_ssl: bool,
    ignore_robots: bool,
) -> None:
    queue = _active_queues[scan_id]

    async def emit(event: dict[str, Any]) -> None:
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            pass  # Drop if full — non-critical

    config = ScanConfig(
        target=url,
        scan_profile=profile,
        ignore_ssl=ignore_ssl,
        ignore_robots=ignore_robots,
    )

    db = Database()
    await db.connect()
    try:
        result = await run_scan(config, event_cb=emit)
        await db.save_scan(result)

        result_dict = result.model_dump(mode="json")
        _scan_store[scan_id].update({"status": "done", "result": result_dict})
        await emit({"type": "done", "result": result_dict})

    except Exception as exc:
        err_msg = str(exc)
        _scan_store[scan_id].update({"status": "failed", "error": err_msg})
        await emit({"type": "error", "message": err_msg})

    finally:
        await db.close()
        # Sentinel — tells the SSE generator to stop
        try:
            queue.put_nowait(None)
        except asyncio.QueueFull:
            pass
        # Clean up queue after a short delay
        await asyncio.sleep(60)
        _active_queues.pop(scan_id, None)


# ── Server launcher ───────────────────────────────────────────────────────────

def start_server(
    host: str = "0.0.0.0",
    port: int | None = None,
    open_browser: bool = True,
) -> None:
    """Start uvicorn and (optionally) open the browser."""
    configure_logging(verbose=False)

    # Render (and other cloud platforms) set PORT env variable
    resolved_port = port or int(os.environ.get("PORT", 8719))

    if open_browser:
        def _opener() -> None:
            time.sleep(1.5)  # Brief wait for the server to bind
            webbrowser.open(f"http://127.0.0.1:{resolved_port}")

        threading.Thread(target=_opener, daemon=True).start()

    print(f"\n  VulnScan Pro Web UI  →  http://{host}:{resolved_port}\n")
    uvicorn.run(
        app,
        host=host,
        port=resolved_port,
        log_level="warning",
        access_log=False,
    )
