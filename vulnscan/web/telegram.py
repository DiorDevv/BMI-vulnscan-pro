"""
Telegram notifier — contact formadan xabar kelganda @akhdior ga yuboradi.

Sozlash:
  1. @BotFather ga yozing → /newbot → token oling
  2. Botga o'zingiz xabar yuboring (yoki guruhga qo'shing)
  3. https://api.telegram.org/bot{TOKEN}/getUpdates — chat_id ni oling
  4. .env ga yoki Render environment variables ga qo'shing:
       TELEGRAM_BOT_TOKEN=1234567890:ABCdef...
       TELEGRAM_CHAT_ID=123456789
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

import httpx
import structlog

logger = structlog.get_logger(__name__)

_TG_API = "https://api.telegram.org/bot{token}/{method}"

SUBJECT_LABELS: dict[str, str] = {
    "bug":      "🐛 Bug xabari",
    "feature":  "💡 Yangi modul taklifi",
    "security": "🔒 Xavfsizlik masalasi",
    "help":     "❓ Foydalanishda yordam",
    "report":   "📊 Hisobot bilan bog'liq",
    "other":    "📌 Boshqa",
}


class TelegramNotifier:
    """
    Telegram Bot API orqali xabar yuboradi.
    Token yoki chat_id yo'q bo'lsa — jim o'tadi (enabled=False).
    """

    def __init__(
        self,
        token: str | None = None,
        chat_id: str | None = None,
    ) -> None:
        self.token   = token   or os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
        self.chat_id = chat_id or os.environ.get("TELEGRAM_CHAT_ID", "").strip()

    @property
    def enabled(self) -> bool:
        return bool(self.token and self.chat_id)

    async def notify_contact(
        self,
        *,
        name: str,
        email: str,
        subject: str,
        message: str,
        url: str | None = None,
        ip: str | None = None,
    ) -> bool:
        """
        Yangi aloqa xabari haqida Telegram ga bildirishnoma yuboradi.
        Returns True if sent successfully.
        """
        if not self.enabled:
            logger.warning(
                "telegram_disabled",
                hint="TELEGRAM_BOT_TOKEN va TELEGRAM_CHAT_ID ni o'rnating",
            )
            return False

        subject_label = SUBJECT_LABELS.get(subject, subject)
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        parts = [
            "🔔 <b>VulnScan Pro — Yangi Xabar</b>",
            "─" * 32,
            f"👤 <b>Ism:</b>   {_esc(name)}",
            f"📧 <b>Email:</b>  {_esc(email)}",
            f"📋 <b>Mavzu:</b>  {subject_label}",
        ]
        if url:
            parts.append(f"🌐 <b>URL:</b>    {_esc(url)}")
        if ip:
            parts.append(f"🌍 <b>IP:</b>     <code>{_esc(ip)}</code>")
        parts.append(f"⏰ <b>Vaqt:</b>   {timestamp}")
        parts.append("─" * 32)
        parts.append("💬 <b>Xabar:</b>")
        parts.append(_esc(message[:3000]))

        text = "\n".join(parts)
        return await self._send(text)

    async def _send(self, text: str) -> bool:
        api_url = _TG_API.format(token=self.token, method="sendMessage")
        payload = {
            "chat_id":    self.chat_id,
            "text":       text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(api_url, json=payload)
                if resp.status_code == 200:
                    logger.info("telegram_sent", chat_id=self.chat_id)
                    return True
                logger.warning(
                    "telegram_send_failed",
                    status=resp.status_code,
                    body=resp.text[:200],
                )
                return False
        except Exception as exc:
            logger.error("telegram_error", error=str(exc))
            return False


def _esc(text: str) -> str:
    """HTML maxsus belgilardan qochish (Telegram HTML mode uchun)."""
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
    )
