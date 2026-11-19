"""Real-time WebSocket broadcaster + external Discord/Slack/n8n Webhook & Telegram Bot alert sender."""

import json
from typing import Any, Dict, Set
from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)

    async def broadcast(self, event_type: str, payload: Dict[str, Any]):
        if not self.active_connections:
            return
        message = json.dumps({"type": event_type, "data": payload}, default=str)
        dead = []
        for ws in list(self.active_connections):
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.active_connections.discard(ws)


ws_manager = ConnectionManager()


async def dispatch_external_alert(alert: dict, settings) -> None:
    if not settings:
        return
    try:
        import httpx
    except ImportError:
        return

    text = (
        f"[GARUDA v3 ALERT · {alert['severity'].upper()}]\n"
        f"{alert['title']}\n\n"
        f"What happened: {alert['plain_explanation']}\n"
        f"What to do: {alert['what_to_do']}"
    )

    async with httpx.AsyncClient(timeout=4.0) as client:
        if settings.webhook_url:
            try:
                await client.post(settings.webhook_url, json={"content": text, "text": text, "garuda_alert": alert})
            except Exception:
                pass
        if settings.telegram_bot_token and settings.telegram_chat_id:
            try:
                url = f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage"
                await client.post(url, json={"chat_id": settings.telegram_chat_id, "text": text})
            except Exception:
                pass
