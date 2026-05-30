from __future__ import annotations

try:
    from flask_socketio import SocketIO
except Exception:  # pragma: no cover - optional dependency until installed
    SocketIO = None


socketio = SocketIO(cors_allowed_origins="*", async_mode="threading") if SocketIO else None


def emit_event(event: str, payload: dict) -> None:
    if socketio:
        socketio.emit(event, payload)
