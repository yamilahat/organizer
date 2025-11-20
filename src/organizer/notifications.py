# notifications.py
from __future__ import annotations
import os, sys, subprocess, threading
from pathlib import Path
from typing import Optional
from collections import deque

try:
    from win11toast import toast as _toast
except Exception:
    _toast = None

# -------------------- tiny rate limiter --------------------
_last_toasts: list[float] = []
_TOAST_LIMIT = 5        # max 5
_TOAST_WINDOW = 10.0    # per 10 seconds

# -------------------- move aggregator --------------------
_pending_moves: deque[tuple[str, str]] = deque()  # (src, dest)
_flush_timer: threading.Timer | None = None
_AGGREGATE_WINDOW = 1.2  # seconds
_pending_lock = threading.Lock()

def _rate_ok(now: float) -> bool:
    from time import monotonic
    global _last_toasts
    _last_toasts = [t for t in _last_toasts if now - t < _TOAST_WINDOW]
    return len(_last_toasts) < _TOAST_LIMIT

# -------------------- resource helpers --------------------
def resource_path(rel: str) -> str:
    """Resolve resource path (dev + PyInstaller)."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return str((base / rel).resolve())

def bundled_icon() -> Optional[str]:
    """Prefer bundled icon: assets/icon.png (in repo or bundled)."""
    p = Path(resource_path("assets/icon.png"))
    return str(p) if p.exists() else None

def _user_icon() -> Optional[str]:
    p = Path(os.environ.get("LOCALAPPDATA", ".")) / "Organizer" / "icon.png"
    return str(p) if p.exists() else None

def _resolve_icon() -> Optional[str]:
    return bundled_icon() or _user_icon()

def _open_in_explorer(target: str | None) -> None:
    try:
        if not target:
            return
        p = Path(target)
        if p.is_file():
            subprocess.Popen(["explorer", "/select,", str(p)])
        else:
            subprocess.Popen(["explorer", str(p)])
    except Exception:
        pass

# -------------------- public API --------------------
def send_notification(title: str, body: str, enable: bool = True, path: str | None = None) -> None:
    """
    Fire a Windows 11 toast (win11toast) with app icon.
    - Non-blocking (runs in a thread)
    - Rate-limited
    - Click opens the destination in Explorer when available
    """
    if not enable or _toast is None:
        return

    from time import monotonic
    now = monotonic()
    if not _rate_ok(now):
        return
    _last_toasts.append(now)

    icon = _resolve_icon()
    click_handler = (lambda: _open_in_explorer(path)) if path else None

    def _fire():
        try:
            _toast(
                title,
                body,
                duration="short",
                icon=icon,
                on_click=click_handler,
            )
        except Exception:
            pass

    threading.Thread(target=_fire, daemon=True).start()


def send_move_notice(src: str, dest: str, enable: bool = True) -> None:
    """
    Aggregate move notifications to avoid toast spam.
    Flushes after a short window; click opens the first destination folder.
    """
    if not enable:
        return
    with _pending_lock:
        _pending_moves.append((src, dest))
        global _flush_timer
        if _flush_timer is None:
            _flush_timer = threading.Timer(_AGGREGATE_WINDOW, _flush_moves, kwargs={"enable": enable})
            _flush_timer.daemon = True
            _flush_timer.start()


def _flush_moves(enable: bool = True) -> None:
    global _flush_timer
    with _pending_lock:
        batch = list(_pending_moves)
        _pending_moves.clear()
        _flush_timer = None
    if not batch:
        return
    if len(batch) == 1:
        src, dest = batch[0]
        send_notification("Organizer", f"Moved {Path(src).name} to {dest}", enable=enable, path=dest)
        return
    count = len(batch)
    names = [Path(item[0]).name for item in batch[:3]]
    if count > 3:
        names.append("...")
    summary = ", ".join(names)
    first_dest = batch[0][1]
    send_notification("Organizer", f"Moved {count} files \u00b7 {summary}", enable=enable, path=first_dest)
