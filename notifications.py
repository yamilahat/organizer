# notifications.py
from __future__ import annotations
import os, sys, subprocess, threading
from pathlib import Path
from typing import Optional

try:
    from win11toast import toast as _toast
except Exception:
    _toast = None

# -------------------- tiny rate limiter --------------------
_last_toasts: list[float] = []
_TOAST_LIMIT = 5        # max 5
_TOAST_WINDOW = 10.0    # per 10 seconds

def _rate_ok(now: float) -> bool:
    from time import monotonic
    global _last_toasts
    _last_toasts = [t for t in _last_toasts if now - t < _TOAST_WINDOW]
    return len(_last_toasts) < _TOAST_LIMIT

# -------------------- Explorer opener --------------------
def _open_in_explorer_select(path: str) -> None:
    """Open Explorer selecting the file (or the folder if not a file)."""
    try:
        abspath = os.path.abspath(path)
        if os.path.isfile(abspath):
            # explorer.exe /select,"C:\path\file.ext"
            subprocess.Popen(["explorer.exe", "/select,", abspath])
        else:
            subprocess.Popen(["explorer.exe", abspath])
    except Exception:
        pass

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
    """Optional user override: %LOCALAPPDATA%\Organizer\icon.png"""
    p = Path(os.environ.get("LOCALAPPDATA", ".")) / "Organizer" / "icon.png"
    return str(p) if p.exists() else None

def _resolve_icon() -> Optional[str]:
    return bundled_icon() or _user_icon()

# -------------------- public API --------------------
def send_notification(title: str, body: str, enable: bool = True, path: str | None = None) -> None:
    """
    Fire a Windows 11 toast (win11toast) with app icon.
    - Non-blocking (runs in a thread)
    - Rate-limited
    - No click handler (win11toast on_click is flaky across versions)
    """
    if not enable or _toast is None:
        return

    from time import monotonic
    now = monotonic()
    if not _rate_ok(now):
        return
    _last_toasts.append(now)

    icon = _resolve_icon()

    def _fire():
        try:
            # If you later trust on_click, uncomment the line below and pass:
            # on_click=lambda: _open_in_explorer_select(path) if path else None
            _toast(
                title,
                body,
                duration="short",
                icon=icon
            )
        except Exception:
            pass

    threading.Thread(target=_fire, daemon=True).start()
