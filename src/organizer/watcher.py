import argparse
import atexit
import ctypes
import ctypes.wintypes as wt
import json
import os
import shutil
import sys
import threading
import time
import traceback
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from queue import Empty, Queue
from subprocess import run
from typing import Callable

from loguru import logger
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from organizer.notifications import send_move_notice, send_notification
from organizer.planner import TEMP_SUFFIXES, decide_action

DEFAULT_BUCKETS = {
    "archives": "archives",
    "installers": "installers",
    "docs": "docs",
    "images": "images",
}

POLL_INTERVAL = 0.5
STABILIZE_SECONDS = 3.0
JOURNAL_PATH = os.path.join(
    os.environ.get("LOCALAPPDATA", "."), "Organizer", "journal.ndjson"
)
SESSION_ID = str(uuid.uuid4())
VERSION = "0.1.0"
CONFIG: dict | None = None

FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4
FILE_ATTRIBUTE_INVALID = 0xFFFFFFFF
LARGE_MB = 500
MIN_FREE_MB = 200
SHUTDOWN_SENTINEL = object()

_GetFileAttributesW = ctypes.windll.kernel32.GetFileAttributesW
_GetFileAttributesW.argtypes = [wt.LPCWSTR]
_GetFileAttributesW.restype = wt.DWORD


@dataclass(slots=True)
class FileState:
    last_size: int
    last_seen_ts: float


class WatchHandler(FileSystemEventHandler):
    def __init__(self, tracked_files: dict[str, FileState], lock: threading.Lock):
        self._tracked_files = tracked_files
        self._lock = lock

    def on_created(self, event) -> None:
        if event.is_directory:
            return
        self._track_path(event.src_path)

    def on_moved(self, event) -> None:
        if event.is_directory:
            return

        now = time.monotonic()
        src = normalize_path(event.src_path)
        dest = normalize_path(event.dest_path)
        with self._lock:
            state = self._tracked_files.pop(src, FileState(last_size=-1, last_seen_ts=now))
            self._tracked_files[dest] = FileState(state.last_size, now)
        logger.debug(f"moved {src} -> {dest}")

    def _track_path(self, path: str) -> None:
        normalized = normalize_path(path)
        with self._lock:
            self._tracked_files.setdefault(
                normalized,
                FileState(last_size=-1, last_seen_ts=time.monotonic()),
            )
        logger.debug(f"tracking {normalized}")


class MoveWorker:
    def __init__(self, dry_run: bool, notify: bool):
        self._dry_run = dry_run
        self._notify = notify
        self._queue: Queue[tuple[str, str] | object] = Queue()
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._run, name="organizer-move-worker", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def submit(self, src: str, dest: str) -> None:
        self._queue.put((src, dest))

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        self._queue.put(SHUTDOWN_SENTINEL)
        self._thread.join(timeout=timeout)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                item = self._queue.get(timeout=POLL_INTERVAL)
            except Empty:
                continue

            try:
                if item is SHUTDOWN_SENTINEL:
                    return

                src, abs_dest = item
                ok = execute("move", src, abs_dest, dry_run=self._dry_run)
                if ok:
                    logger.success(f"executed: {src} -> {abs_dest}")
                    journal("executed", src=src, dest=abs_dest, op="move", reason="ok")
                    send_move_notice(src, abs_dest, enable=self._notify)
                else:
                    logger.error(f"failed: {src} -> {abs_dest}")
                    journal(
                        "failed",
                        src=src,
                        dest=abs_dest,
                        op="move",
                        reason="executed_failed",
                    )
                    send_notification(
                        "Organizer - Move failed",
                        f"Failed to move {os.path.basename(src)}",
                        enable=self._notify,
                        path=src,
                    )
            finally:
                self._queue.task_done()


def normalize_path(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


def is_hidden_or_system(path: str) -> bool:
    try:
        attrs = _GetFileAttributesW(path)
        return attrs != FILE_ATTRIBUTE_INVALID and bool(
            attrs & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)
        )
    except Exception:
        return False


def under_root(path: str, root: str) -> bool:
    try:
        return Path(path).resolve().is_relative_to(Path(root).resolve())
    except AttributeError:
        resolved_path = Path(path).resolve()
        resolved_root = Path(root).resolve()
        return str(resolved_path).startswith(str(resolved_root))


def dest_has_space(dest_dir: str, size_bytes: int) -> bool:
    try:
        free = shutil.disk_usage(dest_dir).free
    except Exception:
        return True
    return free >= max(MIN_FREE_MB * 1024**2, size_bytes)


def configure_logger(verbose: bool) -> None:
    logger.remove()
    fmt = (
        "<green>{time:HH:mm:ss}</green> | <level>{level: <7}</level> | "
        "{name}:{function}:{line} | {message}"
        if verbose
        else "<green>{time:HH:mm:ss}</green> | <level>{level}</level> | {message}"
    )
    logger.add(
        sys.stderr,
        level="DEBUG" if verbose else "INFO",
        backtrace=verbose,
        diagnose=verbose,
        format=fmt,
    )
    logger.info("logger ready")


def _default_dest_dirs() -> dict[str, str]:
    here = Path(__file__).resolve()
    repo_root = here.parent.parent.parent
    demo_root = repo_root / "demo"
    downloads = Path.home() / "Downloads"

    dests: dict[str, str] = {}
    for category, folder in DEFAULT_BUCKETS.items():
        demo_candidate = demo_root / folder
        if demo_candidate.exists():
            dests[category] = str(demo_candidate.resolve())
            continue

        fallback = downloads / folder.capitalize()
        fallback.mkdir(parents=True, exist_ok=True)
        dests[category] = str(fallback.resolve())
    return dests


def load_config(config_path: str | None = None) -> dict:
    defaults = {"dest_dirs": _default_dest_dirs(), "rules": []}
    path = config_path or os.path.join(
        os.environ.get("LOCALAPPDATA", "."), "Organizer", "config.json"
    )

    try:
        with open(path, "r", encoding="utf-8") as file:
            cfg = json.load(file)
    except FileNotFoundError:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as file:
            json.dump(defaults, file, indent=2)
        cfg = defaults

    dest_dirs = {
        category: normalize_path(folder)
        for category, folder in cfg.get("dest_dirs", {}).items()
    }
    rules = cfg.get("rules", [])
    return {"path": path, "dest_dirs": dest_dirs, "rules": rules}


def journal(event: str, **fields) -> None:
    record = {
        "ts_iso": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "pid": os.getpid(),
        "session_id": SESSION_ID,
        "version": VERSION,
        **fields,
    }
    try:
        os.makedirs(os.path.dirname(JOURNAL_PATH), exist_ok=True)
        with open(JOURNAL_PATH, "a", encoding="utf-8", newline="\n") as file:
            file.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception as exc:
        logger.warning(f"journal failed: {exc}")
    else:
        maybe_rotate_journal()


def maybe_rotate_journal(max_bytes: int = 10_000_000) -> None:
    try:
        if os.path.exists(JOURNAL_PATH) and os.path.getsize(JOURNAL_PATH) > max_bytes:
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            base = os.path.splitext(JOURNAL_PATH)[0]
            os.replace(JOURNAL_PATH, f"{base}-{ts}.ndjson")
    except Exception as exc:
        logger.warning(f"journal rotate failed: {exc}")


def extract_args(argv) -> tuple[str, bool, bool, bool]:
    parser = argparse.ArgumentParser(
        prog="organizer", description="Downloads organizer (MVP)"
    )
    parser.add_argument("--watch", help="Directory to watch", required=True)
    parser.add_argument("--dry-run", action="store_true", help="Plan actions only")
    parser.add_argument(
        "--verbose", action="store_true", help="Enable DEBUG logs and diagnostics"
    )
    parser.add_argument(
        "--notify",
        action="store_true",
        help="Show a Windows toast when a file is moved",
    )
    args = parser.parse_args(argv)
    return (args.watch, args.dry_run, args.verbose, args.notify)


def run_stabilizer(
    curr_files: dict[str, FileState],
    lock: threading.Lock,
    on_finalize: Callable[[str, str], tuple[str, str | None, str]],
    stop_event: threading.Event,
    root: str,
) -> None:
    while not stop_event.is_set():
        now = time.monotonic()
        with lock:
            snapshot = list(curr_files.items())

        to_update: list[tuple[str, FileState]] = []
        to_finalize: list[str] = []
        to_drop: list[str] = []

        for file_path, file_state in snapshot:
            if file_path.lower().endswith(TEMP_SUFFIXES):
                continue

            try:
                curr_size = os.path.getsize(file_path)
            except FileNotFoundError:
                to_drop.append(file_path)
                continue
            except PermissionError:
                logger.debug(f"permission error while probing {file_path}")
                continue

            if curr_size != file_state.last_size:
                to_update.append((file_path, FileState(curr_size, now)))
                continue

            if now - file_state.last_seen_ts >= STABILIZE_SECONDS:
                to_finalize.append(file_path)

        with lock:
            for path in to_drop:
                curr_files.pop(path, None)
            for path, new_state in to_update:
                curr_files[path] = new_state
            for path in to_finalize:
                curr_files.pop(path, None)

        for path in to_finalize:
            logger.info(f"finalized {path}")
            on_finalize(path, root)

        stop_event.wait(POLL_INTERVAL)


def on_finalize_cb(path: str, root: str, move_worker: MoveWorker):
    if CONFIG is None:
        raise RuntimeError("watcher configuration was not loaded")

    if is_hidden_or_system(path) or Path(path).name.startswith("."):
        journal("skip", src=path, reason="guard:hidden_or_system")
        return ("skip", None, "guard:hidden_or_system")

    if not under_root(path, root):
        journal("skip", src=path, reason="guard:outside_root")
        return ("skip", None, "guard:outside_root")

    op, category, base, reason = decide_action(path, CONFIG.get("rules", []))
    if op == "skip":
        logger.info(f"planned skip: {path} ({reason})")
        return (op, base, reason)

    if op != "move":
        logger.error(f"unknown operation: {op}")
        return ("skip", None, f"unknown operation: {op}")

    dst_dir = CONFIG["dest_dirs"].get(category)
    if not dst_dir:
        logger.warning(f"skip: category {category} not configured for {path}")
        journal("skip", src=path, reason=f"unconfigured_category:{category}")
        return ("skip", None, f"unconfigured_category:{category}")

    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0

    if size >= LARGE_MB * 1024**2 and not dest_has_space(dst_dir, size):
        journal(
            "skip",
            src=path,
            dest=dst_dir,
            reason="guard_low_free_space",
            extra={"size": size},
        )
        return ("skip", None, "guard_low_free_space")

    abs_dest = os.path.join(dst_dir, base)
    logger.info(f"planned move: {path} -> {abs_dest} ({reason})")
    journal(
        "planned",
        src=path,
        dest=abs_dest,
        op=op,
        reason=reason,
        category=category,
    )
    move_worker.submit(path, abs_dest)
    return (op, abs_dest, reason)


def next_available(path: str) -> str:
    if not os.path.exists(path):
        return path

    base, ext = os.path.splitext(path)
    suffix = 2
    while True:
        candidate = f"{base} ({suffix}){ext}"
        if not os.path.exists(candidate):
            return candidate
        suffix += 1


def execute(
    op: str,
    src: str,
    dst: str,
    *,
    dry_run: bool,
    retries: int = 3,
    backoff_ms: int = 200,
) -> bool:
    if op != "move":
        logger.error(f"unsupported operation: {op}")
        return False

    final = next_available(dst)
    if dry_run:
        logger.info(f"DRY-RUN move: {src} -> {final}")
        return True

    os.makedirs(os.path.dirname(final), exist_ok=True)
    for attempt in range(retries + 1):
        try:
            shutil.move(src, final)
            logger.debug(f"moved on attempt {attempt + 1} -> {final}")
            return True
        except (PermissionError, OSError) as exc:
            retryable = isinstance(exc, PermissionError) or getattr(exc, "winerror", 0) in (32, 33)
            if retryable and attempt < retries:
                time.sleep((backoff_ms / 1000) * (attempt + 1))
                continue
            logger.error(f"move failed after {attempt + 1} attempts: {exc}")
            return False


def _write_crash(exc: BaseException) -> None:
    try:
        log_dir = os.path.join(os.environ.get("LOCALAPPDATA", "."), "Organizer")
        os.makedirs(log_dir, exist_ok=True)
        with open(
            os.path.join(log_dir, "watcher_crash.log"),
            "a",
            encoding="utf-8",
        ) as file:
            file.write(f"\n=== {datetime.now().isoformat(timespec='seconds')} ===\n")
            file.write("Python: " + sys.executable + "\n")
            traceback.print_exception(type(exc), exc, exc.__traceback__, file=file)
    except Exception:
        pass


def _pidfile_path() -> str:
    return os.path.join(os.environ.get("LOCALAPPDATA", "."), "Organizer", "watcher.pid")


def _write_pidfile(pid: int, watch_root: str) -> None:
    path = _pidfile_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    record = {
        "pid": pid,
        "watch_root": watch_root,
        "module": "organizer.watcher",
        "ts": datetime.now().isoformat(timespec="seconds"),
    }
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as file:
        json.dump(record, file, indent=2)
    os.replace(tmp, path)


def _remove_pidfile() -> None:
    try:
        os.remove(_pidfile_path())
    except FileNotFoundError:
        pass


def _watcher_running_for_root(watch_root: str) -> bool:
    try:
        with open(_pidfile_path(), "r", encoding="utf-8") as file:
            record = json.load(file)
    except FileNotFoundError:
        return False
    except Exception:
        return False

    if str(record.get("watch_root", "")).lower() != watch_root.lower():
        return False

    pid = record.get("pid", -1)
    result = run(["tasklist", "/FI", f"PID eq {pid}"], capture_output=True, text=True)
    return str(pid) in result.stdout


def main(argv=None):
    global CONFIG

    curr_files: dict[str, FileState] = {}
    lock = threading.Lock()

    watch_dir, dry_run, verbose, notify = extract_args(argv)
    watch_dir = normalize_path(watch_dir)
    configure_logger(verbose=verbose)

    if not os.path.isdir(watch_dir):
        raise FileNotFoundError(f"watch directory does not exist: {watch_dir}")

    CONFIG = load_config()
    logger.info(
        f"config: dryrun={dry_run}, verbose={verbose}, notify={notify}, {CONFIG['path']}"
    )

    if _watcher_running_for_root(watch_dir):
        logger.warning("another watcher is already running for this watch_root; exiting")
        return

    logger.info(
        "watcher boot",
        extra={"event": "boot", "python": sys.version, "exe": sys.executable},
    )
    _write_pidfile(os.getpid(), watch_dir)
    atexit.register(_remove_pidfile)
    maybe_rotate_journal()

    observer = Observer()
    handler = WatchHandler(curr_files, lock)
    observer.schedule(handler, watch_dir, recursive=False)
    move_worker = MoveWorker(dry_run=dry_run, notify=notify)
    stop_event = threading.Event()

    try:
        observer.start()
        move_worker.start()
        run_stabilizer(
            curr_files=curr_files,
            lock=lock,
            on_finalize=lambda path, root: on_finalize_cb(path, root, move_worker),
            stop_event=stop_event,
            root=watch_dir,
        )
    except KeyboardInterrupt:
        logger.info("watcher interrupted; shutting down")
    finally:
        stop_event.set()
        observer.stop()
        observer.join(timeout=5)
        move_worker.stop()
        _remove_pidfile()


if __name__ == "__main__":
    try:
        main()
    except BaseException as exc:
        _write_crash(exc)
        raise
