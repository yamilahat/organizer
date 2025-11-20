import argparse
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from loguru import logger
from collections import namedtuple
from typing import Callable
import sys
import os, traceback
import time
import threading
import shutil
import ctypes, ctypes.wintypes as wt
from queue import Queue
import uuid
from datetime import datetime, timezone
import json, atexit
from organizer.planner import decide_action, TEMP_SUFFIXES
from organizer.notifications import send_notification, send_move_notice
from pathlib import Path
import shutil

DEFAULT_BUCKETS = {
    "archives": "archives",
    "installers": "installers",
    "docs": "docs",
    "images": "images",
}

FileState = namedtuple('FileState', ['last_size', 'last_seen_ts'])

POLL_INTERVAL = 0.5
STABILIZE_SECONDS = 3
JOURNAL_PATH = os.path.join(os.environ.get("LOCALAPPDATA", "."), "Organizer", "journal.ndjson")
SESSION_ID = str(uuid.uuid4()) 
VERSION = "0.1.0"
CONFIG: dict | None = None

FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4
_GetFileAttributesW = ctypes.windll.kernel32.GetFileAttributesW
_GetFileAttributesW.argtypes = [wt.LPCWSTR]
_GetFileAttributesW.restype = wt.DWORD

LARGE_MB = 500
MIN_FREE_MB = 200

exec_q = Queue()

class MyHandler(FileSystemEventHandler):
    def __init__(self, curr_files: dict, lock: threading.Lock):
        self.curr_files = curr_files
        self.lock = lock
    def on_created(self, event):
        if event.is_directory: return
        logger.debug(f"file created: {event.src_path}")
        path = os.path.normcase(os.path.abspath(event.src_path))

        with self.lock:
            if path not in self.curr_files:
                self.curr_files[path] = FileState(-1, time.monotonic())
    def on_moved(self, event):
        if event.is_directory: return
        now = time.monotonic()
        src = os.path.normcase(os.path.abspath(event.src_path))
        dst = os.path.normcase(os.path.abspath(event.dest_path))
        with self.lock:
            state = self.curr_files.pop(src, None)
            if state is None:
                state = FileState(last_size=-1, last_seen_ts=now)
            self.curr_files[dst] = FileState(state.last_size, now)
        logger.debug(f"moved {src} -> {dst}")

def is_hidden_or_system(path: str) -> bool:
    try:
        attrs = _GetFileAttributesW(path)
        return attrs != 0xFFFFFFFF and (attrs & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) != 0
    except Exception:
        return False

def under_root(path: str, root: str) -> bool:
    try:
        return Path(path).resolve().is_relative_to(Path(root).resolve())
    except AttributeError:  # Python < 3.9 style fallback (not needed in 3.12, but safe)
        p, r = Path(path).resolve(), Path(root).resolve()
        return str(p).startswith(str(r))

def dest_has_space(dest_dir: str, size_bytes: int) -> bool:
    try:
        total, used, free = shutil.disk_usage(dest_dir)
        return free >= max(MIN_FREE_MB * 1024**2, size_bytes * 1)  # keep it simple for now
    except Exception:
        return True

def configure_logger(verbose: bool) -> None:
    logger.remove()
    
    fmt = ("<green>{time:HH:mm:ss}</green> | <level>{level: <7}</level> | "
          "{name}:{function}:{line} | {message}") if verbose \
         else "<green>{time:HH:mm:ss}</green> | <level>{level}</level> | {message}"

    logger.add(
        sys.stderr,
        level="DEBUG" if verbose else "INFO",
        backtrace=verbose,
        diagnose=verbose,
        format=fmt,
    )          
    logger.info("logger ready")

def _default_dest_dirs() -> dict[str, str]:
    """
    Build safe first-run defaults:
    - Prefer repo demo buckets when present
    - Otherwise fall back to user Downloads subfolders
    """
    here = Path(__file__).resolve()
    repo_root = here.parent.parent.parent
    demo_root = repo_root / "demo"
    downloads = Path.home() / "Downloads"

    dests = {}
    for category, folder in DEFAULT_BUCKETS.items():
        demo_candidate = demo_root / folder
        if demo_candidate.exists():
            dests[category] = str(demo_candidate.resolve())
        else:
            fallback = downloads / folder.capitalize()
            fallback.mkdir(parents=True, exist_ok=True)
            dests[category] = str(fallback.resolve())
    return dests

def load_config(config_path: str|None = None) -> dict:
    defaults = {
        "dest_dirs": _default_dest_dirs(),
        "rules": [],
    }
    path = config_path or os.path.join(os.environ.get("LOCALAPPDATA", "."), "Organizer", "config.json")
    
    try:
        with open(path, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
    except FileNotFoundError:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(defaults, f, indent=2)
        cfg = defaults
        
    # normalize dest dirs and rules
    dest_dirs = {
        k: os.path.normcase(os.path.abspath(v))
        for k, v in cfg.get("dest_dirs", {}).items()
    }
    
    return {"path": path, "dest_dirs":dest_dirs, "rules": cfg["rules"]}
    
def journal(event: str, **fields) -> None:
    rec = {
        "ts_iso": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "pid": os.getpid(),
        "session_id": SESSION_ID,
        "version": VERSION,
        **fields,
    }
    try:
        os.makedirs(os.path.dirname(JOURNAL_PATH), exist_ok=True)
        with open(JOURNAL_PATH, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as e:
        logger.warning(f"journal failed: {e}")
    else:
        maybe_rotate_journal()

def maybe_rotate_journal(max_bytes: int = 10_000_000) -> None:
    try:
        if os.path.exists(JOURNAL_PATH) and os.path.getsize(JOURNAL_PATH) > max_bytes:
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            base = os.path.splitext(JOURNAL_PATH)[0]
            os.replace(JOURNAL_PATH, f"{base}-{ts}.ndjson")
    except Exception as e:
        logger.warning(f"journal rotate failed: {e}")

def extract_args(argv) -> tuple[str, bool, bool, bool]:
    p = argparse.ArgumentParser(prog="organizer", description="Downloads organizer (MVP)")
    p.add_argument("--watch", help="Directory to watch", required=True)
    p.add_argument("--dry-run", action="store_true", help="Plan actions only")
    p.add_argument("--verbose", action="store_true", help="Enable DEBUG logs and diagnostics")
    p.add_argument("--notify", action="store_true", help="Show a Windows toast when a file is moved")
    args = p.parse_args(argv)
    return (args.watch, args.dry_run, args.verbose, args.notify)

def run_stabilizer(
    curr_files: dict[str, FileState],
    lock: threading.Lock,
    on_finalize: Callable[[str], tuple[str, str, str]],
    stop_event: threading.Event,
    root: str,
) -> None:
    while not stop_event.is_set():
        now = time.monotonic()

        with lock:
            snapshot = list(curr_files.items())
        # logger.info(snapshot)
        to_update = []
        to_finalize = []
        to_drop = []
        
        for file_path, file_state in snapshot:
            if file_path.lower().endswith(TEMP_SUFFIXES):
                continue
            try:
                curr_size = os.path.getsize(file_path)
            except FileNotFoundError:
                to_drop.append(file_path)
                continue
            except PermissionError:
                logger.warning(f"permission error {file_path}")
                continue

            if curr_size != file_state.last_size:
                to_update.append((file_path, FileState(curr_size, now)))
            elif now - file_state.last_seen_ts >= STABILIZE_SECONDS:
                to_finalize.append(file_path)

        with lock:
            for p in to_drop:
                curr_files.pop(p, None)
                logger.debug(f"dropped {p} - file not found")

            for p, new_state in to_update:
                curr_files[p] = new_state
                logger.debug(f"updated {p} - new size")

            for p in to_finalize:
                curr_files.pop(p, None)

        for p in to_finalize:
            logger.info(f"finalized {p}")
            on_finalize(p, root)
        
        time.sleep(POLL_INTERVAL)

def on_finalize_cb(path: str, root: str):
    if is_hidden_or_system(path) or Path(path).name.startswith("."):
        journal("skip", src=path, reason="guard:hidden_or_system")
        return
    if not under_root(path, root):
        journal("skip", src=path, reason="guard:outside_root")
        return
    op, category, base, reason = decide_action(path, CONFIG.get("rules", []))
    match op:
        case "skip":
            logger.info(f"planned skip: {path} ({reason})")
            return (op, base, reason)
        
        case "move":
            dst_dir = CONFIG["dest_dirs"].get(category)
            if not dst_dir:
                logger.warning(f"skip: category {category} not configured for {path}")
                return ("skip", None, f"unconfigured_category:{category}")
            
            try:
                size = os.path.getsize(path)
            except OSError:
                size = 0
            if size >= LARGE_MB * 1024**2 and not dest_has_space(os.path.dirname(dst_dir), size):
                journal("skip", src=path, dest=dst_dir, reason="guard_low_free_space", extra={"size":size})
                return
            
            abs_dest = os.path.join(dst_dir, base)
            logger.info(f"planned move: {path} -> {abs_dest} ({reason})")
            journal("planned", src=path, dest=abs_dest, op=op, reason=reason, category=category)
            exec_q.put((path, abs_dest))
            return (op, abs_dest, reason)
        
        case _:
            logger.error(f"unknown operation: {op}")
            return ("skip", None, f"unknown operation: {op}")

def exec_worker(dry_run: bool, notify: bool):
    while True:
        src, abs_dest = exec_q.get()
        try:
            ok = execute("move", src, abs_dest, dry_run=dry_run)
            if ok:
                logger.success(f"executed: {src} -> {abs_dest}")
                journal("executed", src=src, dest=abs_dest, op="move", reason="ok")
                send_move_notice(src, abs_dest, enable=notify)
            else:
                logger.error(f"failed: {src} -> {abs_dest}")
                journal("failed", src=src, dest=abs_dest, op="move", reason="executed_failed")
                send_notification("Organizer - Move failed", f"Failed to move {os.path.basename(src)}", enable=notify, path=src)
        finally:
            exec_q.task_done()

def next_available(path: str) -> str:
    if not os.path.exists(path):
        return path
    base, ext = os.path.splitext(path)
    n = 2
    while True:
        cand = f"{base} ({n}){ext}"
        if not os.path.exists(cand):
            return cand
        n += 1

def execute(op: str, src: str, dst: str, *, dry_run: bool, retries: int=3, backoff_ms: int =200) -> bool:
    final = next_available(dst)
    if dry_run:
        logger.info(f"DRY-RUN move: {src} -> {final}")
        return True
    
    os.makedirs(os.path.dirname(final), exist_ok=True)

    for attempt in range(1, retries+2):
        try:
            shutil.move(src, final)
            logger.debug(f"moved on attempt {attempt} -> {final}")
            return True
        except (PermissionError, OSError) as e:
            retryable = isinstance(e, PermissionError) or getattr(e, "winerror", 0) in (32, 33)
            if retryable and attempt <= retries:
                time.sleep(0.2*attempt) # linear backoff
                continue
            logger.error(f"move failed after {attempt} attempts: {e}")
            return False

def _write_crash(exc: BaseException) -> None:
    try:
        log_dir = os.path.join(os.environ.get("LOCALAPPDATA", "."), "Organizer")
        os.makedirs(log_dir, exist_ok=True)
        with open(os.path.join(log_dir, "watcher_crash.log"), "a", encoding="utf-8") as f:
            f.write(f"\n=== {datetime.now().isoformat(timespec='seconds')} ===\n")
            f.write("Python: " + sys.executable + "\n")
            traceback.print_exception(type(exc), exc, exc.__traceback__, file=f)
    except Exception:
        pass

def _pidfile_path() -> str:
    return os.path.join(os.environ.get("LOCALAPPDATA", "."), "Organizer", "watcher.pid")

def _write_pidfile(pid: int, watch_root: str) -> None:
    path = _pidfile_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    rec = {
        "pid": pid,
        "watch_root": watch_root,
        "module": "organizer.watcher",
        "ts": datetime.now().isoformat(timespec="seconds"),
    }
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=2)
    os.replace(tmp, path)

def _remove_pidfile() -> None:
    try: os.remove(_pidfile_path())
    except FileNotFoundError: pass

def main(argv=None):
    global CONFIG
    
    curr_files = {}
    lock = threading.Lock()

    dir, dry_run, verbose, notify = extract_args(argv)
    dir = os.path.normcase(os.path.abspath(dir))
    
    configure_logger(verbose=verbose)
    
    CONFIG = load_config()
    logger.info(f"config: dryrun={dry_run}, verbose={verbose}, notify={notify}, {CONFIG['path']} | ")
    
    try:   
        with open(_pidfile_path(), "r", encoding="utf-8") as f:
            rec = json.load(f)
        from subprocess import run
        if str(rec.get("watch_root", "")).lower() == dir.lower():
            out = run(["tasklist", "/FI", f"PID eq {rec.get('pid', -1)}"], capture_output=True, text=True)
            if str(rec.get("pid","")) in out.stdout:
                logger.warning("another watcher is already running for this watch_root; exiting")
                return 
        logger.info("watcher boot", extra={"event": "boot", "python": sys.version, "exe": sys.executable})
    except FileNotFoundError:
        pass
    except Exception:
        pass
    _write_pidfile(os.getpid(), dir)
    atexit.register(_remove_pidfile)
    
    maybe_rotate_journal()

    observer = Observer()
    handler = MyHandler(curr_files, lock)
    observer.schedule(handler, dir, recursive=False)
    observer.start()

    threading.Thread(target=exec_worker, args=(dry_run,notify,), daemon=True).start()
    
    stop = threading.Event()
    try:
        run_stabilizer(curr_files=curr_files,
                       lock=lock,
                       on_finalize=on_finalize_cb,
                       stop_event=stop,
                       root=dir,
                       )          
    except KeyboardInterrupt:
        observer.stop()
        stop.set()
    observer.join()

if __name__ == "__main__":
    try:
        main()
    except BaseException as e:
        _write_crash(e)
        raise
