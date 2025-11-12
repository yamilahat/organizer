import argparse
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from loguru import logger
from collections import namedtuple
from typing import Callable
import sys
import os
import time
import threading

FileState = namedtuple('FileState', ['last_size', 'last_seen_ts'])

POLL_INTERVAL = 0.5
STABILIZE_SECONDS = 3
TEMP_SUFFIXES = {".crdownload", ".tmp", ".part"}
class MyHandler(FileSystemEventHandler):
    def __init__(self, curr_files: dict, lock: threading.Lock):
        self.curr_files = curr_files
        self.lock = lock
    def on_created(self, event):
        if event.is_directory: return
        logger.info(f"file created: {event.src_path}")
        path = os.path.normcase(os.path.abspath(event.src_path))

        with self.lock:
            if path not in self.curr_files:
                self.curr_files[path] = FileState(-1, time.monotonic())
            else:
                pass
        return super().on_created(event)
    def on_modified(self, event):
        # logger.debug(f"file modified: {event.src_path}")
        return super().on_modified(event)
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

def extract_args(argv) -> tuple[str, bool, bool]:
    p = argparse.ArgumentParser(prog="organizer", description="Downloads organizer (MVP)")
    p.add_argument("--watch", help="Directory to watch", required=True)
    p.add_argument("--dry-run", action="store_true", help="Plan actions only")
    p.add_argument("--verbose", action="store_true", help="Enable DEBUG logs and diagnostics")
    args = p.parse_args(argv)
    return (args.watch, args.dry_run, args.verbose)

def run_stabilizer(
    curr_files: dict[str, FileState],
    lock: threading.Lock,
    on_finalize: Callable[[str], None],
    stop_event: threading.Event,
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
            on_finalize(p)
        
        time.sleep(POLL_INTERVAL)

def configure_logger(verbose: bool) -> None:
    logger.remove()
    logger.add(
        sys.stderr,
        level="DEBUG" if verbose else "INFO",
        backtrace=verbose,
        diagnose=verbose,
        format="<green>{time:HH:mm:ss}</green> | <level>{level}</level> | {message}",
    )          
    logger.info("logger ready")

def main(argv=None):
    curr_files = {}
    lock = threading.Lock()

    dir, dry_run, verbose = extract_args(argv)
    configure_logger(verbose=verbose)

    observer = Observer()
    handler = MyHandler(curr_files, lock)
    observer.schedule(handler, dir, recursive=False)
    observer.start()
    logger.info(f"watching {dir}")
    
    stop = threading.Event()
    try:
        run_stabilizer(curr_files=curr_files,
                       lock=lock,
                       on_finalize=lambda p: logger.success(f"finalized {p}"),
                       stop_event=stop,
                       )            
    except KeyboardInterrupt:
        observer.stop()
        stop.set()
    observer.join()


if __name__ == "__main__":
    main()