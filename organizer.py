import argparse
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from loguru import logger
from collections import namedtuple
import sys
import os
import time
import threading

FileState = namedtuple('FileState', ['last_size', 'last_seen_ts'])

POLL_INTERVAL = 0.5
STABILIZE_SECONDS = 3
class MyHandler(FileSystemEventHandler):
    def __init__(self, curr_files: dict, lock: threading.Lock):
        self.curr_files = curr_files
        self.lock = lock
    def on_created(self, event):
        if event.is_directory: return
        logger.info(f"file created: {event.src_path}")
        path = os.path.normpath(os.path.abspath(event.src_path))

        with self.lock:
            if path not in self.curr_files:
                self.curr_files[path] = FileState(-1, time.monotonic())
            else:
                pass
        return super().on_created(event)
    def on_modified(self, event):
        logger.debug(f"file modified: {event.src_path}")
        return super().on_modified(event)
    
def extract_args(argv) -> tuple[str, str]:
    p = argparse.ArgumentParser(prog="organizer", description="Downloads organizer (MVP)")
    p.add_argument("--watch", help="Directory to watch", required=True)
    p.add_argument("--dry-run", action="store_true", help="Plan actions only")
    args = p.parse_args(argv)
    return (args.watch, args.dry_run)

def main(argv=None):
    curr_files = {}
    lock = threading.Lock()

    logger.remove()
    logger.add(sys.stderr, level="INFO")
    logger.info("logger ready")
    
    dir, dry_run = extract_args(argv)

    observer = Observer()
    handler = MyHandler(curr_files, lock)
    observer.schedule(handler, dir, recursive=True)
    observer.start()
    logger.info(f"watching {dir}")
    
    try:
        while True:
            now = time.monotonic()

            with lock:
                snapshot = list(curr_files.items())

            to_update = []
            to_finalize = []
            to_drop = []
            
            for file_path, file_state in snapshot:
                try:
                    curr_size = os.path.getsize(file_path)
                except FileNotFoundError:
                    to_drop.append(file_path)
                    continue
                except PermissionError:
                    continue
                if curr_size != file_state.last_size:
                    to_update.append((file_path, FileState(curr_size, now)))
                elif now - file_state.last_seen_ts >= STABILIZE_SECONDS and not file_path.endswith(".crdownload"):
                    to_finalize.append(file_path) 

            with lock:
                for p in to_drop:
                    curr_files.pop(p, None)
                for p, new_state in to_update:
                    curr_files[p] = new_state
                for p in to_finalize:
                    curr_files.pop(p, None)
            for p in to_finalize:
                logger.success(f"finalized {p}")

            time.sleep(POLL_INTERVAL)
            
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()