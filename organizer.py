import argparse
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class MyHandler(FileSystemEventHandler):
    def on_created(self, event):
        print(f"File created: {event.src_path}")
        return super().on_created(event)
    def on_modified(self, event):
        print(f"File modified: {event.src_path}")
        return super().on_modified(event)
    
def extract_args(argv) -> tuple[str, str]:
    p = argparse.ArgumentParser(prog="organizer", description="Downloads organizer (MVP)")
    p.add_argument("--watch", help="Directory to watch")
    p.add_argument("--dry-run", action="store_true", help="Plan actions only")
    args = p.parse_args(argv)
    return (args.watch, args.dry_run)

def main(argv=None):
    dir, dry_run = extract_args(argv)
    
    observer = Observer()
    handler = MyHandler()
    observer.schedule(handler, dir, recursive=True)
    observer.start()

    while True:
        cmd = input("> ")
        if cmd == 'q': break

    observer.stop()
    observer.join()


if __name__ == "__main__":
    main()