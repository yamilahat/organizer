import argparse
import json
import os
from pathlib import Path

from organizer import ui, watcher


def _config_path() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA", "."))
    return base / "Organizer" / "config.json"


def _load_raw_config() -> dict:
    try:
        with _config_path().open("r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        return {}


def _watch_root_from_config() -> str:
    config = _load_raw_config()
    watch_root = str(config.get("watch_root", "")).strip()
    if watch_root:
        return watch_root
    return str((Path.home() / "Downloads").resolve())


def _notify_from_config() -> bool:
    return bool(_load_raw_config().get("notify", False))


def build_watcher_argv(
    from_config: bool,
    watch: str | None,
    notify: bool | None,
) -> list[str]:
    argv: list[str] = []
    watch_root = _watch_root_from_config() if from_config or not watch else watch.strip()
    if not watch_root:
        raise SystemExit("No watch root configured.")

    argv.extend(["--watch", watch_root])

    notify_enabled = _notify_from_config() if notify is None else notify
    if notify_enabled:
        argv.append("--notify")
    return argv


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="Organizer")
    parser.add_argument("--watcher", action="store_true", help="Run the background watcher.")
    parser.add_argument(
        "--startup",
        action="store_true",
        help="Run the background watcher using the saved configuration.",
    )
    parser.add_argument(
        "--from-config",
        action="store_true",
        help="Read the watch root from config.",
    )
    parser.add_argument("--watch", help="Directory to watch.")
    parser.add_argument(
        "--notify", dest="notify", action="store_true", help="Enable notifications."
    )
    parser.add_argument(
        "--no-notify",
        dest="notify",
        action="store_false",
        help="Disable notifications.",
    )
    parser.set_defaults(notify=None)
    args = parser.parse_args(argv)

    if args.watcher or args.startup:
        watcher_argv = build_watcher_argv(
            from_config=args.startup or args.from_config,
            watch=args.watch,
            notify=args.notify,
        )
        watcher.main(watcher_argv)
        return

    ui.main()


if __name__ == "__main__":
    main()
