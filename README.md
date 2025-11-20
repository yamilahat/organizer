# organizer

Windows downloads organizer with a rule-based watcher plus a tkinter UI.

## Features

- Rule-based classification (glob or extension) with built-in buckets for archives/installers/docs/images
- Moves only after downloads stabilize; skips hidden/system/temp files; collision-safe renames and free-space guard
- ttkbootstrap UI to edit destinations and rules, start/stop the watcher, toggle background + notifications, and view the journal
- Optional Windows toast notifications and autostart via the Startup folder
- NDJSON journal for every planned/skip/execute event to help debug

## Requirements

- Windows (watcher, autostart, and toasts are Windows-only)
- Python 3.12+
- `watchdog`, `loguru`, `ttkbootstrap`, `win11toast` (installed via pip)

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -e .
```

## Run the UI

```powershell
python -m organizer.ui
```

- Pick a watch root (defaults to Downloads on first run)
- Add destination folders for categories (archives/installers/docs/images/custom)
- Add rules (glob patterns or space-separated extensions); first match wins
- Click Save then Start Watcher; toggle "Run in background" and "Notifications" as needed; autostart lives under Settings
- "Recent Activity" shows the tail of `%LOCALAPPDATA%\Organizer\journal.ndjson`

## Run the watcher directly

```powershell
python -m organizer.watcher --watch "C:\Users\you\Downloads" --notify --verbose
```

Flags: `--dry-run`, `--notify`, `--verbose`. Uses `%LOCALAPPDATA%\Organizer\config.json`; PID lives at `%LOCALAPPDATA%\Organizer\watcher.pid`.

## Configuration

- First run writes `%LOCALAPPDATA%\Organizer\config.json` with sample destinations pointing at the `demo/` folders in this repo update them to your own paths via the UI
- Keys: `watch_root`, `dest_dirs` (category -> folder), `rules` (list of `{type: glob|ext, pattern|exts, category, enabled}`), `notify`
- Journal: `%LOCALAPPDATA%\Organizer\journal.ndjson`. Autostart script + icon are stored under `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` and `%LOCALAPPDATA%\Organizer`.

## How it works

- Watches the configured root; waits ~3 seconds of size stability before acting
- Skips dotfiles, system/hidden files, and temp suffixes `.crdownload`, `.tmp`, `.part`
- Checks free space for very large files and renames collisions to `name (2).ext`
- Notifications use `win11toast` with a bundled/appdata icon when available

## Demo

`demo/` contains sample downloads/destinations you can point the watcher to for local testing.
