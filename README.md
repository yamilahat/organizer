# organizer

Windows downloads organizer with a rule-based watcher plus a tkinter UI.

## Features

- Rule-based classification (glob or extension) with built-in buckets for archives/installers/docs/images
- Moves only after downloads stabilize; skips hidden/system/temp files; collision-safe renames and free-space guard
- ttkbootstrap UI to edit destinations and rules, start/stop the watcher, toggle background + notifications, and view the journal
- Optional Windows toast notifications and autostart via the Startup folder
- NDJSON journal for every planned/skip/execute event to help debug
- Packaged executable support through `Organizer.exe`, including startup mode from saved config

## Requirements

- Windows (watcher, autostart, toasts, and packaged startup flow are Windows-only)
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

Or through the shared launcher:

```powershell
organizer
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

Or via the launcher using saved config:

```powershell
organizer --startup
```

Flags: `--dry-run`, `--notify`, `--verbose`. Uses `%LOCALAPPDATA%\Organizer\config.json`; PID lives at `%LOCALAPPDATA%\Organizer\watcher.pid`.

## Build the executable

Install the build extra, then run the build script:

```powershell
pip install -e .[build]
.\scripts\build_exe.ps1
```

The packaged app is written to `dist\Organizer.exe`.

- Running `Organizer.exe` opens the UI.
- Running `Organizer.exe --startup` starts the watcher using the saved `watch_root` and `notify` values from `%LOCALAPPDATA%\Organizer\config.json`.

## Install startup from the executable

After building the executable:

```powershell
.\scripts\install_startup.ps1
```

That creates `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\OrganizerWatcher.cmd`, which launches `Organizer.exe --startup` automatically at sign-in.

## Configuration

- First run writes `%LOCALAPPDATA%\Organizer\config.json` with sample destinations pointing at the `demo/` folders in this repo; update them to your own paths via the UI
- Keys: `watch_root`, `dest_dirs` (category -> folder), `rules` (list of `{type: glob|ext, pattern|exts, category, enabled}`), `notify`
- Journal: `%LOCALAPPDATA%\Organizer\journal.ndjson`. Autostart script + icon are stored under `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` and `%LOCALAPPDATA%\Organizer`.

## How it works

- Watches the configured root; waits ~3 seconds of size stability before acting
- Skips dotfiles, system/hidden files, and temp suffixes `.crdownload`, `.tmp`, `.part`
- Checks free space for very large files and renames collisions to `name (2).ext`
- Notifications use `win11toast` with a bundled/appdata icon when available

## Demo

`demo/` contains sample downloads/destinations you can point the watcher to for local testing.
