# ui.py  - scrollable UI, collapsible Recent Activity, background watcher with PID control
import os
import sys
import json
import webbrowser
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from datetime import datetime

import ttkbootstrap as tb
from ttkbootstrap.constants import *

from organizer.watcher import load_config, JOURNAL_PATH  # reuse existing helpers
from organizer.notifications import send_notification
from pathlib import Path

try:
    import pystray
    from PIL import Image
except Exception:
    pystray = None
    Image = None

# ---------------------------- Small utilities ----------------------------

def save_config_atomic(cfg_path: str, cfg: dict) -> None:
    tmp = cfg_path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, cfg_path)

def read_raw_config(cfg_path: str) -> dict:
    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except Exception:
        return {}

def tail_file_bytes(path: str, last_bytes: int = 120_000) -> list[str]:
    """Read the last ~N bytes and return up to 200 lines (newest last)."""
    if not os.path.exists(path):
        return []
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - last_bytes), os.SEEK_SET)
            data = f.read().decode("utf-8", errors="replace")
        return data.strip().splitlines()[-200:]
    except Exception as e:
        return [f'[journal read error: {e!r}]']

def rules_to_rows(rules: list[dict]) -> list[tuple]:
    rows = []
    for r in rules or []:
        if r.get("type") == "glob":
            rows.append((bool(r.get("enabled", True)), "glob", r.get("pattern", ""), r.get("category", "")))
        elif r.get("type") == "ext":
            rows.append((bool(r.get("enabled", True)), "ext", " ".join(r.get("exts", [])), r.get("category", "")))
    return rows

def rows_to_rules(rows: list[tuple]) -> list[dict]:
    out: list[dict] = []
    for enabled, rtype, field, cat in rows:
        cat = str(cat).strip().lower()
        if str(rtype) == "glob" and str(field).strip():
            out.append({"type": "glob", "pattern": str(field).strip(), "category": cat, "enabled": bool(enabled)})
        elif str(rtype) == "ext" and str(field).strip():
            exts = [e.strip().lower() for e in str(field).split() if e.strip()]
            out.append({"type": "ext", "exts": exts, "category": cat, "enabled": bool(enabled)})
    return out

RULE_TEMPLATES = [
    ("Subtitles (.srt .vtt .ass)", {"type": "ext", "exts": [".srt", ".vtt", ".ass"], "category": "docs", "enabled": True}),
    ("Disc images (.iso .img)", {"type": "ext", "exts": [".iso", ".img"], "category": "archives", "enabled": True}),
    (".torrent", {"type": "ext", "exts": [".torrent"], "category": "archives", "enabled": True}),
    ("Checksums (.sha256 .sha1)", {"type": "ext", "exts": [".sha256", ".sha1"], "category": "docs", "enabled": True}),
    ("Screenshots (glob: *screenshot*)", {"type": "glob", "pattern": "*screenshot*", "category": "images", "enabled": True}),
]

def _load_tray_image() -> "Image.Image | None":
    if Image is None:
        return None
    icon_path = Path(__file__).resolve().parent / "assets" / "icon.png"
    try:
        return Image.open(icon_path)
    except Exception:
        return None

# --- background watcher helpers (PID file + tasklist) ---

def local_appdata() -> str:
    return os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))

def pidfile_path() -> str:
    return os.path.join(local_appdata(), "Organizer", "watcher.pid")

def write_pidfile(pid: int, watch_root: str) -> None:
    path = pidfile_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    rec = {
        "pid": pid,
        "watch_root": watch_root,
        "script": os.path.join(os.path.dirname(__file__), "organizer.py"),
        "ts": datetime.now().isoformat(timespec="seconds"),
    }
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=2)
    os.replace(tmp, path)

def read_pidfile() -> dict | None:
    path = pidfile_path()
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except Exception:
        return None

def remove_pidfile() -> None:
    try:
        os.remove(pidfile_path())
    except FileNotFoundError:
        pass

def is_pid_running(pid: int) -> bool:
    try:
        out = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}"],
            capture_output=True, text=True, check=True
        ).stdout
        return str(pid) in out
    except Exception:
        return False

def pythonw_exe() -> str | None:
    cand = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    return cand if os.path.exists(cand) else None

def _startup_dir() -> Path:
    return Path(os.environ["APPDATA"]) / r"Microsoft\Windows\Start Menu\Programs\Startup"

def _pythonw() -> str:
    p = Path(sys.executable).with_name("pythonw.exe")
    return str(p) if p.exists() else sys.executable

def _autostart_link_path() -> Path:
    return _startup_dir() / "OrganizerWatcher.lnk"

def _autostart_cmd_path() -> Path:
    return _startup_dir() / "OrganizerWatcher.cmd"

def is_autostart_enabled() -> bool:
    return _autostart_link_path().exists() or _autostart_cmd_path().exists()

def enable_autostart(watch_root: str) -> None:
    _startup_dir().mkdir(parents=True, exist_ok=True)
    exe = _pythonw()  # venv\pythonw.exe if present, else python.exe
    log_dir = Path(os.environ.get("LOCALAPPDATA", ".")) / "Organizer"
    log_dir.mkdir(parents=True, exist_ok=True)
    log = log_dir / "autostart.log"

    content = (
        "@echo off\r\n"
        f'echo %DATE% %TIME% launching "{exe}" -m organizer.watcher --watch "{watch_root}" >> "{log}" 2>&1\r\n'
        # /B starts without a new window; START detaches so .cmd can exit immediately
        f'start "" /B "{exe}" -m organizer.watcher --watch "{watch_root}" >> "{log}" 2>&1\r\n'
        "exit /b 0\r\n"
    )
    _autostart_cmd_path().write_text(content, encoding="utf-8")



def disable_autostart() -> None:
    try: _autostart_cmd_path().unlink()
    except FileNotFoundError: pass

def is_autostart_enabled() -> bool:
    return _autostart_cmd_path().exists()


# ---------------------------- UI ----------------------------

def main():
    # Load normalized config (dest_dirs/rules) and raw JSON (for watch_root)
    cfg = load_config()
    cfg_path = cfg["path"]
    raw = read_raw_config(cfg_path)

    dest_dirs: dict = cfg["dest_dirs"]
    rules: list[dict] = cfg.get("rules", [])
    default_downloads = os.path.join(os.path.expanduser("~"), "Downloads")
    watch_root_initial = raw.get("watch_root") or default_downloads

    # Window
    root = tb.Window(themename="minty")
    root.title("Organizer")
    root.geometry("1300x760")
    root.minsize(1100, 740)

    status_var = tk.StringVar(master=root, value="Watcher: unknown")

    # thin scrollbars everywhere
    style = root.style if hasattr(root, "style") else ttk.Style()
    style.configure("Thin.Vertical.TScrollbar", width=8)

    # subtle accents + cards
    style.configure("Hero.TFrame", background="#0b172a")
    style.configure("HeroTitle.TLabel", background="#0b172a", foreground="#e2e8f0", font=("Segoe UI", 18, "bold"))
    style.configure("HeroSubtitle.TLabel", background="#0b172a", foreground="#94a3b8", font=("Segoe UI", 10))
    style.configure("Pill.TLabel", background="#e0f2fe", foreground="#0f172a", padding=(10, 4))
    style.configure("Subtle.TLabel", foreground="#6b7280")
    style.configure("SectionHeading.TLabel", font=("Segoe UI", 10, "bold"))
    style.configure("Card.TLabelframe", padding=(14, 10))
    style.configure("Card.TLabelframe.Label", font=("Segoe UI", 11, "bold"))

    chrome = ttk.Frame(root, padding=(12, 10, 12, 12))
    chrome.pack(fill="both", expand=True)

    hero = ttk.Frame(chrome, padding=(16, 12), style="Hero.TFrame")
    hero.pack(fill="x", pady=(0, 10))
    hero.columnconfigure(0, weight=1)
    ttk.Label(hero, text="Organizer", style="HeroTitle.TLabel").grid(row=0, column=0, sticky="w")
    ttk.Label(hero, text="Keep downloads tidy with smart rules and a background watcher.", style="HeroSubtitle.TLabel").grid(row=1, column=0, sticky="w", pady=(2, 0))
    ttk.Label(hero, textvariable=status_var, style="Pill.TLabel").grid(row=0, column=1, rowspan=2, sticky="e")
    ttk.Label(hero, text=f"Config: {cfg_path}", style="Subtle.TLabel").grid(row=2, column=0, columnspan=2, sticky="w", pady=(10, 0))

    # ---- Scrollable container (Canvas + Frame) ----
    outer = ttk.Frame(chrome)
    outer.pack(fill="both", expand=True)

    canvas = tk.Canvas(outer, highlightthickness=0)
    ysb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview, style="Thin.Vertical.TScrollbar")
    canvas.configure(yscrollcommand=ysb.set)

    ysb.pack_forget()
    canvas.pack(side="left", fill="both", expand=True)

    content = ttk.Frame(canvas)
    content.columnconfigure(0, weight=3)   # left (Notebook)
    content.columnconfigure(1, weight=2)   # right (Actions)
    content.rowconfigure(1, weight=1)
    content.rowconfigure(3, weight=1)

    content_id = canvas.create_window((0, 0), window=content, anchor="nw")
    _hide_after_id = None
    # Resize/scroll bindings
    def _on_content_configure(_event=None):
        canvas.configure(scrollregion=canvas.bbox("all"))
        # keep content width = canvas width
        canvas_width = canvas.winfo_width()
        canvas.itemconfigure(content_id, width=canvas_width)
    content.bind("<Configure>", _on_content_configure)

    def _on_canvas_configure(_event=None):
        # keep content width = canvas width when canvas resized
        canvas.itemconfigure(content_id, width=canvas.winfo_width())
    canvas.bind("<Configure>", _on_canvas_configure)

    # Mousewheel scrolling (Windows)
    def _on_mousewheel(event):
        canvas.yview_scroll(int(-1*(event.delta/120)), "units")
    canvas.bind_all("<MouseWheel>", _on_mousewheel)
    
    def _hide_scrollbar():
      ysb.pack_forget()
      
    def _show_scrollbar():
      nonlocal _hide_after_id
      if not ysb.winfo_ismapped():
          ysb.pack(side="right", fill="y")
      if _hide_after_id:
          canvas.after_cancel(_hide_after_id)
      _hide_after_id = canvas.after(1200, _hide_scrollbar)

    canvas.bind("<Enter>", lambda e: _show_scrollbar())
    canvas.bind("<Motion>", lambda e: _show_scrollbar())
    canvas.bind_all("<MouseWheel>", lambda e: (_show_scrollbar(), canvas.yview_scroll(int(-e.delta/120), "units")))
    
    # ----- Header -----
    header = ttk.Frame(content, padding=(6, 4))
    header.grid(row=0, column=0, columnspan=2, sticky="ew", padx=12, pady=(8, 6))
    header.columnconfigure(1, weight=1)

    ttk.Label(header, text="Watch Root", style="SectionHeading.TLabel").grid(row=0, column=0, sticky="w")
    watch_var = tk.StringVar(master=root, value=watch_root_initial)
    wr_entry = ttk.Entry(header, textvariable=watch_var)
    wr_entry.grid(row=0, column=1, sticky="ew", padx=(10, 6))
    ttk.Button(header, text="Browse...",
               command=lambda: watch_var.set(filedialog.askdirectory(title="Select folder to watch") or watch_var.get())
               ).grid(row=0, column=2, sticky="e")
    ttk.Label(header, text="Choose the folder to monitor for new files.", style="Subtle.TLabel").grid(row=1, column=0, columnspan=3, sticky="w", pady=(4, 0))

    links = ttk.Frame(header)
    links.grid(row=2, column=0, columnspan=3, sticky="w", pady=(6, 0))
    ttk.Button(links, text="Open Config", bootstyle=LINK,
               command=lambda: webbrowser.open(f"file:///{cfg_path}")).pack(side="left")
    ttk.Button(links, text="Open Journal Folder", bootstyle=LINK,
               command=lambda: os.startfile(os.path.dirname(JOURNAL_PATH))).pack(side="left", padx=10)

    # ----- Destinations -----
    # --- Left column: Notebook ---
    left_nb = ttk.Notebook(content, bootstyle=PRIMARY)
    left_nb.grid(row=1, column=0, sticky="nsew", padx=12, pady=8)

    dest_tab = ttk.Frame(left_nb)
    rules_tab = ttk.Frame(left_nb)
    left_nb.add(dest_tab, text="Destinations")
    left_nb.add(rules_tab, text="Rules")

    dest_frame = ttk.Labelframe(dest_tab, text="Destinations", style="Card.TLabelframe")
    dest_frame.pack(fill="both", expand=True, padx=10, pady=10)
    dest_frame.columnconfigure(0, weight=1)
    dest_frame.rowconfigure(0, weight=1)

    for k in ("archives", "installers", "docs"):
        dest_dirs.setdefault(k, dest_dirs.get(k, ""))

    dest_cols = ("category", "folder")
    dest_tree = ttk.Treeview(dest_frame, columns=dest_cols, show="headings", height=8, bootstyle=INFO)
    for c, w in (("category", 240), ("folder", 680)):
        dest_tree.heading(c, text=c.capitalize()); dest_tree.column(c, width=w, anchor="w")
    dest_tree.grid(row=0, column=0, columnspan=6, sticky="nsew", padx=8, pady=8)
    style.configure("Treeview", rowheight=26)
    yscroll_dest = ttk.Scrollbar(dest_frame, orient="vertical", command=dest_tree.yview, style="Thin.Vertical.TScrollbar")
    dest_tree.configure(yscrollcommand=yscroll_dest.set)
    yscroll_dest.grid(row=0, column=6, sticky="ns")

    for k, v in dest_dirs.items():
        dest_tree.insert("", "end", values=(k, v))

    def current_dest_dirs() -> dict:
        out = {}
        for iid in dest_tree.get_children(""):
            cat, folder = dest_tree.item(iid, "values")
            out[str(cat).strip().lower()] = str(folder).strip()
        return out

    def dest_add():
        cat = simpledialog.askstring("Add Category", "Key (lowercase, no spaces):", parent=root)
        if not cat: return
        cat = cat.strip().lower()
        if any(ch.isspace() for ch in cat) or not cat.isascii():
            messagebox.showwarning("Invalid", "Use ASCII without spaces."); return
        if cat in current_dest_dirs():
            messagebox.showwarning("Exists", f"'{cat}' already exists."); return
        folder = filedialog.askdirectory(title=f"Select folder for '{cat}'") or ""
        dest_tree.insert("", "end", values=(cat, folder))

    def dest_rename():
        sel = dest_tree.selection()
        if not sel: return
        old_cat, old_folder = dest_tree.item(sel[0], "values")
        new_cat = simpledialog.askstring("Rename Category", "New key:", initialvalue=old_cat, parent=root)
        if not new_cat: return
        new_cat = new_cat.strip().lower()
        if new_cat != old_cat and new_cat in current_dest_dirs():
            messagebox.showwarning("Exists", f"'{new_cat}' already exists."); return
        dest_tree.item(sel[0], values=(new_cat, old_folder))

    def dest_remove():
        sel = dest_tree.selection()
        if not sel: return
        cat, _ = dest_tree.item(sel[0], "values")
        if cat in ("archives", "installers", "docs"):
            if not messagebox.askyesno("Confirm", f"Remove default '{cat}'?"): return
        dest_tree.delete(sel[0])

    def dest_browse():
        sel = dest_tree.selection()
        if not sel: return
        cat, _ = dest_tree.item(sel[0], "values")
        folder = filedialog.askdirectory(title=f"Select folder for '{cat}'")
        if not folder: return
        dest_tree.item(sel[0], values=(cat, folder))

    def dest_open():
        sel = dest_tree.selection()
        if not sel: return
        _, folder = dest_tree.item(sel[0], "values")
        folder = str(folder).strip()
        if folder and os.path.isdir(folder):
            os.startfile(folder)

    dest_toolbar = ttk.Frame(dest_frame)
    dest_toolbar.grid(row=1, column=0, sticky="w", padx=8, pady=6)
    for btn in (
        ttk.Button(dest_toolbar, text="Add", command=dest_add, bootstyle=SUCCESS),
        ttk.Button(dest_toolbar, text="Rename", command=dest_rename),
        ttk.Button(dest_toolbar, text="Browse...", command=dest_browse),
        ttk.Button(dest_toolbar, text="Remove", command=dest_remove, bootstyle=DANGER),
        ttk.Button(dest_toolbar, text="Open", command=dest_open),
    ):
        btn.pack(side="left", padx=4)

    # ----- Rules -----
    rules_frame = ttk.Labelframe(rules_tab, text="Rules (first match wins)", style="Card.TLabelframe")
    rules_frame.pack(fill="both", expand=True, padx=10, pady=10)
    rules_frame.columnconfigure(0, weight=1)
    rules_frame.rowconfigure(0, weight=1)

    rules_frame.columnconfigure(0, weight=1)
    rules_frame.rowconfigure(0, weight=1)

    rule_cols = ("enabled", "type", "field", "category")
    rule_tree = ttk.Treeview(rules_frame, columns=rule_cols, show="headings", height=8, bootstyle=PRIMARY)
    rule_tree.heading("enabled", text="Enabled")
    rule_tree.heading("type", text="Type")
    rule_tree.heading("field", text="Pattern / Extensions")
    rule_tree.heading("category", text="Category")

    rule_tree.column("enabled", width=90, stretch=False, anchor="w")
    rule_tree.column("type", width=90, stretch=False, anchor="w")
    rule_tree.column("field", width=420, stretch=True, anchor="w")
    rule_tree.column("category", width=140, stretch=False, anchor="w")


    # rule_cols = ("enabled", "type", "field", "category")
    # rule_tree = ttk.Treeview(rules_frame, columns=rule_cols, show="headings", height=6, bootstyle=PRIMARY)
    # for c, w in (("enabled", 110), ("type", 110), ("field", 560), ("category", 200)):
    #     rule_tree.heading(c, text=c.capitalize()); rule_tree.column(c, width=w, anchor="w")
    # rule_tree.grid(row=0, column=0, columnspan=6, sticky="nsew", padx=8, pady=8)
    # yscroll_rule = ttk.Scrollbar(rules_frame, orient="vertical", command=rule_tree.yview)
    # rule_tree.configure(yscrollcommand=yscroll_rule.set)
    # yscroll_rule.grid(row=0, column=6, sticky="ns")

    for row in rules_to_rows(rules):
        rule_tree.insert("", "end", values=row)

    def current_rule_rows() -> list[tuple]:
        return [rule_tree.item(iid, "values") for iid in rule_tree.get_children("")]

    def rule_add():
        rtype = simpledialog.askstring("Rule Type", "Type (glob|ext):", parent=root, initialvalue="glob")
        if not rtype: return
        rtype = rtype.strip().lower()
        if rtype not in ("glob", "ext"):
            messagebox.showwarning("Invalid", "Type must be 'glob' or 'ext'."); return
        field = simpledialog.askstring("Pattern / Exts", "Glob pattern or space-separated extensions:",
                                       parent=root, initialvalue="*invoice*")
        if not field: return
        cat = simpledialog.askstring("Category", "Target category (must exist in Destinations):",
                                     parent=root, initialvalue="docs")
        if not cat: return
        cat = cat.strip().lower()
        if cat not in current_dest_dirs():
            messagebox.showwarning("Unknown category", f"'{cat}' has no destination. Add it first in Destinations."); return
        rule_tree.insert("", "end", values=(True, rtype, field.strip(), cat))

    def rule_edit():
        sel = rule_tree.selection()
        if not sel: return
        en, rtype, field, cat = rule_tree.item(sel[0], "values")
        en2 = simpledialog.askstring("Enabled (true/false)", "Enabled:", initialvalue=str(bool(en)), parent=root) or str(bool(en))
        rtype2 = simpledialog.askstring("Type (glob|ext)", "Type:", initialvalue=rtype, parent=root) or rtype
        field2 = simpledialog.askstring("Pattern / Exts", "Value:", initialvalue=field, parent=root) or field
        cat2 = simpledialog.askstring("Category", "Category:", initialvalue=cat, parent=root) or cat
        rtype2 = rtype2.strip().lower()
        cat2 = cat2.strip().lower()
        if cat2 not in current_dest_dirs():
            messagebox.showwarning("Unknown category", f"'{cat2}' has no destination."); return
        rule_tree.item(sel[0], values=(str(en2).lower().startswith("t"), rtype2, field2.strip(), cat2))

    def rule_delete():
        sel = rule_tree.selection()
        if not sel: return
        rule_tree.delete(sel[0])

    def rule_toggle():
        sel = rule_tree.selection()
        if not sel: return
        en, rtype, field, cat = rule_tree.item(sel[0], "values")
        rule_tree.item(sel[0], values=(not bool(en), rtype, field, cat))

    def rule_move(delta: int):
        sel = rule_tree.selection()
        if not sel: return
        iid = sel[0]
        siblings = rule_tree.get_children("")
        i = siblings.index(iid)
        j = max(0, min(len(siblings) - 1, i + delta))
        if j == i: return
        vals = rule_tree.item(iid, "values")
        rule_tree.delete(iid)
        new_iid = rule_tree.insert("", j, values=vals)
        rule_tree.selection_set(new_iid)

    def rule_template_picker():
        menu = tk.Menu(root, tearoff=0)
        for label, template in RULE_TEMPLATES:
            def _add(t=template):
                cat = t.get("category", "").strip().lower()
                if cat and cat not in current_dest_dirs():
                    messagebox.showwarning("Unknown category", f"'{cat}' is not defined in Destinations.")
                    return
                if t.get("type") == "ext":
                    rule_tree.insert("", "end", values=(bool(t.get("enabled", True)), "ext", " ".join(t.get("exts", [])), cat))
                elif t.get("type") == "glob":
                    rule_tree.insert("", "end", values=(bool(t.get("enabled", True)), "glob", t.get("pattern", ""), cat))
            menu.add_command(label=label, command=_add)
        try:
            menu.tk_popup(root.winfo_pointerx(), root.winfo_pointery())
        finally:
            menu.grab_release()

    def rule_import():
        path = filedialog.askopenfilename(title="Import rules (JSON)", filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, list):
                raise ValueError("Expected a list of rules.")
        except Exception as e:
            messagebox.showerror("Import failed", f"Could not import rules: {e}")
            return
        # clear current
        for iid in rule_tree.get_children(""):
            rule_tree.delete(iid)
        for row in rules_to_rows(data):
            rule_tree.insert("", "end", values=row)
        send_notification("Organizer", f"Imported {len(rule_tree.get_children(''))} rules from {os.path.basename(path)}")

    def rule_export():
        path = filedialog.asksaveasfilename(
            title="Export rules (JSON)",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            rules_out = rows_to_rules(current_rule_rows())
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                json.dump(rules_out, f, indent=2)
            send_notification("Organizer", f"Exported {len(rules_out)} rules to {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Export failed", f"Could not export rules: {e}")

    rule_toolbar = ttk.Frame(rules_frame)
    rule_toolbar.grid(row=1, column=0, sticky="w", padx=8, pady=6)
    for btn in (
        ttk.Button(rule_toolbar, text="Add", command=rule_add, bootstyle=SUCCESS),
        ttk.Button(rule_toolbar, text="Edit", command=rule_edit),
        ttk.Button(rule_toolbar, text="Delete", command=rule_delete, bootstyle=DANGER),
        ttk.Button(rule_toolbar, text="Enable/Disable", command=rule_toggle, bootstyle=WARNING),
        ttk.Button(rule_toolbar, text="Up", command=lambda: rule_move(-1)),
        ttk.Button(rule_toolbar, text="Down", command=lambda: rule_move(1)),
        ttk.Button(rule_toolbar, text="Templates", command=rule_template_picker, bootstyle=INFO),
        ttk.Button(rule_toolbar, text="Import", command=rule_import),
        ttk.Button(rule_toolbar, text="Export", command=rule_export),
    ):
        btn.pack(side="left", padx=4)
    

    # ----- Journal (collapsible + pretty) -----
    journal_visible = tk.BooleanVar(value=False)

    toggle_row = ttk.Frame(content)
    toggle_row.grid(row=2, column=0, columnspan=2, sticky="ew", padx=12, pady=(0,4))

    jrnl_container = ttk.Labelframe(content, text="Recent Activity (journal)", style="Card.TLabelframe")
    jrnl_container.grid(row=3, column=0, columnspan=2, sticky="nsew", padx=12, pady=(0,8))
    jrnl_container.columnconfigure(0, weight=1)
    jrnl_container.rowconfigure(0, weight=1)

    txt = tk.Text(jrnl_container, wrap="none")
    ys = ttk.Scrollbar(jrnl_container, orient="vertical", command=txt.yview, style="Thin.Vertical.TScrollbar")
    txt.configure(yscrollcommand=ys.set, state="disabled")
    txt.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
    ys.grid(row=0, column=1, sticky="ns", pady=8)

    # colored tags
    txt.tag_config("time", foreground="#888")
    txt.tag_config("planned", foreground="#0d6efd")
    txt.tag_config("finalized", foreground="#20c997")
    txt.tag_config("executed", foreground="#198754")
    txt.tag_config("failed", foreground="#dc3545")
    txt.tag_config("skip", foreground="#6c757d")

    def render_line(line: str) -> list[tuple[str, str]]:
        try:
            rec = json.loads(line)
        except Exception:
            return [(line + "\n", "")]
        event = rec.get("event") or rec.get("extra", {}).get("event") or "event"
        ts = rec.get("ts_iso") or rec.get("time") or rec.get("record", {}).get("time")
        src = rec.get("src") or rec.get("extra", {}).get("src")
        dest = rec.get("dest") or rec.get("extra", {}).get("dest")
        op = rec.get("op") or rec.get("extra", {}).get("op")
        reason = rec.get("reason") or rec.get("extra", {}).get("reason")
        cat = rec.get("category") or rec.get("extra", {}).get("category")
        try:
            if isinstance(ts, str) and "T" in ts:
                tdisp = ts.split("T")[1][:8]
            elif isinstance(ts, str):
                tdisp = ts[:8]
            else:
                tdisp = ""
        except Exception:
            tdisp = ""
        parts: list[tuple[str, str]] = []
        if tdisp:
            parts.append((tdisp + " ", "time"))
        tag = str(event).lower()
        parts.append((f"[{event}] ", tag if tag in ("planned","finalized","executed","failed","skip") else ""))
        body = []
        if op: body.append(op)
        if src and dest:
            body.append(f"{src} -> {dest}")
        elif src:
            body.append(src)
        if cat: body.append(f"({cat})")
        if reason: body.append(f"- {reason}")
        parts.append((" ".join(body) + "\n", ""))
        return parts

    def refresh_journal(force: bool = False):
        if not journal_visible.get() and not force:
            root.after(1000, refresh_journal); return
        lines = tail_file_bytes(JOURNAL_PATH)
        txt.configure(state="normal"); txt.delete("1.0", "end")
        for ln in lines:
            for chunk, tag in render_line(ln):
                if tag:
                    txt.insert("end", chunk, tag)
                else:
                    txt.insert("end", chunk)
        txt.configure(state="disabled")
        root.after(1000, refresh_journal)

    def toggle_journal():
        if journal_visible.get():
            journal_visible.set(False)
            jrnl_container.grid_remove()
            toggle_btn.configure(text="Show Recent Activity")
        else:
            journal_visible.set(True)
            jrnl_container.grid()
            toggle_btn.configure(text="Hide Recent Activity")
            refresh_journal(force=True)
        _on_content_configure()  # update scrollregion after show/hide

    toggle_btn = ttk.Button(toggle_row, text="Show Recent Activity", command=toggle_journal, bootstyle=SECONDARY)
    toggle_btn.pack(side="left")

    jrnl_container.grid_remove()   # start hidden
    refresh_journal()              # schedule timer

    # --- Right column: Actions & Settings ---
    right = ttk.Labelframe(content, text="Actions", style="Card.TLabelframe")
    right.grid(row=1, column=1, sticky="nsew", padx=(0,12), pady=8)
    right.columnconfigure(0, weight=1)
    right.rowconfigure(4, weight=1)  # spacer to keep buttons anchored lower

    ttk.Label(right, text="Watcher & notifications", style="SectionHeading.TLabel").grid(row=0, column=0, sticky="w", padx=8, pady=(6,2))
    ttk.Label(right, textvariable=status_var, wraplength=260).grid(row=1, column=0, sticky="w", padx=8, pady=(0,6))

    # toggles
    background_var = tk.BooleanVar(master=root, value=True)
    ttk.Checkbutton(right, text="Run in background", variable=background_var).grid(row=2, column=0, sticky="w", padx=8)

    notify_var = tk.BooleanVar(value=bool(raw.get("notify", False)))
    ttk.Checkbutton(right, text="Notifications", variable=notify_var).grid(row=3, column=0, sticky="w", padx=8)

    def gather_config() -> dict:
      dests = {}
      for iid in dest_tree.get_children(""):
          cat, folder = dest_tree.item(iid, "values")
          dests[str(cat).strip().lower()] = str(folder).strip()
      r_rows = [rule_tree.item(i, "values") for i in rule_tree.get_children("")]
      return {
          "watch_root": watch_var.get().strip(),
          "dest_dirs": dests,
          "rules": rows_to_rules(r_rows),
          "notify": bool(notify_var.get()),   # NEW
      }

    def reload_cfg():
        nonlocal cfg, dest_dirs, rules
        cfg = load_config()
        dest_dirs = cfg["dest_dirs"]
        rules = cfg.get("rules", [])
        raw2 = read_raw_config(cfg["path"])
        watch_var.set(raw2.get("watch_root", watch_var.get()))
        notify_var.set(bool(raw2.get("notify", notify_var.get())))
        # refresh tables
        for iid in dest_tree.get_children(""):
            dest_tree.delete(iid)
        for k, v in dest_dirs.items():
            dest_tree.insert("", "end", values=(k, v))
        for iid in rule_tree.get_children(""):
            rule_tree.delete(iid)
        for row in rules_to_rows(rules):
            rule_tree.insert("", "end", values=row)
        # messagebox.showinfo("Reloaded", "Configuration reloaded from disk.")
        send_notification("Reloaded", "Configuration reloaded from disk.")
        _on_content_configure()

    # ttk.Button(bottom, text="Reload", command=reload_cfg, bootstyle=SECONDARY).pack(side="left", padx=6)

    # --- Tray mode ---
    tray_icon = None
    tray_pause_timer = None

    def show_window():
        root.deiconify()
        root.after(10, lambda: (root.lift(), root.focus_force()))

    def _tray_menu():
        return pystray.Menu(
            pystray.MenuItem("Show Organizer", lambda icon, item: root.after(0, show_window)),
            pystray.MenuItem("Start watcher", lambda icon, item: root.after(0, start_watcher)),
            pystray.MenuItem("Stop watcher", lambda icon, item: root.after(0, stop_watcher)),
            pystray.MenuItem("Pause 30 minutes", lambda icon, item: root.after(0, tray_pause_30m)),
            pystray.MenuItem("Open config", lambda icon, item: root.after(0, lambda: webbrowser.open(f"file:///{cfg_path}"))),
            pystray.MenuItem("Open journal folder", lambda icon, item: root.after(0, lambda: os.startfile(os.path.dirname(JOURNAL_PATH)))),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", lambda icon, item: root.after(0, lambda: (_stop_tray_icon(), root.destroy()))),
        )

    def _stop_tray_icon():
        nonlocal tray_icon
        if tray_icon:
            try:
                tray_icon.stop()
            except Exception:
                pass
            tray_icon = None

    def ensure_tray_icon():
        nonlocal tray_icon
        if pystray is None or Image is None:
            messagebox.showwarning("Tray unavailable", "Install pystray and Pillow to enable the system tray.")
            return None
        if tray_icon:
            return tray_icon
        img = _load_tray_image()
        if img is None:
            messagebox.showwarning("Tray unavailable", "Could not load tray icon image.")
            return None
        tray_icon = pystray.Icon("Organizer", img, "Organizer", _tray_menu())
        threading.Thread(target=tray_icon.run, daemon=True).start()
        return tray_icon

    def hide_to_tray():
        if ensure_tray_icon() is None:
            return
        root.withdraw()
        send_notification("Organizer", "Window hidden; running in system tray.")

    def tray_pause_30m():
        nonlocal tray_pause_timer
        stop_watcher()
        if tray_pause_timer:
            root.after_cancel(tray_pause_timer)
        tray_pause_timer = root.after(30 * 60 * 1000, start_watcher)
        send_notification("Organizer", "Paused for 30 minutes; will auto-resume.")


    # PID-based control so UI restarts can still stop the watcher
    def update_status():
        rec = read_pidfile()
        run_txt = "running" if rec and is_pid_running(rec.get("pid", -1)) else "stopped"
        auto_txt = "autostart:on" if is_autostart_enabled() else "autostart:off"
        if rec and is_pid_running(rec.get("pid", -1)):
            status_var.set(f"Watcher: {run_txt} (PID {rec['pid']}) - {rec.get('watch_root', '')} - {auto_txt}")
        else:
            status_var.set(f"Watcher: {run_txt} - {auto_txt}")
    def start_watcher():
        rec = read_pidfile()
        if rec and is_pid_running(rec.get("pid", -1)):
            # messagebox.showinfo("Watcher", f"Already running (PID {rec['pid']})."); update_status(); return
            send_notification("Organizer", f"Already running (PID {rec['pid']})."); update_status(); return

        root_dir = watch_var.get().strip()
        if not root_dir:
            messagebox.showwarning("Watcher", "Set Watch root first."); return

        # Persist config first so organizer reads latest
        cfg_new = gather_config()
        try:
            save_config_atomic(cfg_path, cfg_new)
        except Exception as e:
            messagebox.showerror("Error", f"Save failed: {e}"); return

        exe = pythonw_exe() if background_var.get() else sys.executable
        flags = 0
        if exe == sys.executable and background_var.get():
            flags = subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP

        cmd = [exe, "-m", "organizer.watcher", "--watch", root_dir]
        if bool(notify_var.get()): cmd.append("--notify")
        try:
            out = subprocess.DEVNULL if background_var.get() else None
            err = subprocess.DEVNULL if background_var.get() else None
            proc = subprocess.Popen(cmd, creationflags=flags, stdout=out, stderr=err, close_fds=True)
            write_pidfile(proc.pid, root_dir)
            send_notification("Organizer", f"Started (PID {proc.pid}).")
            # messagebox.showinfo("Watcher", f"Started (PID {proc.pid}).")
        except Exception as e:
            messagebox.showerror("Watcher", f"Failed to start: {e}")
        finally:
            update_status()

    def stop_watcher():
        rec = read_pidfile()
        if not rec:
            send_notification("Organizer", "Not running"); update_status(); return
            # messagebox.showinfo("Watcher", "Not running (no PID file)."); update_status(); return
            
        pid = int(rec.get("pid", -1))
        if pid < 0 or not is_pid_running(pid):
            remove_pidfile()
            send_notification("Organizer", "Not running"); update_status(); return
            # messagebox.showinfo("Watcher", "Not running."); update_status(); return
        try:
            subprocess.run(["taskkill", "/PID", str(pid), "/T"], check=False, capture_output=True)
            if is_pid_running(pid):
                subprocess.run(["taskkill", "/F", "/PID", str(pid), "/T"], check=False, capture_output=True)
            if not is_pid_running(pid):
                remove_pidfile()
                # messagebox.showinfo("Watcher", "Stopped.")
                send_notification("Organizer", "Stopped")
            else:
                messagebox.showwarning("Watcher", "Failed to stop watcher.")
        except Exception as e:
            messagebox.showerror("Watcher", f"Failed to stop: {e}")
        finally:
            update_status()

    def restart_watcher():
        rec = read_pidfile()
        running = bool(rec and is_pid_running(rec.get("pid", -1)))
        if running:
            stop_watcher()
            start_watcher()
        else:
            start_watcher()

    def save_all():
        cfg_new = gather_config()
        try:
            save_config_atomic(cfg_path, cfg_new)
        except Exception as e:
            messagebox.showerror("Error", f"Save failed: {e}")
            return
        rec = read_pidfile()
        running = bool(rec and is_pid_running(rec.get("pid", -1)))
        if running:
            if messagebox.askyesno("Config saved", "Restart watcher now to apply changes?"):
                restart_watcher()
            else:
                # messagebox.showinfo("Watcher", "Changes will apply on next restart.")
                send_notification("Organizer", "Changes will apply on next restart.")
        else:
            # messagebox.showinfo("Saved", "Configuration saved.")
            send_notification("Saved", "Configuration saved.")
        update_status()

    # buttons
    btns = ttk.Frame(right)
    btns.grid(row=5, column=0, sticky="ew", padx=8, pady=8)
    btns.columnconfigure(0, weight=1)
    actions = [
        ("Start Watcher", start_watcher, SUCCESS, True),
        ("Stop Watcher",  stop_watcher, DANGER, True),
        ("Save",          save_all,     PRIMARY, True),
        ("Reload",        reload_cfg,   SECONDARY, True),
        ("Hide to Tray",  hide_to_tray, INFO, pystray is not None and Image is not None),
    ]
    for text, cmd, style, enabled in actions:
        btn = ttk.Button(btns, text=text, command=cmd, bootstyle=style)
        if not enabled:
            btn.state(["disabled"])
        btn.pack(fill="x", pady=4)

    # ttk.Button(bottom, text="Start Watcher", command=start_watcher, bootstyle=SUCCESS).pack(side="right")
    # ttk.Button(bottom, text="Stop Watcher", command=stop_watcher, bootstyle=DANGER).pack(side="right", padx=6)
    # ttk.Button(bottom, text="Save", command=save_all, bootstyle=PRIMARY).pack(side="right", padx=6)

    # Status ticker + initial fill
    update_status()
    def tick():
        update_status()
        root.after(1500, tick)
    tick()

    # Initial sizing/scroll
    root.after(50, _on_content_configure)
    root.mainloop()


if __name__ == "__main__":
    main()
