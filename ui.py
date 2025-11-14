# ui.py
import os, json, webbrowser, tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog

import ttkbootstrap as tb
from ttkbootstrap.constants import *

from organizer import load_config, JOURNAL_PATH  # reuse your helpers


# ---------- Small utilities ----------

def save_config_atomic(cfg_path: str, cfg: dict) -> None:
    tmp = cfg_path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, cfg_path)

def tail_journal(path: str, last_bytes: int = 120_000) -> str:
    if not os.path.exists(path):
        return ""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END); size = f.tell()
            f.seek(max(0, size - last_bytes), os.SEEK_SET)
            data = f.read().decode("utf-8", errors="replace")
        return "\n".join(data.strip().splitlines()[-200:])
    except Exception as e:
        return f"[journal read error: {e!r}]"


# ---------- Converters (rules <-> tree rows) ----------

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
            out.append({"type":"glob","pattern":str(field).strip(),"category":cat,"enabled":bool(enabled)})
        elif str(rtype) == "ext" and str(field).strip():
            exts = [e.strip().lower() for e in str(field).split() if e.strip()]
            out.append({"type":"ext","exts":exts,"category":cat,"enabled":bool(enabled)})
    return out


# ---------- UI ----------

def main():
    cfg = load_config()
    cfg_path = cfg["path"]
    dest_dirs: dict = cfg["dest_dirs"]
    rules: list[dict] = cfg.get("rules", [])

    # Window (modern theme)
    root = tb.Window(themename="darkly")  # try "flatly", "cosmo", "minty", "darkly"
    root.title("Organizer — Setup")
    root.geometry("980x640")
    root.minsize(880, 560)
    root.columnconfigure(0, weight=1)
    root.rowconfigure(2, weight=1)

    # Header
    header = ttk.Frame(root)
    header.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 6))
    header.columnconfigure(0, weight=1)
    ttk.Label(header, text=f"Config: {cfg_path}", font=("Segoe UI", 10)).grid(row=0, column=0, sticky="w")
    ttk.Button(header, text="Open Config", command=lambda: webbrowser.open(f"file:///{cfg_path}"), bootstyle=SECONDARY).grid(row=0, column=1, padx=6)
    ttk.Button(header, text="Open Journal Folder", command=lambda: os.startfile(os.path.dirname(JOURNAL_PATH)), bootstyle=SECONDARY).grid(row=0, column=2)

    # ----- Destinations (dynamic) -----
    dest_frame = ttk.Labelframe(root, text="Destinations")
    dest_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=6)
    dest_frame.columnconfigure(0, weight=1)
    dest_frame.rowconfigure(0, weight=1)

    # Ensure defaults exist
    for k in ("archives", "installers", "docs"):
        dest_dirs.setdefault(k, dest_dirs.get(k, ""))

    # Tree
    dest_cols = ("category","folder")
    dest_tree = ttk.Treeview(dest_frame, columns=dest_cols, show="headings", height=6, bootstyle=INFO)
    for c, w in (("category", 200),("folder", 640)):
        dest_tree.heading(c, text=c.capitalize())
        dest_tree.column(c, width=w, anchor="w")
    dest_tree.grid(row=0, column=0, columnspan=6, sticky="nsew", padx=6, pady=6)
    ttk.Style().configure("Treeview", rowheight=26)
    yscroll = ttk.Scrollbar(dest_frame, orient="vertical", command=dest_tree.yview)
    dest_tree.configure(yscrollcommand=yscroll.set)
    yscroll.grid(row=0, column=6, sticky="ns")

    # Seed rows
    for k, v in dest_dirs.items():
        dest_tree.insert("", "end", values=(k, v))

    def current_dest_dirs() -> dict:
        out = {}
        for iid in dest_tree.get_children(""):
            cat, folder = dest_tree.item(iid, "values")
            out[str(cat).strip().lower()] = str(folder).strip()
        return out

    def save_all():
        new_cfg = {"dest_dirs": current_dest_dirs(), "rules": rows_to_rules([dest_tree_rules.item(i,"values") for i in dest_tree_rules.get_children("")])}
        try:
            save_config_atomic(cfg_path, new_cfg)
            cfg.update(new_cfg)
        except Exception as e:
            messagebox.showerror("Error", f"Save failed: {e}")

    # Dest actions
    def persist_dests_only():
        new_cfg = {"dest_dirs": current_dest_dirs(), "rules": rules}
        try:
            save_config_atomic(cfg_path, new_cfg)
            cfg.update(new_cfg)
        except Exception as e:
            messagebox.showerror("Error", f"Save failed: {e}")

    def dest_add():
        cat = simpledialog.askstring("Add Category", "Key (lowercase, no spaces):", parent=root)
        if not cat: return
        cat = cat.strip().lower()
        if any(ch.isspace() for ch in cat) or not cat.isascii():
            messagebox.showwarning("Invalid", "Use ASCII without spaces.")
            return
        if cat in current_dest_dirs():
            messagebox.showwarning("Exists", f"'{cat}' already exists.")
            return
        folder = filedialog.askdirectory(title=f"Select folder for '{cat}'") or ""
        dest_tree.insert("", "end", values=(cat, folder))
        persist_dests_only()

    def dest_rename():
        sel = dest_tree.selection()
        if not sel: return
        old_cat, old_folder = dest_tree.item(sel[0], "values")
        new_cat = simpledialog.askstring("Rename Category", "New key:", initialvalue=old_cat, parent=root)
        if not new_cat: return
        new_cat = new_cat.strip().lower()
        if new_cat != old_cat and new_cat in current_dest_dirs():
            messagebox.showwarning("Exists", f"'{new_cat}' already exists.")
            return
        dest_tree.item(sel[0], values=(new_cat, old_folder))
        persist_dests_only()

    def dest_remove():
        sel = dest_tree.selection()
        if not sel: return
        cat, _ = dest_tree.item(sel[0], "values")
        if cat in ("archives","installers","docs"):
            if not messagebox.askyesno("Confirm", f"Remove default '{cat}'?"): return
        dest_tree.delete(sel[0])
        persist_dests_only()

    def dest_browse():
        sel = dest_tree.selection()
        if not sel: return
        cat, _ = dest_tree.item(sel[0], "values")
        folder = filedialog.askdirectory(title=f"Select folder for '{cat}'")
        if not folder: return
        dest_tree.item(sel[0], values=(cat, folder))
        persist_dests_only()

    def dest_open():
        sel = dest_tree.selection()
        if not sel: return
        _, folder = dest_tree.item(sel[0], "values")
        folder = str(folder).strip()
        if folder and os.path.isdir(folder):
            os.startfile(folder)

    ttk.Button(dest_frame, text="Add", command=dest_add, bootstyle=SUCCESS).grid(row=1, column=0, padx=4, pady=4, sticky="w")
    ttk.Button(dest_frame, text="Rename", command=dest_rename).grid(row=1, column=1, padx=4, pady=4, sticky="w")
    ttk.Button(dest_frame, text="Browse…", command=dest_browse).grid(row=1, column=2, padx=4, pady=4, sticky="w")
    ttk.Button(dest_frame, text="Remove", command=dest_remove, bootstyle=DANGER).grid(row=1, column=3, padx=4, pady=4, sticky="w")
    ttk.Button(dest_frame, text="Open", command=dest_open).grid(row=1, column=4, padx=4, pady=4, sticky="e")

    # ----- Rules (add/edit/delete/reorder, auto-save) -----
    rules_frame = ttk.Labelframe(root, text="Rules (first match wins)")
    rules_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=6)
    rules_frame.columnconfigure(0, weight=1)
    rules_frame.rowconfigure(0, weight=1)

    # Tree
    rule_cols = ("enabled","type","field","category")
    dest_tree_rules = ttk.Treeview(rules_frame, columns=rule_cols, show="headings", height=8, bootstyle=PRIMARY)
    for c, w in (("enabled", 90), ("type", 90), ("field", 520), ("category", 160)):
        dest_tree_rules.heading(c, text=c.capitalize())
        dest_tree_rules.column(c, width=w, anchor="w")
    dest_tree_rules.grid(row=0, column=0, columnspan=6, sticky="nsew", padx=6, pady=6)
    ttk.Scrollbar(rules_frame, orient="vertical", command=dest_tree_rules.yview).grid(row=0, column=6, sticky="ns")
    dest_tree_rules.configure(yscrollcommand=lambda *a: None)

    # Seed
    for row in rules_to_rows(rules):
        dest_tree_rules.insert("", "end", values=row)

    def current_rules_rows() -> list[tuple]:
        return [dest_tree_rules.item(iid, "values") for iid in dest_tree_rules.get_children("")]

    def persist_rules_only():
        new_cfg = {"dest_dirs": current_dest_dirs(), "rules": rows_to_rules(current_rules_rows())}
        try:
            save_config_atomic(cfg_path, new_cfg)
            cfg.update(new_cfg)
        except Exception as e:
            messagebox.showerror("Error", f"Save failed: {e}")

    # Rule actions
    def rule_add():
        rtype = simpledialog.askstring("Rule Type", "Type (glob|ext):", parent=root, initialvalue="glob")
        if not rtype: return
        rtype = rtype.strip().lower()
        if rtype not in ("glob","ext"):
            messagebox.showwarning("Invalid", "Type must be 'glob' or 'ext'.")
            return
        field = simpledialog.askstring("Pattern / Exts", "Glob pattern or space-separated extensions:", parent=root, initialvalue="*invoice*")
        if not field: return
        cat = simpledialog.askstring("Category", "Target category (must exist in Destinations):", parent=root, initialvalue="docs")
        if not cat: return
        cat = cat.strip().lower()
        if cat not in current_dest_dirs():
            messagebox.showwarning("Unknown category", f"'{cat}' has no destination. Add it first in Destinations.")
            return
        dest_tree_rules.insert("", "end", values=(True, rtype, field.strip(), cat))
        persist_rules_only()

    def rule_edit():
        sel = dest_tree_rules.selection()
        if not sel: return
        en, rtype, field, cat = dest_tree_rules.item(sel[0], "values")
        en2 = simpledialog.askstring("Enabled (true/false)", "Enabled:", initialvalue=str(bool(en)), parent=root) or str(bool(en))
        rtype2 = simpledialog.askstring("Type (glob|ext)", "Type:", initialvalue=rtype, parent=root) or rtype
        field2 = simpledialog.askstring("Pattern / Exts", "Value:", initialvalue=field, parent=root) or field
        cat2 = simpledialog.askstring("Category", "Category:", initialvalue=cat, parent=root) or cat
        rtype2 = rtype2.strip().lower()
        cat2 = cat2.strip().lower()
        if cat2 not in current_dest_dirs():
            messagebox.showwarning("Unknown category", f"'{cat2}' has no destination.")
            return
        dest_tree_rules.item(sel[0], values=(str(en2).lower().startswith("t"), rtype2, field2.strip(), cat2))
        persist_rules_only()

    def rule_delete():
        sel = dest_tree_rules.selection()
        if not sel: return
        dest_tree_rules.delete(sel[0])
        persist_rules_only()

    def rule_toggle_enable():
        sel = dest_tree_rules.selection()
        if not sel: return
        en, rtype, field, cat = dest_tree_rules.item(sel[0], "values")
        dest_tree_rules.item(sel[0], values=(not bool(en), rtype, field, cat))
        persist_rules_only()

    def rule_move(delta: int):
        sel = dest_tree_rules.selection()
        if not sel: return
        iid = sel[0]
        siblings = dest_tree_rules.get_children("")
        i = siblings.index(iid)
        j = max(0, min(len(siblings)-1, i + delta))
        if j == i: return
        vals = dest_tree_rules.item(iid, "values")
        dest_tree_rules.delete(iid)
        new_iid = dest_tree_rules.insert("", j, values=vals)
        dest_tree_rules.selection_set(new_iid)
        persist_rules_only()

    ttk.Button(rules_frame, text="Add", command=rule_add, bootstyle=SUCCESS).grid(row=1, column=0, padx=4, pady=4, sticky="w")
    ttk.Button(rules_frame, text="Edit", command=rule_edit).grid(row=1, column=1, padx=4, pady=4, sticky="w")
    ttk.Button(rules_frame, text="Delete", command=rule_delete, bootstyle=DANGER).grid(row=1, column=2, padx=4, pady=4, sticky="w")
    ttk.Button(rules_frame, text="Enable/Disable", command=rule_toggle_enable, bootstyle=WARNING).grid(row=1, column=3, padx=4, pady=4, sticky="w")
    ttk.Button(rules_frame, text="Up", command=lambda: rule_move(-1)).grid(row=1, column=4, padx=4, pady=4, sticky="e")
    ttk.Button(rules_frame, text="Down", command=lambda: rule_move(1)).grid(row=1, column=5, padx=4, pady=4, sticky="e")

    # ----- Journal tail -----
    journal_frame = ttk.Labelframe(root, text="Recent Activity (journal tail)")
    journal_frame.grid(row=3, column=0, sticky="nsew", padx=10, pady=(6,10))
    journal_frame.columnconfigure(0, weight=1)
    journal_frame.rowconfigure(0, weight=1)

    txt = tk.Text(journal_frame, height=10, wrap="none")
    txt.configure(state="disabled")
    txt.grid(row=0, column=0, sticky="nsew", padx=6, pady=6)

    def refresh_journal():
        txt.configure(state="normal"); txt.delete("1.0", "end")
        txt.insert("end", tail_journal(JOURNAL_PATH))
        txt.configure(state="disabled")
        root.after(1000, refresh_journal)

    refresh_journal()

    # Bottom bar (Reload + Exit)
    bottom = ttk.Frame(root)
    bottom.grid(row=4, column=0, sticky="ew", padx=10, pady=(0,10))
    bottom.columnconfigure(0, weight=1)

    def reload_cfg():
        nonlocal cfg, dest_dirs, rules
        cfg = load_config()
        dest_dirs = cfg["dest_dirs"]
        rules = cfg.get("rules", [])
        # Dest refresh
        for iid in dest_tree.get_children(""):
            dest_tree.delete(iid)
        for k, v in dest_dirs.items():
            dest_tree.insert("", "end", values=(k, v))
        # Rules refresh
        for iid in dest_tree_rules.get_children(""):
            dest_tree_rules.delete(iid)
        for row in rules_to_rows(rules):
            dest_tree_rules.insert("", "end", values=row)
        messagebox.showinfo("Reloaded", "Configuration reloaded from disk.")

    # Save All (optional manual commit)
    ttk.Button(bottom, text="Reload", command=reload_cfg, bootstyle=SECONDARY).pack(side="left")
    ttk.Button(bottom, text="Save All", command=save_all, bootstyle=PRIMARY).pack(side="right")
    ttk.Button(bottom, text="Exit", command=root.destroy).pack(side="right", padx=6)

    root.mainloop()


if __name__ == "__main__":
    main()
