import os, fnmatch

EXT_SETS = {
    "Archives": {".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz"},
    "Installers": {".exe", ".msi", ".msix", ".msixbundle"},
    "Docs": {".pdf", ".doc", ".docx", ".txt", ".md", ".rtf"},
}

TEMP_SUFFIXES = (".crdownload", ".tmp", ".part")
DEFAULT_RULES: list[dict] = []


def decide_action(path: str, rules: list[dict]=None) -> tuple[str, str, str, str]:
  rules = DEFAULT_RULES if rules is None else rules
  
  base = os.path.basename(path)
  name = base.lower()
  file_ext = os.path.splitext(base)[1].lower()
  
  # custom rules
  for r in rules:
    if not r["enabled"]: continue
    match r.get("type"):
      case "glob":
        if fnmatch.fnmatch(name, r["pattern"].lower()):
          return ("move", r["category"], base, f"rule:glob:{r['pattern']}")
      case "ext":
        if file_ext in r["exts"]:
          return ("move", r["category"], base, f"rule:ext:{r['exts']}")

  # extension fallbacks
  if base.startswith(".") or base.lower().endswith(TEMP_SUFFIXES):
      return ("skip", None, None, "temporary_or_hidden")
  if file_ext in EXT_SETS["Archives"]:
      return ("move", "archives", base, "rule:archives")
  if file_ext in EXT_SETS["Docs"]:
      return ("move", "docs", base, "rule:docs")
  if file_ext in EXT_SETS["Installers"]:
      return ("move", "installers", base, "rule:installers")
    
  return ("skip", None, None, "no_rule")