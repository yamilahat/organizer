import fnmatch
import os

EXT_SETS = {
    "archives": {".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz"},
    "installers": {".exe", ".msi", ".msix", ".msixbundle"},
    "docs": {".pdf", ".doc", ".docx", ".txt", ".md", ".rtf"},
    "images": {".jpeg", ".jpg", ".png", ".gif", ".tiff", ".tif", ".raw", ".heif", ".svg"},
}

TEMP_SUFFIXES = (".crdownload", ".tmp", ".part")
DEFAULT_RULES: list[dict] = []


def _matches_rule(name: str, file_ext: str, rule: dict) -> bool:
    if not rule.get("enabled", True):
        return False

    match rule.get("type"):
        case "glob":
            pattern = str(rule.get("pattern", "")).strip().lower()
            return bool(pattern) and fnmatch.fnmatch(name, pattern)
        case "ext":
            extensions = {
                str(ext).strip().lower()
                for ext in rule.get("exts", [])
                if str(ext).strip()
            }
            return file_ext in extensions
        case _:
            return False


def decide_action(
    path: str,
    rules: list[dict] | None = None,
) -> tuple[str, str | None, str | None, str]:
    rules = DEFAULT_RULES if rules is None else rules

    base = os.path.basename(path)
    name = base.lower()
    file_ext = os.path.splitext(base)[1].lower()

    if base.startswith(".") or name.endswith(TEMP_SUFFIXES):
        return ("skip", None, None, "temporary_or_hidden")

    for rule in rules:
        if not _matches_rule(name, file_ext, rule):
            continue

        category = str(rule.get("category", "")).strip().lower() or None
        reason_value = (
            rule.get("pattern") if rule.get("type") == "glob" else rule.get("exts", [])
        )
        return ("move", category, base, f"rule:{rule.get('type')}:{reason_value}")

    for category, extensions in EXT_SETS.items():
        if file_ext in extensions:
            return ("move", category, base, f"rule:{category}")

    return ("skip", None, None, "no_rule")
