from organizer.planner import decide_action


def test_decide_action_skips_hidden_and_temp_files():
    assert decide_action(r"C:\temp\.secret")[0] == "skip"
    assert decide_action(r"C:\temp\video.mp4.crdownload")[3] == "temporary_or_hidden"


def test_decide_action_prefers_enabled_custom_rule():
    rules = [
        {"type": "glob", "pattern": "*invoice*", "category": "docs", "enabled": True},
        {"type": "ext", "exts": [".pdf"], "category": "archives", "enabled": True},
    ]

    op, category, base, reason = decide_action(r"C:\temp\March-Invoice.pdf", rules)

    assert (op, category, base) == ("move", "docs", "March-Invoice.pdf")
    assert reason == "rule:glob:*invoice*"


def test_decide_action_ignores_disabled_rules_and_uses_fallbacks():
    rules = [
        {"type": "glob", "pattern": "*.zip", "category": "docs", "enabled": False},
    ]

    assert decide_action(r"C:\temp\archive.zip", rules) == (
        "move",
        "archives",
        "archive.zip",
        "rule:archives",
    )


def test_decide_action_handles_extension_rules_case_insensitively():
    rules = [
        {"type": "ext", "exts": [".PDF", " .TXT "], "category": "docs", "enabled": True},
    ]

    assert decide_action(r"C:\temp\notes.txt", rules) == (
        "move",
        "docs",
        "notes.txt",
        "rule:ext:['.PDF', ' .TXT ']",
    )
