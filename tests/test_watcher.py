from pathlib import Path

from organizer.watcher import execute, next_available


def test_next_available_appends_counter(tmp_path: Path):
    target = tmp_path / "report.pdf"
    target.write_text("one", encoding="utf-8")
    (tmp_path / "report (2).pdf").write_text("two", encoding="utf-8")

    assert next_available(str(target)).endswith("report (3).pdf")


def test_execute_dry_run_leaves_source_in_place(tmp_path: Path):
    source = tmp_path / "sample.txt"
    source.write_text("payload", encoding="utf-8")
    dest = tmp_path / "dest" / "sample.txt"

    assert execute("move", str(source), str(dest), dry_run=True)
    assert source.exists()
    assert not dest.exists()


def test_execute_moves_file_and_creates_destination(tmp_path: Path):
    source = tmp_path / "sample.txt"
    source.write_text("payload", encoding="utf-8")
    dest = tmp_path / "nested" / "sample.txt"

    assert execute("move", str(source), str(dest), dry_run=False)
    assert not source.exists()
    assert dest.read_text(encoding="utf-8") == "payload"


def test_execute_rejects_unknown_operations(tmp_path: Path):
    source = tmp_path / "sample.txt"
    source.write_text("payload", encoding="utf-8")
    dest = tmp_path / "nested" / "sample.txt"

    assert not execute("copy", str(source), str(dest), dry_run=False)
    assert source.exists()
