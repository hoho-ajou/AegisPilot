"""Writes into agent-writable folders never follow a planted link (run: python3 tests/test_write_safety.py). Offline."""
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))
import review_report as RR  # noqa: E402
import safe_write  # noqa: E402

with tempfile.TemporaryDirectory() as d:
    d = Path(d)
    victim = d / "bashrc"
    victim.write_text("original\n")
    project = d / "p"
    (project / ".aegis" / "reviews").mkdir(parents=True)

    # a link at the file name is replaced, not followed
    os.symlink(victim, project / ".aegis" / "attack_paths.json")
    safe_write.write_text(project / ".aegis", "attack_paths.json", "{}")
    assert victim.read_text() == "original\n"
    assert not (project / ".aegis" / "attack_paths.json").is_symlink()

    # a dangling link at .gitignore: nothing is created at its target
    os.symlink(d / "outside.txt", project / ".aegis" / ".gitignore")
    assert RR.write_report(project, {"command": "pip install x", "packages": []})
    assert not (d / "outside.txt").exists()

    # a linked folder on the way is refused (the write fails, nothing lands in the link's target)
    elsewhere = d / "elsewhere"
    elsewhere.mkdir()
    os.symlink(elsewhere, project / ".aegis" / "cache")
    try:
        safe_write.write_text(project / ".aegis", "cache/verdicts.json", "{}")
        raise AssertionError("wrote through a linked folder")
    except OSError:
        pass
    assert list(elsewhere.iterdir()) == []

    # .aegis itself a link: refused too
    other = d / "q"
    other.mkdir()
    os.symlink(elsewhere, other / ".aegis")
    assert not RR.write_report(other, {"command": "pip install x", "packages": []})
    assert list(elsewhere.iterdir()) == []

    # the normal case still works
    fresh = d / "fresh"
    fresh.mkdir()
    assert RR.write_report(fresh, {"command": "pip install x", "packages": []})
    assert json.loads((fresh / ".aegis" / "last_review.json").read_text())["command"] == "pip install x"
    assert (fresh / ".aegis" / ".gitignore").read_text().endswith("*\n")


    # a login in a URL is not kept in the record
    RR.write_report(fresh, {"command": "pip install -i https://me:S3CRET@pypi.corp/simple x", "packages": []})
    text = (fresh / ".aegis" / "last_review.json").read_text()
    assert "S3CRET" not in text and "https://***@pypi.corp/simple" in text, text

print("ok")
