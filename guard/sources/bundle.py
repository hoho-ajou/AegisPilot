"""
AegisPilot - files already on disk as a source: a skill folder, a plugin, a hook script, a local MCP
server script.

Nothing is fetched and nothing is run. The files are copied (bounded) into a scan folder named like an unpacked
archive (`<name>.bundle.unpacked/<name>/...`) so the rules read them exactly as they read a package, with the
"bundle" ecosystem: every language is code and no folder is skipped (a skill's scripts/ folder is what runs).
Text that is not a file - a hook's command line - is written in as a file of its own (`texts`).
"""
from __future__ import annotations

import os
import re
import shutil
from pathlib import Path

MAX_FILES = 3000
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "__pycache__", ".mypy_cache", ".pytest_cache"}
# what the rules can read: code of every language the ruleset knows, plus text an agent reads
TEXT_SUFFIXES = {".md", ".markdown", ".txt", ".json", ".yaml", ".yml", ".toml", ".pth"}


def _safe(name: str) -> str:
    return re.sub(r"[^\w.@+-]+", "_", name)[:80] or "bundle"


def copy_into(paths: list[Path | str], dest: Path, name: str, texts: dict[str, str] | None = None) -> tuple[list[Path], list[str]]:
    """(the copied files, notes on what was left out). A directory is copied with its layout; a file goes to the root
    under its own name; symlinks are never followed (a link could point anywhere on the machine)."""
    import rule_engine
    keep = set(rule_engine.current().lang_of_suffix) | TEXT_SUFFIXES
    root = dest / f"{_safe(name)}.bundle.unpacked" / _safe(name)
    root.mkdir(parents=True, exist_ok=True)
    out, notes, total = [], [], 0

    def take(src: Path, rel: str) -> bool:
        nonlocal total
        if len(out) >= MAX_FILES:
            notes.append(f"only the first {MAX_FILES} files checked")
            return False
        try:
            if src.is_symlink() or not src.is_file():
                return True
            size = src.stat().st_size
        except OSError:
            return True
        if src.suffix.lower() not in keep and src.name.lower() not in ("readme", "skill.md"):
            return True
        if size > MAX_FILE_BYTES:
            notes.append(f"{rel[:80]}: too large, skipped")
            return True
        if total + size > MAX_TOTAL_BYTES:
            notes.append(f"only the first {MAX_TOTAL_BYTES >> 20}MB in total checked")
            return False
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, target, follow_symlinks=False)
        total += size
        out.append(target)
        return True

    for p in paths:
        p = Path(p)
        if p.is_symlink():
            notes.append(f"{p.name}: symbolic links are not followed")
            continue
        if p.is_dir():
            for dirpath, dirnames, filenames in os.walk(p, followlinks=False):
                dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
                for fn in sorted(filenames):
                    src = Path(dirpath) / fn
                    if not take(src, str(src.relative_to(p))):
                        return out, sorted(set(notes))
        elif p.is_file():
            if not take(p, p.name):
                break
    for rel, text in (texts or {}).items():
        target = root / _safe(rel)
        target.write_text(text)
        out.append(target)
    return out, sorted(set(notes))
