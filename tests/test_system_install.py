"""System install (guard/system_install.py, guard_cli.py system-install; 2026-10-23), into a temporary root (--root):
files, permissions, compiled cache, Claude Code managed-settings drop-in, refusals. run: python3 tests/test_system_install.py"""
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

with tempfile.TemporaryDirectory() as t:
    t = Path(t)
    dist = t / "dist"
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "build_dist.py"), "test", "--out", str(dist), "--skip-tests"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    cli = lambda *a: subprocess.run([sys.executable, "-I", str(dist / "guard_cli.py"), *a], capture_output=True, text=True)  # noqa: E731

    if os.geteuid() != 0:                                        # a plain user is told to use sudo
        p = cli("system-install")
        assert p.returncode == 2 and "sudo" in p.stdout, p.stdout
    p = cli("system-install", "--dry-run", "--managed-hooks-only")
    assert p.returncode == 0 and '"allowManagedHooksOnly": true' in p.stdout and "/opt/agent-dependency-guard/hooks/pretooluse_check.py" in p.stdout

    root = t / "root"
    p = cli("system-install", "--root", str(root))
    assert p.returncode == 0, p.stdout + p.stderr
    inst = root / "opt" / "agent-dependency-guard"
    assert (inst / "guard_core.py").is_file() and (inst / "RELEASE_MANIFEST.json").is_file()
    assert any(inst.joinpath("__pycache__").glob("guard_core.*.pyc"))                      # compiled at install time
    assert stat.S_IMODE((inst / "guard_core.py").stat().st_mode) == 0o644 and stat.S_IMODE(inst.stat().st_mode) == 0o755
    dropin = json.loads((root / "etc" / "claude-code" / "managed-settings.d" / "aasm-guard.json").read_text())
    cmds = [h["command"] for g in dropin["hooks"]["PreToolUse"] for h in g["hooks"]]
    assert cmds == ["python3 -I /opt/agent-dependency-guard/hooks/pretooluse_check.py",
                    "python3 -I /opt/agent-dependency-guard/hooks/pretooluse_editwrite_check.py"], cmds
    assert "allowManagedHooksOnly" not in dropin                                            # opt-in only
    assert json.loads((root / "etc" / "aasm" / "config.json").read_text()) == {"env": {}}
    p = subprocess.run([sys.executable, "-I", str(inst / "guard_cli.py"), "verify"], capture_output=True, text=True)
    assert p.returncode == 0, p.stdout                                                       # the installed copy checks clean
    # the administrator's switches survive a reinstall
    (root / "etc" / "aasm" / "config.json").write_text('{"env": {"AASM_CACHE": "1"}}')
    assert cli("system-install", "--root", str(root)).returncode == 0
    assert "AASM_CACHE" in (root / "etc" / "aasm" / "config.json").read_text()
    # a changed build is not installed
    (dist / "mode.py").write_text((dist / "mode.py").read_text() + "# changed\n")
    p = cli("system-install", "--root", str(t / "root2"))
    assert p.returncode == 1 and "Not installed" in p.stdout and not (t / "root2" / "opt").exists(), p.stdout
    # uninstall removes the guard and the drop-in, not the administrator's config
    p = cli("system-uninstall", "--root", str(root))
    assert p.returncode == 0 and not inst.exists() and not (root / "etc" / "claude-code" / "managed-settings.d" / "aasm-guard.json").exists()
    assert (root / "etc" / "aasm" / "config.json").exists()
print("system_install: all cases passed")
