# Installing AegisPilot

There are three ways to install AegisPilot. Use one of them.

| Method | For | Who can turn it off |
| --- | --- | --- |
| [Plugin](#plugin-install-recommended) | Claude Code users | the user (`claude plugin disable`) |
| [Manual install from a clone](#manual-install-from-a-clone) | Claude Code without plugins, and Codex CLI | the user (edit the settings file) |
| [System install](#system-install-for-administrators) | administrators of shared or managed machines | root only |

## Requirements

| | Plugin | Manual | System |
| --- | --- | --- | --- |
| Python | 3.11 or later as `python3` | 3.11 or later as `python3` | 3.11 or later as `python3` |
| Python packages | none (the one library it needs, packaging, is bundled) | none | none |
| Agent | Claude Code with plugin support | Claude Code, or Codex CLI | Claude Code |
| Operating system | any that runs Claude Code | any that runs the agent | Linux or macOS |
| Privileges | none | none | root (`sudo`) |
| Network | PyPI, npm registry, OSV (see [privacy.md](privacy.md)) | same | same |

## Plugin install (recommended)

```bash
claude plugin marketplace add hoho-ajou/AegisPilot
claude plugin install aegis-pilot@hoho-ajou
```

Start a new Claude Code session afterwards. The plugin registers:

- a `PreToolUse` hook on `Bash` (`hooks/pretooluse_check.py`), which checks install and settings-change commands;
- a `PreToolUse` hook on `Edit`, `MultiEdit` and `Write` (`hooks/pretooluse_editwrite_check.py`), which checks edits of agent settings, package-index settings and the guard's own files;
- a `SessionStart` hook, which prints a notice when Python 3.11 or later is missing, and a warning when the guard is also registered in a settings file;
- the `aegis` skill. Type `/aegis` (shown as `/aegis-pilot:aegis`) to get the last decision explained.

The marketplace entry pins the plugin to a release tag, so you get a released build with its checksum list.

## Manual install from a clone

Use this when you cannot use plugins, or for Codex CLI.

1. Clone a release tag. A release tag contains the checksum list the integrity check uses; the default branch does not.

   ```bash
   git clone --branch v0.1.0 https://github.com/hoho-ajou/AegisPilot.git ~/AegisPilot
   ```

2. Optional: check that the guard decides as expected. This changes no settings and needs network access to PyPI and OSV.

   ```bash
   python3 ~/AegisPilot/guard/guard_cli.py selftest
   ```

3. Print the hook settings. The command prints a `hooks` block with this clone's absolute paths. It never writes a settings file.

   ```bash
   python3 ~/AegisPilot/guard/guard_cli.py snippet
   ```

   Merge the output into `.claude/settings.json` of a project, or into `~/.claude/settings.json` for every project. Start a new session afterwards.

4. Optional: link the skill folder so that `/aegis` works.

   ```bash
   mkdir -p ~/.claude/skills
   ln -s ~/AegisPilot/guard/skills/aegis ~/.claude/skills/aegis
   ```

   The guard works the same without the skill. Only the `/aegis` explanation is missing.

### Codex CLI

```bash
python3 ~/AegisPilot/guard/guard_cli.py snippet codex
```

Merge the output into `<repo>/.codex/hooks.json` or `~/.codex/hooks.json`. Codex requires a project to be trusted before its project hooks run, and asks you to review new hooks with `/hooks`.

Codex hooks cannot ask a person. Every action that would ask in Claude Code is refused in Codex, with the same reason.

## System install for administrators

A system install puts the guard where the agent cannot change it. An agent runs as the developer and cannot change root-owned files without `sudo`.

Run it from a release build: a clone of a release tag (see above) or the plugin's installed folder. The command refuses to install a guard whose files differ from its own checksums.

```bash
sudo python3 guard/guard_cli.py system-install
```

It does the following:

1. Copies the guard to `/opt/agent-dependency-guard`, owned by root, directories `0755`, files `0644`.
2. Compiles it there as root, so users cannot plant `.pyc` files.
3. Registers the hooks in Claude Code's managed settings with a drop-in file. Hooks in user or project settings cannot remove it.
   - Linux: `/etc/claude-code/managed-settings.d/aasm-guard.json`
   - macOS: `/Library/Application Support/ClaudeCode/managed-settings.d/aasm-guard.json`
4. Creates `/etc/aasm/config.json` for the administrator's switches, if it does not exist. See [configuration.md](configuration.md#environment-switches).

Options:

| Option | Effect |
| --- | --- |
| `--prefix DIR` | install somewhere other than `/opt/agent-dependency-guard` |
| `--managed-hooks-only` | also sets `allowManagedHooksOnly`: only managed hooks run. This turns off every user and project hook, not only other guard hooks. |
| `--dry-run` | print what would be done, including the drop-in file, and change nothing. Does not need root. |

Check the result:

```bash
python3 /opt/agent-dependency-guard/guard_cli.py verify
```

On WSL, `/etc/claude-code` is writable by the user, so a system install there is not out of the agent's reach. Codex has no system-wide hook location that the guard uses; Codex hooks stay per user or per project.

## Using more than one install

If the guard is registered twice (for example the plugin and a hook block in `~/.claude/settings.json`), every check runs twice. AegisPilot looks for this in three places:

- The plugin's `SessionStart` hook prints a warning when the guard is also registered in a settings file.
- `guard_cli.py snippet` and `guard_cli.py system-install` warn when another install exists and ask whether to skip or overwrite.
- `guard_cli.py installs` lists every AegisPilot install it finds: the plugin, guard hooks in settings files, and the system install.

```bash
python3 guard/guard_cli.py installs
```

In an interactive terminal, `installs` lets you choose the one to keep. The others are turned off:

| Install | How it is turned off |
| --- | --- |
| Plugin | disabled in settings |
| Guard hooks in a settings file | removed from the file. The previous file is kept with a `.bak` suffix. |
| System install | not changed. Remove it with `sudo python3 /opt/agent-dependency-guard/guard_cli.py system-uninstall`. |

When these commands run without a terminal (for example, run by an agent), they change nothing and only print the warning. If the agent runs `installs`, `repair`, `system-install` or `system-uninstall`, AegisPilot asks you first. See [usage.md](usage.md#self-protection).

## Updating

Plugin: refresh the marketplace, update the plugin, and start a new session.

```bash
claude plugin marketplace update hoho-ajou
claude plugin update aegis-pilot@hoho-ajou
```

Manual install: check out the new release tag in the same folder (`git fetch --tags && git checkout v<version>`). The hook paths stay the same, so the settings need no change. If you moved the folder, run `guard_cli.py snippet` again and replace the old hook block.

System install: run `sudo python3 guard/guard_cli.py system-install` again from the new release. It replaces the installed copy and the drop-in file, and keeps an existing `/etc/aasm/config.json`.

## Uninstalling

Run these yourself in a terminal. When the agent tries to turn off the guard, AegisPilot asks you first.

Plugin:

```bash
claude plugin uninstall aegis-pilot@hoho-ajou
claude plugin marketplace remove hoho-ajou      # optional
```

To turn it off without uninstalling: `claude plugin disable aegis-pilot@hoho-ajou`.

Manual install: remove the guard's hook entries from the settings file you merged them into, remove the `~/.claude/skills/aegis` link, and delete the clone.

System install:

```bash
sudo python3 /opt/agent-dependency-guard/guard_cli.py system-uninstall
```

This removes the managed-settings drop-in and the installed folder. It does not remove `/etc/aasm/`.

Files the guard wrote stay until you delete them: `.aasm/` in each project and `~/.aasm/` in your home folder. See [privacy.md](privacy.md#files-written).
