# How AegisPilot works

AegisPilot is a set of `PreToolUse` hooks. Claude Code calls them before the agent runs a shell command (`Bash`) or edits a file (`Edit`, `MultiEdit`, `Write`). The hook answers with nothing (the command goes on), "ask" (Claude Code's approval dialog), or "deny" with a reason.

## Pipeline

```
command or file edit
  -> parse          what would be installed or connected
  -> fetch          download the files, unpack without running anything
  -> analyze        static rules + behavior check + OSV
  -> score          weights, thresholds and hard rules
  -> post rules     adjustments that need the package's history
  -> lists          allow and deny lists
  -> verdict        ALLOW, REVIEW or BLOCK
```

### 1. Parse

The shell command is split into its parts (`&&`, `;`, `|`, quotes) and each part is read as an install command: package names and versions, requirements files, index options, git and URL sources, and project installs with their lock files. Commands of the agent's own CLI that add MCP servers, plugins or marketplaces are recognized too.

For a file edit, the guard computes the file's new content and compares it with the current one. New MCP servers, new hook commands and plugins switched on are turned into the code they would run, and that code goes through the same pipeline.

Anything the parser recognizes but cannot scan (an unknown index, an `ssh://` URL, another ecosystem) is kept as "not checked" and leads to a REVIEW.

### 2. Fetch

- PyPI: the release file pip would install (a compatible wheel, else the sdist). For wheels of 16 MB or more, only the `.py` and `.pth` members are fetched with HTTP range requests. Downloads over 250 MB are not read and are reported as not checked.
- npm: the package tarball from the registry.
- Git: GitHub's archive of the requested ref, or for other https hosts a shallow `git fetch` with hooks, LFS and submodules turned off.
- URL archives: https URLs of `.whl`, `.tar.gz`, `.tgz` and `.zip`, up to 100 MB.

Archives are unpacked into a temporary folder that is deleted afterwards. Only the files the analysis reads are extracted. Links, absolute paths and `..` are never followed, and there are limits on member count, size and compression ratio. A member with an unsafe name is skipped and reported, which itself leads to a REVIEW. Package code is never run.

Dependencies pulled in by the package are resolved from registry metadata alone: up to 4 levels and 80 packages. All of them are sent to OSV in one query to find known malicious releases. Releases uploaded in the last 30 days get a full scan (at most 10). These limits are in `guard/rules/post.json`.

### 3. Analyze

- **Static rules** look for patterns in the files: decode then execute, download then execute, install-time hooks in `setup.py`, code in `.pth` files that runs at every interpreter start, obfuscated blobs, text that tries to steer an AI agent, commands that shadow common command names, and more. The rules are JSON files in `guard/rules/`; see [guard/rules/README.md](../guard/rules/README.md).
- **Behavior check** (below) decides what the code does and when.
- **OSV** (`api.osv.dev`) is asked for known vulnerabilities and malicious-package reports for the exact version.

### 4. Score

Evidence is weighted into a score with a review threshold and a block threshold (`guard/rules/scoring.json`). Hard rules set a minimum verdict whatever the score. For example, a CRITICAL vulnerability, a decode-then-execute chain, a reverse shell, or code that reads credentials and sends them to a known collector is always a BLOCK.

### 5. Post rules

Adjustments that need more than the package's own files (`guard/rules/post.json`). The first matching rule applies:

| Rule | Effect |
| --- | --- |
| OSV lists this version as malicious | BLOCK |
| risky code appears that was not in the previous version | REVIEW |
| a file was added to an old release recently | REVIEW |
| OSV could not be reached | REVIEW |
| the name is close to a popular package | REVIEW |
| the package was first published recently | REVIEW |

### 6. Lists and verdict

The allow and deny lists are applied ([configuration.md](configuration.md#allow-and-deny-lists)). The result is written to `.aegis/reviews/<decision id>.json` and `.aegis/last_review.json`, and the hook answers according to the mode ([usage.md](usage.md#modes-user-and-auto)).

### Time limits

All checks of one command share a 540-second budget. The hook stops itself at 570 seconds and the hook timeout in Claude Code is 600 seconds. A hook that reaches Claude Code's timeout, or crashes, lets the command through, so the guard always answers before that. When it cannot finish, it asks instead of passing (or refuses, with `AEGIS_FAIL_CLOSED=1`).

## The behavior check

The behavior check reads Python, JavaScript and shell code (including PowerShell and cmd command lines, and the commands Python and JavaScript code runs) without running it. It rebuilds values that the code assembles at run time, such as decoded strings, joined names and constants, and follows where data flows: a network response that reaches `exec`, a credential file that reaches a network send. From this it records facts about what the code does, together with when it runs: at install time, at interpreter start, at import, only when called, or when run by hand as a script. A policy table in `guard/rules/behavior.json` maps each fact and phase to block, review or nothing. A file over the time or size limits in that table is recorded as not analyzed.

## Self-protection

A hook that is turned off checks nothing, so the guard protects itself from the agent it watches.

### Protected paths

A file edit or a shell command is checked against these paths:

- the guard's own folder, any path containing `aegis-pilot/`, and the agent's installed plugins (`~/.claude/plugins/`);
- `.aegis/` (in any project, and `~/.aegis/`): decision records, settings, acks, rule modules;
- agent settings: `.claude/settings.json`, `.claude/settings.local.json`, `.claude/hooks/`, `.codex/config.toml`, `.codex/hooks.json`, `.codex/hooks/`;
- for shell commands also MCP config files: `.mcp.json`, `.claude.json`.

A folder counts with or without a trailing `/` (`rm -rf .aegis` is caught like `rm -rf .aegis/`). A shell command counts as writing when it names a protected path and contains a write operation (`sed -i`, `mv`, `rm`, `cp`, `truncate`, `tee`, `chmod`, `dd`, or a `>` / `>>` redirect to a file). Redirects such as `2>&1` and `> /dev/null` do not count. Reading a protected file is not affected.

For edits of agent settings files, the guard compares the old and new content. The approval dialog is always used, in both modes, when a guard hook command disappears, the plugin is set to `false` in `"enabledPlugins"`, `"disableAllHooks"` is turned on, or a JSON settings file would no longer parse. Other settings edits go through the normal scan. The list of actions that always ask is in [usage.md](usage.md#self-protection).

### Integrity checksums

A released build contains `RELEASE_MANIFEST.json`, the SHA-256 checksum of every file at build time, and `BUILD_INFO.json`, which records where the build came from. At every install decision the guard compares its files with this list. It reports:

- a changed file;
- a deleted file;
- an added `.py`, `.pth`, `.json` or `.pyc` file (Python would import or run it). Python's own `__pycache__` is ignored.
- a missing or unreadable checksum list. It is never rebuilt from what is on disk.

Any finding turns the decision into a REVIEW and lists the changed files.

A clone of the default branch has no checksum list. There the guard records a baseline of its files on first run (`aegis_manifest.json`) and compares against that.

Hooks run Python with `-I` (isolated mode), so `PYTHON*` environment variables and the user's site-packages, including `.pth` files planted there by a `pip install --user`, do not run inside the guard. The guard folder is placed after the standard library on the import path, so a planted `json.py` next to the guard is not imported.

### verify

```bash
python3 <guard>/guard_cli.py verify
```

Read-only. Prints the build, any ignored environment switches, the rule modules in use, and every file that differs from the build. Exit code 0 when the files match, 1 when they do not.

### repair

```bash
python3 <guard>/guard_cli.py repair --dry-run    # show what would change
python3 <guard>/guard_cli.py repair             # restore, after typing "repair"
```

`repair` puts the guard back to its official build:

1. It gets a source: for a plugin, the public repository at the release tag recorded in `BUILD_INFO.json`, downloaded from GitHub. With `--from DIR`, another built copy of the guard. The source must match its own checksum list, or it is not used.
2. Every file that differs from the source, and every extra `.py`, `.pth`, `.json` or `.pyc` file, is copied to `~/.aegis/quarantine/<time>/` before anything changes. A `REPAIR.json` there records what was done.
3. The source's files are copied over, extra files are removed, and the result is checked again.

| Option | Effect |
| --- | --- |
| `--dry-run` | only show what would change |
| `--from DIR` | restore from another built copy of the guard |
| `--target DIR` | the guard folder to repair (default: the one `guard_cli.py` is in) |
| `--yes` | no typed confirmation. Required outside a terminal. |

The safest way is to run `repair` from a freshly downloaded release and point `--target` at the damaged install. When the agent runs `repair`, AegisPilot asks you first.

### System install

A guard in the user's folders can be changed by anything that runs as that user. A system install moves it to a root-owned folder and pins the hooks in managed settings. See [install.md](install.md#system-install-for-administrators).

## Limits

- **Static only.** Code is read, not run. Code that builds its behavior in ways the analysis cannot rebuild, or that only misbehaves under conditions it cannot see, can pass.
- **ALLOW is not a guarantee.** It means no known risk signal was found.
- **Languages.** Python, JavaScript and shell are read as code. Native binaries are not analyzed. A module shipped only as `.pyc` gets a REVIEW.
- **Sources.** Unknown private indexes, `ssh://` and `git://` sources, conda and other ecosystems are not scanned. They get a REVIEW, not an ALLOW.
- **Known vulnerabilities** come from OSV and are only as complete as OSV. When OSV cannot be reached, the decision is a REVIEW.
- **Dependencies** are followed within the limits above. Older dependencies are checked against OSV, not fully scanned.
- **Only what passes through the hooks.** A command the parser cannot read at all (for example unbalanced quotes) passes. A script that runs an install or writes a config file without the agent naming it in a command is not seen. The same holds for anything done outside the agent.
- **Codex** hooks cannot ask a person, so every "ask" becomes a refusal there.
- **A guard in the user's folders** can be changed by a process that does not go through the agent's tools. Use the system install where that matters. On WSL, `/etc/claude-code` is user-writable, so even the system install is not out of reach.
