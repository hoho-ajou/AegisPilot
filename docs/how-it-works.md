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
- npm: the package tarball from the registry. Its install scripts (`preinstall`, `install`, `postinstall`) are followed the way npm and the shell would run them: `npm run <script>` / `yarn <script>` to that script, `node X` to `X`, `X.js` or `X/index.js` (`node .` to `main`), `node -r` / `--import` to the preloaded file, `sh X` / `python X` / `./X` to that file whatever its extension, `make` to the Makefile, and `node-gyp` (also npm's implicit `node-gyp rebuild` when `binding.gyp` exists and there is no install script) to the `<!(command)` expansions of the `.gyp` / `.gypi` files. All of that is read as install-time code, also when it sits in a `test/` folder. A bare `npm install` (or `yarn`, `pnpm install`, `bun install`) in a project reads the project's own install scripts the same way.
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

All checks of one command share a 540-second budget. The hook stops itself at 570 seconds and the hook timeout in Claude Code is 600 seconds. A hook that reaches Claude Code's timeout, or crashes, lets the command through, so the guard always answers before that. When it cannot finish, it asks instead of passing (or refuses, with `AEGIS_FAIL_CLOSED=1`). On Linux and macOS the check runs in a child process and the time limit is kept by the parent, so a check stuck in one long computation cannot hold it up, and a check process that dies (out of memory, a crash) is answered the same way instead of letting the command through.

## The behavior check

The behavior check reads Python, JavaScript and shell code (including PowerShell and cmd command lines, and the commands Python and JavaScript code runs) without running it. It rebuilds values that the code assembles at run time, such as decoded strings, joined names and constants, and follows where data flows: a network response that reaches `exec`, a credential file that reaches a network send (including raw senders such as `nc` and `scp`), a command that removes the home folder or a system folder. From this it records facts about what the code does, together with when it runs: at install time, at interpreter start, at import, only when called, or when run by hand as a script. A policy table in `guard/rules/behavior.json` maps each fact and phase to block, review or nothing. Test and maintenance files are skipped only while nothing that runs reaches them: a file that install-time code, a `.pth` line, an import, the in-tree build backend named in `pyproject.toml` or a hook command reaches is read at the phase of what reached it. Files an sdist's `setup.py` hands work to (a Makefile, a configure script, CMake files, a data file it `exec`s) are read too, and Python files are decoded with the source encoding they declare; an encoding that rewrites the code (`utf-7`, `unicode_escape`) gets a REVIEW. A file over the size, step or file-count limits in that table is recorded as not analyzed, and one that would run at install, interpreter start or import gets a REVIEW (the time limit alone does not, because it depends on the machine).

## Self-protection

A hook that is turned off checks nothing, so the guard protects itself from the agent it watches.

### Protected paths

A file edit or a shell command is checked against these paths:

- the guard's own folder, any path containing `aegis-pilot/`, and the agent's installed plugins (`~/.claude/plugins/`);
- `.aegis/` (in any project, and `~/.aegis/`): decision records, settings, acks, rule modules;
- agent settings: `.claude/settings.json`, `.claude/settings.local.json`, `.claude/hooks/`, the same files under `~/.config/claude/`, Claude Code's managed settings (`/etc/claude-code/managed-settings.json` and `managed-settings.d/`, on macOS under `/Library/Application Support/ClaudeCode/`), `.codex/config.toml`, `.codex/hooks.json`, `.codex/hooks/`;
- for shell commands also MCP config files: `.mcp.json`, `.claude.json`.

A folder counts with or without a trailing `/` (`rm -rf .aegis` is caught like `rm -rf .aegis/`). A shell command counts as writing when it names a protected path and contains a write operation (`sed -i`, `mv`, `rm`, `cp`, `truncate`, `tee`, `chmod`, `dd`, `ln`, `install`, `rsync`, `touch`, `sponge`, `perl -i`, an editor such as `vim -c`, `ex` or `ed`, `git checkout` / `git restore` and similar, `find -delete`, an archive tool, a download to a file, or a `>` / `>>` redirect to a file), or runs a program that writes, links or deletes: a one-line program (`python3 -c`, `node -e`, `php -r`, ...), or an interpreter that reads its program from a here-document, a here-string or a pipe (`python3 - <<'X' ... X`). Redirects such as `2>&1` and `> /dev/null` do not count. Reading a protected file is not affected.

The command is also read the way the shell would split it, without running it:

- quotes and escapes are removed (`'.claude'/settings.json`, `.cl""aude`, `sett\ings.json`), `//`, `/./` and `..` are resolved, `~`, `$HOME` and `$PWD` are expanded, and names are compared without regard to case (`.AEGIS/policy.json`);
- the writer is recognized however it is spelled or started (`/bin/ln`, `"ln"`, `\ln`, `command ln`, `sudo`, `xargs`, `env`), and the strings run by `sh -c`, `eval`, a here-document fed to a shell, and `$(...)` are read as commands too;
- a relative path is read from the folder set by an earlier `cd` or `pushd` in the same command (`cd ~/.claude && cp x settings.json`);
- braces are expanded and shell patterns are compared with the protected names (`settings.*`, `setting[s].json`, `{settings,x}.json`, `.ae*`); a pattern counts when it keeps at least three letters of the name or follows a protected folder (`.claude/*`), so `rm *.log` and `rm -rf build/*` do not;
- a folder that holds a protected path counts when it is itself removed, moved or copied over (`rm -rf .claude`, `mv ~/.aegis /tmp`), but not a different folder inside it (`rm -rf .claude/worktrees/x`);
- a piece that is built at run time (`$(printf .%s aegis)`, `$D`) counts as protected when the letters around it name a protected folder or it stands in front of a file name of the guard or the agent's settings (`$D/settings.json`, `.aegis` files such as `policy.json`);
- `git clean -f` without a path (it deletes the untracked `.aegis/` and `.claude/settings.local.json`), `git -C <dir>` and `git --no-pager` before the subcommand, `find ... -name policy.json -delete`, and an install run by a program inside a protected folder (`cd ~/.aegis/ml/venv && bin/pip install x`, `pip install --target ~/.aegis/...`) count as writes;
- `claude config set` of `hooks`, `disableAllHooks` or `enabledPlugins`, and setting the variable that moves the agent's config folder (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`) in a command, count like editing the settings: the agent would start without the settings that load the guard.

`pip install`, `npm install`, `git status`, `git checkout main`, `git clean -n`, reading with `cat`, `grep`, `ls` or `less`, a `python3 -c` that only reads, `rm -rf build/`, `rm *.log`, `cd .aegis && ls` and `find . -name '*.pyc' -delete` are not affected.

The check reads the command text; nothing is run. It cannot see a path or a program that is only built when the command runs: a variable set elsewhere (`cp x $D/config.json`), a decoded or downloaded string, a script file whose content is not in the command (`python3 x.py`, `cat x | python3`), or a program that finds the files itself. See [Limits](#limits).

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
- **Sources.** Unknown private indexes, `ssh://` and `git://` sources, conda and other ecosystems (`cargo install`, `gem install`, `go install`, `composer require`, `dotnet add package`, ...) are not scanned. They get a REVIEW, not an ALLOW. `brew` and system package managers are not looked at, and `npm rebuild` (which reruns the install scripts of packages already in `node_modules`) is not checked again.
- **Known vulnerabilities** come from OSV and are only as complete as OSV. When OSV cannot be reached, the decision is a REVIEW.
- **Dependencies** are followed within the limits above. Older dependencies are checked against OSV, not fully scanned.
- **Only what passes through the hooks.** A command the parser cannot read at all (for example unbalanced quotes) passes, and so does a command that builds the install at run time (`P=pip; $P install x`, `eval "$(...)"`, `echo "pip install x" | sh`). A script that runs an install or writes a config file without the agent naming it in a command is not seen. The same holds for anything done outside the agent.
- **Self-protection reads command text.** It catches the common ways to write the guard's files, however they are quoted or spelled, not every program that could: a path built only at run time or a script file whose content is not in the command is not seen. A system install (above) keeps the guard's own files out of the agent's reach; the settings in `.aegis/` stay agent-writable.
- **Codex** hooks cannot ask a person, so every "ask" becomes a refusal there.
- **A guard in the user's folders** can be changed by a process that does not go through the agent's tools. Use the system install where that matters. On WSL, `/etc/claude-code` is user-writable, so even the system install is not out of reach.
