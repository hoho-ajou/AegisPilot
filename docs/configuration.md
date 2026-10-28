# Configuration

AegisPilot works without configuration. This page lists what you can change, where it lives, and the default.

All files below that sit in `.aasm/` or `~/.aasm/` are protected paths. When the agent writes one of them, AegisPilot asks you first. Edit them yourself.

For the mode setting (`user` or `auto`), see [usage.md](usage.md#modes-user-and-auto).

## Allow and deny lists

Lists of packages that people have already judged.

| Layer | File | Notes |
| --- | --- | --- |
| system | `/etc/aasm/policy.json` | Meant to be owned by root, so the agent can read it but not change it. Wins over the project file. |
| project | `<project>/.aasm/policy.json` | The same file that holds `"mode"`. Protected, but only as strong as that protection. |

Default: no lists. Both files are read on every install decision.

Format:

```json
{
  "deny": [
    {"package": "leftpad", "versions": "*", "reason": "not approved", "approver": "security team"}
  ],
  "allow": [
    {"package": "corp-utils", "version": "1.4.2", "reason": "internal service", "approver": "j.kim", "expires": "2026-12-31"}
  ]
}
```

Rules:

- **deny** matches by name. `"versions"` is `"*"` (every version, the default) or a list of exact versions. A match is a BLOCK, whatever the scan found.
- **allow** needs the exact name and the exact `"version"`. It can only turn a REVIEW into an ALLOW. It never lowers a BLOCK.
- An allow entry with `"expires"` (`YYYY-MM-DD`) stops applying after that date.
- Names are compared case-insensitively, with `-`, `_` and `.` treated as the same.
- deny wins over allow. System entries win over project entries.
- The decision record shows which entry applied and its source, reason and approver.
- A file that cannot be read is reported in the decision, and the decision is made without lists.

## Rule modules

The rule files shipped in `guard/rules/` are the base rules. Do not edit them; the integrity check would report them as changed. To add or change rules, write a rule module: a JSON file layered on top of the base rules.

| Location | Who | Read when |
| --- | --- | --- |
| `~/.aasm/rules/*.json` | user | the guard is installed in the user's own folders. Not read by a system install. |
| `/etc/aasm/rules/*.json` | administrator | the folder and files are owned by root and not writable by other users. Applied after user modules. |

Default: no modules. Within one location, modules are applied in file name order.

A module can add signals and rules, add or replace hard rules and post-scan rules, change single values (for example a threshold), append to lists (for example the names checked for impersonation), turn off base rules, and carry its own examples. A broken module is skipped as a whole and the guard runs with the rest.

Minimal example, which adds internal package names to the impersonation check:

```json
{
  "schema": 1,
  "name": "Company rules",
  "add": {"scoring.subscores.typosquat.popular_names": ["corp-sdk", "corp-auth"]}
}
```

Check which modules apply:

```bash
python3 <guard>/guard_cli.py verify          # lists applied and skipped modules
python3 <guard>/rule_check.py --modules      # status of each module, and runs its examples
```

The full format, with every key and a longer example, is in [guard/rules/README.md](../guard/rules/README.md).

## Private package indexes

AegisPilot scans what PyPI and the npm registry serve. It cannot scan packages from another index. Whether that matters depends on who chose the index:

| Index | Treated as |
| --- | --- |
| Found in a config file (`pip.conf`, `uv.toml`, `.npmrc`, ...) or in the session's environment, and not added by the agent | trusted: your own setting. Recorded when first seen. Not flagged. |
| Added by the agent: `pip config set ...`, an edit of an index config file, or a shell command that writes one | not trusted. The install gets a REVIEW (in auto mode, the agent's decision). |
| Named in the install command itself (`-i`, `--index-url`, `--registry`, `PIP_INDEX_URL=...` in the command, an `-i` line in a requirements file) | not trusted, unless it is an index you already use |

Default: no index is known until one is seen.

To use a company index, set it up yourself, outside the agent, before the agent uses it. For example, in your own terminal:

```bash
pip config set global.index-url https://pypi.corp.example/simple
```

State is kept in `~/.aasm/indexes.json`. A config file written by something the guard does not see (for example a script run outside the agent) is treated as your own setting.

## Environment switches

Switches are environment variables named `AASM_*`.

### Switches read from the environment

These do not weaken the checks, so they are always read from the environment.

| Switch | Default | Values |
| --- | --- | --- |
| `AASM_MODE` | not set (`user`, or the project's `.aasm/policy.json`) | `user`, `auto` |
| `AASM_FAIL_CLOSED` | `0` | `1`: when the guard cannot finish (time limit, internal error), it refuses the command instead of asking |
| `AASM_SCAN_PROCESSES` | `1` | `0`: scan several packages with threads only, no worker processes |

### Switches that a built guard ignores in the environment

These switches can weaken the checks. An agent could set them for every later session, for example by writing `export ...` into `~/.bashrc`. So a built guard (the plugin, a release tag clone, a system install) ignores them in the environment and reads them only from a settings file:

| File | Read when |
| --- | --- |
| `/etc/aasm/config.json` | it is owned by root and not writable by group or others. Wins over the user file. |
| `~/.aasm/config.json` | the guard is installed in the user's folders. Not read by a system install. |

Format:

```json
{"env": {"AASM_CACHE": "1"}}
```

| Switch | Default | Effect |
| --- | --- | --- |
| `AASM_RULES_DIR` | the `rules/` folder of the guard | read the base rules from another folder |
| `AASM_RULE_MODULES` | `1` | `0`: do not apply rule modules |
| `AASM_MCP_SCAN` | `1` | `0`: do not scan the code of MCP servers, plugins and hooks; only check their registration |
| `AASM_SYSTEM_POLICY` | `/etc/aasm/policy.json` | read the system allow and deny lists from another file |
| `AASM_HOOK_DEADLINE_SECONDS` | `570` | time limit of one check. When it is reached, the command is not checked and the guard asks (or refuses with `AASM_FAIL_CLOSED=1`). |
| `AASM_ARTIFACT_POLICY` | `installed` | which release file of a PyPI package to read. `installed`: the file pip would install (a compatible wheel, else the sdist). `sdist_first`: the sdist when there is one. |
| `AASM_CACHE` | `0` | `1`: turn on the verdict cache (below) |

`guard_cli.py verify` lists switches that are set in the environment but ignored.

In a clone of the default branch (not a release build), these switches are read from the environment.

## Verdict cache

Off by default. When on, a scan verdict for an exact package version is reused for a while, so running the same install again is faster.

| | |
| --- | --- |
| Turn on | `"AASM_CACHE": "1"` in `~/.aasm/config.json` or `/etc/aasm/config.json` |
| File | `<project>/.aasm/cache/verdicts.json` |
| Lifetime | 6 hours per entry, at most 2000 entries |

What is cached:

- only exact versions. A request for the latest version is always scanned.
- only completed scans. Network failures and timeouts are not cached.
- an entry is not reused when the rules have changed (a guard update or a rule module change).
- entries are dropped when OSV could not be reached.

Why it is off by default: the cache is in a folder the agent can write, so a forged ALLOW entry would skip a scan. The folder is a protected path and entries are plain JSON, which narrows this risk but does not remove it.
