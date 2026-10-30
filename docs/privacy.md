# Privacy: network and files

AegisPilot has no telemetry. It contacts package registries and OSV to check packages, and writes its records to your project and home folders.

## Network

AegisPilot sends package names, versions and source URLs taken from the command. It never sends your code, your files or their contents.

| Host | When | What is sent |
| --- | --- | --- |
| `pypi.org` | a Python package is checked | the package name (and version) to fetch its metadata |
| `files.pythonhosted.org` | a Python package is checked | requests for the release file, or parts of it for large wheels |
| `registry.npmjs.org` | an npm package is checked | the package name to fetch its metadata and tarball |
| `api.osv.dev` | every package check; `guard_cli.py paths --judge` | package names, versions and ecosystem; advisory ids |
| `codeload.github.com` | a `git+https://github.com/...` install, a plugin from GitHub; `repair` of a plugin | the repository and ref to download |
| `github.com`, `pypi.org`, `files.pythonhosted.org` | only `guard_cli.py ml-install` | the [ML model](ml.md) files from this repository's release, and its Python packages |
| the git host or URL in your command | a `git+https://` install from another host, or an https archive URL | an https request, or a shallow `git fetch`, for that source |

Notes:

- Only https sources are fetched. `ssh://`, `git://` and other schemes are not contacted; the install gets a REVIEW instead.
- Indexes other than PyPI and the npm registry are not contacted. Packages from them are reported as not checked.
- MCP servers, hooks and plugins added to settings are fetched from the same hosts, depending on where their code comes from.
- `repair` downloads the guard's own release from the repository recorded in its build (`https://github.com/hoho-ajou/AegisPilot`).

Downloaded files are unpacked into a temporary folder, read as text and deleted. They are never run.

## Files written

### In the project: `.aegis/`

| Path | Written when | Contents |
| --- | --- | --- |
| `.aegis/last_review.json` | every install or settings decision | the latest decision: command, verdict, findings per package |
| `.aegis/reviews/<decision id>.json` | every decision | the same record, one file per decision. The last 200 are kept. |
| `.aegis/profile.json` | install decisions | a summary of the environment for attack paths: which credential files and settings exist and are readable, MCP server names, permission rules. No secret values. |
| `.aegis/attack_paths.json`, `.aegis/attack_paths/<decision id>.json` | install decisions; `guard_cli.py paths` | attack paths for the decision |
| `.aegis/osv/` | `guard_cli.py paths --judge` | OSV advisory texts for the agent to quote |
| `.aegis/reports/*.md` | every BLOCK; `guard_cli.py report --format md` | a Markdown report of the decision |
| `.aegis/cache/verdicts.json` | only when the verdict cache is on | cached verdicts per package version |
| `.aegis/policy.json` | only when you create it | mode, allow and deny lists |

`.aegis-ai/cve_judgments.json` is written by the agent during `paths --judge`, not by the guard.

AegisPilot writes `.aegis/.gitignore` (ignore everything) the first time it creates the folder, so its records stay out of your commits. Delete that file if you want to commit them.

### In your home folder: `~/.aegis/`

| Path | Written when | Contents |
| --- | --- | --- |
| `~/.aegis/acks.json` | auto mode, when an ack id is issued | ack ids, a fingerprint of the refused action, a one-line summary. Entries are dropped after 24 hours. |
| `~/.aegis/indexes.json` | when an install uses a package index other than the defaults | the indexes seen, and whether the agent added them |
| `~/.aegis/mcp_snapshot.json` | when an MCP config file is edited | the MCP servers already seen per config file, so only new ones are flagged |
| `~/.aegis/quarantine/<time>/` | `guard_cli.py repair` | the files repair replaced or removed, and `REPAIR.json` |
| `~/.aegis/config.json` | only when you create it | switches (see [configuration.md](configuration.md#environment-switches)) |
| `~/.aegis/rules/` | only when you create it | your rule modules |
| `~/.aegis/ml/` | only when you run `guard_cli.py ml-install` | the optional [ML model](ml.md): its Python environment and model files |

### Elsewhere

- **Guard folder**: in a clone of the default branch, `aegis_manifest.json`, the baseline of the guard's files made on first run. A release build writes nothing in its own folder except Python's `__pycache__`.
- **Settings files**: only when you choose in a terminal to turn another install off: `guard_cli.py installs`, or "overwrite" in `guard_cli.py snippet` or `system-install`. Guard hooks are removed from a settings file (the previous file is kept with a `.bak` suffix), or the plugin is disabled in settings. Otherwise `snippet` only prints.
- **System install** (run as root): the guard folder (default `/opt/aegis-pilot`), the managed-settings drop-in (`/etc/claude-code/managed-settings.d/aegis-pilot.json` on Linux, `/Library/Application Support/ClaudeCode/managed-settings.d/aegis-pilot.json` on macOS), and `/etc/aegis/config.json` if it does not exist.
