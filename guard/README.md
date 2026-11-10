# AegisPilot plugin

This folder is the AegisPilot plugin for Claude Code. It contains the `PreToolUse` hooks, the decision engine, the rule files (`rules/`) and the `aegis` skill. Before the agent runs a package install or a settings change that adds an MCP server, plugin or hook, the hooks download the package, read its code without executing it, and allow, ask or block.

Install:

```bash
claude plugin marketplace add hoho-ajou/AegisPilot && claude plugin install aegis-pilot@hoho-ajou
```

Type `/aegis` in Claude Code to get the last decision explained. Run `python3 guard_cli.py verify` in this folder to check that its files match the release.

Verdicts: BLOCK only for a release OSV records as malicious, a deny-list entry, or dangerous code that runs by itself (at install, Python start or import, or as a hook or MCP server); REVIEW (Claude Code asks you) for known vulnerabilities, versions published less than 24 hours ago, other rule findings, ML scores over the review threshold and anything that could not be checked; ALLOW otherwise.

What it reads on your machine: the command, the files it names (requirements and lock files, settings files that add MCP servers, plugins or hooks), and, to explain what a flagged package could reach, whether common credential and settings files exist and are readable. It never reads or sends their contents.

Network: package names and versions (never your code or files) go to `pypi.org`, `files.pythonhosted.org`, `registry.npmjs.org` and `api.osv.dev`, and for git/URL installs and `repair` to `github.com` / `codeload.github.com` or the host in the command. No telemetry. Files written: decision records in `.aegis/` in each project, and small state files in `~/.aegis/` (ack ids, package indexes seen, MCP servers seen). It changes no Claude Code settings by itself. Two commands you run yourself do: `system-install` (with sudo) pins the guard's hooks in the managed settings, and `repair` restores the guard's own files from its release.

ML model: on its first PyPI check the guard downloads two model files from the `ml-models-v2` GitHub release into `~/.aegis/ml/models` (checked by SHA-256, read with the standard library only). `python3 guard_cli.py ml-install` downloads them ahead of time; `AEGIS_ML=0` or `ml-uninstall` turns ML off. When the model cannot be used, verdicts are rule-based and the result says so.

Documentation:

- [Install](https://github.com/hoho-ajou/AegisPilot/blob/v0.1.2/docs/install.md)
- [Usage](https://github.com/hoho-ajou/AegisPilot/blob/v0.1.2/docs/usage.md)
- [Configuration](https://github.com/hoho-ajou/AegisPilot/blob/v0.1.2/docs/configuration.md)
- [How it works](https://github.com/hoho-ajou/AegisPilot/blob/v0.1.2/docs/how-it-works.md)
- [ML model](https://github.com/hoho-ajou/AegisPilot/blob/v0.1.2/docs/ml.md)
- [Privacy](https://github.com/hoho-ajou/AegisPilot/blob/v0.1.2/docs/privacy.md)
- [Rule files](https://github.com/hoho-ajou/AegisPilot/blob/v0.1.2/guard/rules/README.md)

License: Apache-2.0 (`LICENSE`).
