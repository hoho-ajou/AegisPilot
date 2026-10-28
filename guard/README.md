# AegisPilot plugin

This folder is the AegisPilot plugin for Claude Code. It contains the `PreToolUse` hooks, the decision engine, the rule files (`rules/`) and the `aegis` skill. Before the agent runs a package install or a settings change that adds an MCP server, plugin or hook, the hooks download the package, read its code without executing it, and allow, ask or block.

Install:

```bash
claude plugin marketplace add hoho-ajou/AegisPilot && claude plugin install aegis-pilot@hoho-ajou
```

Type `/aegis` in Claude Code to get the last decision explained. Run `python3 guard_cli.py verify` in this folder to check that its files match the release.

Network: package names and versions (never your code or files) go to `pypi.org`, `files.pythonhosted.org`, `registry.npmjs.org` and `api.osv.dev`, and for git/URL installs and `repair` to `github.com` / `codeload.github.com` or the host in the command. No telemetry. Files written: decision records in `.aasm/` in each project, and small state files in `~/.aasm/` (ack ids, package indexes seen, MCP servers seen).

Documentation:

- [Install](https://github.com/hoho-ajou/AegisPilot/blob/main/docs/install.md)
- [Usage](https://github.com/hoho-ajou/AegisPilot/blob/main/docs/usage.md)
- [Configuration](https://github.com/hoho-ajou/AegisPilot/blob/main/docs/configuration.md)
- [How it works](https://github.com/hoho-ajou/AegisPilot/blob/main/docs/how-it-works.md)
- [Privacy](https://github.com/hoho-ajou/AegisPilot/blob/main/docs/privacy.md)
- [Rule files](https://github.com/hoho-ajou/AegisPilot/blob/main/guard/rules/README.md)

License: Apache-2.0 (`LICENSE`).
