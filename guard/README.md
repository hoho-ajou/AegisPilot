# AegisPilot plugin

This folder is the AegisPilot plugin for Claude Code. It contains the `PreToolUse` hooks, the decision engine, the rule files (`rules/`) and the `aegis` skill. Before the agent runs a package install or a settings change that adds an MCP server, plugin or hook, the hooks download the package, read its code without executing it, and allow, ask or block.

Install:

```bash
claude plugin marketplace add hoho-ajou/AegisPilot && claude plugin install aegis-pilot@hoho-ajou
```

Type `/aegis` in Claude Code to get the last decision explained. Run `python3 guard_cli.py verify` in this folder to check that its files match the release.

Network: package names and versions (never your code or files) go to `pypi.org`, `files.pythonhosted.org`, `registry.npmjs.org` and `api.osv.dev`, and for git/URL installs and `repair` to `github.com` / `codeload.github.com` or the host in the command. No telemetry. Files written: decision records in `.aegis/` in each project, and small state files in `~/.aegis/` (ack ids, package indexes seen, MCP servers seen).

Optional ML model: `python3 guard_cli.py ml-install` sets up `~/.aegis/ml` (a Python environment with scikit-learn and shap from PyPI, and model files from the `ml-models-v1` GitHub release, checked by SHA-256). Without it, verdicts are rule-based.

Documentation:

- [Install](https://github.com/hoho-ajou/AegisPilot/blob/v0.1.0/docs/install.md)
- [Usage](https://github.com/hoho-ajou/AegisPilot/blob/v0.1.0/docs/usage.md)
- [Configuration](https://github.com/hoho-ajou/AegisPilot/blob/v0.1.0/docs/configuration.md)
- [How it works](https://github.com/hoho-ajou/AegisPilot/blob/v0.1.0/docs/how-it-works.md)
- [ML model](https://github.com/hoho-ajou/AegisPilot/blob/v0.1.0/docs/ml.md)
- [Privacy](https://github.com/hoho-ajou/AegisPilot/blob/v0.1.0/docs/privacy.md)
- [Rule files](https://github.com/hoho-ajou/AegisPilot/blob/v0.1.0/guard/rules/README.md)

License: Apache-2.0 (`LICENSE`).
