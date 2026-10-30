# AegisPilot

AegisPilot is a Claude Code plugin that checks what your coding agent is about to install or connect, before it runs. When the agent runs `pip install`, `npm install`, a `git+https://` or URL install, or changes a settings file to add an MCP server, a plugin or a hook, AegisPilot downloads the package and reads its code without executing it. It then allows the action, asks, or blocks it, and explains why.

## Install

```bash
claude plugin marketplace add hoho-ajou/AegisPilot
claude plugin install aegis-pilot@hoho-ajou
```

Requires Python 3.11 or later as `python3`. Nothing else is installed: AegisPilot uses the Python standard library and bundles one small library ([packaging](guard/_vendor/README.md)). Other install methods (manual, Codex, system-wide) are in [docs/install.md](docs/install.md).

Optional: an ML model that adds a learned score for PyPI packages, installed with one command into `~/.aegis/ml`. See [docs/ml.md](docs/ml.md).

## What you see

When the agent runs `pip install pyyaml==5.3.1`, the command is stopped and you see:

```
[AegisPilot BLOCK] pyyaml 5.3.1
Reason    1 CRITICAL vulnerability GHSA-8q59-q68h-6hv4
          (CVE-2020-14343, CWE-20)
Impact    remote (network) · no login needed · high
          confidentiality, integrity, availability impact
Evidence  setup.py:171 install hook (no dangerous call)
          lib/yaml/constructor.py:538 uses a dangerous API
Fix       upgrade to pyyaml>=5.4 (OSV fixed version)
Limits    older dependencies are checked against OSV only;
          native binaries are not scanned
```

The agent then asks you whether to switch to the fixed version. Type `/aegis` in Claude Code to get any decision explained.

## Verdicts

- **ALLOW**: no known risk signal was found. The command runs and nothing is shown.
- **REVIEW**: a suspicious signal was found, or part of the install could not be checked. Claude Code asks you before the command runs.
- **BLOCK**: a critical vulnerability, a known malicious release, or code that runs downloaded or hidden code. The command is stopped.

## Modes

AegisPilot runs in **user mode** by default: every REVIEW and BLOCK is decided by you. For unattended runs you can switch to **auto mode**, where the agent gets the evidence and decides by itself (it can then go ahead even after a BLOCK). Actions that would turn the guard off or change it always ask you, in both modes. See [docs/usage.md](docs/usage.md#modes-user-and-auto).

## Documentation

- [docs/install.md](docs/install.md): plugin, manual and system install; several installs; updating and uninstalling
- [docs/usage.md](docs/usage.md): what is checked, verdicts, modes, `/aegis`, attack paths, self-protection
- [docs/configuration.md](docs/configuration.md): allow and deny lists, rule modules, private indexes, switches, cache
- [docs/how-it-works.md](docs/how-it-works.md): the pipeline, the behavior check, integrity checks, limits
- [docs/ml.md](docs/ml.md): the optional ML model: install, what it changes, the model and its training data
- [docs/privacy.md](docs/privacy.md): what is sent over the network and what is written to disk
- [guard/rules/README.md](guard/rules/README.md): rule files and how to write rule modules
- [benchmark/README.md](benchmark/README.md): detection, false-positive and latency measurements

## Repository

| Path | Contents |
| --- | --- |
| `guard/` | The plugin: hooks, decision engine, rules. This folder is what gets installed. |
| `docs/` | User documentation |
| `tests/` | Tests. Run with `python3 scripts/run_tests.py` |
| `benchmark/` | Measurement scripts and results against public malware datasets and GuardDog |
| `scripts/` | `run_tests.py`, and `build_dist.py` for builds and release tags |

## License

Apache License 2.0. See [LICENSE](LICENSE).
