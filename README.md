# AegisPilot

AegisPilot is a Claude Code plugin that checks what your coding agent is about to install or connect, before it runs. When the agent runs `pip install`, `npm install`, a `git+https://` or URL install, or changes a settings file to add an MCP server, a plugin or a hook, AegisPilot downloads the package and reads its code without executing it. It then allows the action, asks, or blocks it, and explains why.

> **Test release.** 0.1.2 is a test release (beta), not a stable release yet. Rules, messages and settings may still change. A stable release will be marked as such. Please tell us what goes wrong: see [Feedback](#feedback).

## Install

```bash
claude plugin marketplace add hoho-ajou/AegisPilot
claude plugin install aegis-pilot@hoho-ajou
```

Start a new Claude Code session after installing. Requires Python 3.11 or later as `python3`. Nothing else is installed: AegisPilot uses the Python standard library and bundles one small library ([packaging](guard/_vendor/README.md)). Other install methods (manual, Codex, system-wide) are in [docs/install.md](docs/install.md).

An ML model adds a learned score for PyPI packages. The guard downloads it (two hash-checked files, about 9 MB) on its first PyPI check; `AEGIS_ML=0` turns it off. See [docs/ml.md](docs/ml.md).

## Feedback

Your reports decide what we fix first.

- **A safe package was blocked or asked about:** [report a false alarm](https://github.com/hoho-ajou/AegisPilot/issues/new?template=false-alarm.yml)
- **A malicious or vulnerable package got through:** [report a missed package](https://github.com/hoho-ajou/AegisPilot/issues/new?template=missed-package.yml)
- **Anything else:** [open an issue](https://github.com/hoho-ajou/AegisPilot/issues/new/choose) or write to hohojeonseung@gmail.com

Include the decision id from the message (for example `decision id D57eb`) if there was one. Remove paths, project names and tokens before you paste output.

## What you see

When the agent installs a release that OSV records as malicious, the command is stopped and you see (shortened):

```
[AegisPilot BLOCK] ctx 0.2.2
Reason    known malicious version: OSV records this release
          as malicious
Impact    a malicious version uploaded from a hijacked
          account (supply chain attack) may be installed
Evidence  GHSA-67r3-h899-9w95, PYSEC-2022-199 known
          malicious version
Fix       check that the package is needed; if not, do not
          install it
```

A known vulnerability is a REVIEW, not a BLOCK: for `pip install pyyaml==5.3.1` (CVE-2020-14343, CRITICAL) Claude Code asks you first, and the card shows the fixed version (`pyyaml>=5.4`). Type `/aegis` in Claude Code to get any decision explained.

## Verdicts

- **BLOCK**: only three things: a release OSV records as malicious, a package on your deny list, or code that runs by itself (at install, at Python start, at import, or as a hook or MCP server the agent starts) and runs downloaded or hidden code, sends credentials or data out, opens a remote shell, registers itself to run at startup or deletes your files. The command is stopped.
- **REVIEW**: a rule flagged something that is not a BLOCK: a known vulnerability (any severity, shown with the fixed version), dangerous code that runs only when called, a suspicious install step, a name close to a popular package, risky code new in this release, an ML score at or above its review threshold. Or part of the install could not be checked. Claude Code asks you before the command runs.
- **ALLOW**: neither of the above. The command runs and nothing is shown. ALLOW means no evidence of a problem was found, not that the package is verified safe.

BLOCK and REVIEW differ in what is certain, not in how bad it could be: BLOCK is for evidence of malice, REVIEW for what needs your context (a vulnerability in a part you may not use, a name you may have meant) or could not be checked. Both come with the evidence.

## Modes

AegisPilot runs in **user mode** by default: every REVIEW and BLOCK is decided by you. For unattended runs you can switch to **auto mode**, where the agent gets the evidence and decides by itself (it can then go ahead even after a BLOCK). Actions that would turn the guard off or change it always ask you, in both modes. See [docs/usage.md](docs/usage.md#modes-user-and-auto).

## Documentation

- [docs/install.md](docs/install.md): plugin, manual and system install; several installs; updating and uninstalling
- [docs/usage.md](docs/usage.md): what is checked, verdicts, modes, `/aegis`, attack paths, self-protection
- [docs/configuration.md](docs/configuration.md): allow and deny lists, rule modules, private indexes, switches, cache
- [docs/how-it-works.md](docs/how-it-works.md): the pipeline, the behavior check, integrity checks, limits
- [docs/ml.md](docs/ml.md): the ML model: download, what it changes, the model and its training data, how to turn it off
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
