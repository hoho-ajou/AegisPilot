# ML model (optional)

AegisPilot works without it. The optional ML model adds a learned score for PyPI packages, next to the rules: it looks at how a release was published and at what its code does when it is installed or imported, and it scores how much the release looks like known malicious packages.

It is not installed by default, because it needs scikit-learn and shap (about 200 MB), which the guard itself does not use. It runs on Linux, macOS and WSL, and `ml-install` needs Python's `venv` module (on Debian and Ubuntu: `sudo apt install python3-venv`).

## Install

In your own terminal (not through the agent):

```bash
python3 <guard>/guard_cli.py ml-install
```

`<guard>` is the AegisPilot folder: for the plugin, `~/.claude/plugins/cache/hoho-ajou/aegis-pilot/<version>`; for a manual install, the `guard/` folder of the clone.

This creates `~/.aegis/ml/`:

| Folder | Contents |
| --- | --- |
| `venv/` | a Python environment with the packages in [guard/ml/requirements.txt](../guard/ml/requirements.txt), exact versions, binary wheels only |
| `models/` | the two model files listed in [guard/ml/models.json](../guard/ml/models.json), downloaded from the `ml-models-v1` release of this repository |

Each model file is checked against the SHA-256 in `models.json` when it is installed and again before every check. A file that differs is not used: model files are loaded with joblib (Python pickle), which can run code, so only the published files are loaded.

The environment is installed from PyPI only: pip runs isolated from `pip.conf` and `PIP_*` variables, and with binary wheels only. Its files are not checked again later. `~/.aegis/` is a protected path, so the agent cannot change it without asking you, but other programs running as you can.

Options:

- `--from DIR` copies the model files from a folder instead of downloading them (offline machines). The hashes are checked the same way.
- `--yes` skips the typed confirmation.

`guard_cli.py verify` shows whether the ML model is installed and used. `guard_cli.py ml-uninstall` deletes `~/.aegis/ml/`.

When the agent runs `ml-install` or `ml-uninstall`, AegisPilot asks you first, in both modes.

## What it changes

Only PyPI packages are scored. npm, git/URL installs, MCP servers, plugins and hooks are checked by the rules alone.

With the ML model installed, a PyPI package gets a second score next to the rules: the vulnerability score (OSV), the typosquat score and the ML score. The verdict is the stricter of the two, so installing the ML model never lowers a verdict. Everything that blocks on its own stays: hard rules for critical vulnerabilities and known malicious releases, the behavior check, the allow and deny lists.

The ML score is scaled so that its alert threshold lands on the REVIEW threshold. On its own it can raise a package to REVIEW, never to BLOCK.

The model reads the release file it was trained on (the sdist when there is one), which is not always the file pip installs (often a wheel). The rules always read the file pip installs.

When the model finds behavior that runs at install time in a package it does not alert on, the decision lists it as an `[ML note]` without changing the verdict.

If the ML model cannot run (not installed, a model file changed, time limit of 45 seconds per package, any error), the verdict is made by the rules alone and the decision says why.

## The model

| | Full model | Metadata model |
| --- | --- | --- |
| Used when | the code of the release could be read | it could not (no file of 20 MB or less, an unreadable archive) |
| Features | 33: 6 upload, 7 packaging, 20 code | 13: 6 upload, 7 packaging |
| Training packages | 1,351 malicious, 1,833 benign | 11,666 malicious, 5,996 benign |
| Alert threshold | 0.225 | 0.587 |

Both are random forests (scikit-learn 1.9.1), trained on 2026-10-01 from a data snapshot of 2026-09-25. Malicious samples come from public datasets of malicious PyPI packages; benign samples are two sets of PyPI packages.

The alert threshold is set from 5-fold out-of-fold scores so that 5% of benign training packages would alert. This is a property of the training data, not a measured false alarm rate on new packages.

Features:

- **Upload**: number of versions so far, days since the first upload, release files in this version, free mail address, number of e-mail addresses, empty author.
- **Packaging**: wheel published, total size, number of dependencies, homepage, license, number of classifiers, summary length.
- **Code** (read as text and parsed, never run): Python files, lines, longest line, rate of hiding signals, and counts of `exec`/`eval`, decoding, long encoded strings, external commands, network access and data theft traces, both overall and in `setup.py`, an installation hook (`cmdclass`), and which of these run at import or install time, including decoded data passed straight to `exec`.

The reasons shown for an alert are the features that raised the score most for that package (SHAP values), written as sentences.

## Network and files

- `ml-install` downloads the model files from `github.com` (the release) and the packages of `requirements.txt` from PyPI. Nothing else.
- At check time the model reads the release file the guard already downloaded. When there is none, it downloads the release file itself from `files.pythonhosted.org` (sdist first, 20 MB or less). Nothing is sent anywhere else.
- Files: `~/.aegis/ml/` only.

## Settings

| Switch | Default | Effect |
| --- | --- | --- |
| `AEGIS_ML` | on when installed | `0`: do not use the ML model; `1`: use it (an error when it is not installed) |
| `AEGIS_ML_DIR` | `~/.aegis/ml` | another folder for the environment and the models. It names the Python the guard runs, so a built guard reads it from a settings file only ([configuration.md](configuration.md#switches-that-a-built-guard-ignores-in-the-environment)) |
| `AEGIS_ML_TIMEOUT` | `45` | seconds per package |
