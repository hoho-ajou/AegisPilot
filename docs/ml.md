# ML model (optional)

AegisPilot works without it. The optional ML model adds a learned score for PyPI packages, next to the rules: it looks at how a release was published and at what its code does when it is installed or imported, and it scores how much the release looks like known malicious packages.

It is off until you install it. Version 2 runs with the Python standard library only (no scikit-learn, numpy or other packages): installing it downloads two model files (about 9 MB) and takes a few seconds. It runs wherever the guard runs (Linux, macOS, WSL, Windows).

When it is not installed, each result says so in one line: `ML detection off — run python3 guard_cli.py ml-install to turn it on (a few seconds)`.

## Install

In your own terminal (not through the agent):

```bash
python3 <guard>/guard_cli.py ml-install
```

`<guard>` is the AegisPilot folder: for the plugin, `~/.claude/plugins/cache/hoho-ajou/aegis-pilot/<version>`; for a manual install, the `guard/` folder of the clone.

This puts the two model files listed in [guard/ml/models.json](../guard/ml/models.json) into `~/.aegis/ml/models/`, downloaded from the `ml-models-v2` release of this repository. They are JSON (a random forest written out as numbers), read by [guard/ml/forest.py](../guard/ml/forest.py).

Each model file is checked against the SHA-256 in `models.json` when it is installed and again before every check, and a file is parsed only after its hash matches. A file that differs is not used. Files over 64 MB (also after unpacking) are refused. `~/.aegis/` is a protected path, so the agent cannot change it without asking you, but other programs running as you can.

Options:

- `--from DIR` (or `--source DIR`) copies the model files from a folder instead of downloading them (offline machines). The hashes are checked the same way.
- `--yes` skips the typed confirmation.

`guard_cli.py verify` shows whether the ML model is installed and used. `guard_cli.py ml-uninstall` deletes `~/.aegis/ml/`.

Upgrading from version 1: `~/.aegis/ml/venv/` (scikit-learn, about 200 MB) is no longer used. `ml-install` leaves it in place and `verify` mentions it; you can delete it.

When the agent runs `ml-install` or `ml-uninstall`, AegisPilot asks you first, in both modes.

## What it changes

Only PyPI packages are scored. npm, git/URL installs, MCP servers, plugins and hooks are checked by the rules alone.

With the ML model installed, a PyPI package gets a second score next to the rules: the vulnerability score (OSV), the typosquat score and the ML score. The verdict is the stricter of the two, so installing the ML model never lowers a verdict. Everything that blocks on its own stays: hard rules for critical vulnerabilities and known malicious releases, the behavior check, the allow and deny lists.

### Two stages: REVIEW or note

An ML result has a level:

| Level | Full model (code read) | Metadata model (code not read) | Effect |
| --- | --- | --- | --- |
| `review` — `[ML review]` | score ≥ 0.2352 **and** a risky behavior found in the code | score ≥ 0.9464 | raises the package to REVIEW |
| `note` — `[ML note]` | score ≥ 0.2352 without such a behavior | 0.9002 ≤ score < 0.9464 | shown with its reasons; does not change the verdict |
| `pass` | below 0.2352 | below 0.9002 | nothing (an install-time behavior is still listed as a note) |

"Risky behavior in the code" means one of the severe install-time signals is present (code decoded and run, commands, code or network run at install or import, `setup.py` that runs commands, decodes, goes online, takes over the installation, or traces of data theft), or another behavior signal (network access, `exec`/`eval`, decoding, long encoded strings, external commands, a line over 1,000 characters, hiding signals) is present and raised the score.

The ML score is scaled so that the review threshold lands on the REVIEW threshold. On its own it can raise a package to REVIEW, never to BLOCK, and it is labelled "risk detected (ML)", not "malicious". A note is capped below the REVIEW line.

The model reads the release file it was trained on (the sdist when there is one), which is not always the file pip installs (often a wheel). The rules always read the file pip installs.

If the ML model cannot run (not installed, a model file changed, time limit of 45 seconds per package, any error), the verdict is made by the rules alone and the decision says why.

## How well it works

Measured on 650 benign PyPI packages that were not used for training or for choosing the model (collected 2026-11-05: 250 created on 2026-11-01, 250 random from the PyPI index, 150 from ranks 6,001-10,000 of the most downloaded), with the package installed on the day of its first upload (the worst case) and 1-30 days later:

| False alarms (benign packages) | REVIEW | note or REVIEW (stage 1) |
| --- | --- | --- |
| all, installed the same day | 2.0% (13/650) | 8.9% (58/650) |
| new packages, the same day | 4.0% (10/250) | 21.6% (54/250) |
| new packages, 1-30 days later | 0.4% (1/250) | 2.4-2.8% |
| random index packages | 0.8% (2/250) | 1.2% (3/250) |
| popular packages | 0.7% (1/150) | 0.7% (1/150) |

On recently published malicious packages (time split: trained on the older 80%, tested on the newest 20%, 271 with readable code), 93.0% reach REVIEW (seeds 42-46: 92.3-93.4%). When a malicious release is installed a day or more after the project's first upload, that drops to about 88-89%.

The metadata model (used only when the code cannot be read) reaches REVIEW on about 57% of the same malicious packages in the time split, and on the 650 benign packages its REVIEW rate is at most 5.2% (new packages, same day).

Limits:

- **Taken-over packages** (a malicious release of an old, popular project) look like the project's history: the model rarely flags them.
- **Dependency attacks**: only the package being installed is scored, not what it pulls in (the rules check dependencies for known vulnerabilities and malicious versions).
- **Agent-facing text** (instructions hidden in a README or docstring for a coding agent) is not a feature of the model.
- Packages installed on the day of their first upload get many more notes (1 in 5 new packages in the check above); most of them stay notes because no risky behavior is found.

## The model

| | Full model | Metadata model |
| --- | --- | --- |
| Used when | the code of the release could be read | it could not (no file of 20 MB or less, an unreadable or AES-encrypted archive) |
| Features | 32: 5 upload, 7 packaging, 20 code | 12: 5 upload, 7 packaging |
| Training packages | 1,351 malicious, 1,833 + 498 benign | 11,666 malicious, 5,996 + 498 benign |
| Alert threshold | 0.2352 | 0.9002 |
| Review threshold | 0.2352 + a code behavior signal | 0.9464 |

Both are random forests (300 trees), trained with scikit-learn 1.9.1 on 2026-11-05 from a data snapshot of 2026-09-25 plus 498 newly published benign packages, and converted to JSON ([guard/ml/convert.py](../guard/ml/convert.py)). The converted forest gives the same scores as scikit-learn (largest difference below 1e-12 on the measured sets).

The package age is the age of the project when it is checked: whole days from its first upload to the scan time. During training, new benign packages were also shown at 0-30 days and malicious ones at every age up to their report, so that a package is not judged by its age alone. The thresholds are the lowest that keep the false alarms on 494 other benign packages within all goals (all ≤ 5%, popular ≤ 2%, new and random index ≤ 8%) at install ages of 0-30 days.

Features:

- **Upload**: number of versions so far, days since the project's first upload, free mail address, number of e-mail addresses, empty author.
- **Packaging**: wheel published, total size, number of dependencies, homepage, license, number of classifiers, summary length.
- **Code** (read as text and parsed, never run): Python files, lines, longest line, rate of hiding signals, and counts of `exec`/`eval`, decoding, long encoded strings, external commands, network access and data theft traces, both overall and in `setup.py`, an installation hook (`cmdclass`), and which of these run at import or install time, including decoded data passed straight to `exec`.

The reasons shown for an alert are the features that raised the score most for that package (TreeSHAP values, computed only for an alert), written as sentences.

## Network and files

- `ml-install` downloads the two model files from `github.com` (the release). Nothing else.
- At check time the model reads the release file the guard already downloaded. When there is none, it downloads the release file itself from `files.pythonhosted.org` (sdist first, 20 MB or less). Nothing is sent anywhere else.
- Files: `~/.aegis/ml/` only.

## Settings

| Switch | Default | Effect |
| --- | --- | --- |
| `AEGIS_ML` | on when installed | `0`: do not use the ML model; `1`: use it (an error when it is not installed) |
| `AEGIS_ML_DIR` | `~/.aegis/ml` | another folder for the models. It names the model files the guard loads, so a built guard reads it from a settings file only ([configuration.md](configuration.md#switches-that-a-built-guard-ignores-in-the-environment)) |
| `AEGIS_ML_TIMEOUT` | `45` | seconds per package |
