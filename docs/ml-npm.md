# ML model for npm

The PyPI model ([ml.md](ml.md)) reads PyPI data and Python code. This page explains why npm got its own models instead of one model for both, which features they read, and how they are trained, measured and switched on.

**Status (2026-11-17):** the code is in place (features, scoring, guard hook, training scripts, tests) and model v2 is trained and measured (below). `guard/ml/models.json` carries its `npm` block (npm_full only). The model file `aegis-ml-npm-full-2.json.gz` is on the GitHub release `ml-models-npm-2`: the guard downloads it on the first npm check and checks its SHA-256. Until it can be downloaded, npm packages are checked by the rules alone (a failed automatic download is tried again after 6 hours, or at once with `guard_cli.py ml-install`).

## Results (model v2)

Trained with [training/npm](../training/npm/README.md) (`--mal-all-ages --model-version 2`): 23,481 malicious samples (DataDog, found 2024–2026; those found on or after 2026-03-01 are the test set), 4,500 benign packages (1,500 popular, 1,500 long tail, 1,500 created in the last 30 days), and a separate final set of 660 benign packages measured once.

| | npm_full v2 |
| --- | --- |
| Threshold | 0.2716 |
| Malicious REVIEW, installed 0 / 7 / 30 days after publishing | 82.2% / 82.1% / 82.0% |
| Benign REVIEW, all packages | 4.1–4.7% (goal 5%) |
| Goal missed | final set, packages created in the last 30 days, at 0–1 day: 21 of 252 (8.33%, goal 8%) |
| Pure-Python forest vs scikit-learn | largest score difference 1.1e-16 |

- Model v1 (malicious rows only at the ages they were installable, i.e. mostly day 0) leaned on the package's age: 79.7% at day 0, 74.0% at day 30. v2 trains every malicious row at every install age, as the PyPI model R3f does.
- Weak spot: malicious versions that stayed on the registry a week or more get REVIEW in 3–13% of cases; their scores are high (80–92% alert), but their code shows no behavior signal, so the second stage keeps them at "note".
- **Only npm_full is released.** npm_pkg (no registry document) raised false alarms in v2 (5.24% overall, 2.88% popular, 8.92% long tail), so a version whose registry document cannot be read (over 16 MB, no answer) gets no ML verdict and no ML line; the rules still check it.
- One model for both ecosystems: about the same on npm (AUC 0.965 vs 0.967), worse on PyPI (88.9% vs 91.5% detection at 2% false alarms) — separate models stay.

## One model or two?

Every PyPI feature was checked for an npm counterpart that exists both in the malicious training samples and at install time in the guard:

| PyPI feature (group) | npm counterpart | Same quantity? |
| --- | --- | --- |
| n_versions, age_days (upload) | registry `time`: versions up to this one, days since `created` | yes, from the registry's full document |
| free_email, email_count, author_empty | package.json author / contributors / maintainers, registry maintainers | yes |
| has_home, has_license, summary_len, n_requires (packaging) | homepage/repository/bugs, license, description, dependencies | yes |
| total_size | the files the guard keeps | yes |
| has_wheel, n_classifiers | — (npm has no wheels or classifiers; keywords are not the same thing) | **no counterpart** |
| n_py, code_lines, obfuscation_rate, exec / decode / long_blob / process / network / sensitive counts | the same ideas in JavaScript (`eval`, `Function`, `vm`, `Buffer.from(…,'base64')`, `child_process`, `https`, `fetch`…) | same idea, **different measurement** (another language, another parser) |
| max_line_len | longest line | **different meaning**: a 1-line minified file is normal in npm, a strong sign of hidden code in PyPI |
| setup_* , install_hook | code the lifecycle scripts run (`preinstall`, `install`, `postinstall`), `node -e` | same idea, different mechanism |
| auto_* | calls at the top level of a file (not inside a function) | same idea |
| — | `recon_cnt` (os.hostname, userInfo… — dependency-confusion probes), `obf_ident_cnt` (javascript-obfuscator `_0x…`), `version_major` (999.9.9 tricks), `script_network`, `has_bin`, `has_gyp` | **npm only** |

About two thirds of the ideas carry over, but not the numbers behind them. A single forest over both ecosystems would have to learn each ecosystem's normal separately anyway (it would split on the ecosystem first), it would mislearn the features whose meaning differs (line length), it could not use the npm-only signals for PyPI or the PyPI-only ones for npm, and retraining it would void the PyPI model's measured numbers (2.0% false REVIEW, 93.0% recall), which were measured once on a frozen model.

**Decision: separate models, shared method.** npm has its own models and feature code; everything else is the PyPI model's: the same runtime (`forest.py`, JSON forests checked by SHA-256), the same two stages (an alert becomes REVIEW only with a behavior signal found in the code), the same scaling into the verdict (ML alone never blocks), the same way of choosing the threshold (false-alarm goals at install ages 0–30 days, then one measurement). `training/npm/train.py --joint-pypi` repeats the comparison with numbers: a forest on the 30 shared ideas trained on PyPI + npm against one trained on npm only, both measured on the npm test set.

## Features

`guard/ml/npm_features.py` and `guard/ml/js_code_features.py`, standard library only. The same code computes the training data and the guard's input, from a tarball/sample zip or from the guard's unpacked folder (a test checks they agree).

- **Registry (4):** `n_versions` (published up to this version), `age_days` (whole days since the package was created, at scan time, as for PyPI), `n_maintainers`, `maint_free_email`. From the registry's full document, which `ml/scan.py` fetches (up to 16 MB, 15 seconds; otherwise `npm_pkg` is used). The malicious samples of the DataDog dataset carry that document as it was when they were found (`package_info-*.json`).
- **Package (18):** package.json (dependencies, license, homepage, description, keywords, author/e-mail, bin, version major), file list (files, size, README, binding.gyp) and the lifecycle scripts (present, length, network commands, `node -e`).
- **Code (22):** counts over the JavaScript files, the install-time versions of them (`install_*`: the files the lifecycle scripts run, followed through `npm run`, `sh`, `node -e`), and top-level calls (`auto_*`; a function called in place — `(function(){…})()` — counts as top level). Comments are removed first; a top-level `require('https')` alone is not a network call.
- **Time budget:** install-time files are always read in full; the others smallest first until 8 million characters, then only counted and measured (a malicious CLI sample carried 58 MB of bundles). The slowest of 750 samples took 13 s including zip decryption.

Two models are trained: `npm_full` (all 44) and `npm_pkg` (without the registry 4, for a version whose registry document cannot be read). A release may ship `npm_full` alone; without `npm_pkg` such a version gets no ML verdict.

### Two stages

As for PyPI. The npm lists are in `npm_features.py`:

- severe (always a behavior signal when present): decoded data run as code, top-level `eval`/command calls, anything the install scripts run that executes strings, decodes, runs commands, goes online or touches secrets, traces of data theft, network commands or `node -e` in the install scripts;
- other behavior (a signal only when it also raised the score): top-level network calls, obfuscation, `eval`/decode/long encoded strings/obfuscator names, commands, network code, machine fingerprinting, an install script.

Line length and minified files are package profile in npm, not behavior.

## In the guard

npm packages go through the same per-package pipeline as PyPI (`scan_engine._scan_release`): the download, rules and behavior analysis, the dependency list, OSV and the ML model run at the same time, then the verdict. Once the version is unpacked, `ml_bridge.ml_predict_npm` runs `ml/scan.py --ecosystem npm --dir <unpacked>` in a separate process (45 s limit). When OSV lists the version as malicious, the model process is stopped, or not started if OSV answers first (the verdict is BLOCK either way). The result is used exactly like the PyPI one. Model files of the npm group are downloaded on the first npm check, apart from the PyPI ones (`ml_install`, group `npm`); a failure is remembered for npm only. `AEGIS_ML=0` and `ml-uninstall` turn off both. `guard_cli.py verify` shows an `ML (npm)` line.

Dependencies: those with install scripts that the guard scans (checks/npm.py, up to 15 per command) get the model too, as PyPI dependencies do. Not covered: npm packages installed from git or a URL (no registry history), and the other dependencies (OSV still checks the whole tree for malicious releases).

## Training and measurement

See [training/npm/README.md](../training/npm/README.md). In short: malicious samples from the DataDog dataset (about 26,700 npm samples found 2024–2026, `malicious_intent` and `compromised_lib`), split by the day they were found; benign packages in three groups (popular, long tail, created in the last 30 days); names of the benchmark sets left out so the benchmark stays independent; identical malicious copies capped at three; the threshold chosen from out-of-fold predictions on the training benign packages; the test sets measured once.
