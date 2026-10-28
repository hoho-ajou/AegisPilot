# Rule files

Everything the guard looks for in package files, and how it reaches a verdict, lives in the JSON files in this folder. `guard/rule_engine.py` is the engine that reads and applies them; it holds no rule values of its own. **To change or add a rule, edit these files, not the code.**

| File | Contents |
|---|---|
| `signals.json` | What to look for: the pattern dictionary (dangerous keywords, decode / exec / download calls, setup.py patterns, dangerous calls in `.pth` files, long encoded blobs), what counts as a test or dev folder, alias-resolution targets, and exceptions for chains inside strings |
| `rules.json` | Where and how to look, and what evidence to record. Applied top to bottom; this order is the order in which evidence accumulates |
| `scoring.json` | The verdict: weights, block and review thresholds, reference values for subscores, hard rules (order, condition, block/review, reason text), and the weight of the ML score |
| `post.json` | Verdict adjustments after the scan (`post_rules.py`): known malicious version, risky code new in this version, files added later, OSV unreachable, name impersonation, new package. Also the patterns and reference values used to compare against the previous version (`version_diff.py`) |
| `behavior.json` | The policy table for the behavior check (`guard/behavior`): behavior (finding) x execution time (auto = install, interpreter start, import; call) -> block / review / null, the vocabulary used to classify recovered values (credential and auto-run paths, collection and messenger addresses, build tools), and time and size limits. The analyzer builds behavior facts from recovered values and data flow, not from text patterns, and this table decides the verdict. The `scoring.json` hard rules `behavior_block` / `behavior_review` feed the result into the verdict |

## Base rules and rule modules

The files in this folder are the **base rules**. They are maintained by the project and ship with the guard. Users and administrators do not edit them; they layer **rule modules** on top (`guard/rule_modules.py`).

| Location | Who | When it is read |
|---|---|---|
| `~/.aasm/rules/*.json` | User | When the guard is installed in the user's own folder. Not read for a system install (a guard the user cannot write to) |
| `/etc/aasm/rules/*.json` | Administrator | When the folder and files are owned by root and not writable by other users. Applied after user modules, so they take precedence |

- Within one location, modules are applied in file name order.
- **Protection:** `~/.aasm/` is a protected path. When an agent writes a module, the guard asks for confirmation, the same as when it edits guard files. In auto mode it returns an evidence card and an ack id.
- **Failure handling:** a broken module is skipped as a whole, for example on a JSON error, an unknown key, a missing id, or a rule the engine cannot read. The guard keeps running with the rest.
- **Checking:** `python3 guard/guard_cli.py verify` shows which modules were applied and which were skipped. `python3 guard/rule_check.py --modules` shows the status of each module and runs the examples inside it.
- **Cache:** the verdict cache is not reused when the rule fingerprint differs. Changing a module triggers a rescan.

A module is `{"schema": 1, "name": ..., "about": ...}` plus any of the keys below:

| Key | What it does |
|---|---|
| `signals` | `{name: signal}`: add a signal or replace one with the same name |
| `rules` | `[rule]`: add a `rules.json` rule or replace one with the same id. The display text is the rule's `report` |
| `hard_rules` | `[hard rule]`: add a `scoring.json` hard rule (at the end) or replace one with the same id |
| `post_rules` | `[rule]`: add a `post.json` verdict adjustment (at the end) or replace one with the same id |
| `findings` | `{behavior: {auto, call, label, text, phases}}`: change an existing behavior in the behavior policy (`behavior.json`). New behaviors cannot be added, because the analyzer has to produce them |
| `set` | `{"<file>.<key>.<key>": value}`: change a single value. Example: `"scoring.thresholds.review": 0.2` |
| `add` | `{"<file>.<key>.<key>": [..]}`: append to a list. Example: `"scoring.subscores.typosquat.popular_names": ["langchain"]` |
| `disable` | `{"rules" \| "hard_rules" \| "post_rules" \| "findings": [id]}`: turn off base entries |
| `examples` | `{"static" \| "hard" \| "post": {id: [example]}}`: examples for this module. Same format as `examples/` |

`<file>` is one of `signals`, `rules`, `scoring`, `post`, `behavior`.

Example: ask for review when a package contains an internal secret marker, and include internal package names in the impersonation check.

```json
{
  "schema": 1,
  "name": "Company rules",
  "signals": {"corp_marker": {"description": "Internal secret marker", "regex": ["CORP-SECRET-[0-9]{4}"], "quick": ["corp-secret-"]}},
  "rules": [{"id": "corp_secret_marker", "title": "Internal secret marker", "detector": "first_line", "signal": "corp_marker",
             "text": "original", "files": "code", "report": {"label": "Internal secret marker", "reason": "Internal secret marker string"}}],
  "hard_rules": [{"id": "corp_secret_marker", "when": {"evidence": "corp_secret_marker"}, "action": "review",
                  "reason": "[Company rules] internal secret marker -> review"}],
  "add": {"scoring.subscores.typosquat.popular_names": ["corp-sdk", "corp-auth"]},
  "examples": {"static": {"corp_secret_marker": [
    {"expect": "hit", "why": "marker", "files": {"pkg/a.py": "k = 'CORP-SECRET-0001'\n"}},
    {"expect": "miss", "why": "other text", "files": {"pkg/a.py": "k = 'CORP-PUBLIC'\n"}}]}}
}
```

Limits: evidence added by a module has no meaning in the attack path capability table (`capabilities.json`), so it does not appear in the attack path diagram. It does appear in the verdict and the evidence card.

The ML model and its features are not here. Changing features requires new data collection and retraining, so they live in `guard/r3`. `scoring.json` only sets how much the ML score counts.

## Detectors the engine knows

Each rule in `rules.json` picks one of the detectors below and supplies its values. Edit `rule_engine.py` **only when a new detector is needed**.

| detector | What it does | Main values |
|---|---|---|
| `keyword_count` | Counts the signal's strings per file and records the first line for each keyword as evidence | `signal` |
| `chain` | Records evidence (two lines) when the first signal and the second signal appear within N lines. Pairs inside descriptive strings are excluded | `first`, `then`, `within_lines`, `first_in_strings` (count the first signal even inside a one-line string, such as a file path), `then_in_strings` (the second signal is inside a one-line string and the first must be code: a call that runs a command written as a string, like `os.system("curl … \| sh")`), `max_line_chars` (skip lines longer than this: minified code is one line, so "nearby" means nothing) |
| `entropy_blocks` | Records evidence when the entropy of a long blob (decoded first if base64) exceeds the threshold | `signal`, `min_entropy`, `skip_url_tokens` |
| `first_line` | Records the first line where the signal appears | `signal`, `text` (normalized/original), `skip_docstrings` (exclude multi-line docstrings, original only), `unless_near` (`{"signal", "lines"}`: do not count a line when that signal is within N lines, for example defensive docs that *discuss* attack phrases) |
| `startup` | Chains, dangerous calls and entropy in `.pth` import lines or sitecustomize | `select` (pth/startup_py), `chains`, `risky`, `entropy` |
| `setup_local_imports` | Dangerous keywords in local modules imported by an install hook | `signal`, `keywords` |
| `placement` | Judges a file by **where it is installed** (wheel standard: `<dist>.data/purelib` and `platlib` -> site-packages, `scripts` -> bin, `data` -> environment root) | `check`: `command_shadowing` (installs a command with a common command name, `signals.json` `commands`), `sourceless_bytecode` (.pyc with no .py), `environment_index` (pip or uv config at the environment root pointing to a different index) |

Common values: `lang` (languages to read: `python` (default), `js`, `shell`, or a list. File extensions and languages are in `signals.json` `languages`), `evidence` (name of the evidence to record; defaults to `id`. A rule that finds the same thing in another language can use an existing evidence name and inherits its hard rules, report text and attack path meaning: JavaScript `eval(atob(…))` is also `decode_then_exec`), `id` (rule name. The output module `r4/text_format.py` picks text by this name, so update it there too if you rename), `files` (`code` = .py files outside test and dev folders, `install_setup` = setup.py run at install time, `text` = all text files outside test and dev folders (.js, .md, METADATA and so on; types and size limit in `signals.json` `paths.text_files`), only with `first_line` + `text: original`), `sets` (signal names to set).

Optional signal values (`signals.json`): `quick` (list of lowercase substrings. If none appears in the file, the patterns are skipped. Every string the patterns match must contain one of them), `lowercase` (write the patterns in lowercase and match them against lowercased text. Faster than case-insensitive patterns).

`report` (optional): the text used to show this rule's evidence to the agent and the person. `label` (short name), `path` (how it runs), `risk` (impact), `reason` (why it matched), `benign` (legitimate cases), `lead` (if true, shown first, right after block-level evidence). Text for older rules still lives in code (`review_report.py`, `r4/text_format.py`); new rules only need this.

Hard rule conditions in `scoring.json` are written as `{"field": name}` (value is true), `{"field": name, "equals": value}`, `{"evidence": rule id}` (that rule recorded evidence; new rules do not need a separate scan result field), `{"all": [...]}`, `{"any": [...]}`. The reason text variable `join_evidence` joins the names of the remaining evidence. `{window}` in reason text follows the `within_lines` of the rule named in `window_from`.

## Scan targets (ecosystems)

`ecosystems` in `signals.json` sets which languages are read as code for each scan target. A rule applies only when the file's language is a code language of that target and is listed in the rule's `lang`.

| Target | Languages read as code | Skipped folders |
|---|---|---|
| `pypi` | python | tests, top-level maintenance folders (`paths.dev_toplevel`) |
| `npm` | js, shell (package.json install scripts are read as `package.json#<event>.sh`, `node -e` code as `.js`) | tests, `dev_names` (`scripts/` is not skipped for npm, because it runs at install time) |
| `bundle` | python, js, shell (skills, plugins, hooks) | none |

PyPI package scans read only .py files, exactly as before languages were added (checked against a fixed sample set).

Files with no extension get their language from the first line (`#!`). In a wheel, **files installed outside the package** (commands in bin, files at the environment root) are read as code in any language, because they can run without being imported. `.pth` and sitecustomize files count as files run at startup not only at the wheel top level but also at the top level of `<dist>.data/purelib` and `platlib`.

Lines starting with the `comment_prefixes` in `languages` (js: `//`, `/*`, `*`; shell: `#`) and quoted text printed by `message_commands` (shell: echo, printf) are not seen by code rules, because they do not run. If the output is piped onward it is not a message, so it is seen. Evidence snippets show the original line. Python handling is unchanged.

## Verdict adjustments after the scan (post.json)

`rules` are checked top to bottom, and only the first rule that matches and whose `applies_to` contains the scan verdict is applied. On a match the verdict becomes `verdict`. Removing a rule turns that check off; reordering changes what is reported first. Each rule name must be one of the six below (add new kinds in `post_rules.py`).

| id | Matches when | Value |
|---|---|---|
| `known_malicious` | OSV reports this version as malicious (including removed versions) | `known_malicious` |
| `new_risky_code` | Risky code appears that was not in the previous version | `version_diff` |
| `late_file` | A file to be installed was recently added to an old version | `late_file` |
| `osv_unavailable` | OSV could not be reached during the scan | `osv_probe` |
| `typosquat` | The name is close to a popular package name (distance threshold in `scoring.json`) | `typosquat` |
| `new_package` | The package was first registered recently | `new_package` |

`transitive` in `post.json` sets the scope of the transitive dependency check (dependencies pulled in by the package being installed directly): how many levels to follow (`max_depth`), how many packages (`max_packages`), how many days old a version can be and still get a full scan (`recent_days`), how many full scans at most (`max_scans`), and the time budget (`budget_seconds`). All dependencies found are sent to OSV in one query to find known malicious versions (`guard/transitive.py`).

## Examples and the rule list

Each rule has examples that must match (hit) and examples that must pass (miss) in `examples/` (`static.json` = rules.json, `hard.json` = hard rules, `post.json` = verdict adjustments, `version_diff.json` = version comparison signals). Examples are only read, never executed.

- `python3 guard/rule_check.py`: runs all examples. Fails when an example does not hold, when a rule has no hit or no miss example, or when examples remain for a rule that no longer exists. When you add a rule, add its examples too.
- `python3 guard/rule_check.py --doc`: regenerates `RULES.md` (the rule list) from the rule files. Do not edit `RULES.md` by hand. If you change rules without regenerating it, the tests fail.

## Checks after a change

1. `python3 scripts/run_tests.py`: `test_rule_engine.py` reports format errors in the files, and `test_rule_examples.py` reports failing examples or a stale `RULES.md`.
2. If the change can affect verdicts, compare before and after on a fixed sample set of benign and malicious packages, and confirm that every difference is intended.
3. After committing, rebuild the stable build (`python3 scripts/build_dist.py stable`). The hook uses the rule files of the stable build.

If a rule file is broken, the guard does not let the install through; it asks for review with "rule file error: …". The four rule files are covered by the guard's self-protection (checksums). To test with rules from another folder, use `AASM_RULES_DIR`.
