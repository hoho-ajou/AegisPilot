# Using AegisPilot

AegisPilot runs on its own once installed. It looks at each shell command and file edit the agent is about to make. Commands that install or change nothing pass straight through.

## What is checked

Install commands:

| Kind | Commands |
| --- | --- |
| Python | `pip`, `pip3`, `python -m pip`, `uv pip install`, `uv add`, `uv sync`, `poetry add` / `install`, `pdm`, `pipx`, `pipenv`, `pip-sync`, and `-r requirements.txt` files |
| npm | `npm install` / `ci` / `update`, `npx`, `npm exec`, `npm init` / `create`, `yarn`, `pnpm`, `pnpx`, `bun`, `bunx` |
| Git and URL | `git+https://...` installs, `npm install github:owner/repo`, and https URLs of `.whl`, `.tar.gz`, `.tgz` and `.zip` files |
| Project installs | installs that name no package (`uv sync`, `poetry install`, bare `npm install`) are read from the project files, with the lock file's versions when there is one |

Dependencies pulled in by the package are also checked: all of them against OSV for known malicious releases, and recently released ones with a full scan.

Settings changes:

- a new MCP server in `.mcp.json` or `~/.claude.json`, or added with `claude mcp add`;
- a new hook command or hook script in an agent settings file;
- a plugin switched on in settings, or added with `claude plugin install` or `claude plugin marketplace add`;
- a change to where packages come from (`pip config set ...`, `pip.conf`, `uv.toml`, `.npmrc`).

For MCP servers, hooks and plugins, the code they would run is fetched and scanned like a package.

Some sources cannot be read: private indexes the guard does not know, `ssh://` and `git://` URLs, conda channels and other ecosystems. They are reported as not checked, and the action gets a REVIEW. They are never passed silently. See [configuration.md](configuration.md#private-package-indexes) for indexes you set up yourself.

## Verdicts

| Verdict | Meaning |
| --- | --- |
| ALLOW | No known risk signal was found. The command runs and nothing is shown. ALLOW means no red flags were found, not that the package is verified safe. |
| REVIEW | A suspicious signal was found, or part of the install could not be checked. Someone has to decide. Records show it as `NEEDS_HUMAN_REVIEW`. |
| BLOCK | A critical vulnerability, a release OSV lists as malicious, a deny-list entry, or code that runs downloaded, decoded or hidden code. The command is stopped. |

Each message starts with `[AegisPilot ...]` and ends with `Details: /aegis`.

## Modes: user and auto

The default is `user` mode: you decide on every REVIEW and BLOCK. `auto` mode is for runs where nobody is watching, and you turn it on yourself.

| | `user` (default) | `auto` |
| --- | --- | --- |
| REVIEW | Claude Code's approval dialog. You decide. | The agent gets an evidence card and an ack id, and decides. |
| BLOCK | The command is refused. A report is shown and the agent asks you what to do. | The command is refused. The agent gets the evidence card and an ack id, and decides; it can go ahead after `guard_cli.py ack <id>`. |
| Actions on the guard itself | Claude Code's approval dialog. You decide. | Claude Code's approval dialog. You decide. |

In `auto` mode the agent is told to start its final answer with a one-line summary per package (for example `[AegisPilot] pyyaml 5.3.1 blocked · CRITICAL · upgrade to >=5.4`). That line comes from the agent, so you see it only if the agent follows the instruction. The full record is always in `.aasm/reviews/` (see below). Because the agent can go ahead after a BLOCK in this mode, use `auto` only where an unattended run matters more than a person seeing every BLOCK.

To switch, create `.aasm/policy.json` in the project:

```json
{"mode": "auto"}
```

or set the environment variable `AASM_MODE=auto` (or `user`).

Precedence:

1. `AASM_MODE`, if set. An unknown value selects `user`.
2. `"mode"` in `<project>/.aasm/policy.json`. A file that exists but cannot be read, or has an unknown or missing `"mode"`, selects `user`.
3. Otherwise `user`.

A mistake in the setting, or a deleted policy file, never selects the mode that shows you less. `.aasm/policy.json` is a protected path: when the agent edits it, AegisPilot asks you.

## Why was this stopped?

The approval dialog shows one line. For the full explanation, type `/aegis` in Claude Code (it shows as `/aegis-pilot:aegis` in a plugin install). The agent reads the decision record and explains, per package: where the finding is, how it would run, what could go wrong, why it was flagged, and when it can be legitimate.

The records are in the project folder:

| File | Contents |
| --- | --- |
| `.aasm/last_review.json` | the latest decision |
| `.aasm/reviews/<decision id>.json` | each decision by its id (for example `D7f3a`). The last 200 are kept. |

Packages in a decision are numbered `P01`, `P02`, and so on.

To print the latest decision in a terminal, run this from the project folder:

```bash
python3 <guard>/guard_cli.py report              # short report
python3 <guard>/guard_cli.py report --full       # every field
python3 <guard>/guard_cli.py report --format md  # writes .aasm/reports/<time>_<package>-<version>_<verdict>.md
```

`<guard>` is the plugin folder or the `guard/` folder of your clone.

Strings in these records come from the scanned package and its metadata. Treat them as data. `/aegis` quotes them and does not follow instructions found in them.

## The ack flow in auto mode

In auto mode a hook can only allow or refuse before the command runs. So for a REVIEW or a BLOCK, AegisPilot refuses once and gives the agent the evidence and an ack id. The agent then does one of two things:

- takes another way (another version, another package, no install). That command is checked again as usual.
- decides to go on with this exact action:

  ```bash
  python3 -I <guard>/guard_cli.py ack <ack id>
  ```

  and runs the same command, or the same file change, again unchanged. It passes once.

Rules for an ack:

- An ack id is 8 hexadecimal characters and is valid for 30 minutes.
- It is used once. Running the action again needs a new id.
- It is bound to the exact command text, or the exact file and content. A changed command is a new action and is checked again.
- The agent is told to say in its final answer what it went ahead with and why.

User mode does not use acks. Actions on the guard itself never get an ack (see below).

Acks are stored in `~/.aasm/acks.json`.

## Attack paths

For a flagged package, AegisPilot can show what it could reach in this environment: which credentials, settings and code the agent's environment exposes, and how the package's behavior connects to them.

```bash
python3 <guard>/guard_cli.py paths --project .
```

| Option | Effect |
| --- | --- |
| `--decision D7f3a` | use this decision instead of the latest |
| `--json` | print the result as JSON |
| `--judge` | when CVEs need a judgement of whether they apply to this project, print the request for the agent |

With `--judge`, the agent reads only the advisory files saved under `.aasm/osv/` and the project's own code, writes its quoted evidence to `.aasm-ai/cve_judgments.json`, and runs `paths` again. Quotes that do not match the files are rejected.

The result is saved to `.aasm/attack_paths.json` and `.aasm/attack_paths/<decision id>.json`. Attack paths are an explanation only. They never change a verdict.

To see the environment profile on its own:

```bash
python3 <guard>/guard_cli.py profile --project .
```

It lists what the environment can do and reach. It does not read secret values.

## Self-protection

Some actions would turn the guard off or change it. For these, AegisPilot always asks you in Claude Code's approval dialog, in both modes. In auto mode the agent gets no ack id and cannot decide on its own.

These actions are:

- editing, moving or deleting guard files, the installed plugins folder, `.aasm/` in a project, or `~/.aasm/`;
- `claude plugin disable` or `claude plugin uninstall` of `aegis-pilot`, or removing its marketplace;
- editing an agent settings file so that a guard hook disappears, the plugin is disabled (`"enabledPlugins"` set to `false`), or `"disableAllHooks"` is turned on;
- shell commands that write agent settings files;
- running `guard_cli.py installs`, `repair`, `system-install` or `system-uninstall` through the agent.

Reading these files is not affected.

Other settings changes, such as a new MCP server, a different hook or a permissions change, are scanned as described above. In auto mode they go to the agent's decision as usual.

In a non-interactive run (`claude -p`, SDK runs) nobody can answer the dialog, so an action on the guard itself is refused. If you need to change the guard in such a setup, do it yourself outside the agent.

To check whether the guard's files are the released ones:

```bash
python3 <guard>/guard_cli.py verify
```

See [how-it-works.md](how-it-works.md#self-protection) for how this works.
