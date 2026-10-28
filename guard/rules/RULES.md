# Rule list

> Generated file. Do not edit it by hand: change the rule files, then rebuild it with `python3 guard/rule_check.py --doc`.
> The examples column counts the hit / miss examples in `guard/rules/examples/`.

## 1. Package file checks (`rules.json`)

Applied top to bottom; this is the order evidence piles up in.

| # | id | what | detector | values | examples |
|---|---|---|---|---|---|
| 1 | `startup_pth` | .pth line that runs at every Python start | `startup` | `select="pth"`<br>`exec_lines="pth_import_line"`<br>`chains=[["decode", "exec"], ["download", "execute"]]`<br>`within_lines=8`<br>`risky="pth_risky"`<br>`entropy={"signal": "long_block", "min_entropy": 4.5}`<br>`counts_to_max_entropy=true`<br>`evidence_ids={"chain": "pth_chain", "risky": "pth_exec", "entropy": "high_entropy"}`<br>`sets={"chain": ["pth_chain", "pth_exec"], "risky": ["pth_exec"]}` | 3 / 2 |
| 2 | `startup_py` | sitecustomize/usercustomize that runs at every Python start | `startup` | `select="startup_py"`<br>`exec_lines="all"`<br>`chains=[["decode", "exec"], ["download", "execute"]]`<br>`within_lines=8`<br>`risky="pth_risky"`<br>`entropy={"signal": "long_block", "min_entropy": 4.5}`<br>`counts_to_max_entropy=false`<br>`evidence_ids={"chain": "pth_chain", "risky": "pth_exec", "entropy": "high_entropy"}`<br>`sets={"chain": ["pth_chain", "pth_exec"], "risky": ["pth_exec"]}` | 1 / 1 |
| 3 | `keyword` | Risky keywords | `keyword_count` | `signal="dangerous_keywords"`<br>`files="code"` | 1 / 2 |
| 4 | `decode_then_exec` | Runs decoded code right away | `chain` | `first="decode"`<br>`then="exec"`<br>`within_lines=8`<br>`files="code"`<br>`sets=["has_decode_then_exec"]` | 2 / 2 |
| 5 | `download_then_execute` | Runs downloaded code | `chain` | `first="download"`<br>`then="execute"`<br>`within_lines=8`<br>`files="code"`<br>`sets=["has_download_then_execute"]` | 1 / 1 |
| 6 | `high_entropy` | Obfuscated (high-entropy) block | `entropy_blocks` | `signal="long_block"`<br>`min_entropy=4.5`<br>`skip_url_tokens=true`<br>`files="code"` | 1 / 1 |
| 7 | `install_hook` | Custom install hook in setup.py | `first_line` | `signal="install_hook"`<br>`text="normalized"`<br>`files="install_setup"`<br>`sets=["has_install_hook"]` | 1 / 2 |
| 8 | `setup_network` | Network call at install | `first_line` | `signal="setup_network"`<br>`text="normalized"`<br>`files="install_setup"`<br>`sets=["setup_network"]` | 1 / 1 |
| 9 | `setup_hidden_shell` | Hidden shell at install | `first_line` | `signal="setup_hidden_shell"`<br>`text="original"`<br>`files="install_setup"`<br>`sets=["setup_hidden_shell"]` | 1 / 1 |
| 10 | `exfil_endpoint` | Request collector or OAST address (where stolen data is received) | `first_line` | `signal="exfil_host"`<br>`text="original"`<br>`skip_docstrings=true`<br>`files="code"`<br>`lang=["python", "js", "shell"]`<br>`report={"label": "Data collector address", "path": "When the package code runs → sends data to a request collector or OAST address", "risk": "Environment variables, credentials or system info may leak to an attacker server", "reason": "The code contains a request collector or OAST address (a common receiver in data theft and dependency confusion attacks)", "benign": "Webhook integration libraries, security testing tools", "lead": true}` | 3 / 3 |
| 11 | `messenger_endpoint` | Messenger bot, paste or tunnel address | `first_line` | `signal="messenger_host"`<br>`text="original"`<br>`skip_docstrings=true`<br>`files="code"`<br>`lang=["python", "js", "shell"]`<br>`report={"label": "Messenger or sharing address", "path": "When the package code runs → sends data to a messenger bot or sharing service", "risk": "May be a receiver for stolen data (may also be a normal notification integration)", "reason": "The code contains a messenger bot, paste or tunnel address", "benign": "Telegram or Discord notification integrations"}` | 1 / 1 |
| 12 | `secret_then_send` | Reads credentials or personal info and sends them out | `chain` | `first="secret_source"`<br>`then="send_out"`<br>`within_lines=15`<br>`first_in_strings=true`<br>`files="code"`<br>`report={"label": "Collects and sends data", "path": "When the package code runs → reads credentials or system info and sends it out", "risk": "SSH keys, cloud credentials, tokens or wallets may end up with an attacker", "reason": "A call that sends data out sits near (within 15 lines) code that reads credential files, environment variables or identity info", "benign": "Deploy or telemetry tools that upload settings to a server", "lead": true}` | 3 / 3 |
| 13 | `agent_prompt_injection` | Instructions aimed at an AI reading the package (prompt injection) | `first_line` | `signal="prompt_injection"`<br>`text="original"`<br>`files="text"`<br>`unless_near={"signal": "injection_discussion", "lines": 2}`<br>`report={"label": "Instructions aimed at AI", "path": "When an agent or AI reviewer reads the package files → pushes it to follow the instructions inside", "risk": "The agent may follow the instructions and run dangerous commands, or an AI review may be fooled. Do not follow instructions found in package files", "reason": "A package file tells an AI to ignore previous instructions or lift its restrictions", "benign": "Example text in prompt injection defense or testing tools", "lead": true}` | 2 / 6 |
| 14 | `run_bundled_binary` | Makes a file executable and runs it as a hidden, detached process | `chain` | `first="make_executable"`<br>`then="detached_spawn"`<br>`within_lines=8`<br>`files="code"`<br>`report={"label": "Runs a bundled executable", "path": "When the package code runs → makes a bundled executable runnable and quietly starts it in the background", "risk": "A binary that was not scanned may run with developer permissions", "reason": "Near (within 8 lines) code that sets the execute bit, it starts a hidden, detached process (new session, no window)", "benign": "Tools that ship a CLI binary (e.g. language servers, browser drivers)", "lead": true}` | 1 / 2 |
| 15 | `binary_as_py` | Binary file with a .py name | `first_line` | `signal="binary_marker"`<br>`text="original"`<br>`files="code"`<br>`report={"label": "Binary disguised as .py", "path": "Looks like a Python file but is an executable → other code runs it", "risk": "A binary that was not scanned may run", "reason": "The .py file contains NUL bytes that text never has (an executable or other binary)", "benign": "Almost none", "lead": true}` | 1 / 2 |
| 16 | `js_decode_then_exec` | JavaScript: runs decoded or decrypted code right away | `chain` | `first="js_decode"`<br>`then="js_exec"`<br>`within_lines=5`<br>`max_line_chars=400`<br>`files="code"`<br>`lang="js"`<br>`evidence="decode_then_exec"`<br>`sets=["has_decode_then_exec"]` | 2 / 3 |
| 17 | `js_exec_decoded` | JavaScript: runs a decoded value in place, like eval(atob(…)) | `first_line` | `signal="js_exec_decoded"`<br>`text="original"`<br>`files="code"`<br>`lang="js"`<br>`evidence="decode_then_exec"`<br>`sets=["has_decode_then_exec"]` | 2 / 1 |
| 18 | `js_download_then_execute` | JavaScript: downloads and runs as a process | `chain` | `first="js_download"`<br>`then="js_execute"`<br>`within_lines=8`<br>`max_line_chars=400`<br>`files="code"`<br>`lang="js"`<br>`evidence="js_download_then_execute"`<br>`report={"label": "Downloads and runs", "path": "When the package code runs (install scripts included) → runs something from the internet as a process", "risk": "An executable or script nobody scanned may run with developer permissions", "reason": "A process launch (child_process) sits near (within 8 lines) a download call", "benign": "Tools that fetch and verify a platform binary at install (esbuild, puppeteer and others)", "lead": true}` | 1 / 3 |
| 19 | `js_download_then_eval` | JavaScript: runs downloaded code with eval or new Function | `chain` | `first="js_download"`<br>`then="js_exec"`<br>`within_lines=8`<br>`max_line_chars=400`<br>`files="code"`<br>`lang="js"`<br>`evidence="download_then_execute"`<br>`sets=["has_download_then_execute"]` | 2 / 1 |
| 20 | `js_exec_shell_download` | JavaScript: runs a download-and-run shell command as a process | `chain` | `first="js_execute"`<br>`then="shell_download_exec"`<br>`within_lines=2`<br>`then_in_strings=true`<br>`files="code"`<br>`lang="js"`<br>`evidence="shell_download_exec"` | 1 / 2 |
| 21 | `py_exec_shell_download` | Python: runs a download-and-run shell command as a process | `chain` | `first="execute"`<br>`then="shell_download_exec"`<br>`within_lines=2`<br>`then_in_strings=true`<br>`files="code"`<br>`evidence="shell_download_exec"` | 1 / 1 |
| 22 | `js_secret_then_send` | JavaScript: reads credentials or environment variables and sends them out | `chain` | `first="js_secret_source"`<br>`then="js_send_out"`<br>`within_lines=15`<br>`max_line_chars=400`<br>`first_in_strings=true`<br>`files="code"`<br>`lang="js"`<br>`evidence="secret_then_send"` | 2 / 2 |
| 23 | `shell_download_exec` | Shell: runs downloaded content right away (curl\|sh and similar) | `first_line` | `signal="shell_download_exec"`<br>`text="original"`<br>`files="code"`<br>`lang="shell"`<br>`report={"label": "Downloads and runs right away", "path": "When the script or install command runs → pipes a script from the internet straight into a shell", "risk": "Whatever is served at that moment runs with user permissions, unchecked", "reason": "A command pipes curl or wget output into a shell, or downloads and runs it right away", "benign": "Install instructions that call an official install script (rustup, nvm, uv and others)", "lead": true}` | 8 / 7 |
| 24 | `shell_decode_exec` | Shell: runs decoded content right away (base64 -d \| sh and similar) | `first_line` | `signal="shell_decode_exec"`<br>`text="original"`<br>`files="code"`<br>`lang="shell"`<br>`evidence="decode_then_exec"`<br>`sets=["has_decode_then_exec"]` | 5 / 2 |
| 25 | `reverse_shell` | Reverse shell (shell attached to a remote address) | `first_line` | `signal="reverse_shell"`<br>`text="original"`<br>`files="code"`<br>`lang=["shell", "js", "python"]`<br>`report={"label": "Reverse shell", "path": "When the code runs → connects this machine's shell to a remote address", "risk": "An attacker can run commands remotely with user permissions", "reason": "Contains a reverse shell command such as /dev/tcp, nc -e or bash -i >&", "benign": "Examples in security training or penetration testing tools", "lead": true}` | 3 / 2 |
| 26 | `shell_secret_then_send` | Shell: reads credentials or environment variables and sends them out | `chain` | `first="shell_secret_source"`<br>`then="shell_send_out"`<br>`within_lines=5`<br>`first_in_strings=true`<br>`files="code"`<br>`lang="shell"`<br>`evidence="secret_then_send"` | 3 / 2 |
| 27 | `command_shadowing` | Installed command that uses a common command name (hijack) | `placement` | `check="command_shadowing"`<br>`report={"label": "Command hijack", "path": "The package installs a command named ls, git, python or similar → once the virtualenv is active it runs instead of the real command", "risk": "Package code may run every time the user or agent types an everyday command", "reason": "entry_points.txt or <dist>.data/scripts installs a command with the same name as a common command", "benign": "Alternative implementations of that tool (e.g. another shell or editor)", "lead": true}` | 2 / 3 |
| 28 | `sourceless_bytecode` | Module that ships only .pyc, no source | `placement` | `check="sourceless_bytecode"`<br>`report={"label": ".pyc without source", "path": "When the package is imported → bytecode shipped without source runs", "risk": "With no readable source, code whose behavior was not checked may run", "reason": "Contains a .pyc with no .py of the same name", "benign": "Commercial releases that hide their source (rare)"}` | 1 / 2 |
| 29 | `environment_index` | Index setting placed in the virtualenv root | `placement` | `check="environment_index"`<br>`files=["pip.conf", "pip.ini", "uv.toml"]`<br>`report={"label": "Different index in environment config", "path": "Package install → drops pip.conf or similar into the virtualenv root → later installs in that environment come from another server", "risk": "Packages from an attacker server may be installed instead of the PyPI packages the guard checked", "reason": "<dist>.data/data has a pip or uv config pointing to an index other than PyPI", "benign": "Internal packages that set up a company mirror", "lead": true}` | 1 / 2 |
| 30 | `install_hook_import` | Install hook imports a local module with a dangerous call | `setup_local_imports` | `signal="setup_local_import"`<br>`keywords="dangerous_keywords"` | 1 / 1 |

## 2. Score and verdict (`scoring.json`)

A score of 0.6 or more blocks; 0.25 or more asks for review.

| subscore | weight |
|---|---|
| `vuln` | 0.3 |
| `entropy` | 0.15 |
| `keyword` | 0.15 |
| `install_hook` | 0.15 |
| `typosquat` | 0.15 |
| `reputation` | 0.1 |

With an ML result: ML score weight 0.55, subscores used with it: `vuln`, `typosquat`.

### Hard rules

Checked top to bottom; the first block that matches ends the verdict. A review rule raises the score above the review threshold.

| # | id | action | condition | modes | reason text | examples |
|---|---|---|---|---|---|---|
| 1 | `critical_vuln` | block | `osv_max_severity` = "CRITICAL" | rules, ml | [hard rule] CRITICAL vulnerability → always BLOCK | 1 / 1 |
| 2 | `decode_then_exec` | block | `has_decode_then_exec` | rules, ml | [hard rule] decode_then_exec chain (exec/eval within {window} lines of a decode call) → always BLOCK | 2 / 1 |
| 3 | `pth_chain` | block | `pth_chain` | rules, ml | [hard rule] decode→exec or download→exec chain in .pth/sitecustomize (runs at every interpreter start) → always BLOCK | 2 / 1 |
| 4 | `download_then_execute` | block | `has_download_then_execute` | rules, ml | [hard rule] download_then_execute chain (exec call within {window} lines of a download call) → always BLOCK | 1 / 1 |
| 5 | `behavior_block` | block | `behavior_block` | rules, ml | [hard rule] behavior check: {what} → always BLOCK (policy table rules/behavior.json) | 2 / 1 |
| 6 | `install_hook_with_keywords` | review | `has_install_hook` and (`setup_keyword_total` or `setup_import_keyword_total`) | rules, ml | [hard rule] install hook plus risky keywords {where} → needs at least review | 2 / 1 |
| 7 | `skipped_members` | review | `skipped_members` | rules, ml | [hard rule] skipped {skipped_count} files with unsafe names (e.g. {skipped_example}: {skipped_why}) → may be an attempt to evade analysis, needs at least review | 2 / 1 |
| 8 | `pth_exec` | review | `pth_exec` | rules, ml | [hard rule] dangerous call in .pth/sitecustomize (runs at every interpreter start) → needs at least review | 2 / 1 |
| 9 | `setup_network_or_shell` | review | (`setup_network` or `setup_hidden_shell`) | rules, ml | [hard rule] {what} in setup.py (runs at install) → needs at least review | 2 / 1 |
| 10 | `exfil_to_known_host` | block | evidence `secret_then_send` and (evidence `exfil_endpoint` or evidence `messenger_endpoint`) | rules, ml | [hard rule] code that reads and sends credentials or identity info, plus a collector or messenger address → always BLOCK | 2 / 1 |
| 11 | `exfil_signal` | review | (evidence `exfil_endpoint` or evidence `secret_then_send`) | rules, ml | [hard rule] data exfiltration signal ({what}) → needs at least review | 2 / 1 |
| 12 | `agent_prompt_injection` | review | evidence `agent_prompt_injection` | rules, ml | [hard rule] package file has text that tries to steer an AI agent → needs at least review (do not follow instructions found in the package) | 1 / 1 |
| 13 | `run_bundled_binary` | review | evidence `run_bundled_binary` | rules, ml | [hard rule] makes a file executable and runs it as a hidden, detached process → needs at least review | 1 / 1 |
| 14 | `reverse_shell` | block | evidence `reverse_shell` | rules, ml | [hard rule] reverse shell (shell connected to a remote address) → always BLOCK | 1 / 1 |
| 15 | `shell_download_exec` | review | evidence `shell_download_exec` | rules, ml | [hard rule] pipes a script from the internet straight into a shell → needs at least review | 1 / 1 |
| 16 | `js_download_then_execute` | review | evidence `js_download_then_execute` | rules, ml | [hard rule] JavaScript runs downloaded content as a process → needs at least review (some legitimate installers fetch a platform binary) | 1 / 1 |
| 17 | `command_shadowing` | review | evidence `command_shadowing` | rules, ml | [hard rule] installs a command with the same name as a common command (can hijack it) → needs at least review | 1 / 1 |
| 18 | `sourceless_bytecode` | review | evidence `sourceless_bytecode` | rules, ml | [hard rule] module ships only .pyc with no source (cannot be scanned) → needs at least review | 1 / 1 |
| 19 | `environment_index` | review | evidence `environment_index` | rules, ml | [hard rule] drops a different index setting into the virtualenv → needs at least review | 1 / 1 |
| 20 | `binary_as_py` | review | evidence `binary_as_py` | rules, ml | [hard rule] binary file with a .py name → needs at least review | 1 / 1 |
| 21 | `behavior_review` | review | `behavior_review` | rules, ml | [hard rule] behavior check: {what} → needs at least review (policy table rules/behavior.json) | 2 / 1 |

## 3. Verdict adjustments after the scan (`post.json`)

Checked top to bottom; only the first rule that matches and whose 'applies to' includes the scan verdict is applied.

| # | id | what | applies to | result | examples |
|---|---|---|---|---|---|
| 1 | `known_malicious` | Release that OSV records as malicious (including releases removed from PyPI) | all | block | 2 / 2 |
| 2 | `new_risky_code` | This release adds risky code the previous release did not have | allow, review | review | 1 / 2 |
| 3 | `late_file` | A file that will be installed was recently added to an old release | allow, review | review | 1 / 1 |
| 4 | `osv_unavailable` | Could not reach OSV (vulnerability and malware records) during the scan | allow | review | 1 / 2 |
| 5 | `typosquat` | Recent project with a name close to a popular package | allow | review | 2 / 3 |
| 6 | `new_package` | Newly registered project | allow | review | 1 / 2 |

### Signals checked against the previous release (`post.json` → `version_diff`)

| signal | what | examples |
|---|---|---|
| `import_time` | New dangerous call that runs when the module is imported | 2 / 3 |
| `binary_py` | Binary file with a .py name | 1 / 1 |
| `new_pth` | New .pth file with an import line | 1 / 2 |
| `encoded_payload` | New long encoded string together with decode, exec or write code | 1 / 1 |

## 4. Attack paths (`capabilities.json`)

Path = package capability (what the code does) → who runs it → our capabilities and assets. Paths explain; they do not affect the verdict.

### Package capabilities (reported by code analysis)

| capability | description | how it reaches us |
|---|---|---|
| `process_execute` | runs processes | process |
| `shell_execute` | runs shell commands | process |
| `dynamic_code` | runs dynamic code (exec, eval) | process |
| `file_read` | reads files | file_read |
| `file_write` | writes files | file_write |
| `file_delete` | deletes files | file_write |
| `environment_read` | reads environment variables | environment_read |
| `environment_write` | changes environment variables | none |
| `network_connect` | connects out | channel (sends what was read out) |

Phases: `install` = at install, `interpreter_start` = every time Python starts, `import` = on import, `call` = when a package function is called, `command` = when that script runs.

### Fallback when the code cannot be seen (evidence → capability)

Used for removed malicious releases, source that was not scanned, and evidence that is not code (instructions aimed at the agent). none = not linked into a path.

| evidence | capability | context | confidence |
|---|---|---|---|
| `agent_prompt_injection` | steers the agent into following instructions in a file it reads | agent permissions | possible |
| `binary_as_py` | a binary disguised as .py may run | when the package is used | possible |
| `command_shadowing` | hijacks a common command | when that command runs | possible |
| `decode_then_exec` | runs code at install | at install | confirmed |
| `download_then_execute` | runs code at install | at install | confirmed |
| `environment_index` | makes later installs in that environment come from another server | at install | confirmed |
| `exfil_endpoint` | sends data it read to the outside | decided by evidence location: hooks, MCP servers and plugins use the context in sources; setup.py, package.json install scripts and files they call = at install; .pth, sitecustomize = at Python startup; anything else = when the package is used | confirmed |
| `fetch_error` | none | | |
| `high_entropy` | none | | |
| `install_hook` | runs code at install | at install | confirmed |
| `install_hook_import` | runs code at install | at install | confirmed |
| `js_download_then_execute` | runs something downloaded from the internet | decided by evidence location: hooks, MCP servers and plugins use the context in sources; setup.py, package.json install scripts and files they call = at install; .pth, sitecustomize = at Python startup; anything else = when the package is used | possible |
| `keyword` | none | | |
| `known_malicious` | runs code from a release known to be malicious | at install | confirmed |
| `late_file` | runs code while building source that was not scanned | at install | possible |
| `messenger_endpoint` | sends data it read to the outside | decided by evidence location: hooks, MCP servers and plugins use the context in sources; setup.py, package.json install scripts and files they call = at install; .pth, sitecustomize = at Python startup; anything else = when the package is used | confirmed |
| `new_package` | none | | |
| `new_risky_code` | runs code when the package is imported or used | when the package is used | confirmed |
| `osv` | none | | |
| `osv_unavailable` | none | | |
| `policy_deny` | none | | |
| `pth_chain` | runs code every time Python starts (.pth) | at Python startup | confirmed |
| `pth_exec` | runs code every time Python starts (.pth) | at Python startup | confirmed |
| `reputation` | none | | |
| `reverse_shell` | runs shell commands remotely (reverse shell) | decided by evidence location: hooks, MCP servers and plugins use the context in sources; setup.py, package.json install scripts and files they call = at install; .pth, sitecustomize = at Python startup; anything else = when the package is used | confirmed |
| `run_bundled_binary` | quietly runs a bundled executable (binary that was not scanned) | decided by evidence location: hooks, MCP servers and plugins use the context in sources; setup.py, package.json install scripts and files they call = at install; .pth, sitecustomize = at Python startup; anything else = when the package is used | confirmed |
| `score` | none | | |
| `secret_then_send` | sends data it read to the outside | decided by evidence location: hooks, MCP servers and plugins use the context in sources; setup.py, package.json install scripts and files they call = at install; .pth, sitecustomize = at Python startup; anything else = when the package is used | confirmed |
| `setup_hidden_shell` | runs code at install | at install | confirmed |
| `setup_network` | runs code at install | at install | confirmed |
| `shell_download_exec` | runs something downloaded from the internet | decided by evidence location: hooks, MCP servers and plugins use the context in sources; setup.py, package.json install scripts and files they call = at install; .pth, sitecustomize = at Python startup; anything else = when the package is used | possible |
| `sourceless_bytecode` | runs code that cannot be read (.pyc only) | when the package is used | possible |
| `typosquat` | none | | |
| `unscanned_source` | runs code while building source that was not scanned | at install | possible |

## 5. Signal dictionary (`signals.json`)

| signal | description | patterns |
|---|---|---|
| `dangerous_keywords` | Risky keywords. Counted per file for the keyword score and evidence. bare_builtins are not counted when preceded by . or a word character (re.compile(, df.eval() | 11 |
| `decode` | Decode call (first half of the chain) | 2 |
| `exec` | Dynamic exec (second half of the chain) | 1 |
| `download` | Download call | 4 |
| `execute` | Only calls that actually run something. The bare subprocess. prefix also matches exception classes and constants, causing false positives (unstructured) | 4 |
| `install_hook` | Custom install hook in setup.py | 3 |
| `setup_network` | Network call in setup.py at install time | 1 |
| `setup_hidden_shell` | Hidden shell in setup.py at install time | 1 |
| `secret_source` | Code that reads credentials or personal info: credential file paths, browser, wallet or messenger storage, the whole environment, identity lookups through the shell (whoami and similar). Common calls such as a single os.environ.get or getpass.getuser are not included | 4 |
| `send_out` | Calls that send data out | 1 |
| `exfil_host` | Request collector services and OAST addresses. Library code rarely contains these (examples in docs are excluded with skip_docstrings) | 1 |
| `messenger_host` | Messenger bots and webhooks, paste and file sharing, tunnel addresses. Normal integrations use them too (tqdm's Telegram notifications, for example), so on its own this is kept as evidence only; it affects the verdict only together with code that reads and sends data | 1 |
| `prompt_injection` | Instructions aimed at an AI reading the package (coding agent, AI reviewer): ignore previous instructions, unrestricted mode, swapped system prompt. Almost never in normal package code or docs. Matched against lowercased text (lowercase) | 9 |
| `injection_discussion` | Text that discusses instructions aimed at AI: words that appear around an attack sentence when defense guides, security docs or test data quote it as an example (prompt injection, untrusted, do not follow, treat as data, etc.). Matched in lowercase | 13 |
| `make_executable` | Sets the execute bit on a file or checks that it is executable | 1 |
| `detached_spawn` | Starts a hidden, detached child process (new session, no window, cut off from the parent). Keeps running in the background after install or import | 1 |
| `binary_marker` | NUL bytes that a text file cannot contain: a binary (executable or similar) with a .py name | 1 |
| `js_decode` | JavaScript decode or decrypt (first half of the chain): base64 or hex buffers, atob, deciphers | 3 |
| `js_exec` | JavaScript dynamic exec (second half of the chain): eval, new Function, vm run, module compile | 5 |
| `js_exec_decoded` | Runs a decoded value in place: eval(atob(…)), new Function(Buffer.from(…)) and similar. It fits on one line, so it stays meaningful in minified code | 3 |
| `js_download` | JavaScript download call | 5 |
| `js_execute` | JavaScript process launch (child_process). Regex .exec( is not counted | 3 |
| `js_secret_source` | JavaScript reads credentials or environment info: credential file paths, turning the whole environment into a string. Common pass-through such as {...process.env} is not included | 4 |
| `js_send_out` | JavaScript calls that send data out: HTTP requests, fetch, DNS lookups (DNS exfiltration), sockets | 6 |
| `shell_download_exec` | Shell runs downloaded content right away: curl\|sh, sh -c "$(curl …)", download then chmod +x then run, PowerShell iex(iwr …) | 8 |
| `shell_decode_exec` | Shell decodes an encoded blob embedded in the code (or downloaded) and runs it right away: echo <blob> \| base64 -d \| sh, eval "$(echo <blob> \| base64 -d)", curl … \| base64 -d \| sh, PowerShell -EncodedCommand. Decoding a variable (transport encoding for remote execution) is not included | 5 |
| `reverse_shell` | Reverse shell: attaches the shell's input and output to a remote address (/dev/tcp, nc -e, bash -i >&, socat exec) | 5 |
| `shell_secret_source` | Shell reads credentials or environment info: credential file paths, the whole environment (env, printenv) | 2 |
| `shell_send_out` | Shell sends data out: curl data or file upload, wget POST, nc connecting to an address | 3 |
| `setup_local_import` | Indented import inside setup.py (an import that runs only inside the install hook). Top-level imports such as setuptools are excluded | 1 |
| `pth_import_line` | .pth lines that Python executes: start with import followed by a space or tab | 1 |
| `pth_risky` | Dangerous calls in .pth or sitecustomize | 1 |
| `long_block` | Candidate long encoded blob (entropy is measured on these) | 1 |
