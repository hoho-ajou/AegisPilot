"""
AegisPilot - what the code under development does: read with the AST, never imported or run.

Feeds two parts of the attack path:
  code location   where the project calls something an attacker can abuse (yaml.full_load, pickle.loads, eval, ...) and
                  where a flagged package is imported - the AI judgement "does this CVE's condition hold in our code"
                  starts from these lines
  capabilities    what the code itself touches: files (read / write / delete), environment variables, network targets,
                  processes and shells - each with the enclosing function, whether it sits under a condition, and when it
                  runs (at import, in a function call, under `if __name__ == "__main__"`)
  secrets         environment variable names, credential paths, secrets written into the source (location only, never the value)

The capability part follows the approach of the independent Profile analyzer (guard/profile/analyzer.py: lexical
scopes so a local name shadows an import, open() modes, pathlib.Path / socket / requests.Session objects, shell=True
detection, only the executable of a command is kept), re-implemented here so the guard does not depend on that draft.

Skipped: virtualenvs, site-packages, node_modules, .git, build output; files over MAX_FILE_BYTES; more than MAX_FILES.
Not followed: calls across functions or files, values built at runtime (a URL in a variable has no known host).
"""
from __future__ import annotations

import ast
import os
import re
import shlex
from pathlib import Path
from urllib.parse import urlsplit

MAX_FILES = 2000
MAX_FILE_BYTES = 1_000_000
SKIP_DIRS = {".git", ".venv", "venv", "env", ".env", "node_modules", "site-packages", "__pycache__", "build", "dist",
             ".tox", ".mypy_cache", ".pytest_cache", ".aegis", ".claude"}

# calls an attacker can abuse when the argument is attacker-controlled
RISKY_CALLS = {
    "yaml.load": "deserialization (yaml.load)", "yaml.full_load": "deserialization (yaml.full_load)", "yaml.unsafe_load": "deserialization (yaml.unsafe_load)",
    "pickle.load": "deserialization (pickle)", "pickle.loads": "deserialization (pickle)", "marshal.loads": "deserialization (marshal)",
    "builtins.eval": "code execution (eval)", "builtins.exec": "code execution (exec)", "os.system": "shell execution", "os.popen": "shell execution",
    "subprocess.run": "process execution", "subprocess.Popen": "process execution", "subprocess.call": "process execution",
    "subprocess.check_call": "process execution", "subprocess.check_output": "process execution",
    "tarfile.open": "archive extraction (path traversal risk)", "zipfile.ZipFile": "archive extraction (path traversal risk)",
}
_NETWORK = {"urllib.request.urlopen", "urllib.request.urlretrieve", "socket.create_connection", "requests.request"}
_NETWORK_PREFIX = ("requests.", "httpx.")
_NETWORK_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "request", "stream", "connect", "connect_ex"}
_PROCESS = {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_call", "subprocess.check_output"}
_SHELL = {"os.system", "os.popen"}
_DELETE = {"os.remove", "os.unlink", "os.rmdir", "shutil.rmtree"}
_COPY = {"shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.move", "os.rename", "os.replace"}
_ENV_READ = {"os.getenv", "os.environ.get", "os.environ.setdefault", "os.environ.pop"}
_ENV_WRITE = {"os.putenv", "os.unsetenv", "os.environ.setdefault", "os.environ.pop"}
_PATH_CTORS = {"pathlib.Path", "pathlib.PosixPath", "pathlib.WindowsPath"}
_PATH_METHODS = {"read_text": ["file_read"], "read_bytes": ["file_read"], "write_text": ["file_write"],
                 "write_bytes": ["file_write"], "unlink": ["file_delete"], "rmdir": ["file_delete"]}

# SDKs that make a project an agent / LLM app (the Profile's first classification)
LLM_SDKS = {"openai", "anthropic", "claude_agent_sdk", "claude_code_sdk", "google.generativeai", "google.genai", "mistralai",
            "cohere", "litellm", "ollama", "groq", "langchain", "langchain_core", "langchain_openai", "langchain_anthropic",
            "langgraph", "llama_index", "autogen", "crewai", "smolagents", "pydantic_ai", "mcp", "fastmcp"}
_MCP_KEYWORDS = {"mcp_servers", "mcpServers"}
# calls that return model output (LLM output -> dangerous sink)
_LLM_METHODS = {"create", "stream", "generate_content", "invoke", "ainvoke", "predict", "complete", "completion",
                "chat", "generate", "run", "query", "send_message", "acompletion"}
_LLM_FUNCS = {"claude_agent_sdk.query", "claude_code_sdk.query", "litellm.completion", "litellm.acompletion",
              "ollama.chat", "ollama.generate"}
# sinks where attacker-chosen text becomes code or a command
_CODE_SINKS = {"builtins.eval", "builtins.exec", "os.system", "os.popen", "subprocess.run", "subprocess.Popen",
               "subprocess.call", "subprocess.check_call", "subprocess.check_output", "pickle.loads", "pickle.load",
               "marshal.loads", "yaml.load", "yaml.full_load", "yaml.unsafe_load"}
_MCP_CALLS = {"claude_agent_sdk.create_sdk_mcp_server", "claude_code_sdk.create_sdk_mcp_server"}
_CRED_PATH = re.compile(r"(^|[/~])(\.env(\.[\w-]+)?|\.ssh|\.aws|\.kube|\.docker|\.netrc|\.pypirc|\.git-credentials)(/|$)|credential|secret|token", re.I)
_CONFIG_PATH = re.compile(r"(^|/)(\.config|etc)(/|$)|settings(\.local)?\.json$", re.I)
_AGENT_PATH = re.compile(r"(^|/)(\.claude|\.codex)(/|$)|\.mcp\.json$|(^|/)skills?(/|$)", re.I)
_SECRET_NAME = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|_PAT)\b", re.I)
_SECRET_VALUE = re.compile(r"^(sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_\w{20,}|AKIA[0-9A-Z]{16}|xox[abp]-[\w-]{10,}|glpat-[\w-]{16,}|hf_[A-Za-z0-9]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)")


def path_categories(target) -> list[str]:
    if not isinstance(target, str):
        return []
    low = target.replace("\\", "/")
    return [name for name, rx in (("credential_path", _CRED_PATH), ("configuration_path", _CONFIG_PATH),
                                  ("agent_configuration_path", _AGENT_PATH)) if rx.search(low)]


def _literal(node):
    """A string, or a list/tuple of str/int constants; anything computed -> None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, (ast.Tuple, ast.List)) and all(isinstance(x, ast.Constant) and isinstance(x.value, (str, int)) for x in node.elts):
        return [x.value for x in node.elts]
    return None


def _is_test(rel: str) -> bool:
    parts = rel.replace("\\", "/").split("/")
    return any(p in ("tests", "test") for p in parts[:-1]) or parts[-1].startswith("test_") or parts[-1].endswith("_test.py")


def _dict_literal(node):
    return {(_literal(k) or ""): None for k in node.keys if k is not None} if isinstance(node, ast.Dict) else None


def _call_name(func) -> str:
    return func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else "call"


def _safe_target(value):
    """URLs lose userinfo, query and fragment (they can hold tokens); (host, port) pairs become host:port."""
    if isinstance(value, list):
        return f"{value[0]}:{value[1]}" if len(value) == 2 and isinstance(value[0], str) and isinstance(value[1], int) else None
    if isinstance(value, str) and "://" in value:
        try:
            u = urlsplit(value)
            return f"{u.scheme}://{u.hostname or ''}{':' + str(u.port) if u.port else ''}{u.path}"
        except ValueError:
            return None
    return value


class _Scan(ast.NodeVisitor):
    def __init__(self, rel: str):
        self.rel = rel
        self.scopes: list[dict] = [{}]       # name -> dotted import path, ("path"|"socket"|"session", target) object, or None (local)
        self.function, self.conditional, self.phase = None, 0, "import"
        self.imports, self.calls, self.secrets, self.caps, self.limits = [], [], [], [], set()
        self.mcp_wiring, self.permission_bypass = [], []
        self.llm_calls = []

    # ---- names -------------------------------------------------------------------------------------------------
    def _where(self, node) -> str:
        return f"{self.rel}:{getattr(node, 'lineno', 0)}"

    def _lookup(self, name):
        for scope in reversed(self.scopes):
            if name in scope:
                return scope[name], True
        return None, False

    def resolve(self, node):
        if isinstance(node, ast.Name):
            value, found = self._lookup(node.id)
            if found:
                return value if isinstance(value, str) else None
            if node.id in ("open", "eval", "exec") and not any("*" in s for s in self.scopes):
                return "builtins." + node.id
            return None
        if isinstance(node, ast.Attribute):
            base = self.resolve(node.value)
            return f"{base}.{node.attr}" if base else None
        return None

    def _object(self, node):
        if isinstance(node, ast.Name):
            value, _ = self._lookup(node.id)
            return value if isinstance(value, tuple) else None
        if isinstance(node, ast.Call):
            name = self.resolve(node.func)
            if name in _PATH_CTORS:
                return ("path", _literal(node.args[0]) if node.args else None)
            if name == "socket.socket":
                return ("socket", None)
            if name in ("requests.Session", "requests.session", "httpx.Client"):
                return ("session", None)
            if name and name.split(".")[0] in LLM_SDKS:          # anthropic.Anthropic(), openai.OpenAI(), ChatOpenAI(...)
                return ("llm", name.split(".")[0])
        if isinstance(node, ast.Attribute):                      # client.messages -> still the client
            return self._object(node.value)
        return None

    def _llm_call(self, node, name) -> str | None:
        """The SDK if this call returns model output: a known function, or a method chain on an SDK client object."""
        if name in _LLM_FUNCS:
            return name.split(".")[0]
        if isinstance(node.func, ast.Attribute) and node.func.attr in _LLM_METHODS:
            obj = self._object(node.func.value)
            if obj and obj[0] == "llm":
                return obj[1]
            if name and name.split(".")[0] in LLM_SDKS:          # module-level helper, e.g. openai.chat.completions.create
                return name.split(".")[0]
        return None

    def _bind(self, target, value=None):
        """Bind the names an assignment target creates. `x.attr = ...` and `x[k] = ...` create no name (binding `x` here
        once hid the `os` module after `os.environ["K"] = v`, so a later os.system was missed)."""
        if isinstance(target, ast.Name):
            self.scopes[-1][target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._bind(elt)
        elif isinstance(target, ast.Starred):
            self._bind(target.value)
        else:
            self.visit(target)

    # ---- output ------------------------------------------------------------------------------------------------
    def emit(self, kind, node, target=None, confidence="high", **extra):
        target = _safe_target(target)
        self.caps.append({"kind": kind, "target": target, "at": self._where(node), "symbol": self.function,
                          "conditional": bool(self.conditional), "phase": self.phase, "confidence": confidence,
                          "path_categories": path_categories(target) if kind.startswith("file_") else [], **extra})

    # ---- scopes and statements ---------------------------------------------------------------------------------
    def visit_Import(self, node):
        for a in node.names:
            top = a.name.split(".")[0]
            self.scopes[-1][a.asname or top] = a.name if a.asname else top
            self.imports.append((top, self._where(node)))
            if a.name != top:
                self.imports.append((a.name, self._where(node)))

    def visit_ImportFrom(self, node):
        if node.module and not node.level:
            self.imports.append((node.module.split(".")[0], self._where(node)))
            if "." in node.module:
                self.imports.append((node.module, self._where(node)))
        for a in node.names:
            if a.name == "*":
                self.limits.add("star import cannot be resolved")
                self.scopes[-1]["*"] = None
            else:
                self.scopes[-1][a.asname or a.name] = f"{node.module}.{a.name}" if node.module and not node.level else None

    def visit_Assign(self, node):
        value = _literal(node.value)
        if isinstance(value, str) and _SECRET_VALUE.match(value):       # recorded with its name before the value is visited
            name = next((t.id if isinstance(t, ast.Name) else getattr(t, "attr", None) for t in node.targets), None)
            self.secrets.append({"at": self._where(node), "name": name})
        self.visit(node.value)
        obj = self._object(node.value)
        for t in node.targets:
            self._bind(t, obj)

    def visit_AnnAssign(self, node):
        if node.value:
            self.visit(node.value)
        self._bind(node.target, self._object(node.value) if node.value else None)

    def visit_AugAssign(self, node):
        self.visit(node.value)
        self._bind(node.target)

    def visit_For(self, node):
        self.visit(node.iter)
        self._bind(node.target)
        self.conditional += 1
        for n in node.body + node.orelse:
            self.visit(n)
        self.conditional -= 1
    visit_AsyncFor = visit_For

    def visit_With(self, node):
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self._bind(item.optional_vars, self._object(item.context_expr))
        for n in node.body:
            self.visit(n)
    visit_AsyncWith = visit_With

    def visit_If(self, node):
        self.visit(node.test)
        main = (isinstance(node.test, ast.Compare) and isinstance(node.test.left, ast.Name) and node.test.left.id == "__name__"
                and any(isinstance(c, ast.Constant) and c.value == "__main__" for c in node.test.comparators))
        old_phase = self.phase
        self.conditional += 0 if main else 1
        if main:
            self.phase = "main_script"
        before = dict(self.scopes[-1])
        for n in node.body:
            self.visit(n)
        left, self.scopes[-1] = self.scopes[-1], dict(before)
        self.phase = old_phase
        for n in node.orelse:
            self.visit(n)
        right = self.scopes[-1]
        # after the branch nothing is claimed about which one ran: a name bound differently is unknown
        self.scopes[-1] = {k: left.get(k) if left.get(k) == right.get(k) else None for k in left.keys() | right.keys()}
        self.conditional -= 0 if main else 1

    def visit_While(self, node):
        self.visit(node.test)
        self.conditional += 1
        for n in node.body + node.orelse:
            self.visit(n)
        self.conditional -= 1

    def visit_Try(self, node):
        for n in node.body:
            self.visit(n)
        self.conditional += 1
        for h in node.handlers:
            if h.type is not None:
                self.visit(h.type)
            if h.name:
                self.scopes[-1][h.name] = None
            for n in h.body:
                self.visit(n)
        for n in node.orelse + node.finalbody:
            self.visit(n)
        self.conditional -= 1
    visit_TryStar = visit_Try

    def _function(self, node, name, args, body):
        old = (self.phase, self.function, self.conditional)
        self.phase, self.function, self.conditional = "function_call", (f"{self.function}.{name}" if self.function else name), 0
        params = [a.arg for a in args.posonlyargs + args.args + args.kwonlyargs] + [a.arg for a in (args.vararg, args.kwarg) if a]
        self.scopes.append({p: None for p in params})
        for n in body:
            self.visit(n)
        self.scopes.pop()
        self.phase, self.function, self.conditional = old

    def visit_FunctionDef(self, node):
        for d in node.decorator_list + node.args.defaults + [x for x in node.args.kw_defaults if x is not None]:
            self.visit(d)
        self.scopes[-1][node.name] = None
        self._function(node, node.name, node.args, node.body)
    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node):
        old = self.function
        self._function(node, "<lambda>", node.args, [ast.Expr(node.body)])
        self.function = old

    def visit_ClassDef(self, node):
        for n in node.bases + node.decorator_list:
            self.visit(n)
        self.scopes[-1][node.name] = None
        old = self.function
        self.function = f"{old}.{node.name}" if old else node.name
        self.scopes.append({})
        for n in node.body:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # names bound in a class body are not visible inside its methods
                class_scope = self.scopes.pop()
                self.visit(n)
                self.scopes.append(class_scope)
            else:
                self.visit(n)
        self.scopes.pop()
        self.function = old

    def visit_ListComp(self, node):
        self.scopes.append({})
        for gen in node.generators:
            self.visit(gen.iter)
            self._bind(gen.target)
            for cond in gen.ifs:
                self.visit(cond)
        for field in ("elt", "key", "value"):
            if hasattr(node, field):
                self.visit(getattr(node, field))
        self.scopes.pop()
    visit_SetComp = visit_DictComp = visit_GeneratorExp = visit_ListComp

    # ---- what the code does ------------------------------------------------------------------------------------
    def visit_Subscript(self, node):
        if self.resolve(node.value) == "os.environ":
            self.emit("environment_read" if isinstance(node.ctx, ast.Load) else "environment_write", node, _literal(node.slice))
        self.generic_visit(node)

    def _mcp(self, node, pattern, value=None):
        names = sorted(k for k in (value.keys() if isinstance(value, dict) else []) if isinstance(k, str))[:10]
        self.mcp_wiring.append({"pattern": pattern, "at": self._where(node), "symbol": self.function, "servers": names,
                                "in_test": _is_test(self.rel)})

    def visit_Dict(self, node):
        for k, v in zip(node.keys, node.values):
            key = _literal(k) if k is not None else None
            if key in _MCP_KEYWORDS and isinstance(v, (ast.Dict, ast.List)):   # a literal config, not e.g. a result field
                self._mcp(node, f"{key}: ...", _dict_literal(v))
            if key == "type" and _literal(v) == "mcp_toolset":          # Messages API tool entry for a connected MCP server
                self._mcp(node, "type: mcp_toolset")
            if key in ("permission_mode", "permissionMode") and _literal(v) == "bypassPermissions":
                self.permission_bypass.append({"at": self._where(node), "symbol": self.function})
        self.generic_visit(node)

    def visit_Constant(self, node):
        if isinstance(node.value, str) and _SECRET_VALUE.match(node.value) and not any(s["at"] == self._where(node) for s in self.secrets):
            self.secrets.append({"at": self._where(node), "name": None})

    def visit_Call(self, node):
        name = self.resolve(node.func)
        args, kw = node.args, {k.arg: k.value for k in node.keywords if k.arg}
        first = args[0] if args else kw.get("file") or kw.get("path") or kw.get("url") or kw.get("key") or kw.get("args")
        target = _literal(first) if first is not None else None
        sdk = self._llm_call(node, name)
        if sdk:
            self.llm_calls.append({"at": self._where(node), "symbol": self.function, "sdk": sdk})
        if name in RISKY_CALLS:
            loader = kw.get("Loader")
            self.calls.append({"call": name.replace("builtins.", ""), "what": RISKY_CALLS[name], "at": self._where(node),
                               "symbol": self.function, "loader": self.resolve(loader) if loader is not None else None})
        for k in node.keywords:
            if k.arg in _MCP_KEYWORDS:
                self._mcp(node, f"{(name or _call_name(node.func)).rsplit('.', 1)[-1]}({k.arg}=...)", _dict_literal(k.value))
            if k.arg in ("permission_mode", "permissionMode") and _literal(k.value) == "bypassPermissions":
                self.permission_bypass.append({"at": self._where(node), "symbol": self.function})
        if name in _MCP_CALLS:
            self._mcp(node, "create_sdk_mcp_server(...)")
        if name in ("builtins.eval", "builtins.exec"):
            self.limits.add("dynamic code (eval/exec) not analyzed")
        if name in ("builtins.open", "io.open"):
            mode_node = args[1] if len(args) > 1 else kw.get("mode")
            mode = "r" if mode_node is None else _literal(mode_node)
            if isinstance(mode, str):
                if "r" in mode or "+" in mode:
                    self.emit("file_read", node, target)
                if any(c in mode for c in "wax+"):
                    self.emit("file_write", node, target)
            else:
                self.emit("file_read", node, target, "low", access_mode="unknown")
                self.emit("file_write", node, target, "low", access_mode="unknown")
        elif name == "os.open":
            flags = args[1] if len(args) > 1 else kw.get("flags")
            names = {self.resolve(n) for n in ast.walk(flags)} if flags is not None else set()
            if "os.O_WRONLY" not in names:
                self.emit("file_read", node, target, "medium")
            if names & {"os.O_WRONLY", "os.O_RDWR", "os.O_CREAT", "os.O_TRUNC", "os.O_APPEND"} or not names & {"os.O_RDONLY"}:
                self.emit("file_write", node, target, "medium")
        elif name in _DELETE:
            self.emit("file_delete", node, target)
        elif name in _COPY:
            self.emit("file_read", node, target)
            self.emit("file_write", node, _literal(args[1]) if len(args) > 1 else _literal(kw.get("dst")) if kw.get("dst") else None)
            if name in ("shutil.move", "os.rename", "os.replace"):
                self.emit("file_delete", node, target)
        elif name in _ENV_READ or name in _ENV_WRITE:
            if name in _ENV_READ:
                self.emit("environment_read", node, target)
            if name in _ENV_WRITE:
                self.emit("environment_write", node, target)
        elif name and (name in _NETWORK or name.startswith(_NETWORK_PREFIX)) and name.rsplit(".", 1)[-1] in _NETWORK_METHODS | {"urlopen", "urlretrieve", "create_connection"}:
            if name.endswith(".request"):
                target = _literal(args[1]) if len(args) > 1 else _literal(kw["url"]) if "url" in kw else None
            self.emit("network_connect", node, target)
        elif name in _PROCESS or name in _SHELL:
            shell = name in _SHELL or (isinstance(kw.get("shell"), ast.Constant) and kw["shell"].value is True)
            # command lines can carry secrets: only the executable is kept
            exe = target[0] if isinstance(target, list) and target else None
            if isinstance(target, str):
                try:
                    tokens = shlex.split(target)
                    exe = tokens[0] if tokens and "=" not in tokens[0] else None
                except ValueError:
                    exe = None
            self.emit("shell_execute" if shell else "process_execute", node, exe,
                      shell=("enabled" if shell else "unknown" if "shell" in kw and not isinstance(kw["shell"], ast.Constant) else "disabled"))
        elif isinstance(node.func, ast.Attribute):
            obj, method = self._object(node.func.value), node.func.attr
            if obj and obj[0] == "path":
                if method in _PATH_METHODS:
                    for kind in _PATH_METHODS[method]:
                        self.emit(kind, node, obj[1])
                elif method == "open":
                    mode = _literal(args[0]) if args else _literal(kw["mode"]) if "mode" in kw else "r"
                    kinds = ["file_read", "file_write"] if not isinstance(mode, str) else \
                        (["file_read"] if "r" in mode or "+" in mode else []) + (["file_write"] if any(c in mode for c in "wax+") else [])
                    for kind in kinds:
                        self.emit(kind, node, obj[1])
            elif obj and obj[0] in ("socket", "session") and method in _NETWORK_METHODS:
                if method == "request":
                    target = _literal(args[1]) if len(args) > 1 else _literal(kw["url"]) if "url" in kw else None
                self.emit("network_connect", node, target)
        self.generic_visit(node)


def _llm_sink_candidates(llm_calls: list, sinks: list) -> list:
    out = []
    for snk in sinks:
        if snk.get("call") in ("yaml.load",) and snk.get("loader") in ("yaml.SafeLoader", "yaml.CSafeLoader"):
            continue                                      # safe loader: not a code sink
        file = snk["at"].rsplit(":", 1)[0]
        near = [c for c in llm_calls if c["at"].rsplit(":", 1)[0] == file and c["symbol"] == snk["symbol"]]
        if near:
            out.append({"llm_call": near[0]["at"], "sdk": near[0]["sdk"], "sink": snk["at"], "sink_call": snk["call"],
                        "symbol": snk["symbol"]})
    return out


def _requirements(project: Path) -> list[str]:
    names = []
    for f in sorted(project.glob("requirements*.txt")):
        try:
            for line in f.read_text(errors="replace").splitlines():
                line = line.split("#", 1)[0].strip()
                m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", line)
                if m and not line.startswith("-"):
                    names.append(m.group(1).lower())
        except OSError:
            pass
    return sorted(set(names))


def scan(project_dir) -> dict:
    project = Path(project_dir).resolve()
    files, skipped, errors = [], 0, []
    for root, dirs, names in os.walk(project):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.endswith(".egg-info")]
        files += [Path(root) / n for n in names if n.endswith(".py")]
    files.sort()
    if len(files) > MAX_FILES:
        skipped, files = len(files) - MAX_FILES, files[:MAX_FILES]
    imports, calls, secrets, caps, limits, scanned = {}, [], [], [], set(), 0
    mcp_wiring, bypass, llm_calls, sinks = [], [], [], []
    for f in files:
        rel = str(f.relative_to(project))
        try:
            if f.stat().st_size > MAX_FILE_BYTES:
                skipped += 1
                continue
            tree = ast.parse(f.read_text(errors="replace"), filename=rel)
            s = _Scan(rel)
            if f.name == "setup.py":
                s.phase = "install_or_build"      # setup.py runs when the project is built or installed from source
            for node in tree.body:
                s.visit(node)
        except (OSError, SyntaxError, ValueError, RecursionError) as e:
            errors.append(f"{rel}: {type(e).__name__}")
            continue
        scanned += 1
        for mod, at in s.imports:
            imports.setdefault(mod, []).append(at)
        calls += s.calls
        secrets += s.secrets
        caps += s.caps
        limits |= s.limits
        mcp_wiring += s.mcp_wiring
        llm_calls += s.llm_calls
        sinks += [c for c in s.calls if ("builtins." + c["call"] if c["call"] in ("eval", "exec") else c["call"]) in _CODE_SINKS]
        bypass += s.permission_bypass
    env = {}
    for c in caps:
        if c["kind"] == "environment_read" and isinstance(c["target"], str):
            env.setdefault(c["target"], []).append(c["at"])
    sdks = {m: at for m, at in imports.items() if m in LLM_SDKS or m.split(".")[0] in {"langchain", "llama_index", "autogen"}}
    return {
        "agent_project": bool(sdks),
        "llm_sdks": {m: at[:5] for m, at in sorted(sdks.items())},
        "mcp_wiring": mcp_wiring[:50],
        "permission_bypass": bypass[:50],
        "llm_calls": llm_calls[:50],
        # A model call and a code/command sink in the same function. Whether the model's text really
        # reaches the sink is judged later (attack_path: AI judgement with verified quotes); here it is only a candidate.
        "llm_sink_candidates": _llm_sink_candidates(llm_calls, sinks)[:30],
        # Hard rule: tools that are auto-approved never reach the SDK's checking callback, and MCP servers
        # wired in code bring tools nobody reviewed - the two together are flagged
        "bypass_with_mcp": bool([x for x in bypass if not _is_test(x["at"].rsplit(":", 1)[0])]
                                and [w for w in mcp_wiring if not w["in_test"]]),
        "files_scanned": scanned,
        "files_skipped": skipped,
        "parse_errors": errors[:20],
        "limits": sorted(limits),
        "requirements": _requirements(project),
        "imports": {m: at[:5] for m, at in sorted(imports.items()) if "." not in m},
        "capabilities": caps[:300],
        "env_reads": [{"name": n, "secret_like": bool(_SECRET_NAME.search(n)), "at": at[:5]} for n, at in sorted(env.items())],
        "credential_paths": [{"path": c["target"], "access": c["kind"], "at": c["at"]} for c in caps
                             if c["kind"].startswith("file_") and "credential_path" in c["path_categories"]][:50],
        "network": [{"host": urlsplit(c["target"]).hostname if isinstance(c["target"], str) and "://" in c["target"] else c["target"],
                     "at": c["at"], "symbol": c["symbol"]} for c in caps if c["kind"] == "network_connect"][:50],
        "risky_calls": calls[:100],
        "hardcoded_secrets": secrets[:50],
    }
