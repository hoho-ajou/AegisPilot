"""Shell / PowerShell / cmd command front end of the behavior analysis: what a command line does.

The command is split into simple commands (; && || & newlines) and pipelines (|); each simple command is read by its
program name and arguments. Facts: a fetcher (curl, wget, iwr, certutil, WebClient...) piped into an interpreter or
whose output file is later run -> download_exec; identity substitutions ($(whoami), %USERNAME%...) or secret files
sent by a fetcher / DNS tool -> sysinfo / secret; decoders piped into an interpreter, `powershell -enc`, `python -c`
/ `node -e` code (handed to the Python / JS front end) -> decode_exec or the nested code's own facts; crontab, rc files,
systemd, launchctl, Run keys, schtasks -> persistence; /dev/tcp and nc -e -> remote_shell.
"""
from __future__ import annotations

import base64
import re
import shlex

from .values import DECODED, NET, SECRET, SYSINFO, endpoint_class, path_class, policy

FETCH = {"curl", "wget", "iwr", "invoke-webrequest", "irm", "invoke-restmethod", "certutil", "certutil.exe", "bitsadmin",
         "start-bitstransfer", "fetch", "aria2c", "tftp", "ftp", "lwp-download", "http", "httpie", "xh"}
DNS = {"nslookup", "dig", "host", "ping", "resolve-dnsname", "drill"}
DECODERS = {"base64", "base32", "xxd", "openssl", "gunzip", "zcat", "rev", "uudecode"}
SYSINFO_SUB = re.compile(r"\$\(\s*(whoami|hostname|id|uname|pwd|curl\s+[^)]*ip|ifconfig|ip\s+a)[^)]*\)|`\s*(whoami|hostname|id|uname|pwd)[^`]*`"
                         r"|\$\{?(USER|USERNAME|HOSTNAME|HOME|PWD|LOGNAME)\b\}?|%(USERNAME|COMPUTERNAME|USERDOMAIN|USERPROFILE)%"
                         r"|\$env:(USERNAME|COMPUTERNAME|USERDOMAIN)|\[Environment\]::(UserName|MachineName)", re.I)
WHOLE_ENV = re.compile(r"^(env|printenv|set|get-childitem\s+env:|gci\s+env:|dir\s+env:)\b", re.I)
PERSIST_CMD = {"crontab", "schtasks", "schtasks.exe", "launchctl", "systemctl", "reg", "reg.exe", "new-itemproperty",
               "set-itemproperty", "new-scheduledtask", "register-scheduledtask"}
URL = re.compile(r"(?:https?|ftp)://[^\s'\"<>|;)]+|\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:/[^\s'\"<>|;)]*)?", re.I)


def _split_commands(text: str) -> list[list[str]]:
    """[[simple command, ... (a pipeline)], ...] - quotes respected roughly; never raises."""
    out, cur_pipe, buf, q, i = [], [], [], None, 0
    while i < len(text):
        ch = text[i]
        if q:
            buf.append(ch)
            if ch == q and (q == "'" or text[i - 1] != "\\"):
                q = None
        elif ch in "'\"":
            q = ch
            buf.append(ch)
        elif ch == "|" and text[i:i + 2] != "||":
            cur_pipe.append("".join(buf).strip())
            buf = []
        elif ch in ";\n" or text[i:i + 2] in ("&&", "||") or (ch == "&" and text[i - 1:i] != ">" and text[i + 1:i + 2] != ">"):
            cur_pipe.append("".join(buf).strip())
            out.append([c for c in cur_pipe if c])
            cur_pipe, buf = [], []
            if text[i:i + 2] in ("&&", "||"):
                i += 1
        else:
            buf.append(ch)
        i += 1
    cur_pipe.append("".join(buf).strip())
    out.append([c for c in cur_pipe if c])
    return [p for p in out if p]


def _argv(cmd: str) -> list[str]:
    try:
        return shlex.split(cmd, posix=True)
    except ValueError:
        return cmd.split()


def _prog(argv: list[str]) -> str:
    i = 0
    while i < len(argv) and (re.match(r"^\w+=", argv[i]) or argv[i] in ("sudo", "nohup", "exec", "env", "time", "start", "&",
                                                                          "call", "-b", "/b", "/min")):
        i += 1
    p = argv[i] if i < len(argv) else ""
    return p.replace("\\", "/").rsplit("/", 1)[-1].lower() if not p.startswith("./") else p


def _fetch_output(argv: list[str]) -> str | None:
    for i, a in enumerate(argv):
        if a in ("-o", "-O", "--output", "-OutFile", "-outfile", "--output-document") and i + 1 < len(argv):
            return argv[i + 1]
        if a.startswith("--output="):
            return a.split("=", 1)[1]
        if a.lower().startswith("-outfile"):
            return a.split(":", 1)[-1] if ":" in a else (argv[i + 1] if i + 1 < len(argv) else None)
    prog = _prog(argv)
    if prog == "wget" and "-O" not in argv:
        url = next((a for a in argv[1:] if URL.search(a)), None)
        if url:
            name = url.rstrip("/").rsplit("/", 1)[-1].split("?")[0]
            return name or None
    if prog.startswith("certutil") and len(argv) >= 2:
        return argv[-1]
    return None


def _ps_decode(argv: list[str]) -> str | None:
    for i, a in enumerate(argv):
        if a.lower() in ("-enc", "-e", "-encodedcommand", "-ec") and i + 1 < len(argv):
            try:
                return base64.b64decode(argv[i + 1] + "===").decode("utf-16-le", "replace")
            except Exception:
                return None
    return None


def _ps_code(argv: list[str]) -> str | None:
    for i, a in enumerate(argv):
        if a.lower() in ("-c", "-command", "/c") and i + 1 < len(argv):
            return " ".join(argv[i + 1:])
    return None


def analyze(text: str, ctx, phase: str, file: str, line: int, depth: int = 0) -> dict:
    """Facts of one command line into ctx (behavior.Context). Returns {"programs": [...], "sysinfo": bool,
    "network": bool} so a caller (Python's check_output, a JS execSync) can taint what the command prints."""
    pol = policy()
    info = {"programs": [], "sysinfo": False, "network": False}
    if not isinstance(text, str) or not text.strip() or depth > pol.limits["max_depth"]:
        return info
    text = text[: pol.limits["max_string"]]
    low = text.lower()
    if re.search(r"/dev/tcp/|\bnc(at)?\b[^|;\n]*\s-[a-z]*e\s|\bsocat\b[^\n]*exec:|bash\s+-i\s*>&", low):
        ctx.emit("remote_shell", phase, file, line, text)
    # PowerShell expression forms that fetch and run in one go
    if re.search(r"\b(iex|invoke-expression)\b[^\n]*\b(iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring|net\.webclient)\b"
                 r"|\b(iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring)\b[^\n]*\|\s*(iex|invoke-expression)\b", low):
        ctx.emit("download_exec", phase, file, line, text)
    if re.search(r"\b(sh|bash|zsh)\s+(-\w+\s+)*-c\s+[\"']?\$\(\s*(curl|wget)\b|\beval\s+[\"']?\$\(\s*(curl|wget)\b|<\(\s*(curl|wget)\b", low):
        ctx.emit("download_exec", phase, file, line, text)
    if re.search(r"downloadfile\s*\(", low) and re.search(r"start-process|invoke-item|\.exe\b|&\s*\$", low):
        ctx.emit("download_exec", phase, file, line, text)
    for pipeline in _split_commands(text):
        fetched = False
        decoded = False
        secret_in = False
        for k, cmd in enumerate(pipeline):
            argv = _argv(cmd)
            if not argv:
                continue
            prog = _prog(argv)
            info["programs"].append(prog)
            cmd_low = cmd.lower()
            if k > 0 and (prog in pol.interpreters or prog.startswith(("python", "node", "perl", "ruby"))):
                if fetched:
                    ctx.emit("download_exec", phase, file, line, " | ".join(pipeline))
                elif decoded:
                    ctx.emit("decode_exec", phase, file, line, " | ".join(pipeline))
            if prog in FETCH or (prog.startswith(("powershell", "pwsh")) and re.search(r"net\.webclient|invoke-webrequest|iwr|downloadstring", cmd_low)):
                info["network"] = True
                urls = URL.findall(cmd)
                payload = SYSINFO_SUB.search(cmd) is not None
                sends_file = re.search(r"(-d|--data(-binary|-raw)?|-F|--form|-T|--upload-file)\s+['\"]?[^'\"]*@([^\s'\"]+)", cmd)
                if sends_file and path_class(sends_file.group(3)) == "credential" or (k > 0 and secret_in):
                    ctx.emit("secret_exfil", phase, file, line, " | ".join(pipeline))
                cls = next((endpoint_class(u) for u in urls if endpoint_class(u)), None)
                if payload:
                    ctx.emit("suspicious_send" if cls else "sysinfo_beacon", phase, file, line, cmd)
                elif cls in ("collector", "messenger") and phase in pol.auto:
                    ctx.emit("suspicious_send", phase, file, line, cmd)
                out = _fetch_output(argv)
                if out:
                    ctx.add_downloaded(out.strip("'\""))
                fetched = True
            elif prog in DNS:
                if SYSINFO_SUB.search(cmd):
                    ctx.emit("sysinfo_beacon", phase, file, line, cmd)
            elif prog in DECODERS and re.search(r"(^|\s)(-d|--decode|-D|-r)\b|\benc\s+-d\b", cmd) or prog in ("rev",):
                decoded = True
            elif prog in ("cat", "type", "get-content", "gc") and any(path_class(a) == "credential" for a in argv[1:]):
                secret_in = True
            elif WHOLE_ENV.match(cmd.strip()):
                secret_in = True
            if prog in PERSIST_CMD:
                if prog.startswith("reg") and "currentversion\\run" not in cmd_low and "currentversion/run" not in cmd_low:
                    pass
                elif prog in ("systemctl",) and "enable" not in argv:
                    pass
                elif prog == "launchctl" and "load" not in argv and "bootstrap" not in argv:
                    pass
                else:
                    ctx.emit("persistence", phase, file, line, cmd)
            m = re.search(r">>?\s*['\"]?([^\s'\";|&]+)", cmd)
            if m and path_class(m.group(1)) == "autostart":
                ctx.emit("persistence", phase, file, line, cmd)
            # running a file this command line (or earlier code) downloaded
            target = argv[1] if prog in ("sh", "bash", "zsh", "python", "python3", "node", "start-process", "start", "invoke-item",
                                         "cmd", "powershell", "pwsh", "msiexec", "rundll32", "regsvr32", "wscript", "cscript", "mshta") \
                and len(argv) > 1 else argv[0]
            t = target.strip("'\"").replace("\\", "/")
            if ctx.was_downloaded(t):
                ctx.emit("download_exec", phase, file, line, cmd)
            if prog in ("chmod",) and len(argv) > 2 and ctx.was_downloaded(argv[-1]):
                ctx.mark_executable(argv[-1])
            if prog.startswith(("powershell", "pwsh")):
                enc = _ps_decode(argv)
                if enc:
                    ctx.emit("decode_exec", phase, file, line, cmd)
                    analyze(enc, ctx, phase, file, line, depth + 1)
                code = _ps_code(argv)
                if code and code != text:
                    analyze(code, ctx, phase, file, line, depth + 1)
            if prog in ("cmd", "cmd.exe"):
                code = _ps_code(argv)
                if code and code != text:
                    analyze(code, ctx, phase, file, line, depth + 1)
            if prog in ("sh", "bash", "zsh", "dash") and "-c" in argv:
                code = argv[argv.index("-c") + 1] if argv.index("-c") + 1 < len(argv) else ""
                if code and code != text:
                    analyze(code, ctx, phase, file, line, depth + 1)
            if prog.startswith("python") and "-c" in argv and argv.index("-c") + 1 < len(argv):
                ctx.nested_python(argv[argv.index("-c") + 1], phase, file, line, depth + 1)
            if prog in ("node", "bun", "deno") and ("-e" in argv or "--eval" in argv):
                flag = "-e" if "-e" in argv else "--eval"
                if argv.index(flag) + 1 < len(argv):
                    ctx.nested_js(argv[argv.index(flag) + 1], phase, file, line, depth + 1)
            if prog in ("whoami", "hostname", "id", "uname", "ipconfig", "ifconfig", "systeminfo", "pwd") or SYSINFO_SUB.search(cmd):
                info["sysinfo"] = True
    return info


def first_program(text: str) -> str:
    cmds = _split_commands(text or "")
    return _prog(_argv(cmds[0][0])) if cmds and cmds[0] else ""


__all__ = ["analyze", "first_program", "NET", "SECRET", "SYSINFO", "DECODED"]
