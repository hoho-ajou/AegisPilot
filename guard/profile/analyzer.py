"""Analyze supplied Python text without importing or executing it."""
from __future__ import annotations
import ast
import hashlib
import json
import re
import shlex
from urllib.parse import urlsplit, urlunsplit
from . import VERSION

KINDS = ('file_read', 'file_write', 'file_delete', 'environment_read',
         'environment_write', 'network_connect', 'process_execute', 'shell_execute')



def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def safe_target(value):
    """Never export URL userinfo/query/fragment; source snippets are never exported."""
    if not isinstance(value, str):
        return None
    if '://' in value:
        try:
            u = urlsplit(value)
            host = u.hostname or ''
            if ':' in host:
                host = '[' + host + ']'
            if u.port:
                host += ':' + str(u.port)
            return urlunsplit((u.scheme, host, u.path, '', ''))
        except ValueError:
            return None
    return value


def path_categories(target):
    if not target:
        return []
    low = target.lower().replace('\\', '/')
    categories = []
    if re.search(r'(^|/)(\.env(?:\.[^/]*)?|\.aws|\.ssh)(/|$)|credential|secret|token', low):
        categories.append('credential_path')
    if re.search(r'(^|/)(\.config|etc)(/|$)|config[./]|settings(?:\.local)?\.json', low):
        categories.append('configuration_path')
    if re.search(r'(^|/)(skills?)(/|$)|skill\.md$', low):
        categories.append('skill_path')
    if re.search(r'(^|/)(\.claude|\.codex)(/|$)|\.mcp\.json$', low):
        categories.append('agent_configuration_path')
    return categories


def network_target(value):
    if isinstance(value, list):
        return value[0] + ':' + str(value[1]) if len(value) == 2 and isinstance(value[0], str) and isinstance(value[1], int) else None
    return value


def literal(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, (ast.Tuple, ast.List)) and all(isinstance(x, ast.Constant) and isinstance(x.value, (str, int)) for x in node.elts):
        return [x.value for x in node.elts]
    return None


class Bindings(ast.NodeVisitor):
    """Names local to this scope; do not descend into child lexical scopes."""
    def __init__(self):
        self.names = set()
    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.names.add(node.id)
    def visit_FunctionDef(self, node):
        self.names.add(node.name)
    visit_AsyncFunctionDef = visit_FunctionDef
    def visit_ClassDef(self, node):
        self.names.add(node.name)
    def visit_Lambda(self, node):
        pass
    def visit_Import(self, node):
        self.names.update(a.asname or a.name.split('.')[0] for a in node.names)
    def visit_ImportFrom(self, node):
        self.names.update(a.asname or a.name for a in node.names)


class Scanner(ast.NodeVisitor):
    def __init__(self, path, file_hash, artifact_hash, phase, bindings):
        self.path, self.file_hash, self.artifact_hash = path, file_hash, artifact_hash
        self.phase = phase
        self.scopes = []
        self.capabilities, self.evidence, self.limits = [], [], []
        self.bindings = bindings
        self.function = None
        self.conditional = 0

    def scope(self, body, params=()):
        b = Bindings()
        for node in body:
            b.visit(node)
        self.scopes.append({name: None for name in b.names | set(params)})

    def resolve(self, node):
        if isinstance(node, ast.Name):
            for scope in reversed(self.scopes):
                if node.id in scope:
                    return scope[node.id]
            return 'builtins.open' if node.id == 'open' and not any('*' in scope for scope in self.scopes) else None
        if isinstance(node, ast.Attribute):
            base = self.resolve(node.value)
            return base + '.' + node.attr if isinstance(base, str) else None
        return None

    def object(self, node):
        if isinstance(node, ast.Name):
            for scope in reversed(self.scopes):
                if node.id in scope:
                    v = scope[node.id]
                    return v if isinstance(v, tuple) else None
        if isinstance(node, ast.Call):
            name = self.resolve(node.func)
            if name in ('pathlib.Path', 'pathlib.PosixPath', 'pathlib.WindowsPath'):
                return ('path', literal(node.args[0]) if node.args else None)
            if name == 'socket.socket':
                return ('socket', None)
            if name == 'requests.Session':
                return ('session', None)
        return None

    def emit(self, kind, node, target=None, confidence='high', basis='resolved imported or builtin call', **extra):
        target = safe_target(target)
        loc = {'file': self.path, 'line': node.lineno, 'column': node.col_offset,
               'end_line': getattr(node, 'end_lineno', node.lineno), 'end_column': getattr(node, 'end_col_offset', node.col_offset)}
        identity = {'artifact_sha256': self.artifact_hash, 'file_sha256': self.file_hash,
                    'location': loc, 'kind': kind}
        eid = 'ev-' + digest(identity)
        self.evidence.append({'evidence_id': eid, **identity, 'analyzer': 'profile-python-ast', 'analyzer_version': VERSION})
        bound = [b for b in self.bindings if b['file'] == self.path and b.get('symbol') == self.function and self.function is not None]
        self.capabilities.append({'kind': kind, 'status': 'detected', 'target': target,
            'target_status': 'known' if target is not None else 'unknown',
            'execution_phase': self.phase, 'execution_status': 'static_candidate',
            'conditional': bool(self.conditional), 'symbol': self.function,
            'binding': 'provided' if bound else 'unknown', 'reachability': 'unknown',
            'binding_ids': [b['binding_id'] for b in bound],
            'confidence': confidence, 'confidence_basis': basis,
            'sensitive_path': bool(path_categories(target)) if kind.startswith('file_') else False,
            'path_categories': path_categories(target) if kind.startswith('file_') else [],
            'evidence_ids': [eid], **extra})

    def visit_Import(self, node):
        for a in node.names:
            self.scopes[-1][a.asname or a.name.split('.')[0]] = a.name if a.asname else a.name.split('.')[0]

    def visit_ImportFrom(self, node):
        for a in node.names:
            if a.name == '*':
                self.limits.append('star import cannot be resolved')
                self.scopes[-1]['*'] = None
            else:
                self.scopes[-1][a.asname or a.name] = (node.module + '.' + a.name) if node.module and not node.level else None

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.scopes[-1][node.id] = None

    def visit_Assign(self, node):
        self.visit(node.value)
        obj = self.object(node.value)
        for t in node.targets:
            self.visit(t)
            for name in ast.walk(t):
                if isinstance(name, ast.Name) and isinstance(name.ctx, ast.Store):
                    self.scopes[-1][name.id] = obj if isinstance(t, ast.Name) else None

    def visit_AnnAssign(self, node):
        if node.value:
            self.visit(node.value)
        self.visit(node.target)
        if isinstance(node.target, ast.Name):
            self.scopes[-1][node.target.id] = self.object(node.value) if node.value else None

    def visit_AugAssign(self, node):
        self.generic_visit(node)
        if isinstance(node.target, ast.Name):
            self.scopes[-1][node.target.id] = None

    def visit_If(self, node):
        self.visit(node.test)
        # No branch outcome or merged binding is claimed.
        self.conditional += 1
        original = dict(self.scopes[-1])
        self.scopes[-1] = dict(original)
        old_phase = self.phase
        if isinstance(node.test, ast.Compare) and isinstance(node.test.left, ast.Name) and node.test.left.id == '__name__' and any(isinstance(c, ast.Constant) and c.value == '__main__' for c in node.test.comparators):
            self.phase = 'unknown'
        for n in node.body:
            self.visit(n)
        self.phase = old_phase
        left = self.scopes[-1]
        self.scopes[-1] = dict(original)
        for n in node.orelse:
            self.visit(n)
        right = self.scopes[-1]
        self.scopes[-1] = {k: left.get(k) if left.get(k) == right.get(k) else None for k in left.keys() | right.keys()}
        self.conditional -= 1

    def visit_FunctionDef(self, node):
        for d in node.decorator_list + node.args.defaults + [x for x in node.args.kw_defaults if x is not None]:
            self.visit(d)
        old_phase, old_fn = self.phase, self.function
        self.phase = 'function_call'
        self.function = (old_fn + '.' if old_fn else '') + node.name
        params = [a.arg for a in node.args.posonlyargs + node.args.args + node.args.kwonlyargs]
        params += [a.arg for a in (node.args.vararg, node.args.kwarg) if a]
        self.scope(node.body, params)
        for n in node.body:
            self.visit(n)
        self.scopes.pop()
        self.phase, self.function = old_phase, old_fn
    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node):
        old, old_fn = self.phase, self.function
        self.phase, self.function = 'function_call', None
        params = [a.arg for a in node.args.posonlyargs + node.args.args + node.args.kwonlyargs]
        params += [a.arg for a in (node.args.vararg, node.args.kwarg) if a]
        self.scope([], params)
        self.visit(node.body)
        self.scopes.pop()
        self.phase, self.function = old, old_fn

    def visit_ListComp(self, node):
        # Comprehension targets have their own scope in Python 3.
        self.scope([])
        for gen in node.generators:
            self.visit(gen.iter)
            self.visit(gen.target)
            for cond in gen.ifs:
                self.visit(cond)
        for field in ('elt', 'key', 'value'):
            if hasattr(node, field):
                self.visit(getattr(node, field))
        self.scopes.pop()
    visit_SetComp = visit_DictComp = visit_GeneratorExp = visit_ListComp

    def visit_ClassDef(self, node):
        for n in node.bases + node.decorator_list:
            self.visit(n)
        self.scope(node.body)
        for n in node.body:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                class_scope = self.scopes.pop()
                old_fn = self.function
                self.function = (old_fn + '.' if old_fn else '') + node.name
                self.visit(n)
                self.function = old_fn
                self.scopes.append(class_scope)
            else:
                self.visit(n)
        self.scopes.pop()

    def visit_ExceptHandler(self, node):
        if node.type:
            self.visit(node.type)
        if node.name:
            self.scopes[-1][node.name] = None
        for statement in node.body:
            self.visit(statement)
        if node.name:
            self.scopes[-1][node.name] = None

    def visit_Subscript(self, node):
        if self.resolve(node.value) == 'os.environ':
            self.emit('environment_read' if isinstance(node.ctx, ast.Load) else 'environment_write', node, literal(node.slice))
        self.generic_visit(node)

    def visit_Call(self, node):
        name = self.resolve(node.func)
        args = node.args
        keywords = {k.arg: k.value for k in node.keywords}
        target_node = args[0] if args else keywords.get('file') or keywords.get('path') or keywords.get('url') or keywords.get('key')
        target = literal(target_node)
        if name in ('builtins.open', 'io.open'):
            mode_node = args[1] if len(args) > 1 else keywords.get('mode')
            mode = 'r' if mode_node is None else literal(mode_node)
            if isinstance(mode, str):
                if 'r' in mode or '+' in mode:
                    self.emit('file_read', node, target)
                if any(c in mode for c in 'wax+'):
                    self.emit('file_write', node, target)
            else:
                self.emit('file_read', node, target, 'low', 'open call with unresolved access mode', access_mode='unknown')
                self.emit('file_write', node, target, 'low', 'open call with unresolved access mode', access_mode='unknown')
        elif name in ('os.remove', 'os.unlink', 'os.rmdir', 'shutil.rmtree'):
            self.emit('file_delete', node, target)
        elif name in ('shutil.copy', 'shutil.copy2', 'shutil.copyfile', 'shutil.move', 'os.rename', 'os.replace'):
            self.emit('file_read', node, target)
            destination = literal(args[1]) if len(args) > 1 else literal(keywords.get('dst'))
            self.emit('file_write', node, destination)
            if name in ('shutil.move', 'os.rename', 'os.replace'):
                self.emit('file_delete', node, target)
        elif name in ('os.open',):
            flags = args[1] if len(args) > 1 else keywords.get('flags')
            flag_names = {self.resolve(n) for n in ast.walk(flags)} if flags is not None else set()
            if 'os.O_WRONLY' not in flag_names:
                self.emit('file_read', node, target, 'medium', 'os.open flags interpreted conservatively', access_mode='known' if flag_names & {'os.O_RDONLY', 'os.O_RDWR'} else 'unknown')
            if flag_names & {'os.O_WRONLY', 'os.O_RDWR', 'os.O_CREAT', 'os.O_TRUNC', 'os.O_APPEND'} or not flag_names & {'os.O_RDONLY'}:
                self.emit('file_write', node, target, 'medium', 'os.open flags interpreted conservatively', access_mode='known' if flag_names & {'os.O_WRONLY', 'os.O_RDWR'} else 'unknown')
        elif name in ('os.getenv', 'os.environ.get', 'os.environ.setdefault', 'os.environ.pop'):
            self.emit('environment_read', node, target)
            if name.endswith(('setdefault', 'pop')):
                self.emit('environment_write', node, target)
        elif name in ('os.putenv', 'os.unsetenv'):
            self.emit('environment_write', node, target)
        elif name in ('urllib.request.urlopen', 'urllib.request.urlretrieve', 'requests.get', 'requests.post', 'requests.put', 'requests.patch', 'requests.delete', 'requests.head', 'requests.options', 'requests.request', 'httpx.get', 'httpx.post', 'socket.create_connection'):
            if name == 'requests.request':
                target = literal(args[1]) if len(args) > 1 else literal(keywords.get('url'))
            self.emit('network_connect', node, network_target(target))
        elif name in ('subprocess.run', 'subprocess.call', 'subprocess.Popen', 'subprocess.check_call', 'subprocess.check_output', 'os.system', 'os.popen',
                      # shell helpers and the exec/spawn family
                      'subprocess.getoutput', 'subprocess.getstatusoutput', 'os.execv', 'os.execve', 'os.execl', 'os.execle',
                      'os.execlp', 'os.execlpe', 'os.execvp', 'os.execvpe', 'os.spawnv', 'os.spawnve', 'os.spawnl', 'os.spawnle',
                      'os.spawnlp', 'os.spawnvp', 'os.startfile', 'pty.spawn'):
            shell = name in ('os.system', 'os.popen', 'subprocess.getoutput', 'subprocess.getstatusoutput') or \
                (isinstance(keywords.get('shell'), ast.Constant) and keywords['shell'].value is True)
            # Arguments/command bodies can contain secrets: only a list-form executable is exported.
            executable = target[0] if isinstance(target, list) and target else None
            if isinstance(target, str):
                try:
                    tokens = shlex.split(target)
                    executable = tokens[0] if tokens and '=' not in tokens[0] else None
                except ValueError:
                    pass
            self.emit('shell_execute' if shell else 'process_execute', node, executable,
                      shell_status='enabled' if shell else 'unknown' if 'shell' in keywords and not isinstance(keywords['shell'], ast.Constant) else 'disabled')
        elif isinstance(node.func, ast.Attribute):
            obj = self.object(node.func.value)
            method = node.func.attr
            if obj and obj[0] == 'path':
                kind = {'read_text': 'file_read', 'read_bytes': 'file_read', 'write_text': 'file_write', 'write_bytes': 'file_write', 'unlink': 'file_delete', 'rmdir': 'file_delete'}.get(method)
                if kind:
                    self.emit(kind, node, obj[1])
                elif method == 'open':
                    mode = literal(args[0]) if args else literal(keywords['mode']) if 'mode' in keywords else 'r'
                    for kind in (['file_read', 'file_write'] if mode is None else (['file_read'] if 'r' in mode or '+' in mode else []) + (['file_write'] if any(c in mode for c in 'wax+') else [])):
                        self.emit(kind, node, obj[1], access_mode='unknown' if mode is None else 'known')
            elif obj and obj[0] in ('socket', 'session') and method in ('connect', 'connect_ex', 'get', 'post', 'put', 'delete', 'request'):
                if method == 'request':
                    target = literal(args[1]) if len(args) > 1 else literal(keywords.get('url'))
                self.emit('network_connect', node, network_target(target))
        if name in ('builtins.exec', 'builtins.eval') or isinstance(node.func, ast.Name) and node.func.id in ('exec', 'eval'):
            self.limits.append('dynamic code not analyzed')
        self.generic_visit(node)


def analyze_file(path, source, file_hash, artifact_hash, phase, bindings):
    tree = ast.parse(source, filename=path)
    scanner = Scanner(path, file_hash, artifact_hash, phase, bindings)
    scanner.scope(tree.body)
    for node in tree.body:
        scanner.visit(node)
    return scanner.capabilities, scanner.evidence, sorted(set(scanner.limits))
