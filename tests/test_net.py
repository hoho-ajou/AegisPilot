"""Retries inside the guard (guard/net.py): a dropped connection or a 429 / 5xx is tried again with a pause; a timeout and
any other HTTP error are not. run: python3 tests/test_net.py"""
import socket
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))
import net  # noqa: E402


def run(errors):
    """net.urlopen against a fake urlopen that raises `errors` in turn, then answers 'ok'; returns (result, calls, pauses)."""
    calls, pauses = [], []

    def fake(req, timeout=None):
        calls.append(req)
        if len(calls) <= len(errors):
            raise errors[len(calls) - 1]
        return "ok"
    keep = urllib.request.urlopen
    urllib.request.urlopen = fake
    try:
        try:
            out = net.urlopen("https://x.example/", sleep=pauses.append)
        except Exception as e:
            out = e
    finally:
        urllib.request.urlopen = keep
    return out, len(calls), pauses


def http(code):
    return urllib.error.HTTPError("https://x.example/", code, "x", {}, None)


out, n, p = run([urllib.error.URLError(ConnectionRefusedError()), http(503)])
assert out == "ok" and n == 3 and p == [1.0, 3.0], (out, n, p)                  # passes on the third try
out, n, p = run([http(429)] * 3)
assert isinstance(out, urllib.error.HTTPError) and n == 3, (out, n)              # still failing: the error is raised
out, n, p = run([urllib.error.URLError(socket.timeout("timed out"))])
assert isinstance(out, urllib.error.URLError) and n == 1 and p == [], (out, n)   # a timeout: no retry
out, n, p = run([TimeoutError("timed out")])
assert n == 1, n
out, n, p = run([http(404)])
assert isinstance(out, urllib.error.HTTPError) and n == 1, (out, n)              # not there: no retry
assert net.retryable(http(502)) and not net.retryable(http(403))
print("net: all cases passed")
