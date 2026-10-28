"""Shared test helpers: a synthetic wheel and a local HTTP server that speaks Range."""
import io
import os
import random
import re
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAYLOAD = b"import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n"


def make_wheel(extra=None, n_small=0, binary_mb=6) -> bytes:
    rnd = random.Random(1)
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("pkg/__init__.py", "x = 1\n")
        z.writestr("pkg/a.py", PAYLOAD)
        z.writestr("pkg/lib.cpython-310-x86_64-linux-gnu.so", bytes(rnd.getrandbits(8) for _ in range(binary_mb * 1024 * 1024 // 8)) * 8)
        z.writestr("pkg/data/blob.bin", os.urandom(3 * 1024 * 1024))
        z.writestr("pkg/b.py", "y = 2\n" * 100)
        z.writestr("evil.pth", "import os; exec(__import__('base64').b64decode('cHJpbnQoMSk='))\n")
        z.writestr("pkg-1.0.dist-info/METADATA", "Name: pkg\n")
        for i in range(n_small):
            z.writestr(f"pkg/m{i}.py", f"v{i} = {i}\n" * 50)
        for name, data in (extra or {}).items():
            z.writestr(name, data)
    return bio.getvalue()


def serve(blob: bytes, honour_range=True, corrupt_at=None):
    data = bytearray(blob)
    if corrupt_at is not None:
        data[corrupt_at] ^= 0xFF
    data = bytes(data)
    log = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass

        def handle(self):
            try:
                super().handle()
            except (ConnectionResetError, BrokenPipeError):
                pass            # the client hung up early (it refused a non-Range answer): not a test failure

        def do_GET(self):
            rng = self.headers.get("Range")
            m = re.match(r"bytes=(\d+)-(\d+)", rng or "")
            if not (m and honour_range):
                self.send_response(200); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data); return
            a, b = int(m.group(1)), min(int(m.group(2)), len(data) - 1)
            log.append((a, b))
            self.send_response(206)
            self.send_header("Content-Range", f"bytes {a}-{b}/{len(data)}"); self.send_header("Accept-Ranges", "bytes")
            self.send_header("Content-Length", str(b - a + 1)); self.end_headers(); self.wfile.write(data[a:b + 1])

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/pkg.whl", log


