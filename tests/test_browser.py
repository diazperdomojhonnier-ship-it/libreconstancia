"""Optional real-browser smoke tests, skipped when Chromium is unavailable."""

from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from threading import Thread
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from libreconstancia.core import issue, make_verification_url, public_key_record


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass


@unittest.skipUnless(shutil.which("chromium"), "Chromium no está instalado")
class BrowserTests(unittest.TestCase):
    def test_real_browser_validates_signed_credential(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            static = files("libreconstancia").joinpath("static")
            for filename in ("index.html", "verify.js"):
                (root / filename).write_bytes(static.joinpath(filename).read_bytes())
            private = Ed25519PrivateKey.generate()
            credential = issue(private, issuer="Centro de prueba", participant="Persona de ejemplo",
                               program="Lectura", hours=80, issued_on="2026-11-17")
            (root / "trusted-keys.json").write_text(json.dumps({"keys": [public_key_record(private.public_key())]}))
            server = ThreadingHTTPServer(("127.0.0.1", 0), partial(QuietHandler, directory=str(root)))
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = make_verification_url(f"http://127.0.0.1:{server.server_port}/index.html", credential)
                result = subprocess.run([
                    shutil.which("chromium"), "--headless=new", "--no-sandbox", "--disable-gpu",
                    "--disable-dev-shm-usage", "--virtual-time-budget=3000", "--dump-dom", url
                ], capture_output=True, text=True, timeout=25)
                if result.returncode != 0 and "Operation not permitted" in result.stderr:
                    self.skipTest("El entorno impide abrir sockets de Chromium")
                self.assertEqual(result.returncode, 0, result.stderr[-1500:])
                self.assertIn("Firma válida", result.stdout)
                self.assertIn("Persona de ejemplo", result.stdout)
                self.assertNotIn('id="status" role="status" aria-live="polite">No verificado', result.stdout)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)
