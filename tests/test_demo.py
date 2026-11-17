"""Ensure the public fixtures remain valid and usable without private keys."""

from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
import subprocess
import sys

from libreconstancia import cli
from libreconstancia.core import VerificationError, load_public_key_record, verify
import json


class DemoTests(unittest.TestCase):
    def setUp(self):
        self.demo = Path(__file__).resolve().parents[1] / "examples" / "demo"
        self.public = self.demo / "public-key.json"
        self.revocations = self.demo / "revocations.json"

    def test_public_sample_signatures_and_revocation_status(self):
        key = load_public_key_record(json.loads(self.public.read_text(encoding="utf-8")))
        snapshot = json.loads(self.revocations.read_text(encoding="utf-8"))
        valid = json.loads((self.demo / "credential-valid.json").read_text(encoding="utf-8"))
        revoked = json.loads((self.demo / "credential-revoked.json").read_text(encoding="utf-8"))
        self.assertEqual(verify(valid, key, revocations=snapshot)["hours"], 24)
        with self.assertRaisesRegex(VerificationError, "revocada"):
            verify(revoked, key, revocations=snapshot)

    def test_demo_can_be_published_and_shared_without_private_key(self):
        with TemporaryDirectory() as tmp:
            with redirect_stdout(StringIO()):
                self.assertEqual(cli.main([
                    "publish", "--public-key", str(self.public),
                    "--revocations", str(self.revocations), "--output", tmp + "/public"
                ]), 0)
            self.assertTrue((Path(tmp) / "public" / "revocations.json").is_file())
            output = StringIO()
            with redirect_stdout(output), redirect_stderr(StringIO()):
                self.assertEqual(cli.main([
                    "link", "--certificate", str(self.demo / "credential-valid.json"),
                    "--public-key", str(self.public),
                    "--verify-url", "https://example.org/index.html"
                ]), 0)
            self.assertIn("https://example.org/index.html#c=", output.getvalue())

    def test_pages_demo_is_reproducible_and_does_not_include_private_keys(self):
        root = self.demo.parents[1]
        builder = root / "tools" / "build_demo_site.py"
        result = subprocess.run([sys.executable, str(builder), "--check"],
                                cwd=root, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((root / "docs" / "verify" / "private.pem").exists())
        self.assertNotIn(b"PRIVATE KEY", (root / "docs" / "verify" / "trusted-keys.json").read_bytes())

    def test_demo_site_is_generated_correctly_in_a_clean_directory(self):
        root = self.demo.parents[1]
        builder = root / "tools" / "build_demo_site.py"
        with TemporaryDirectory() as tmp:
            subprocess.run([sys.executable, str(builder), "--output", tmp],
                           cwd=root, capture_output=True, text=True, check=True)
            result = subprocess.run([sys.executable, str(builder), "--output", tmp, "--check"],
                                    cwd=root, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue((Path(tmp) / "verify" / "verify.js").is_file())


if __name__ == "__main__":
    unittest.main()
