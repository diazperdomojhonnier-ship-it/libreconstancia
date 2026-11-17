import json
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from libreconstancia import cli
from libreconstancia.core import (VerificationError, b64decode, canonical_bytes, issue,
                                 key_id, load_public_key_record, make_verification_url,
                                 public_key_record, verify)


class CertificateTests(unittest.TestCase):
    def setUp(self):
        self.private = Ed25519PrivateKey.generate()
        self.document = issue(self.private, issuer="Organización de ejemplo",
                              participant="María Álvarez", program="Historia y ciudadanía",
                              hours=120, issued_on="2026-11-17")

    def test_signature_is_valid(self):
        actual = verify(self.document, self.private.public_key())
        self.assertEqual(actual["participant"], "María Álvarez")
        self.assertEqual(actual["hours"], 120)

    def test_tampering_is_rejected(self):
        altered = json.loads(json.dumps(self.document))
        altered["payload"]["hours"] = 160
        with self.assertRaisesRegex(VerificationError, "Firma inválida"):
            verify(altered, self.private.public_key())

    def test_wrong_issuer_key_is_rejected(self):
        wrong = Ed25519PrivateKey.generate().public_key()
        with self.assertRaises(VerificationError):
            verify(self.document, wrong)

    def test_public_key_round_trip(self):
        record = public_key_record(self.private.public_key())
        trusted = load_public_key_record(record)
        self.assertEqual(key_id(trusted), self.document["key_id"])
        self.assertEqual(verify(self.document, trusted)["hours"], 120)

    def test_public_key_id_tampering_is_rejected(self):
        record = public_key_record(self.private.public_key())
        record["key_id"] = "0" * 32
        with self.assertRaises(VerificationError):
            load_public_key_record(record)

    def test_invalid_hours_and_schema_are_rejected(self):
        for hours in (True, 0, -2, "80", 100001):
            with self.subTest(hours=hours), self.assertRaises(VerificationError):
                issue(self.private, issuer="Emisor", participant="Participante",
                      program="Curso", hours=hours)

    def test_url_roundtrip_and_private_fragment(self):
        link = make_verification_url("https://certificados.example.org/index.html", self.document)
        parsed = urlsplit(link)
        self.assertEqual(parsed.path, "/index.html")
        self.assertEqual(parsed.fragment[:2], "c=")
        self.assertEqual(json.loads(b64decode(parsed.fragment[2:])), self.document)
        self.assertNotIn("María", parsed.path)

    def test_invalid_url_is_rejected(self):
        with self.assertRaises(ValueError):
            make_verification_url("file:///tmp/index.html", self.document)

    def test_canonical_serialization_is_independent_of_key_order(self):
        first = canonical_bytes({"b": 2, "a": "á"})
        second = canonical_bytes({"a": "á", "b": 2})
        self.assertEqual(first, second)

    def test_key_generation_and_web_publish_end_to_end(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            with patch("libreconstancia.cli.getpass", side_effect=["clave-larga-segura", "clave-larga-segura"]):
                self.assertEqual(cli.main(["keygen", "--output", str(root / "keys")]), 0)
            private_file = root / "keys" / "private.pem"
            public_file = root / "keys" / "public.json"
            self.assertTrue(private_file.exists())
            self.assertEqual(private_file.stat().st_mode & 0o777, 0o600)
            self.assertIn(b"ENCRYPTED", private_file.read_bytes())
            with patch("libreconstancia.cli.getpass", return_value="clave-larga-segura"):
                self.assertEqual(cli.main([
                    "issue", "--private-key", str(private_file),
                    "--issuer", "Emisor", "--participant", "Participante",
                    "--program", "Curso", "--hours", "80", "--output", str(root / "cert.json"),
                    "--verify-url", "https://example.org/index.html"
                ]), 0)
            self.assertEqual(cli.main([
                "verify", "--certificate", str(root / "cert.json"),
                "--public-key", str(public_file)
            ]), 0)
            self.assertEqual(cli.main([
                "publish", "--public-key", str(public_file), "--output", str(root / "public")
            ]), 0)
            self.assertTrue((root / "public" / "index.html").exists())
            self.assertTrue((root / "public" / "verify.js").exists())
            bundle = json.loads((root / "public" / "trusted-keys.json").read_text())
            self.assertEqual(bundle["keys"][0], json.loads(public_file.read_text()))

    @unittest.skipUnless(importlib.util.find_spec("qrcode"), "Dependencia opcional QR no instalada")
    def test_issue_creates_readable_qr_png(self):
        from cryptography.hazmat.primitives import serialization
        with TemporaryDirectory() as temp:
            root = Path(temp)
            private = Ed25519PrivateKey.generate()
            encrypted = private.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(b"clave-larga-segura"),
            )
            (root / "private.pem").write_bytes(encrypted)
            with patch("libreconstancia.cli.getpass", return_value="clave-larga-segura"):
                rc = cli.main([
                    "issue", "--private-key", str(root / "private.pem"),
                    "--issuer", "Emisor", "--participant", "Persona",
                    "--program", "Programa", "--hours", "80",
                    "--verify-url", "https://example.org/index.html",
                    "--output", str(root / "constancia.json"),
                    "--qr", str(root / "constancia.png"),
                ])
            self.assertEqual(rc, 0)
            from PIL import Image
            with Image.open(root / "constancia.png") as img:
                self.assertGreaterEqual(img.width, 200)
                self.assertEqual(img.width, img.height)


if __name__ == "__main__":
    unittest.main()
