"""Run the actual static verifier with mocked DOM/fetch and real Node WebCrypto."""

import json
from pathlib import Path
import shutil
import subprocess
import unittest
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from libreconstancia.core import issue, make_verification_url, public_key_record, sign_revocation_list


NODE_HARNESS = r"""
import {readFileSync} from 'node:fs';
import {webcrypto} from 'node:crypto';
import vm from 'node:vm';

let input = '';
for await (const part of process.stdin) input += part;
const fixture = JSON.parse(input);
const elements = {};
for (const key of ['status', 'details', 'revocation-status', 'participant', 'program',
                   'issuer', 'issued_on', 'certificate_id', 'hours']) {
  elements[key] = {textContent: '', className: '', hidden: true};
}
const context = {
  window: {location: {hash: fixture.fragment}},
  document: {
    querySelector: selector => elements[selector.slice(1)],
    getElementById: id => elements[id],
  },
  crypto: webcrypto,
  URLSearchParams, TextDecoder, TextEncoder,
  atob: text => Buffer.from(text, 'base64').toString('binary'),
  fetch: async url => {
    if (url === './trusted-keys.json') return {ok: true, json: async () => fixture.keys};
    if (url === './revocations.json' && fixture.registry) {
      return {ok: true, json: async () => fixture.registry};
    }
    return {ok: false, status: 404};
  },
};
const source = readFileSync(process.argv[1], 'utf8');
vm.runInNewContext(source.replace(/\bmain\(\);\s*$/, 'globalThis.__done = main();'), context);
await context.__done;
process.stdout.write(JSON.stringify({
  signature: elements.status.textContent,
  revocation: elements['revocation-status'].textContent,
  revocationClass: elements['revocation-status'].className,
  participant: elements.participant.textContent,
}));
"""


@unittest.skipUnless(shutil.which("node"), "Node.js no está instalado")
class StaticVerifierTests(unittest.TestCase):
    def setUp(self):
        self.private = Ed25519PrivateKey.generate()
        self.document = issue(self.private, issuer="Centro de prueba", participant="Ejemplo sintético",
                              program="Historia", hours=80, issued_on="2026-11-17")

    def run_verifier(self, registry):
        script = Path(__file__).resolve().parents[1] / "src" / "libreconstancia" / "static" / "verify.js"
        fixture = {
            "fragment": "#" + urlsplit(make_verification_url("https://example.org/index.html", self.document)).fragment,
            "keys": {"keys": [public_key_record(self.private.public_key())]},
            "registry": registry,
        }
        result = subprocess.run([shutil.which("node"), "--input-type=module", "-e", NODE_HARNESS, str(script)],
                                input=json.dumps(fixture, ensure_ascii=False),
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_valid_signature_and_empty_revocation_list(self):
        registry = sign_revocation_list(self.private, [], updated_on="2026-11-17")
        actual = self.run_verifier(registry)
        self.assertIn("Firma válida", actual["signature"])
        self.assertIn("No figura revocada", actual["revocation"])
        self.assertEqual(actual["participant"], "Ejemplo sintético")

    def test_revoked_certificate_is_reported(self):
        registry = sign_revocation_list(self.private,
                                        [self.document["payload"]["certificate_id"]], updated_on="2026-11-17")
        actual = self.run_verifier(registry)
        self.assertIn("Firma válida", actual["signature"])
        self.assertIn("CONSTANCIA REVOCADA", actual["revocation"])
        self.assertEqual(actual["revocationClass"], "error")

    def test_missing_registry_does_not_claim_current_status(self):
        actual = self.run_verifier(None)
        self.assertIn("Firma válida", actual["signature"])
        self.assertIn("NO COMPROBADO", actual["revocation"])
        self.assertEqual(actual["revocationClass"], "warning")

    def test_tampered_registry_is_not_trusted(self):
        registry = sign_revocation_list(self.private, [], updated_on="2026-11-17")
        registry["updated_on"] = "2026-11-18"
        actual = self.run_verifier(registry)
        self.assertIn("Firma válida", actual["signature"])
        self.assertIn("NO COMPROBADO", actual["revocation"])
        self.assertEqual(actual["revocationClass"], "warning")
