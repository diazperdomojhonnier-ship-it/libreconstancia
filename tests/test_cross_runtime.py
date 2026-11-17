"""Check that the Python signing format is interoperable with JavaScript WebCrypto."""

import json
import shutil
import subprocess
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from libreconstancia.core import issue, public_key_record, sign_revocation_list


@unittest.skipUnless(shutil.which("node"), "Node.js no está instalado")
class CrossRuntimeTests(unittest.TestCase):
    def test_webcrypto_verifies_python_signature(self):
        private = Ed25519PrivateKey.generate()
        document = issue(private, issuer="Centro Amazónico", participant="Niño Ñandú",
                         program="Lectura crítica", hours=80, issued_on="2026-11-17")
        record = public_key_record(private.public_key())
        script = r"""
const {webcrypto} = await import('node:crypto');
const {document, record} = JSON.parse(await new Promise(resolve => {
  let s = ''; process.stdin.setEncoding('utf8');
  process.stdin.on('data', x => s += x); process.stdin.on('end', () => resolve(s));
}));
const decode = s => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
const canonical = value => value && typeof value === 'object' && !Array.isArray(value)
  ? '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}'
  : JSON.stringify(value);
const pub = await webcrypto.subtle.importKey('raw', decode(record.public_key), {name:'Ed25519'}, false, ['verify']);
const ok = await webcrypto.subtle.verify('Ed25519', pub, decode(document.signature),
                                       new TextEncoder().encode(canonical(document.payload)));
process.stdout.write(ok ? 'VALID' : 'INVALID');
"""
        result = subprocess.run([shutil.which("node"), "--input-type=module", "-e", script],
                                input=json.dumps({"document": document, "record": record}, ensure_ascii=False),
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "VALID")

    def test_webcrypto_verifies_revocation_snapshot(self):
        private = Ed25519PrivateKey.generate()
        record = public_key_record(private.public_key())
        registry = sign_revocation_list(private, ["123e4567-e89b-12d3-a456-426614174000"],
                                        updated_on="2026-11-17")
        script = r"""
const {webcrypto} = await import('node:crypto');
let text = ''; process.stdin.setEncoding('utf8');
for await (const chunk of process.stdin) text += chunk;
const {registry, record} = JSON.parse(text);
const decode = s => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
const canonical = value => value && typeof value === 'object' && !Array.isArray(value)
  ? '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}'
  : Array.isArray(value) ? '[' + value.map(canonical).join(',') + ']' : JSON.stringify(value);
const {signature, ...payload} = registry;
const key = await webcrypto.subtle.importKey('raw', decode(record.public_key), {name:'Ed25519'}, false, ['verify']);
const ok = await webcrypto.subtle.verify('Ed25519', key, decode(signature),
                                        new TextEncoder().encode(canonical(payload)));
process.stdout.write(ok ? 'VALID' : 'INVALID');
"""
        result = subprocess.run([shutil.which("node"), "--input-type=module", "-e", script],
                                input=json.dumps({"registry": registry, "record": record}),
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "VALID")
