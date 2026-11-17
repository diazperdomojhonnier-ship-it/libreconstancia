# LibreConstancia

**Open-source, self-hosted, digitally signed educational credentials.**

LibreConstancia helps small educational organizations and community training programs issue Ed25519-signed JSON credentials and share a QR code linking to a browser-based verification page. No commercial service, account or database is required.

**Status:** working initial MVP, v0.1. It is not yet a full student management system.

## Quick start

Requires Python 3.10+:

```bash
python -m pip install -e '.[qr]'
libreconstancia keygen --output private-keys
libreconstancia publish --public-key private-keys/public.json --output public
python -m http.server 8000 --directory public
```

In another terminal:

```bash
libreconstancia issue --private-key private-keys/private.pem \
  --issuer "Example Learning Center" --participant "Example Learner" \
  --program "Critical reading" --hours 80 --output credential.json \
  --verify-url "http://localhost:8000/index.html" --qr credential-qr.png
libreconstancia verify --certificate credential.json --public-key private-keys/public.json
```

The browser verifier relies on a trusted issuer public key stored on the website. A successful signature proves integrity and origin relative to that key; it does **not** prove attendance, legal accreditation or institutional approval. The QR encodes personal data in plaintext. This first version does not support revocation. See [README.md](README.md) and [SECURITY.md](SECURITY.md) for the full security model.

Contributions and translations are welcome. License: MIT.
