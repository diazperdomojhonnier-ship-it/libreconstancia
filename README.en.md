# LibreConstancia

**Open-source, self-hosted, digitally signed educational credentials.**

LibreConstancia helps small educational organizations and community training programs issue Ed25519-signed JSON credentials and share a QR code linking to a browser-based verification page. No commercial service, account or database is required.

**Status:** working experimental MVP, v0.2, with signed revocation snapshots. It is not a full student management system.

## Quick start

Requires Python 3.10+:

```bash
python -m pip install -e '.[qr]'
libreconstancia keygen --output private-keys
libreconstancia revocations --private-key private-keys/private.pem --output revocations.json
libreconstancia publish --public-key private-keys/public.json \
  --revocations revocations.json --output public
python -m http.server 8000 --directory public
```

In another terminal:

```bash
libreconstancia issue --private-key private-keys/private.pem \
  --issuer "Example Learning Center" --participant "Example Learner" \
  --program "Critical reading" --hours 80 --output credential.json \
  --verify-url "http://localhost:8000/index.html" --qr credential-qr.png
libreconstancia verify --certificate credential.json \
  --public-key private-keys/public.json --revocations revocations.json
```

To revoke a credential, run `libreconstancia revocations --private-key private-keys/private.pem --previous revocations.json --revoke YOUR-CERTIFICATE-UUID --output updated-revocations.json`, then re-publish into a **new** output directory and deploy the updated files. Keep the previous snapshot as a backup.

The browser verifier relies on a trusted issuer public key stored on the website. A valid signature proves integrity relative to that key; it does **not** prove attendance, legal accreditation or institutional approval. The QR encodes personal data in plaintext. A signed revocation list only proves the published state **as of its date**; it may be outdated. Without a valid published list, the browser reports revocation status as unknown rather than current.

Try the public synthetic credentials in [`examples/demo/`](examples/demo/README.md). See [README.md](README.md) and [SECURITY.md](SECURITY.md) for the complete security model.

The reproducible two-button browser demo is in `docs/`. Run `python -m http.server 8000 --directory docs` and visit `http://localhost:8000` to compare a signed non-revoked credential and an authentic but revoked one. Rebuild via `python tools/build_demo_site.py` and check for drift via `python tools/build_demo_site.py --check`.

Use `libreconstancia link --certificate credential.json --public-key public.json --verify-url https://your-domain.example/index.html` to produce a shareable verification URL for an existing signed credential without the issuer's private key.

Contributions and translations are welcome. License: MIT.
