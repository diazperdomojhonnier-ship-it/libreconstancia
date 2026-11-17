"""Generate the self-contained GitHub Pages demo from checked-in source fixtures."""

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]


def expected_files() -> dict[str, bytes]:
    sample = ROOT / "examples" / "demo"
    static = ROOT / "src" / "libreconstancia" / "static"
    public_key = json.loads((sample / "public-key.json").read_text(encoding="utf-8"))
    return {
        "index.html": (sample / "landing.html").read_bytes(),
        "demo.js": (sample / "demo.js").read_bytes(),
        "credential-valid.json": (sample / "credential-valid.json").read_bytes(),
        "credential-revoked.json": (sample / "credential-revoked.json").read_bytes(),
        "verify/index.html": (static / "index.html").read_bytes(),
        "verify/verify.js": (static / "verify.js").read_bytes(),
        "verify/trusted-keys.json": (json.dumps({"keys": [public_key]}, ensure_ascii=False,
                                          sort_keys=True, indent=2) + "\n").encode("utf-8"),
        "verify/revocations.json": (sample / "revocations.json").read_bytes(),
        ".nojekyll": b"",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the public synthetic demo site")
    parser.add_argument("--output", type=Path, default=ROOT / "docs")
    parser.add_argument("--check", action="store_true", help="report drift without writing")
    args = parser.parse_args()
    failures = []
    for name, data in expected_files().items():
        dest = args.output / name
        if args.check:
            if not dest.is_file() or dest.read_bytes() != data:
                failures.append(name)
        else:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
    if failures:
        print("La demo no coincide con el código fuente: " + ", ".join(failures), file=sys.stderr)
        return 1
    print("Demo verificada" if args.check else f"Demo generada en: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
