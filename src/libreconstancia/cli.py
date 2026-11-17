"""Command-line interface: keygen, issue, verify and publish."""

import argparse
from getpass import getpass
from importlib.resources import files
import json
import os
from pathlib import Path
import shutil
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .core import (VerificationError, issue, load_public_key_record,
                   make_verification_url, public_key_record, verify)


def _read_json(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _write_new(path: Path, data: bytes, *, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, mode)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)


def _json_bytes(value: dict) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def cmd_keygen(args: argparse.Namespace) -> None:
    directory = Path(args.output)
    private_file, public_file = directory / "private.pem", directory / "public.json"
    if private_file.exists() or public_file.exists():
        raise ValueError("Las claves ya existen: escoge una carpeta nueva. Nunca se sobrescriben.")
    password = getpass("Contraseña nueva para la clave privada: ")
    confirm = getpass("Repite la contraseña: ")
    if len(password) < 12 or password != confirm:
        raise ValueError("La contraseña debe tener al menos 12 caracteres y coincidir")
    private = Ed25519PrivateKey.generate()
    pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password.encode("utf-8")),
    )
    _write_new(private_file, pem, mode=0o600)
    _write_new(public_file, _json_bytes(public_key_record(private.public_key())))
    print(f"Claves generadas: {private_file} (PRIVADA) y {public_file} (PÚBLICA)")
    print("Guarda una copia cifrada de la clave privada. No la publiques ni la subas a GitHub.")


def cmd_issue(args: argparse.Namespace) -> None:
    if args.qr and not args.verify_url:
        raise ValueError("Para generar el QR indica --verify-url con la dirección pública del verificador")
    password = getpass("Contraseña de la clave privada: ").encode("utf-8")
    pem = Path(args.private_key).read_bytes()
    private = serialization.load_pem_private_key(pem, password=password)
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError("Se necesita una clave privada Ed25519")
    document = issue(private, issuer=args.issuer, participant=args.participant,
                     program=args.program, hours=args.hours, issued_on=args.date)
    target = Path(args.output)
    link = make_verification_url(args.verify_url, document) if args.verify_url else None
    qr_image = None
    if args.qr:
        try:
            import qrcode
        except ImportError as exc:
            raise ValueError("Para el QR instala: pip install 'libreconstancia[qr]'") from exc
        qr_image = qrcode.make(link)
        if Path(args.qr).exists():
            raise ValueError("El archivo QR ya existe; elige otra ruta")
    _write_new(target, _json_bytes(document))
    if args.qr and qr_image is not None:
        Path(args.qr).parent.mkdir(parents=True, exist_ok=True)
        qr_image.save(args.qr)
    if link:
        print(f"Enlace verificable (contiene datos del participante):\n{link}")
    print(f"Constancia firmada: {target}")


def cmd_verify(args: argparse.Namespace) -> None:
    trusted = load_public_key_record(_read_json(args.public_key))
    result = verify(_read_json(args.certificate), trusted)
    print(f"FIRMA VÁLIDA: {result['participant']} — {result['program']} ({result['hours']} h)")
    print("La firma comprueba integridad y procedencia criptográfica; no acredita validez legal.")


def cmd_publish(args: argparse.Namespace) -> None:
    record = _read_json(args.public_key)
    load_public_key_record(record)
    dest = Path(args.output)
    targets = [dest / "index.html", dest / "verify.js", dest / "trusted-keys.json"]
    if any(p.exists() for p in targets):
        raise ValueError("Los archivos de la web ya existen. Escoge una carpeta vacía.")
    dest.mkdir(parents=True, exist_ok=True)
    static = files("libreconstancia").joinpath("static")
    for name in ("index.html", "verify.js"):
        shutil.copyfile(static.joinpath(name), dest / name)
    _write_new(dest / "trusted-keys.json", _json_bytes({"keys": [record]}))
    print(f"Verificador web listo en: {dest}")
    print("Publícalo mediante HTTPS en un dominio auténtico que tú controles.")


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Certificados abiertos firmados digitalmente")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("keygen", help="crear par de claves Ed25519")
    p.add_argument("--output", required=True, help="carpeta nueva de claves")
    p.set_defaults(action=cmd_keygen)
    p = sub.add_parser("issue", help="emitir una constancia firmada")
    p.add_argument("--private-key", required=True)
    p.add_argument("--issuer", required=True)
    p.add_argument("--participant", required=True)
    p.add_argument("--program", required=True)
    p.add_argument("--hours", type=int, required=True)
    p.add_argument("--date", help="fecha AAAA-MM-DD (por defecto, fecha local del sistema)")
    p.add_argument("--output", required=True)
    p.add_argument("--verify-url", help="dirección de index.html en tu sitio web")
    p.add_argument("--qr", help="ruta de salida de la imagen QR (requiere dependencia opcional)")
    p.set_defaults(action=cmd_issue)
    p = sub.add_parser("verify", help="comprobar firma contra la clave pública de confianza")
    p.add_argument("--certificate", required=True)
    p.add_argument("--public-key", required=True)
    p.set_defaults(action=cmd_verify)
    p = sub.add_parser("publish", help="exportar el verificador estático sin servidor de aplicaciones")
    p.add_argument("--public-key", required=True)
    p.add_argument("--output", required=True)
    p.set_defaults(action=cmd_publish)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)
    try:
        args.action(args)
        return 0
    except (VerificationError, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
