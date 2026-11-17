"""Stable, auditable format for educational certificates (schema v1)."""

import base64
from collections.abc import Iterable
from datetime import date
import hashlib
import json
import re
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class VerificationError(ValueError):
    """Raised when a credential is malformed or does not verify."""


FIELDS = frozenset({"schema", "certificate_id", "issuer", "participant", "program", "hours", "issued_on"})
REVOCATION_FIELDS = frozenset({"schema", "key_id", "updated_on", "revoked"})
MAX_REVOKED = 10_000


def canonical_bytes(value: dict) -> bytes:
    """Canonical JSON for this strictly typed and fixed-key schema (not RFC 8785)."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64decode(value: str) -> bytes:
    if not isinstance(value, str) or not value or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        raise VerificationError("Codificación base64url inválida")
    if len(value) % 4 == 1:
        raise VerificationError("Longitud base64url inválida")
    try:
        result = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, base64.binascii.Error) as exc:
        raise VerificationError("No se pudo decodificar base64url") from exc
    if b64encode(result) != value:
        raise VerificationError("base64url no canónico")
    return result


def key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:32]


def public_key_record(public_key: Ed25519PublicKey) -> dict:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"algorithm": "Ed25519", "key_id": key_id(public_key), "public_key": b64encode(raw)}


def load_public_key_record(record: dict) -> Ed25519PublicKey:
    if not isinstance(record, dict) or set(record) != {"algorithm", "key_id", "public_key"}:
        raise VerificationError("Formato de clave pública inválido")
    if record["algorithm"] != "Ed25519":
        raise VerificationError("Algoritmo no admitido")
    raw = b64decode(record["public_key"])
    if len(raw) != 32:
        raise VerificationError("La clave pública Ed25519 debe tener 32 bytes")
    pub = Ed25519PublicKey.from_public_bytes(raw)
    if record["key_id"] != key_id(pub):
        raise VerificationError("El identificador de clave no coincide")
    return pub


def _canonical_uuid(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return str(UUID(value)) == value
    except (TypeError, ValueError, AttributeError):
        return False


def _valid_date(value: object) -> bool:
    if not isinstance(value, str) or re.fullmatch(r"\d{4}-\d{2}-\d{2}", value) is None:
        return False
    try:
        return date.fromisoformat(value).isoformat() == value
    except ValueError:
        return False


def validate_payload(payload: dict) -> None:
    if not isinstance(payload, dict) or set(payload) != FIELDS:
        raise VerificationError("Campos del certificado incorrectos")
    if type(payload["schema"]) is not int or payload["schema"] != 1:
        raise VerificationError("Versión de certificado no admitida")
    if not _canonical_uuid(payload["certificate_id"]):
        raise VerificationError("Identificador del certificado inválido o no canónico")
    for field in ("issuer", "participant", "program"):
        value = payload[field]
        if not isinstance(value, str) or not value.strip() or len(value) > 250:
            raise VerificationError(f"Campo obligatorio inválido: {field}")
    if type(payload["hours"]) is not int or not 1 <= payload["hours"] <= 100_000:
        raise VerificationError("La intensidad debe ser un entero positivo")
    if not _valid_date(payload["issued_on"]):
        raise VerificationError("Fecha de expedición inválida (usa AAAA-MM-DD)")


def validate_revocation_payload(payload: dict) -> None:
    """Validate the fixed revocation-list v1 schema before checking its signature."""
    if not isinstance(payload, dict) or set(payload) != REVOCATION_FIELDS:
        raise VerificationError("Campos del registro de revocaciones incorrectos")
    if type(payload["schema"]) is not int or payload["schema"] != 1:
        raise VerificationError("Versión del registro de revocaciones no admitida")
    if not isinstance(payload["key_id"], str) or re.fullmatch(r"[0-9a-f]{32}", payload["key_id"]) is None:
        raise VerificationError("Identificador de clave del registro inválido")
    if not _valid_date(payload["updated_on"]):
        raise VerificationError("Fecha del registro inválida (usa AAAA-MM-DD)")
    revoked = payload["revoked"]
    if not isinstance(revoked, list) or len(revoked) > MAX_REVOKED:
        raise VerificationError("La lista de revocaciones es inválida o demasiado grande")
    if not all(_canonical_uuid(item) for item in revoked) or revoked != sorted(set(revoked)):
        raise VerificationError("La lista debe contener UUID canónicos, ordenados y sin duplicados")


def sign_revocation_list(private_key: Ed25519PrivateKey, revoked: Iterable[str],
                         *, updated_on: str | None = None) -> dict:
    """Create a signed snapshot; consumers must not treat it as proof of current status."""
    if isinstance(revoked, (str, bytes)):
        raise VerificationError("La lista de revocaciones debe ser una secuencia de UUID")
    identifiers = list(revoked)
    if len(identifiers) > MAX_REVOKED:
        raise VerificationError("Demasiadas revocaciones")
    if not all(_canonical_uuid(item) for item in identifiers):
        raise VerificationError("UUID de revocación inválido")
    payload = {
        "schema": 1,
        "key_id": key_id(private_key.public_key()),
        "updated_on": updated_on if updated_on is not None else date.today().isoformat(),
        "revoked": sorted(set(identifiers)),
    }
    validate_revocation_payload(payload)
    return {**payload, "signature": b64encode(private_key.sign(canonical_bytes(payload)))}


def verify_revocation_list(registry: dict, trusted_public_key: Ed25519PublicKey) -> dict:
    """Authenticate a revocation snapshot against the same trusted issuer key."""
    if not isinstance(registry, dict) or set(registry) != REVOCATION_FIELDS | {"signature"}:
        raise VerificationError("Estructura del registro de revocaciones incorrecta")
    payload = {field: registry[field] for field in REVOCATION_FIELDS}
    validate_revocation_payload(payload)
    if payload["key_id"] != key_id(trusted_public_key):
        raise VerificationError("El registro pertenece a otra clave emisora")
    signature = b64decode(registry["signature"])
    if len(signature) != 64:
        raise VerificationError("Firma del registro de revocaciones inválida")
    try:
        trusted_public_key.verify(signature, canonical_bytes(payload))
    except InvalidSignature as exc:
        raise VerificationError("Firma del registro de revocaciones inválida") from exc
    return payload


def issue(private_key: Ed25519PrivateKey, *, issuer: str, participant: str, program: str,
          hours: int, issued_on: str | None = None, certificate_id: str | None = None) -> dict:
    payload = {
        "schema": 1,
        "certificate_id": certificate_id or str(uuid4()),
        "issuer": issuer,
        "participant": participant,
        "program": program,
        "hours": hours,
        "issued_on": issued_on or date.today().isoformat(),
    }
    validate_payload(payload)
    signature = private_key.sign(canonical_bytes(payload))
    return {"payload": payload, "key_id": key_id(private_key.public_key()), "signature": b64encode(signature)}


def verify(document: dict, trusted_public_key: Ed25519PublicKey,
           *, revocations: dict | None = None) -> dict:
    if not isinstance(document, dict) or set(document) != {"payload", "key_id", "signature"}:
        raise VerificationError("Estructura del documento firmado inválida")
    payload = document["payload"]
    validate_payload(payload)
    if document["key_id"] != key_id(trusted_public_key):
        raise VerificationError("Esta constancia no fue firmada por la entidad de confianza seleccionada")
    signature = b64decode(document["signature"])
    if len(signature) != 64:
        raise VerificationError("Longitud de firma incorrecta")
    try:
        trusted_public_key.verify(signature, canonical_bytes(payload))
    except InvalidSignature as exc:
        raise VerificationError("Firma inválida: el documento cambió o no pertenece al emisor") from exc
    if revocations is not None:
        snapshot = verify_revocation_list(revocations, trusted_public_key)
        if payload["certificate_id"] in snapshot["revoked"]:
            raise VerificationError("Constancia revocada según el registro firmado")
    return payload


def make_verification_url(base_url: str, document: dict) -> str:
    parsed = urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("La dirección de verificación debe empezar por https:// o http://")
    encoded_document = b64encode(canonical_bytes(document))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, "c=" + encoded_document))
