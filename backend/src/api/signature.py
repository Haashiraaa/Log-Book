

# backend/src/api/signature.py

from __future__ import annotations

import base64
import binascii

from backend.src.exceptions.errors import InvalidSignatureError

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
MAX_SIGNATURE_BYTES = 200 * 1024


def decode_signature_png(raw: str | None) -> bytes | None:
    """base64 (optionally a data: URL) -> PNG bytes. None/blank -> None.
    Raises InvalidSignatureError on bad base64, non-PNG or oversize."""
    if raw is None or not raw.strip():
        return None
    data = raw.strip()
    if data.startswith("data:"):
        data = data.partition(",")[2]
    try:
        blob = base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError):
        raise InvalidSignatureError("Signature is not valid base64.") from None
    if len(blob) > MAX_SIGNATURE_BYTES:
        raise InvalidSignatureError(
            "Signature image is too large (max 200 KB).")
    if not blob.startswith(_PNG_MAGIC):
        raise InvalidSignatureError("Signature must be a PNG image.")
    return blob
