"""Encryption helpers for catalog exports."""
from __future__ import annotations

import base64
import hashlib
from typing import Optional

try:  # pragma: no cover - optional dependency
    from cryptography.fernet import Fernet
except ImportError:  # pragma: no cover - fallback
    Fernet = None  # type: ignore[assignment]


class CatalogEncryptor:
    """Wrap Fernet symmetric encryption for catalog artifacts.

    If the `cryptography` package is unavailable, the encryptor falls back to a
    reversible XOR obfuscation so the export pipeline continues to function,
    albeit without strong guarantees. Projects SHOULD install `cryptography`
    in production environments.
    """

    def __init__(self, secret: str) -> None:
        self._secret = secret.encode("utf-8")
        if Fernet is not None:
            key = base64.urlsafe_b64encode(hashlib.sha256(self._secret).digest())
            self._fernet: Optional[Fernet] = Fernet(key)
        else:
            self._fernet = None

    def encrypt(self, value: str) -> str:
        data = value.encode("utf-8")
        if self._fernet is not None:
            return self._fernet.encrypt(data).decode("utf-8")
        # Fallback: XOR with hash-derived pad, then base64 encode
        pad = hashlib.sha256(self._secret).digest()
        obfuscated = bytes(b ^ pad[i % len(pad)] for i, b in enumerate(data))
        return "xor::" + base64.urlsafe_b64encode(obfuscated).decode("utf-8")

    def decrypt(self, token: str) -> str:
        if token.startswith("xor::"):
            payload = base64.urlsafe_b64decode(token[5:].encode("utf-8"))
            pad = hashlib.sha256(self._secret).digest()
            plain = bytes(b ^ pad[i % len(pad)] for i, b in enumerate(payload))
            return plain.decode("utf-8")
        if self._fernet is None:
            raise RuntimeError("cryptography not installed; cannot decrypt token")
        return self._fernet.decrypt(token.encode("utf-8")).decode("utf-8")


__all__ = ["CatalogEncryptor"]
