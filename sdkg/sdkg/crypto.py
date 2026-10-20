"""Cryptographic primitives: canonical hashing, Ed25519 signatures, key registry.

Every fact entering the graph is signed by the *source* that produced it. The graph
only accepts facts whose signature verifies against a registered, non-revoked key.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def canonical(obj: Any) -> bytes:
    """Deterministic JSON encoding so the same content always hashes/signs the same."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fingerprint(obj: Any) -> str:
    return sha256(canonical(obj))


class Signer:
    """Holds a private key. In production this would live in an HSM / KMS."""

    def __init__(self, name: str):
        self.name = name
        self._sk = Ed25519PrivateKey.generate()

    def public_key(self) -> Ed25519PublicKey:
        return self._sk.public_key()

    def sign(self, payload: Any) -> str:
        return self._sk.sign(canonical(payload)).hex()

    def sign_bytes(self, data: bytes) -> str:
        return self._sk.sign(data).hex()


def verify_bytes(pk: Ed25519PublicKey, data: bytes, sig_hex: str) -> bool:
    try:
        pk.verify(bytes.fromhex(sig_hex), data)
        return True
    except (InvalidSignature, ValueError):
        return False


class KeyRegistry:
    """Registry of trusted knowledge sources and their public keys (with revocation)."""

    def __init__(self) -> None:
        self._keys: dict[str, Ed25519PublicKey] = {}
        self._revoked: set[str] = set()

    def register(self, source_id: str, pk: Ed25519PublicKey) -> None:
        self._keys[source_id] = pk
        self._revoked.discard(source_id)

    def revoke(self, source_id: str) -> None:
        self._revoked.add(source_id)

    def is_known(self, source_id: str) -> bool:
        return source_id in self._keys

    def is_revoked(self, source_id: str) -> bool:
        return source_id in self._revoked

    def verify(self, source_id: str, payload: Any, sig_hex: str, allow_revoked: bool = False) -> bool:
        pk = self._keys.get(source_id)
        if pk is None:
            return False
        if source_id in self._revoked and not allow_revoked:
            return False
        return verify_bytes(pk, canonical(payload), sig_hex)
