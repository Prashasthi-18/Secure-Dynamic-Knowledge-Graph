"""Tamper-evident audit ledger.

Each entry is hash-chained to the previous one AND signed by the graph's own key.
A plain hash chain can be fully recomputed by an attacker with write access to
storage; the signature prevents that unless the signing key is also compromised.
"""
from __future__ import annotations

import time
from typing import Any, Optional

from .crypto import Signer, canonical, sha256, verify_bytes

GENESIS = "0" * 64
_BODY_KEYS = ("seq", "ts", "actor", "action", "subject", "details", "prev")


class AuditLedger:
    def __init__(self, signer: Signer):
        self._signer = signer
        self._pk = signer.public_key()
        self.entries: list[dict[str, Any]] = []

    def append(self, actor: str, action: str, subject: str, details: Optional[dict] = None) -> dict:
        prev = self.entries[-1]["hash"] if self.entries else GENESIS
        body = {
            "seq": len(self.entries), "ts": time.time(), "actor": actor,
            "action": action, "subject": subject, "details": details or {}, "prev": prev,
        }
        h = sha256(canonical(body))
        entry = {**body, "hash": h, "sig": self._signer.sign_bytes(h.encode())}
        self.entries.append(entry)
        return entry

    def verify(self) -> tuple[bool, list[str]]:
        problems: list[str] = []
        prev = GENESIS
        for i, e in enumerate(self.entries):
            body = {k: e.get(k) for k in _BODY_KEYS}
            if e.get("seq") != i:
                problems.append(f"entry {i}: sequence number mismatch (deleted/reordered entry?)")
            if e.get("prev") != prev:
                problems.append(f"entry {i}: broken chain link")
            h = sha256(canonical(body))
            if h != e.get("hash"):
                problems.append(f"entry {i}: content hash mismatch (entry modified)")
            if not verify_bytes(self._pk, e.get("hash", "").encode(), e.get("sig", "")):
                problems.append(f"entry {i}: invalid ledger signature")
            prev = e.get("hash")
        return (not problems, problems)

    def last(self, subject: str, action: str) -> Optional[dict]:
        for e in reversed(self.entries):
            if e["subject"] == subject and e["action"] == action:
                return e
        return None

    def for_subject(self, subject: str) -> list[dict]:
        return [e for e in self.entries if e["subject"] == subject]
