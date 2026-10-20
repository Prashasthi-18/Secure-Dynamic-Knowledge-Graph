"""SecureKnowledgeGraph: a versioned graph store with a secure update pipeline.

Every write goes through:
    authorize -> authenticate source -> validate -> corroborate/conflict check
    -> trust score -> (quarantine | approval quorum | commit) -> audit ledger
"""
from __future__ import annotations

import copy
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterator, Optional, Union

from .crypto import KeyRegistry, Signer
from .ledger import AuditLedger
from .models import Edge, Level, Node, Principal, Provenance, SecurityLabel, Status
from .policy import PolicyEngine
from .trust import TrustEngine
from .validation import Validator

Fact = Union[Node, Edge]


class AccessDenied(Exception):
    pass


@dataclass
class UpdateResult:
    update_id: str
    status: str            # committed | corroborated | quarantined | pending_approval | rejected
    object_id: str
    reasons: list[str] = field(default_factory=list)
    trust: float = 0.0

    def __str__(self) -> str:
        why = f" ({'; '.join(self.reasons)})" if self.reasons else ""
        return f"[{self.status.upper()}] {self.object_id} trust={self.trust:.2f}{why}"


@dataclass
class _Pending:
    fact: Fact
    proposer: str
    needed: int
    retire: list[str]
    approvals: set[str] = field(default_factory=set)


DEFAULT_QUORUM = {Level.PUBLIC: 0, Level.INTERNAL: 0, Level.CONFIDENTIAL: 1, Level.SECRET: 2}


class SecureKnowledgeGraph:
    def __init__(self, policy: PolicyEngine, keys: KeyRegistry, trust: TrustEngine,
                 validator: Validator, approval_quorum: Optional[dict[Level, int]] = None):
        self.policy, self.keys, self.trust, self.validator = policy, keys, trust, validator
        self.quorum = approval_quorum or DEFAULT_QUORUM
        self.nodes: dict[str, Node] = {}
        self.edges: dict[str, Edge] = {}
        self.quarantine: dict[str, Fact] = {}
        self.pending: dict[str, _Pending] = {}
        self.history: dict[str, list[Fact]] = defaultdict(list)
        self.ledger = AuditLedger(Signer("graph-ledger"))

    # ------------------------------------------------------------------ writes
    def propose_node(self, principal: Principal, *, node_id: str, type: str, properties: dict,
                     label: SecurityLabel, source_id: str, signature: str,
                     session_label: Optional[SecurityLabel] = None) -> UpdateResult:
        node = Node(node_id, type, dict(properties), label,
                    [Provenance(source_id, principal.id, signature, time.time())])
        return self._submit(principal, node, session_label)

    def propose_edge(self, principal: Principal, *, src: str, relation: str, dst: str,
                     properties: Optional[dict] = None, label: SecurityLabel, source_id: str,
                     signature: str, session_label: Optional[SecurityLabel] = None) -> UpdateResult:
        edge = Edge(src, relation, dst, dict(properties or {}), label,
                    [Provenance(source_id, principal.id, signature, time.time())])
        return self._submit(principal, edge, session_label)

    def _store(self, fact: Fact) -> dict:
        return self.nodes if fact.kind == "node" else self.edges

    def _submit(self, principal: Principal, fact: Fact,
                session_label: Optional[SecurityLabel]) -> UpdateResult:
        uid = uuid.uuid4().hex[:12]
        prov = fact.provenance[0]

        def reject(reason: str) -> UpdateResult:
            self.ledger.append(principal.id, "reject", fact.id, {"update": uid, "reason": reason})
            return UpdateResult(uid, "rejected", fact.id, [reason])

        # 1. Authorization (RBAC + MLS + write-down + ABAC)
        d = self.policy.check(principal, "propose", fact.label, {"session_label": session_label})
        if not d.allowed:
            return reject(d.reason)

        # 2. Source authenticity: signature over canonical content by a registered key
        if not self.keys.verify(prov.source_id, fact.content(), prov.signature):
            return reject(f"invalid signature or unknown/revoked source '{prov.source_id}'")

        # 3. Validation (schema, injection, label consistency)
        report = (self.validator.validate_node(fact) if fact.kind == "node"
                  else self.validator.validate_edge(fact, self.nodes))
        if not report.ok:
            return reject("; ".join(report.errors))

        # 4. Corroboration: identical content from another source strengthens the fact
        store = self._store(fact)
        existing = store.get(fact.id) or self.quarantine.get(fact.id)
        if existing is not None and existing.fingerprint() == fact.fingerprint() \
                and existing.status in (Status.ACTIVE, Status.QUARANTINED):
            return self._corroborate(principal, existing, prov, uid)

        # 5. Conflict detection
        conflicts, retire = [], []
        if fact.id in store and store[fact.id].status == Status.ACTIVE:
            conflicts.append("modifies an existing fact")
        if fact.kind == "edge":
            retire = self.validator.contradictions(fact, self.edges)
            if retire:
                conflicts.append(f"contradicts {retire}")

        # 6. Trust scoring
        fact.trust = self.trust.score(fact.provenance, report.injection_risk)
        reasons = report.warnings + conflicts
        if fact.trust < self.trust.quarantine_below:
            fact.status = Status.QUARANTINED
            self.quarantine[fact.id] = fact
            self.ledger.append(principal.id, "quarantine", fact.id,
                               {"update": uid, "trust": fact.trust, "source": prov.source_id})
            return UpdateResult(uid, "quarantined", fact.id,
                                reasons + [f"trust below {self.trust.quarantine_below}"], fact.trust)

        # 7. Approval quorum (sensitive labels or conflicting changes need humans)
        needed = self.quorum[fact.label.level]
        if conflicts:
            needed = max(needed, 1)
        if needed > 0:
            fact.status = Status.PENDING
            self.pending[uid] = _Pending(fact, principal.id, needed, retire)
            self.ledger.append(principal.id, "pending", fact.id,
                               {"update": uid, "needed": needed, "conflicts": conflicts})
            return UpdateResult(uid, "pending_approval", fact.id,
                                reasons + [f"needs {needed} approval(s)"], fact.trust)

        self._commit(principal.id, fact, uid, retire)
        return UpdateResult(uid, "committed", fact.id, reasons, fact.trust)

    def _corroborate(self, principal: Principal, existing: Fact, prov: Provenance,
                     uid: str) -> UpdateResult:
        if prov.source_id in existing.sources():
            return UpdateResult(uid, "rejected", existing.id, ["duplicate assertion from same source"],
                                existing.trust)
        existing.provenance.append(prov)
        existing.trust = self.trust.score(existing.provenance)
        self.ledger.append(principal.id, "corroborate", existing.id,
                           {"update": uid, "source": prov.source_id, "trust": existing.trust})
        if existing.status == Status.QUARANTINED and existing.trust >= self.trust.quarantine_below:
            del self.quarantine[existing.id]
            if self.quorum[existing.label.level] == 0:
                self._commit(principal.id, existing, uid, [])
                return UpdateResult(uid, "committed", existing.id,
                                    ["released from quarantine by corroboration"], existing.trust)
            existing.status = Status.PENDING
            self.pending[uid] = _Pending(existing, principal.id, self.quorum[existing.label.level], [])
            return UpdateResult(uid, "pending_approval", existing.id, ["corroborated"], existing.trust)
        return UpdateResult(uid, "corroborated", existing.id, [], existing.trust)

    def _commit(self, actor: str, fact: Fact, uid: str, retire: list[str]) -> None:
        store = self._store(fact)
        prev = store.get(fact.id)
        fact.version = (prev.version + 1) if prev else 1
        fact.status = Status.ACTIVE
        store[fact.id] = fact
        self.history[fact.id].append(copy.deepcopy(fact))
        for rid in retire:
            if rid in self.edges:
                self.edges[rid].status = Status.SUPERSEDED
                self.ledger.append(actor, "supersede", rid, {"by": fact.id, "update": uid})
        self.ledger.append(actor, "commit", fact.id, {
            "update": uid, "version": fact.version, "fingerprint": fact.fingerprint(),
            "trust": fact.trust, "sources": fact.sources(), "label": str(fact.label)})

    # ------------------------------------------------------------- governance
    def _require(self, p: Principal, action: str, label: Optional[SecurityLabel] = None) -> None:
        d = self.policy.check(p, action, label)
        if not d.allowed:
            self.ledger.append(p.id, "access_denied", action, {"reason": d.reason})
            raise AccessDenied(d.reason)

    def approve(self, principal: Principal, update_id: str) -> UpdateResult:
        pend = self.pending.get(update_id)
        if pend is None:
            raise KeyError(f"no pending update {update_id}")
        self._require(principal, "approve", pend.fact.label)
        if principal.id == pend.proposer:
            self.ledger.append(principal.id, "access_denied", pend.fact.id, {"reason": "self-approval"})
            raise AccessDenied("separation of duties: proposer cannot approve own update")
        pend.approvals.add(principal.id)
        self.ledger.append(principal.id, "approve", pend.fact.id,
                           {"update": update_id, "approvals": sorted(pend.approvals)})
        if len(pend.approvals) >= pend.needed:
            del self.pending[update_id]
            self._commit(principal.id, pend.fact, update_id, pend.retire)
            for src in pend.fact.sources():
                self.trust.reward(src, 0.5)
            return UpdateResult(update_id, "committed", pend.fact.id, [], pend.fact.trust)
        return UpdateResult(update_id, "pending_approval", pend.fact.id,
                            [f"{len(pend.approvals)}/{pend.needed} approvals"], pend.fact.trust)

    def reject_pending(self, principal: Principal, update_id: str, reason: str,
                       false_info: bool = True) -> None:
        pend = self.pending.get(update_id)
        if pend is None:
            raise KeyError(f"no pending update {update_id}")
        self._require(principal, "approve", pend.fact.label)
        del self.pending[update_id]
        pend.fact.status = Status.RETRACTED
        if false_info:
            for s in pend.fact.sources():
                self.trust.penalize(s)
        self.ledger.append(principal.id, "reject_pending", pend.fact.id,
                           {"update": update_id, "reason": reason})

    def review_quarantine(self, principal: Principal, fact_id: str, accept: bool, note: str = "") -> str:
        fact = self.quarantine.get(fact_id)
        if fact is None:
            raise KeyError(fact_id)
        self._require(principal, "review", fact.label)
        del self.quarantine[fact_id]
        if accept:
            for s in fact.sources():
                self.trust.reward(s)
            self._commit(principal.id, fact, "review", [])
        else:
            for s in fact.sources():
                self.trust.penalize(s)
            fact.status = Status.RETRACTED
            self.ledger.append(principal.id, "discard", fact_id, {"note": note, "sources": fact.sources()})
        return fact.status

    def retract(self, principal: Principal, fact_id: str, reason: str, false_info: bool = True) -> None:
        fact = self.nodes.get(fact_id) or self.edges.get(fact_id)
        if fact is None:
            raise KeyError(fact_id)
        self._require(principal, "retract", fact.label)
        fact.status = Status.RETRACTED
        if false_info:
            for s in fact.sources():
                self.trust.penalize(s)
        self.ledger.append(principal.id, "retract", fact_id, {"reason": reason, "false_info": false_info})
        if fact.kind == "node":   # cascade: edges touching a retracted node are retracted too
            for e in self.edges.values():
                if e.status == Status.ACTIVE and fact_id in (e.src, e.dst):
                    e.status = Status.RETRACTED
                    self.ledger.append(principal.id, "retract", e.id, {"reason": f"cascade from {fact_id}"})

    def rollback(self, principal: Principal, fact_id: str, version: int) -> Fact:
        snaps = self.history.get(fact_id, [])
        snap = next((s for s in snaps if s.version == version), None)
        if snap is None:
            raise KeyError(f"{fact_id} v{version}")
        self._require(principal, "rollback", snap.label)
        restored = copy.deepcopy(snap)
        self._commit(principal.id, restored, f"rollback-to-v{version}", [])
        return restored

    # ------------------------------------------------------------------ reads
    def can_read(self, principal: Principal, fact: Fact) -> bool:
        return fact.status == Status.ACTIVE and self.policy.check(principal, "read", fact.label).allowed

    def get_node(self, principal: Principal, node_id: str) -> Optional[Node]:
        node = self.nodes.get(node_id)
        if node is None or not self.can_read(principal, node):
            # Same answer for "missing" and "forbidden": avoids existence oracles.
            if node is not None:
                self.ledger.append(principal.id, "access_denied", node_id, {"action": "read"})
            return None
        return node

    def visible_nodes(self, principal: Principal) -> Iterator[Node]:
        return (n for n in self.nodes.values() if self.can_read(principal, n))

    def neighbors(self, principal: Principal, node_id: str) -> list[tuple[Edge, Node]]:
        out = []
        for e in self.edges.values():
            if node_id not in (e.src, e.dst) or not self.can_read(principal, e):
                continue
            other = self.nodes.get(e.dst if e.src == node_id else e.src)
            if other is not None and self.can_read(principal, other):
                out.append((e, other))
        return out

    # -------------------------------------------------------------- integrity
    def verify_integrity(self, auditor: Optional[Principal] = None) -> dict:
        if auditor is not None:
            self._require(auditor, "audit")
        ok, problems = self.ledger.verify()
        for store in (self.nodes, self.edges):
            for fid, fact in store.items():
                last = self.ledger.last(fid, "commit")
                if last is None:
                    problems.append(f"{fid}: present in store but never committed (injected)")
                elif last["details"]["fingerprint"] != fact.fingerprint():
                    problems.append(f"{fid}: content differs from committed fingerprint (tampered)")
                for p in fact.provenance:
                    if not self.keys.verify(p.source_id, fact.content(), p.signature, allow_revoked=True):
                        problems.append(f"{fid}: provenance signature from {p.source_id} no longer valid")
        return {"ok": not problems, "problems": problems, "ledger_entries": len(self.ledger.entries)}
