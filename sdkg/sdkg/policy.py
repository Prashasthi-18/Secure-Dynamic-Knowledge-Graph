"""Access control: RBAC (what you may do) + MLS labels (what you may see) + ABAC rules.

Rules enforced:
  * no read-up       : clearance must dominate the object's label to read it
  * no blind write-up: you cannot create facts above your own clearance
  * no write-down    : an agent session that has read data at label L can only
                       write facts labelled >= L (prevents laundering secrets
                       into lower-classified knowledge)
  * ABAC rules       : pluggable, deny-overrides (e.g. time-of-day, purpose, tenant)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from .models import Principal, SecurityLabel

DEFAULT_ROLE_PERMISSIONS: dict[str, set[str]] = {
    "reader": {"read"},
    "agent": {"read", "propose"},
    "contributor": {"read", "propose"},
    "curator": {"read", "propose", "approve", "retract", "rollback", "review"},
    "auditor": {"read", "audit"},
    "admin": {"read", "propose", "approve", "retract", "rollback", "review", "audit", "manage_keys"},
}


@dataclass
class Decision:
    allowed: bool
    reason: str = "ok"


AbacRule = Callable[[Principal, str, Optional[SecurityLabel], dict], Optional[Decision]]


class PolicyEngine:
    def __init__(self, role_permissions: Optional[dict[str, set[str]]] = None):
        self.role_permissions = role_permissions or DEFAULT_ROLE_PERMISSIONS
        self.rules: list[AbacRule] = []

    def add_rule(self, rule: AbacRule) -> None:
        self.rules.append(rule)

    def permissions(self, p: Principal) -> set[str]:
        perms: set[str] = set()
        for r in p.roles:
            perms |= self.role_permissions.get(r, set())
        return perms

    def check(self, p: Principal, action: str, label: Optional[SecurityLabel] = None,
              context: Optional[dict] = None) -> Decision:
        context = context or {}
        if action not in self.permissions(p):
            return Decision(False, f"role(s) {sorted(p.roles)} lack '{action}' permission")

        if label is not None and not p.clearance.dominates(label):
            if action == "read":
                return Decision(False, f"no read-up: clearance {p.clearance} < {label}")
            return Decision(False, f"'{action}' above clearance: {p.clearance} < {label}")

        session_label: Optional[SecurityLabel] = context.get("session_label")
        if action == "propose" and session_label is not None and label is not None:
            if not label.dominates(session_label):
                return Decision(False, f"no write-down: session has read {session_label}, "
                                       f"cannot write at {label}")

        for rule in self.rules:
            d = rule(p, action, label, context)
            if d is not None and not d.allowed:
                return d
        return Decision(True)
