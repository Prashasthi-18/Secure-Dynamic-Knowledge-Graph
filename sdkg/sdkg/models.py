"""Core data model: security labels, principals, provenance, nodes and edges."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

from .crypto import fingerprint


class Level(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    SECRET = 3


@dataclass(frozen=True)
class SecurityLabel:
    """Multi-level security label: a hierarchical level plus need-to-know compartments."""

    level: Level = Level.PUBLIC
    compartments: frozenset[str] = frozenset()

    @staticmethod
    def of(level: str | Level = "PUBLIC", *compartments: str) -> "SecurityLabel":
        lvl = Level[level] if isinstance(level, str) else level
        return SecurityLabel(lvl, frozenset(compartments))

    def dominates(self, other: "SecurityLabel") -> bool:
        return self.level >= other.level and self.compartments >= other.compartments

    def join(self, other: "SecurityLabel") -> "SecurityLabel":
        """Least upper bound of two labels."""
        return SecurityLabel(Level(max(self.level, other.level)), self.compartments | other.compartments)

    def to_dict(self) -> dict:
        return {"level": self.level.name, "compartments": sorted(self.compartments)}

    def __str__(self) -> str:
        comps = f"[{','.join(sorted(self.compartments))}]" if self.compartments else ""
        return f"{self.level.name}{comps}"


class Status:
    ACTIVE = "active"
    PENDING = "pending_approval"
    QUARANTINED = "quarantined"
    RETRACTED = "retracted"
    SUPERSEDED = "superseded"


@dataclass(frozen=True)
class Principal:
    """A human user or an AI agent acting on the graph."""

    id: str
    roles: frozenset[str]
    clearance: SecurityLabel
    attributes: dict[str, Any] = field(default_factory=dict, hash=False, compare=False)


@dataclass
class Provenance:
    source_id: str      # who produced the fact (signs it)
    submitted_by: str   # which principal pushed it into the graph
    signature: str      # source's Ed25519 signature over the canonical content
    timestamp: float


def node_content(node_id: str, type_: str, properties: dict, label: SecurityLabel) -> dict:
    return {"kind": "node", "id": node_id, "type": type_, "properties": properties, "label": label.to_dict()}


def edge_id(src: str, relation: str, dst: str) -> str:
    return f"{src}-[{relation}]->{dst}"


def edge_content(src: str, relation: str, dst: str, properties: dict, label: SecurityLabel) -> dict:
    return {
        "kind": "edge", "id": edge_id(src, relation, dst), "src": src, "relation": relation,
        "dst": dst, "properties": properties, "label": label.to_dict(),
    }


@dataclass
class Node:
    id: str
    type: str
    properties: dict[str, Any]
    label: SecurityLabel
    provenance: list[Provenance]
    trust: float = 0.0
    version: int = 1
    status: str = Status.PENDING
    kind: str = "node"

    def content(self) -> dict:
        return node_content(self.id, self.type, self.properties, self.label)

    def fingerprint(self) -> str:
        return fingerprint(self.content())

    def sources(self) -> list[str]:
        return sorted({p.source_id for p in self.provenance})


@dataclass
class Edge:
    src: str
    relation: str
    dst: str
    properties: dict[str, Any]
    label: SecurityLabel
    provenance: list[Provenance]
    trust: float = 0.0
    version: int = 1
    status: str = Status.PENDING
    kind: str = "edge"

    @property
    def id(self) -> str:
        return edge_id(self.src, self.relation, self.dst)

    def content(self) -> dict:
        return edge_content(self.src, self.relation, self.dst, self.properties, self.label)

    def fingerprint(self) -> str:
        return fingerprint(self.content())

    def sources(self) -> list[str]:
        return sorted({p.source_id for p in self.provenance})
