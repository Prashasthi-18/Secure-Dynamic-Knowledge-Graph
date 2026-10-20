"""Data validation for incoming knowledge.

Three layers:
  1. Ontology / schema: allowed node types, required typed properties, allowed relations.
  2. Content scanning: prompt-injection, markup, query-injection and hidden-unicode
     patterns. Knowledge graphs feeding RAG/agents are an indirect prompt-injection
     vector, so text is treated as hostile until proven otherwise.
  3. Consistency: contradictions with existing knowledge (functional relations) and
     label consistency (an edge must not be less classified than its endpoints).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from .models import Edge, Node, Status

INJECTION_PATTERNS: list[tuple[str, float, str]] = [
    (r"ignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions|rules|context)", 1.0, "instruction override"),
    (r"disregard\s+(all\s+|the\s+)?(system|previous|above|prior)", 1.0, "instruction override"),
    (r"\byou\s+are\s+now\b|\bact\s+as\s+(an?\s+)?(admin|root|system)", 0.8, "role hijack"),
    (r"\b(system|developer)\s+(prompt|message|instructions?)\b", 0.6, "prompt reference"),
    (r"<\s*/?\s*(system|assistant|user|script|iframe|img)\b", 0.9, "markup / role tags"),
    (r"\b(exfiltrate|send|post|upload|forward)\b.{0,40}(https?://|api[\s_-]?key|password|credential|token)", 0.9, "exfiltration attempt"),
    (r"\{\{.*?\}\}|\$\{.*?\}", 0.5, "template injection"),
    (r"\b(drop|truncate)\s+(table|database|graph)\b|detach\s+delete|;\s*match\s*\(", 0.8, "query injection"),
]
_COMPILED = [(re.compile(p, re.IGNORECASE | re.DOTALL), w, n) for p, w, n in INJECTION_PATTERNS]
HIDDEN_UNICODE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]")
ID_PATTERN = re.compile(r"^[A-Za-z0-9_.:\-]{1,128}$")


@dataclass
class ValidationReport:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    injection_risk: float = 0.0

    @property
    def ok(self) -> bool:
        return not self.errors


@dataclass
class RelationSpec:
    src_type: str
    dst_type: str
    functional: bool = False   # at most one active target per source (e.g. attributed_to)


class Ontology:
    def __init__(self) -> None:
        self.node_types: dict[str, tuple[dict[str, tuple], dict[str, tuple]]] = {}
        self.relations: dict[str, RelationSpec] = {}

    def node_type(self, name: str, required: dict[str, Any], optional: Optional[dict[str, Any]] = None):
        norm = lambda d: {k: v if isinstance(v, tuple) else (v,) for k, v in (d or {}).items()}
        self.node_types[name] = (norm(required), norm(optional))
        return self

    def relation(self, name: str, src_type: str, dst_type: str, functional: bool = False):
        self.relations[name] = RelationSpec(src_type, dst_type, functional)
        return self


def scan_text(text: str) -> tuple[float, list[str]]:
    """Return (risk score in [0,1], findings)."""
    findings, risk = [], 0.0
    if HIDDEN_UNICODE.search(text):
        findings.append("hidden/bidi unicode characters")
        risk = max(risk, 0.7)
    for rx, weight, name in _COMPILED:
        if rx.search(text):
            findings.append(name)
            risk = max(risk, weight)
    return risk, findings


def _strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield str(k)
            yield from _strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _strings(v)


class Validator:
    def __init__(self, ontology: Ontology, max_str_len: int = 2000, max_props: int = 40,
                 injection_block: float = 0.8, injection_warn: float = 0.5):
        self.ontology = ontology
        self.max_str_len = max_str_len
        self.max_props = max_props
        self.injection_block = injection_block
        self.injection_warn = injection_warn

    def _check_props(self, props: dict, report: ValidationReport) -> None:
        if len(props) > self.max_props:
            report.errors.append(f"too many properties ({len(props)} > {self.max_props})")
        for s in _strings(props):
            if len(s) > self.max_str_len:
                report.errors.append(f"string exceeds {self.max_str_len} chars")
            risk, findings = scan_text(s)
            report.injection_risk = max(report.injection_risk, risk)
            if risk >= self.injection_block:
                report.errors.append(f"content blocked ({', '.join(findings)})")
            elif risk >= self.injection_warn:
                report.warnings.append(f"suspicious content ({', '.join(findings)})")

    def validate_node(self, node: Node) -> ValidationReport:
        r = ValidationReport()
        if not ID_PATTERN.match(node.id):
            r.errors.append(f"invalid node id {node.id!r}")
        spec = self.ontology.node_types.get(node.type)
        if spec is None:
            r.errors.append(f"unknown node type {node.type!r}")
            return r
        required, optional = spec
        for k, types in required.items():
            if k not in node.properties:
                r.errors.append(f"missing required property {k!r}")
            elif not isinstance(node.properties[k], types):
                r.errors.append(f"property {k!r} has wrong type")
        for k, v in node.properties.items():
            if k not in required and k not in optional:
                r.errors.append(f"property {k!r} not allowed for {node.type}")
            elif k in optional and not isinstance(v, optional[k]):
                r.errors.append(f"property {k!r} has wrong type")
        self._check_props(node.properties, r)
        return r

    def validate_edge(self, edge: Edge, nodes: dict[str, Node]) -> ValidationReport:
        r = ValidationReport()
        spec = self.ontology.relations.get(edge.relation)
        if spec is None:
            r.errors.append(f"unknown relation {edge.relation!r}")
            return r
        src, dst = nodes.get(edge.src), nodes.get(edge.dst)
        for end, n in (("source", src), ("target", dst)):
            if n is None or n.status != Status.ACTIVE:
                r.errors.append(f"{end} node does not exist or is not active")
        if r.errors:
            return r
        if src.type != spec.src_type or dst.type != spec.dst_type:
            r.errors.append(f"{edge.relation} must link {spec.src_type}->{spec.dst_type}, "
                            f"got {src.type}->{dst.type}")
        required = src.label.join(dst.label)
        if not edge.label.dominates(required):
            r.errors.append(f"edge label {edge.label} would leak endpoints labelled {required}")
        self._check_props(edge.properties, r)
        return r

    def contradictions(self, edge: Edge, edges: dict[str, Edge]) -> list[str]:
        spec = self.ontology.relations.get(edge.relation)
        if not spec or not spec.functional:
            return []
        return [e.id for e in edges.values()
                if e.status == Status.ACTIVE and e.src == edge.src
                and e.relation == edge.relation and e.dst != edge.dst]
