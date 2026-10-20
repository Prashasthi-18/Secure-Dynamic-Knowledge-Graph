"""Builds a ready-to-use SDKG for a cyber threat-intelligence domain (used by demo + tests)."""
from __future__ import annotations

from dataclasses import dataclass, field

from .crypto import KeyRegistry, Signer
from .graph import SecureKnowledgeGraph
from .models import Principal, SecurityLabel, edge_content, node_content
from .policy import PolicyEngine
from .retrieval import SecureRetriever
from .trust import TrustEngine
from .validation import Ontology, Validator

L = SecurityLabel.of


def threat_intel_ontology() -> Ontology:
    num = (int, float)
    return (Ontology()
            .node_type("ThreatActor", {"name": str}, {"country": str, "motivation": str})
            .node_type("Malware", {"name": str}, {"family": str, "description": str})
            .node_type("Vulnerability", {"cve_id": str, "cvss": num}, {"description": str})
            .node_type("Asset", {"hostname": str}, {"owner": str, "ip": str})
            .relation("uses", "ThreatActor", "Malware")
            .relation("exploits", "Malware", "Vulnerability")
            .relation("affects", "Vulnerability", "Asset")
            .relation("targets", "ThreatActor", "Asset")
            .relation("attributed_to", "Malware", "ThreatActor", functional=True))


@dataclass
class Env:
    graph: SecureKnowledgeGraph
    retriever: SecureRetriever
    keys: KeyRegistry
    trust: TrustEngine
    signers: dict[str, Signer] = field(default_factory=dict)
    users: dict[str, Principal] = field(default_factory=dict)

    def add_source(self, source_id: str, alpha: float, beta: float) -> Signer:
        s = Signer(source_id)
        self.keys.register(source_id, s.public_key())
        self.trust.register_source(source_id, alpha, beta)
        self.signers[source_id] = s
        return s

    # Client-side helpers: a source signs exactly the canonical content the graph verifies.
    def node(self, who: str, source: str, node_id: str, type_: str, props: dict, label=None, **kw):
        label = label or L("PUBLIC")
        sig = self.signers[source].sign(node_content(node_id, type_, props, label))
        return self.graph.propose_node(self.users[who], node_id=node_id, type=type_, properties=props,
                                       label=label, source_id=source, signature=sig, **kw)

    def edge(self, who: str, source: str, src: str, rel: str, dst: str, label=None, props=None, **kw):
        label, props = label or L("PUBLIC"), props or {}
        sig = self.signers[source].sign(edge_content(src, rel, dst, props, label))
        return self.graph.propose_edge(self.users[who], src=src, relation=rel, dst=dst, properties=props,
                                       label=label, source_id=source, signature=sig, **kw)


def build_env() -> Env:
    keys, trust, policy = KeyRegistry(), TrustEngine(quarantine_below=0.5), PolicyEngine()
    graph = SecureKnowledgeGraph(policy, keys, trust, Validator(threat_intel_ontology()))
    env = Env(graph, SecureRetriever(graph, min_trust=0.6), keys, trust)

    env.add_source("nvd_feed", alpha=19, beta=1)        # rep 0.95 – authoritative
    env.add_source("soc_analysts", alpha=9, beta=1)     # rep 0.90
    env.add_source("partner_isac", alpha=7, beta=3)     # rep 0.70
    env.add_source("osint_scraper", alpha=3, beta=7)    # rep 0.30 – noisy open web
    env.add_source("osint_mirror", alpha=3, beta=7)     # rep 0.30
    env.add_source("agent_summarizer", alpha=6, beta=4) # rep 0.60 – LLM-generated knowledge

    def user(uid, roles, level, *comps, **attrs):
        env.users[uid] = Principal(uid, frozenset(roles), L(level, *comps), attrs)

    user("alice", ["curator"], "SECRET", "APT")
    user("carol", ["curator"], "SECRET", "APT")
    user("bob", ["contributor"], "CONFIDENTIAL", "APT")
    user("mallory", ["contributor"], "INTERNAL")
    user("rag_agent", ["agent"], "CONFIDENTIAL", "APT")
    user("intern", ["reader"], "PUBLIC")
    user("auditor", ["auditor"], "PUBLIC")
    return env
