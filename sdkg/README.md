# Secure Dynamic Knowledge Graph (SDKG)

A security-aware knowledge graph for protecting dynamic knowledge consumed by
retrieval-augmented generation (RAG) and autonomous agents. Demo domain: cyber
threat intelligence (actors, malware, CVEs, assets).

## Quick start

```bash
pip install cryptography pytest
python demo.py          # normal operation + 9 attack scenarios
python -m pytest -q     # 20 security tests
```

## Architecture

```
            sources (feeds, analysts, OSINT, LLM agents) ── sign facts (Ed25519)
                                   │
                                   ▼
 ┌──────────────────────── SECURE UPDATE PIPELINE (graph.py) ───────────────────────┐
 │ 1 Authorize   RBAC + MLS labels + no write-down + ABAC        (policy.py)        │
 │ 2 Authenticate source signature vs key registry, revocation    (crypto.py)        │
 │ 3 Validate    ontology, prompt/query-injection scan, label leak (validation.py)   │
 │ 4 Corroborate identical facts from independent sources merge provenance          │
 │ 5 Conflicts   functional-relation contradictions, modifications                  │
 │ 6 Trust       Beta reputation × noisy-OR corroboration × freshness (trust.py)    │
 │ 7 Decide      quarantine │ approval quorum (separation of duties) │ commit       │
 └──────────────────────────────────────┬───────────────────────────────────────────┘
                                        ▼
       versioned store + rollback ◄──► signed hash-chain audit ledger (ledger.py)
                                        ▼
 ┌──────────────────────── SECURE RETRIEVAL (retrieval.py) ─────────────────────────┐
 │ policy-filtered, trust-thresholded, provenance-tagged, re-sanitised context;     │
 │ per-session high-water mark, query budget, every retrieval audited               │
 └──────────────────────────────────────────────────────────────────────────────────┘
                                        ▼
                                RAG pipeline / LLM agent
```

| Module | Responsibility |
|---|---|
| `models.py` | Security labels (level + compartments), principals, provenance, nodes, edges |
| `crypto.py` | Canonical hashing, Ed25519 signing, source key registry with revocation |
| `policy.py` | RBAC permissions, Bell-LaPadula style no-read-up / no-write-down, ABAC hooks |
| `validation.py` | Ontology enforcement, injection detection, contradiction and label-leak checks |
| `trust.py` | Source reputation learned from curator feedback, corroboration, decay |
| `ledger.py` | Append-only audit log, hash-chained and signed by the graph |
| `graph.py` | Update pipeline, approvals, quarantine review, retraction, rollback, integrity audit |
| `retrieval.py` | Secure retriever and agent sessions |

## Threat model (STRIDE mapping)

| Threat | Example attack | Control | Demo / test |
|---|---|---|---|
| Spoofing | Attacker submits facts claiming to be NVD | Per-source signatures, key registry | Attack 1 |
| Tampering (data) | Insider edits CVSS score in storage | Committed fingerprints, signature re-verification, rollback | Attack 8 |
| Tampering (logs) | Insider rewrites audit history | Signed hash chain | Attack 8 |
| Repudiation | “I never approved that” | Every decision ledgered with actor | Audit trail |
| Information disclosure | Agent/reader accesses SECRET intel | MLS labels + compartments, edge label ≥ endpoints, uniform “not found” | Attack 5 |
| Information disclosure | Agent launders secrets into public summaries | Session high-water mark, no write-down | Attack 6 |
| Information disclosure | Bulk scraping via RAG queries | Per-session query budget | Attack 7 |
| Elevation of privilege | Self-approval of own change | Separation of duties, role checks | Phase 1 |
| Knowledge poisoning | False-flag attribution via weak/Sybil sources | Trust scoring, quarantine, corroboration floor | Attack 2 |
| Knowledge poisoning | Contradicting established facts | Functional-relation conflict detection + human review, reputation penalty | Attack 3 |
| Indirect prompt injection | Instructions hidden in scraped OSINT | Write-time scanning + read-time sanitisation + data-only prompt framing | Attack 4 |
| Key compromise | Stolen source key | Revocation | Attack 9 |

## Known limitations (good material for your report's “future work”)

Regex-based injection detection is evadable; replace or complement it with an
ML classifier. Storage is in-memory; port to Neo4j or another graph DB with the
same pipeline in front. Retrieval is keyword-based; add vector embeddings while
keeping policy filtering *before* ranking. The ledger key lives in process memory;
in production use an HSM/KMS and periodically anchor ledger heads externally.
Property-level labels, differential privacy on aggregate queries, and a REST API
with OAuth/JWT authentication are natural next milestones.
