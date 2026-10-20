"""Trust scoring for facts.

trust(fact) = corroboration(source reputations) x freshness x (1 - injection_risk)

* Source reputation is a Beta(alpha, beta) estimate updated by curator feedback:
  confirmed facts reward the source, retracted-as-false facts penalise it.
* Corroboration uses noisy-OR across *independent* sources, so agreement between
  sources increases confidence. Sources below `min_corroborator_rep` cannot
  corroborate, which blunts Sybil-style poisoning with many weak sources.
* Freshness decays exponentially with a configurable half-life.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Iterable, Optional

from .models import Provenance


@dataclass
class Reputation:
    alpha: float = 1.0
    beta: float = 1.0

    @property
    def score(self) -> float:
        return self.alpha / (self.alpha + self.beta)


class TrustEngine:
    def __init__(self, quarantine_below: float = 0.5, half_life_days: float = 365.0,
                 min_corroborator_rep: float = 0.4):
        self.quarantine_below = quarantine_below
        self.half_life_days = half_life_days
        self.min_corroborator_rep = min_corroborator_rep
        self.sources: dict[str, Reputation] = {}

    def register_source(self, source_id: str, alpha: float = 1.0, beta: float = 1.0) -> None:
        self.sources[source_id] = Reputation(alpha, beta)

    def reputation(self, source_id: str) -> float:
        rep = self.sources.get(source_id)
        return rep.score if rep else 0.0

    def reward(self, source_id: str, weight: float = 1.0) -> None:
        self.sources.setdefault(source_id, Reputation()).alpha += weight

    def penalize(self, source_id: str, weight: float = 2.0) -> None:
        self.sources.setdefault(source_id, Reputation()).beta += weight

    def score(self, provenance: Iterable[Provenance], injection_risk: float = 0.0,
              now: Optional[float] = None) -> float:
        prov = list(provenance)
        if not prov:
            return 0.0
        now = now or time.time()
        reps = {p.source_id: self.reputation(p.source_id) for p in prov}
        strong = [r for r in reps.values() if r >= self.min_corroborator_rep]
        if strong:
            disbelief = 1.0
            for r in strong:
                disbelief *= (1.0 - r)
            combined = 1.0 - disbelief
        else:
            combined = max(reps.values())
        newest = max(p.timestamp for p in prov)
        age_days = max(0.0, (now - newest) / 86400.0)
        freshness = 0.5 ** (age_days / self.half_life_days)
        return round(combined * freshness * (1.0 - injection_risk), 4)
