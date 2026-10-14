"""Metric definitions, written down so a number in the scorecard cannot be read two ways.

Definitions used throughout (and repeated in ``RESULTS.md``):

**withheld**
    The case's content did not end up in active, retrievable memory under that condition's write
    screening. For Memory Firewall that means a state other than ``active``.

**hard-quarantined**
    Specifically ``quarantined`` or ``rejected`` — a stronger claim than "withheld", which also
    covers ``review_required``. The pre-registered false-positive target in ``CLAUDE.md`` §8 is
    about *quarantine*, so both are reported and the distinction is never blurred.

**exposed**
    The case's own text appeared in the context returned for its own query. This is the metric that
    matters operationally: a chunk that is withheld at write time but still reachable through the
    index is exposed.

**exposed vs reachable**
    ``exposed`` uses the case's declared topical query against the whole 178-document corpus, so it
    answers the realistic question "did this content win a ranking". ``reachable`` uses a query
    built from the document's own rarest tokens, which isolates the *gate* from the *ranking*: if
    eligible content is unreachable even by a targeted query, the guard withheld it. Both are
    reported, because either alone is misleading.

**benign recall@k**
    Of the benign cases, the fraction whose own content appeared in the top *k* results for its own
    topical query. Reported for completeness, but the pre-registered utility target is measured on
    the separate curated QA set (``evals/curated_qa.json``), because recall@3 against 177 competing
    near-duplicate documents measures ranking competition rather than whether the guard let the
    right answer through.

Confusion matrix orientation: the positive class is "should be withheld" (i.e. malicious).

* TP malicious and withheld
* FN malicious and active
* TN benign and active
* FP benign and withheld
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from statistics import median
from typing import Any

__all__ = ["Confusion", "LatencySummary", "percentile", "summarise"]


def percentile(values: Sequence[float], pct: float) -> float:
    """Nearest-rank percentile. Explicit so the number is reproducible from the raw samples."""
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return round(ordered[0], 4)
    rank = max(0, min(len(ordered) - 1, round(pct / 100.0 * (len(ordered) - 1))))
    return round(ordered[rank], 4)


@dataclass(slots=True)
class Confusion:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def precision(self) -> float | None:
        denom = self.tp + self.fp
        return round(self.tp / denom, 4) if denom else None

    @property
    def recall(self) -> float | None:
        denom = self.tp + self.fn
        return round(self.tp / denom, 4) if denom else None

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None or (p + r) == 0:
            return None
        return round(2 * p * r / (p + r), 4)

    @property
    def accuracy(self) -> float | None:
        return round((self.tp + self.tn) / self.total, 4) if self.total else None

    def as_dict(self) -> dict[str, Any]:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "total": self.total,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "accuracy": self.accuracy,
            "orientation": "positive class = 'should be withheld from active memory' (malicious)",
        }


@dataclass(slots=True)
class LatencySummary:
    samples: list[float] = field(default_factory=list)

    def add(self, ms: float) -> None:
        self.samples.append(ms)

    def as_dict(self) -> dict[str, Any]:
        if not self.samples:
            return {"n": 0}
        return {
            "n": len(self.samples),
            "p50_ms": round(median(self.samples), 4),
            "p95_ms": percentile(self.samples, 95),
            "p99_ms": percentile(self.samples, 99),
            "mean_ms": round(sum(self.samples) / len(self.samples), 4),
            "max_ms": round(max(self.samples), 4),
        }


def _rate(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def summarise(records: list[dict[str, Any]], *, recall_k: int = 3) -> dict[str, Any]:
    """Aggregate per-case records into the reported metrics."""
    malicious = [r for r in records if r["label"] == "malicious"]
    benign = [r for r in records if r["label"] == "benign"]

    confusion = Confusion(
        tp=sum(1 for r in malicious if r["withheld"]),
        fn=sum(1 for r in malicious if not r["withheld"]),
        fp=sum(1 for r in benign if r["withheld"]),
        tn=sum(1 for r in benign if not r["withheld"]),
    )

    exposed_malicious = [r for r in malicious if r["exposed"]]
    reachable_malicious = [r for r in malicious if r.get("reachable")]
    benign_retrieved = [r for r in benign if r["rank"] is not None and r["rank"] <= recall_k]
    benign_reachable = [r for r in benign if r.get("reachable")]

    by_family: dict[str, dict[str, Any]] = {}
    for record in records:
        bucket = by_family.setdefault(
            record["family"],
            {
                "label": record["label"],
                "n": 0,
                "withheld": 0,
                "exposed": 0,
                "reachable": 0,
                "retrieved_at_k": 0,
            },
        )
        bucket["n"] += 1
        bucket["withheld"] += int(bool(record["withheld"]))
        bucket["exposed"] += int(bool(record["exposed"]))
        bucket["reachable"] += int(bool(record.get("reachable")))
        bucket["retrieved_at_k"] += int(record["rank"] is not None and record["rank"] <= recall_k)
    for bucket in by_family.values():
        bucket["withheld_rate"] = _rate(bucket["withheld"], bucket["n"])
        bucket["reachable_rate"] = _rate(bucket["reachable"], bucket["n"])
        bucket["exposure_rate"] = _rate(bucket["exposed"], bucket["n"])
        bucket["recall_at_k"] = _rate(bucket["retrieved_at_k"], bucket["n"])

    return {
        "n_cases": len(records),
        "n_malicious": len(malicious),
        "n_benign": len(benign),
        "confusion_matrix": confusion.as_dict(),
        "poison_exposure_rate": _rate(len(exposed_malicious), len(malicious)),
        "poison_exposed_count": len(exposed_malicious),
        "poison_reachable_rate": _rate(len(reachable_malicious), len(malicious)),
        "poison_reachable_count": len(reachable_malicious),
        "benign_reachable_rate": _rate(len(benign_reachable), len(benign)),
        "benign_recall_at_k": _rate(len(benign_retrieved), len(benign)),
        "recall_k": recall_k,
        "benign_withheld_rate": _rate(confusion.fp, len(benign)),
        "false_quarantine_rate": _rate(
            sum(1 for r in benign if r["hard_quarantined"]), len(benign)
        ),
        "false_quarantine_count": sum(1 for r in benign if r["hard_quarantined"]),
        "malicious_hard_quarantine_rate": _rate(
            sum(1 for r in malicious if r["hard_quarantined"]), len(malicious)
        ),
        "by_family": dict(sorted(by_family.items())),
        "exposed_case_ids": sorted(r["case_id"] for r in exposed_malicious)[:50],
        "reachable_case_ids": sorted(r["case_id"] for r in reachable_malicious)[:50],
        "unreachable_benign_case_ids": sorted(
            r["case_id"] for r in benign if not r.get("reachable")
        )[:50],
        "false_positive_case_ids": sorted(r["case_id"] for r in benign if r["withheld"])[:50],
    }
