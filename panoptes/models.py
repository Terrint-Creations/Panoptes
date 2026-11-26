"""Core data model: entities (things we search) and findings (things we learn)."""
from __future__ import annotations

import time
from dataclasses import dataclass, field

KINDS = ("username", "email", "phone", "domain", "ip", "name", "company", "location", "crypto", "file", "onion", "bssid")


@dataclass(frozen=True)
class Entity:
    kind: str
    value: str

    def key(self) -> tuple[str, str]:
        return (self.kind, self.value.strip().lower())

    def __str__(self) -> str:
        return f"{self.kind}:{self.value}"


def combine_confidence(a: float, b: float) -> float:
    """Two independent sources agreeing raise confidence (noisy-OR), capped below 1."""
    return min(0.99, 1 - (1 - a) * (1 - b))


def _base_domain(host: str) -> str:
    parts = host.removeprefix("www.").split(".")
    if len(parts) > 2 and len(parts[-2]) <= 3 and len(parts[-1]) == 2:  # example.co.uk
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def entity_from_str(s: str) -> Entity:
    kind, _, value = s.partition(":")
    return Entity(kind, value)


@dataclass
class Finding:
    category: str               # account, profile, dns, subdomain, network, geolocation, breach, ...
    title: str                  # short label: site name, record type, field name
    value: str                  # the actual data
    source: str                 # module that produced it
    target: Entity              # entity that was searched
    confidence: float = 0.8
    url: str | None = None
    data: dict = field(default_factory=dict)
    pivots: list[Entity] = field(default_factory=list)
    sources: set[str] = field(default_factory=set)
    timestamp: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if not self.sources:
            self.sources = {self.source}

    def key(self) -> tuple:
        value = self.value.strip().lower().rstrip("/")
        if self.category == "account" and "/" not in value and "." in value:
            # bare-domain account hits (email registration checks) merge across sources
            value = _base_domain(value)
        return (self.target.key(), self.category, self.title.strip().lower(), value)

    def merge(self, other: "Finding") -> None:
        new_sources = other.sources - self.sources
        if new_sources:
            self.confidence = combine_confidence(self.confidence, other.confidence)
        else:
            self.confidence = max(self.confidence, other.confidence)
        self.sources |= other.sources
        for k, v in other.data.items():
            self.data.setdefault(k, v)
        if not self.url and other.url:
            self.url = other.url
        for p in other.pivots:
            if p not in self.pivots:
                self.pivots.append(p)

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        return cls(category=d["category"], title=d["title"], value=d["value"], source=(d.get("sources") or ["?"])[0],
                   target=entity_from_str(d["target"]), confidence=d.get("confidence", 0.5), url=d.get("url"),
                   data=d.get("data") or {}, pivots=[entity_from_str(p) for p in d.get("pivots", [])],
                   sources=set(d.get("sources") or []), timestamp=d.get("timestamp", 0))

    def to_dict(self) -> dict:
        return {
            "target": str(self.target),
            "category": self.category,
            "title": self.title,
            "value": self.value,
            "url": self.url,
            "confidence": round(self.confidence, 3),
            "sources": sorted(self.sources),
            "data": self.data,
            "pivots": [str(p) for p in self.pivots],
            "timestamp": self.timestamp,
        }


@dataclass
class Report:
    targets: list[Entity]
    findings: dict[tuple, Finding] = field(default_factory=dict)
    entities: dict[tuple, tuple[Entity, int, str | None]] = field(default_factory=dict)  # key -> (entity, depth, found_via)
    errors: list[str] = field(default_factory=list)
    started: float = field(default_factory=time.time)
    finished: float | None = None
    meta: dict = field(default_factory=dict)   # case name, notes, investigation form

    def add(self, finding: Finding) -> tuple[Finding, bool]:
        key = finding.key()
        existing = self.findings.get(key)
        if existing is None:
            self.findings[key] = finding
            return finding, True
        existing.merge(finding)
        return existing, False

    @classmethod
    def from_dict(cls, d: dict) -> "Report":
        r = cls(targets=[entity_from_str(t) for t in d.get("targets", [])], errors=d.get("errors", []),
                started=d.get("started") or 0, finished=d.get("finished"))
        r.meta = d.get("meta", {})
        for e in d.get("entities", []):
            ent = entity_from_str(e["entity"])
            r.entities[ent.key()] = (ent, e.get("depth", 0), e.get("found_via"))
        for fd in d.get("findings", []):
            r.add(Finding.from_dict(fd))
        return r

    def by_entity(self) -> dict[str, dict[str, list[Finding]]]:
        out: dict[str, dict[str, list[Finding]]] = {}
        for f in self.findings.values():
            out.setdefault(str(f.target), {}).setdefault(f.category, []).append(f)
        for cats in out.values():
            for items in cats.values():
                items.sort(key=lambda f: (-f.confidence, f.title.lower()))
        return out

    def to_dict(self) -> dict:
        return {
            "tool": "panoptes",
            "meta": self.meta,
            "targets": [str(t) for t in self.targets],
            "started": self.started,
            "finished": self.finished,
            "entities": [
                {"entity": str(e), "depth": d, "found_via": via}
                for e, d, via in self.entities.values()
            ],
            "findings": [f.to_dict() for f in sorted(
                self.findings.values(), key=lambda f: (str(f.target), f.category, -f.confidence))],
            "errors": self.errors,
        }
