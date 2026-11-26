"""The search engine: runs every relevant source concurrently, merges duplicate findings,
and follows pivots (an email found on a domain becomes the next search) up to a depth."""
from __future__ import annotations

import asyncio
import logging
import logging.handlers
import time

import httpx

from panoptes.config import DATA_DIR, Config
from panoptes.knowledge import Knowledge, crosscheck
from panoptes.models import Entity, Finding, Report
from panoptes.sources import SOURCES, Context, SearchOptions, Source
from panoptes.sources.base import USER_AGENT, current_run

STAGES = ("primary", "enrich", "late")
# Leads produced by guessing rather than by a profile stating something - they start with low trust.
GUESS_SOURCES = ("Alias", "alt on", "Username candidate", "Likely email", "Domain named after", "Same/similar image",
                 "Frequently mentions", "Tagged / mentioned", "Network:", "@handle in image")
LOG_FILE = DATA_DIR / "logs" / "panoptes.log"


def file_logger() -> logging.Logger:
    log = logging.getLogger("panoptes")
    if not log.handlers:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        h = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s"))
        log.addHandler(h)
        log.setLevel(logging.INFO)
    return log


class Events:
    """Callback sink. The CLI and GUI subclass this to render progress live."""

    def on_entity(self, entity: Entity, depth: int, via: str | None) -> None: ...
    def on_finding(self, finding: Finding, is_new: bool) -> None: ...
    def on_progress(self, source: str, entity: Entity, done: int, total: int) -> None: ...
    def on_source_start(self, source: str, entity: Entity) -> None: ...
    def on_source_done(self, source: str, entity: Entity, count: int, error: str | None) -> None: ...
    def on_log(self, level: str, message: str) -> None: ...


class _Logged(Events):
    """Forwards events and mirrors log lines / source outcomes into the rotating log file."""

    def __init__(self, inner: Events):
        self.inner = inner
        self.log = file_logger()

    def on_entity(self, entity, depth, via):
        self.log.info("entity %s depth=%s via=%s", entity, depth, via)
        self.inner.on_entity(entity, depth, via)

    def on_finding(self, finding, is_new):
        self.inner.on_finding(finding, is_new)

    def on_progress(self, source, entity, done, total):
        self.inner.on_progress(source, entity, done, total)

    def on_source_start(self, source, entity):
        self.inner.on_source_start(source, entity)

    def on_source_done(self, source, entity, count, error):
        (self.log.warning if error else self.log.info)("source %s on %s: %s findings%s", source, entity, count,
                                                       f" ({error})" if error else "")
        self.inner.on_source_done(source, entity, count, error)

    def on_log(self, level, message):
        self.log.log({"error": logging.ERROR, "warning": logging.WARNING, "debug": logging.DEBUG}.get(level, logging.INFO),
                     message)
        self.inner.on_log(level, message)


def make_client(config: Config, options: SearchOptions) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.9",
                 "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,*/*;q=0.7"},
        follow_redirects=True,
        timeout=httpx.Timeout(options.timeout, connect=min(options.timeout, 10)),
        limits=httpx.Limits(max_connections=options.concurrency * 4, max_keepalive_connections=options.concurrency),
        proxy=config.get("proxy") or None,
        verify=True,
    )


class Engine:
    def __init__(self, config: Config | None = None, options: SearchOptions | None = None,
                 events: Events | None = None, sources: list[Source] | None = None):
        self.config = config or Config.load()
        self.options = options or SearchOptions()
        self.events = _Logged(events or Events())
        self.sources = sources or SOURCES
        self.report: Report | None = None  # live report, readable even if the run is interrupted
        self.knowledge = Knowledge(self.options.hint_min_confidence)
        self._used: dict[str, Source] = {}

    def plan(self, entity: Entity) -> tuple[list[Source], list[tuple[Source, str]]]:
        """Sources that will run for an entity, and those skipped (with reason)."""
        run, skipped = [], []
        for s in self.sources:
            if entity.kind not in s.kinds:
                continue
            if self.options.include and s.name not in self.options.include:
                continue
            if s.name in self.options.exclude:
                continue
            if s.option and not getattr(self.options, s.option, True):
                skipped.append((s, f"option '{s.option}' is off"))
                continue
            ok, why = s.available(self.config)
            if ok:
                run.append(s)
            else:
                skipped.append((s, why))
        return run, skipped

    async def run(self, targets: list[Entity], report: Report | None = None, via: str | None = None) -> Report:
        """Search `targets`. Passing an existing `report` extends that case (Maltego-style transforms):
        new findings merge into it and what it already knows seeds the cooperative knowledge base."""
        if report is None:
            report = Report(targets=list(targets))
        else:
            for f in report.findings.values():
                self.knowledge.observe(f)
            for e, d, _ in report.entities.values():
                self.knowledge.add_entity(e, user_supplied=d == 0)
            report.finished = None
        self.report = report
        from panoptes.sources.base import set_process_priority
        set_process_priority(self.options.profile)
        self.events.on_log("info", f"Search started: {', '.join(map(str, targets))} (resource profile: {self.options.profile})")
        for t in targets:
            self.knowledge.add_entity(t, user_supplied=via is None)
        async with make_client(self.config, self.options) as client:
            ctx = Context(client, self.config, self.options, self.events)
            ctx.report = report
            ctx.knowledge = self.knowledge
            ctx.heavy = {s.name for s in self.sources if s.heavy}
            level: list[tuple[Entity, str | None]] = [(t, via) for t in targets]
            depth = 0
            try:
                while level:
                    for ent, via in level:
                        report.entities[ent.key()] = (ent, depth, via)
                        self.events.on_entity(ent, depth, via)
                    await asyncio.gather(*(self._search_entity(ent, ctx, report) for ent, _ in level))
                    self._crosscheck(report)
                    if depth >= self.options.depth:
                        break
                    level = self._next_level(report, depth)
                    for ent, _ in level:
                        self.knowledge.add_entity(ent)
                    depth += 1
                await self._finalize(ctx, report)
                self._crosscheck(report)
                self._discount_untrusted(report)
                if self.options.correlate:
                    from panoptes.correlate import correlate
                    for finding in correlate(report):
                        self._add(report, finding)
            finally:
                report.finished = time.time()
                self.events.on_log("info", f"Search finished: {len(report.findings)} findings, "
                                           f"{len(report.entities)} entities, {report.finished - report.started:.0f}s")
        return report

    def _discount_untrusted(self, report: Report) -> None:
        """Findings about entities we can't tie to the subject: keep them, but their confidence says so."""
        from panoptes.knowledge import doubtful_entities
        doubtful = doubtful_entities(report)
        for f in report.findings.values():
            if str(f.target) in doubtful and "trust_adjusted" not in f.data:
                f.data["trust_adjusted"] = round(f.confidence, 3)
                f.data["note"] = "about an unverified lead - may be a different person"
                f.confidence = round(f.confidence * 0.5, 3)
                self.events.on_finding(f, False)

    async def wrap_up(self, budget: float = 25.0) -> None:
        """After a stop: cross-check, run the global passes briefly, and correlate - so a stopped search still
        gets a full overview of everything found so far."""
        report = self.report
        if report is None:
            return
        self._crosscheck(report)
        try:
            async with make_client(self.config, self.options) as client:
                ctx = Context(client, self.config, self.options, self.events)
                ctx.report, ctx.knowledge = report, self.knowledge
                await asyncio.wait_for(self._finalize(ctx, report), budget)
        except (asyncio.TimeoutError, Exception):
            pass
        self._discount_untrusted(report)
        if self.options.correlate:
            from panoptes.correlate import correlate
            for finding in correlate(report):
                self._add(report, finding)
        report.finished = time.time()

    def _crosscheck(self, report: Report) -> None:
        if not self.options.cooperative:
            return
        for f in crosscheck(report, self.knowledge):
            self.events.on_finding(f, False)

    async def _finalize(self, ctx: Context, report: Report) -> None:
        """Global passes that need every entity's results (avatar/face clustering, etc.)."""
        for source in self._used.values():
            fin = getattr(source, "finalize", None)
            if not fin:
                continue
            try:
                for f in await asyncio.wait_for(fin(ctx, report), self.options.source_timeout):
                    self._add(report, f)
            except Exception as exc:
                report.errors.append(f"{source.name} (finalize): {exc.__class__.__name__}: {exc}")
                self.events.on_log("error", f"{source.name} finalize failed: {exc}")

    def _add(self, report: Report, finding: Finding) -> bool:
        merged, is_new = report.add(finding)
        if self.options.cooperative:
            self.knowledge.observe(merged)
        self.events.on_finding(merged, is_new)
        return is_new

    def _next_level(self, report: Report, depth: int) -> list[tuple[Entity, str | None]]:
        current = {k for k, (_, d, _) in report.entities.items() if d == depth}
        candidates: dict[tuple, tuple[Entity, str, float]] = {}
        doubtful, ambiguous = set(), set()
        if self.options.cooperative:
            from panoptes.knowledge import ambiguous_handles, doubtful_entities, owned
            doubtful = doubtful_entities(report)
            ambiguous = ambiguous_handles(report)
            for key in sorted(doubtful):
                self.events.on_log("info", f"not following leads from {key}: its profiles name a different person")
            for key in sorted(ambiguous - doubtful):
                self.events.on_log("info", f"{key} is shared by several different people - only following leads "
                                           f"from accounts corroborated as the subject's")
        for f in report.findings.values():
            if f.target.key() not in current or f.confidence < self.options.pivot_min_confidence:
                continue
            if str(f.target) in doubtful:
                continue
            if ambiguous and not owned(report, f, ambiguous):
                continue
            if f.data.get("conflicts_with"):
                continue  # don't follow leads out of findings that look like a different person
            for p in f.pivots:
                if p.kind not in self.options.pivot_kinds or p.key() in report.entities:
                    continue
                if p.kind == "name" and f.confidence < 0.9 and not f.data.get("corroborated_by"):
                    continue  # only follow a real name once it's well established
                prev = candidates.get(p.key())
                if prev is None or f.confidence > prev[2]:
                    candidates[p.key()] = (p, f"{f.target} → {f.title}", f.confidence)
        ranked = sorted(candidates.values(), key=lambda c: -c[2])
        # Trust propagates down the pivot chain. Guess-type leads (aliases, alt candidates, name-generated handles,
        # guessed emails) start low. Low-trust entities are searched, but they don't feed the subject's profile or
        # spawn further leads until something independently ties them to the subject.
        trust = report.meta.setdefault("trust", {})
        spec = report.meta.setdefault("speculative", [])
        for e, via, conf in ranked[: self.options.max_entities_per_level]:
            parent = via.split(" → ")[0]
            t = conf * trust.get(parent, 1.0)
            if any(k in via for k in GUESS_SOURCES):
                t = min(t, 0.6)
            trust[str(e)] = round(t, 3)
            if t < 0.8 and str(e) not in spec:
                spec.append(str(e))
        if len(ranked) > self.options.max_entities_per_level:
            self.events.on_log("warning", f"{len(ranked)} pivots found; following the top "
                                          f"{self.options.max_entities_per_level} by confidence")
        return [(e, via) for e, via, _ in ranked[: self.options.max_entities_per_level]]

    async def _search_entity(self, entity: Entity, ctx: Context, report: Report) -> None:
        run, skipped = self.plan(entity)
        for s, why in skipped:
            self.events.on_log("debug", f"{s.name}: skipped ({why})")
        for stage in STAGES:
            await asyncio.gather(*(self._run_source(s, entity, ctx, report) for s in run if s.stage == stage))
            if stage == "enrich":
                self._crosscheck(report)  # late-stage sources (aliases, alts, emails) see corroborated accounts

    async def _run_source(self, source: Source, entity: Entity, ctx: Context, report: Report) -> None:
        """Run one source with a watchdog: stopped if it goes quiet for idle_timeout or exceeds source_timeout."""
        self._used[source.name] = source
        self.events.on_source_start(source.name, entity)
        key = (source.name, str(entity))
        count, error = 0, None
        start = time.monotonic()
        ctx.activity[key] = start

        async def consume():
            nonlocal count
            async for finding in source.search(entity, ctx):
                ctx.activity[key] = time.monotonic()
                count += self._add(report, finding)

        token = current_run.set(key)
        task = asyncio.ensure_future(consume())  # inherits current_run, so its requests count as activity
        current_run.reset(token)
        stopped_by_watchdog = False
        try:
            while not task.done():
                await asyncio.wait({task}, timeout=5)
                if task.done():
                    break
                now = time.monotonic()
                idle = now - ctx.activity.get(key, start)
                if idle > self.options.idle_timeout or now - start > self.options.source_timeout:
                    stopped_by_watchdog = True
                    error = (f"stopped: no activity for {idle:.0f}s" if idle > self.options.idle_timeout
                             else f"stopped: exceeded {self.options.source_timeout:.0f}s")
                    self.events.on_log("warning", f"{source.name} on {entity} {error} - keeping its {count} results")
                    task.cancel()
                    break
            try:
                await task
            except asyncio.CancelledError:
                if not stopped_by_watchdog:
                    raise
        except asyncio.CancelledError:
            task.cancel()
            error = error or "cancelled"
            raise
        except Exception as exc:  # one broken source must never sink the whole search
            error = f"{exc.__class__.__name__}: {exc}"
            report.errors.append(f"{source.name} ({entity}): {error}")
            self.events.on_log("error", f"{source.name} failed for {entity}: {error}")
        finally:
            ctx.activity.pop(key, None)
            self.events.on_source_done(source.name, entity, count, error)


def investigation_options(depth: int = 2, scope: str = "full", nsfw: bool = False, passive: bool = False,
                          has_name: bool = False) -> SearchOptions:
    """Full-investigation preset: every capability on, deep pivots, full site catalog, bigger crawl."""
    options = SearchOptions(depth=depth, scope=scope, nsfw=nsfw, active_dns=not passive, name_permutations=has_name,
                            max_entities_per_level=40, crawl_pages=60)
    options.pivot_kinds |= {"name", "location", "company"}
    return options


def search(targets: list[Entity], options: SearchOptions | None = None, events: Events | None = None,
           config: Config | None = None) -> Report:
    """Synchronous convenience wrapper."""
    return asyncio.run(Engine(config, options, events).run(targets))
