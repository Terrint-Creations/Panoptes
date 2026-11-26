"""Terminal interface."""
from __future__ import annotations

import asyncio
import datetime as dt
import re
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from panoptes import __version__
from panoptes.config import CONFIG_FILE, KNOWN_KEYS, Config
from panoptes.detect import parse_target
from panoptes.engine import Engine, Events, investigation_options, make_client
from panoptes.models import KINDS, Entity, Finding, Report
from panoptes.report import category_rank, export
from panoptes.sources import SOURCES, SearchOptions
from panoptes.sources import sitedb

app = typer.Typer(add_completion=False, no_args_is_help=True, rich_markup_mode="rich",
                  help="[bold yellow]◉ PANOPTES[/] - the all-seeing OSINT super tool.\n\n"
                       "One search fans out to every relevant source, merges duplicate results, "
                       "and follows what it finds.")
config_app = typer.Typer(help="View or change API keys and settings.", no_args_is_help=True)
app.add_typer(config_app, name="config")
console = Console(highlight=False)

BANNER = r"""[bold yellow]
   ___  ___   _  ______  ____  ______________
  / _ \/ _ | / |/ / __ \/ _ \/_  __/ __/ __/
 / ___/ __ |/    / /_/ / ___/ / / / _/_\ \
/_/  /_/ |_/_/|_/\____/_/    /_/ /___/___/  [/][dim]v{v} · the all-seeing OSINT tool[/]
"""
CATEGORY_STYLE = {"account": "green", "profile": "cyan", "email": "magenta", "breach": "red", "exposure": "red",
                  "registration": "blue", "dns": "blue", "geolocation": "yellow", "network": "yellow",
                  "subdomain": "dim", "lead": "dim", "web": "cyan", "phone": "cyan", "key": "magenta",
                  "threat": "red", "lookalike": "yellow", "person": "cyan", "location": "yellow", "wallet": "magenta",
                  "url": "dim", "metadata": "dim", "tls": "blue", "summary": "bold yellow", "insight": "bold red"}
QUIET_STREAM = {"subdomain", "lead", "url", "metadata", "summary", "insight", "lookalike"}
SEV_STYLE = {"high": "bold red", "medium": "yellow", "low": "cyan", "info": "dim"}  # too many to stream; summarised at the end


class CLIEvents(Events):
    def __init__(self, progress: Progress, verbose: bool, quiet: bool):
        self.progress = progress
        self.verbose = verbose
        self.quiet = quiet
        self.tasks: dict[tuple, int] = {}

    def _task(self, source: str, entity: Entity):
        key = (source, entity.key())
        if key not in self.tasks:
            self.tasks[key] = self.progress.add_task(f"{source} [dim]{entity.value}[/]", total=None)
        return self.tasks[key]

    def on_entity(self, entity, depth, via):
        if depth:
            self.progress.console.print(f"[bold yellow]↳ pivot[/] {entity.kind} [bold]{entity.value}[/] "
                                        f"[dim](from {via})[/]")
        else:
            self.progress.console.print(f"[bold yellow]◉ target[/] {entity.kind} [bold]{entity.value}[/]")

    def on_source_start(self, source, entity):
        self._task(source, entity)

    def on_progress(self, source, entity, done, total):
        self.progress.update(self._task(source, entity), completed=done, total=total)

    def on_source_done(self, source, entity, count, error):
        tid = self._task(source, entity)
        self.progress.remove_task(tid)
        if self.verbose:
            self.progress.console.print(f"  [dim]✓ {source} on {entity.value}: {count} findings"
                                        f"{' - ' + error if error else ''}[/]")

    def on_finding(self, f: Finding, is_new):
        if not is_new or self.quiet or f.category in QUIET_STREAM:
            return
        style = CATEGORY_STYLE.get(f.category, "white")
        line = Text("  [+] ", style=style)
        line.append(f"{f.category:<12}", style=style)
        line.append(f"{f.title[:32]:<33}", style="bold")
        line.append(f.value[:110])
        if f.category == "account" and len(f.sources) > 1:
            line.append(f"  ({', '.join(sorted(f.sources))})", style="dim")
        self.progress.console.print(line)

    def on_log(self, level, message):
        if level == "debug" and not self.verbose:
            return
        style = {"error": "red", "warning": "yellow", "debug": "dim"}.get(level, "dim cyan")
        self.progress.console.print(f"  [{style}]» {message}[/]")


def print_overview(report: Report) -> None:
    summary = sorted((f for f in report.findings.values() if f.category == "summary"), key=lambda f: (f.title, -f.confidence))
    insights = sorted((f for f in report.findings.values() if f.category == "insight"),
                      key=lambda f: ["high", "medium", "low", "info"].index(f.data.get("severity", "info")))
    if summary:
        t = Table(title="[bold yellow]Identity summary[/]", title_justify="left", border_style="yellow", expand=True)
        t.add_column("Field", style="bold", no_wrap=True)
        t.add_column("Value", ratio=3, overflow="fold")
        t.add_column("Corroborated by", style="dim", ratio=1)
        for f in summary:
            t.add_row(f.title, f.value, ", ".join(sorted(f.sources)) if f.sources != {"correlation"} else "")
        console.print(t)
    if insights:
        t = Table(title="[bold red]Insights[/]", title_justify="left", border_style="red", expand=True)
        t.add_column("Severity", no_wrap=True)
        t.add_column("Insight", style="bold", no_wrap=True)
        t.add_column("Detail", ratio=3, overflow="fold")
        t.add_column("About", style="dim")
        for f in insights:
            sev = f.data.get("severity", "info")
            t.add_row(Text(sev.upper(), style=SEV_STYLE[sev]), f.title, f.value, str(f.target))
        console.print(t)


def print_summary(report: Report, show_all: bool) -> None:
    print_overview(report)
    for target, cats in report.by_entity().items():
        cats = {k: v for k, v in cats.items() if k not in ("summary", "insight")}
        if not cats:
            continue
        table = Table(title=f"[bold]{target}[/]", title_justify="left", expand=True, show_lines=False,
                      border_style="grey37", header_style="bold yellow")
        table.add_column("Category", style="dim", no_wrap=True)
        table.add_column("Title", no_wrap=True, max_width=34)
        table.add_column("Value", overflow="fold", ratio=3)
        table.add_column("Sources", style="dim", ratio=1)
        table.add_column("Conf", justify="right", no_wrap=True)
        for cat in sorted(cats, key=category_rank):
            items = cats[cat]
            limit = len(items) if show_all or cat not in QUIET_STREAM else 40
            for f in items[:limit]:
                conf = int(f.confidence * 100)
                cstyle = "green" if conf >= 80 else "yellow" if conf >= 60 else "red"
                table.add_row(Text(cat, style=CATEGORY_STYLE.get(cat, "")), f.title, f.value,
                              ", ".join(sorted(f.sources)), Text(f"{conf}%", style=cstyle))
            if len(items) > limit:
                table.add_row("", f"[dim]… {len(items) - limit} more[/]", "[dim]use --all or export a report[/]", "", "")
        console.print(table)
    elapsed = (report.finished or report.started) - report.started
    counts = {}
    for f in report.findings.values():
        counts[f.category] = counts.get(f.category, 0) + 1
    breakdown = " · ".join(f"{n} {c}" for c, n in sorted(counts.items(), key=lambda kv: category_rank(kv[0])))
    console.print(Panel(f"[bold]{len(report.findings)}[/] findings across [bold]{len(report.entities)}[/] "
                        f"entities in {elapsed:.1f}s\n[dim]{breakdown}[/]", border_style="yellow", expand=False))


def _split(value: Optional[str]) -> Optional[set[str]]:
    return {v.strip() for v in value.split(",") if v.strip()} if value else None


@app.command()
def search(
    targets: List[str] = typer.Argument(..., help="Username, email, phone, domain, IP, URL or \"Full Name\". Several allowed."),
    type: str = typer.Option("auto", "--type", "-t", help=f"Force target type: auto, all, {', '.join(KINDS)}"),
    depth: int = typer.Option(1, "--depth", "-d", min=0, max=4, help="Pivot hops to follow (0 = target only)"),
    scope: str = typer.Option("standard", "--scope", "-s", help="Username site scope: quick | standard | full"),
    nsfw: bool = typer.Option(False, "--nsfw", help="Include adult sites in username search"),
    no_verify: bool = typer.Option(False, "--no-verify", help="Skip false-positive re-check of account hits (faster)"),
    disputed: bool = typer.Option(False, "--disputed", help="Also report account hits where databases disagree 50/50"),
    only: Optional[str] = typer.Option(None, "--only", help="Comma-separated sources to run exclusively"),
    skip: Optional[str] = typer.Option(None, "--skip", help="Comma-separated sources to skip"),
    pivot: Optional[str] = typer.Option(None, "--pivot", help="Entity kinds to pivot into (default: username,email,domain,ip,phone)"),
    output: List[Path] = typer.Option([], "--output", "-o", help="Write report (.html, .json, .csv, .stix.json). Repeatable."),
    passive: bool = typer.Option(False, "--passive", help="No active DNS (brute force, zone transfer, lookalike resolution)"),
    perms: bool = typer.Option(False, "--name-perms", help="Turn full names into candidate usernames and search them"),
    no_save: bool = typer.Option(False, "--no-save", help="Don't save this search as a case"),
    case: Optional[str] = typer.Option(None, "--case", help="Case name to save under"),
    no_coop: bool = typer.Option(False, "--no-coop", help="Don't let sources cross-verify each other with shared facts"),
    no_faces: bool = typer.Option(False, "--no-faces", help="Skip local face detection/matching"),
    no_reverse: bool = typer.Option(False, "--no-reverse-image", help="Skip automated reverse image search (it uploads local photos to Yandex)"),
    no_alts: bool = typer.Option(False, "--no-alts", help="Skip the alternate-account finder"),
    no_discovery: bool = typer.Option(False, "--no-discovery", help="Don't learn/check new sites from profile links"),
    no_darkweb: bool = typer.Option(False, "--no-darkweb", help="Skip dark-web index lookups"),
    no_websearch: bool = typer.Option(False, "--no-websearch", help="Skip search engines, news and public records"),
    profile: str = typer.Option("balanced", "--profile", "-P", help="Resources: light (run in background, slower) | balanced | heavy - same results, different speed"),
    timeout: float = typer.Option(15.0, "--timeout", help="Per-request timeout in seconds"),
    concurrency: int = typer.Option(50, "--concurrency", "-c", min=1, max=500, help="Parallel HTTP requests"),
    show_all: bool = typer.Option(False, "--all", "-a", help="Show every finding in the summary"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Don't stream findings; just print the summary"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show per-source status and debug messages"),
):
    """Investigate one or more targets across every relevant source."""
    if scope not in ("quick", "standard", "full"):
        raise typer.BadParameter("scope must be quick, standard or full")
    try:
        from panoptes.detect import parse_all
        entities = [e for t in targets for e in (parse_all(t) if type == "all" else [parse_target(t, type)])]
    except ValueError as exc:
        raise typer.BadParameter(str(exc))
    options = SearchOptions(depth=depth, scope=scope, nsfw=nsfw, verify=not no_verify, include_disputed=disputed, timeout=timeout,
                            concurrency=concurrency, include=_split(only), exclude=_split(skip) or set(),
                            active_dns=not passive, name_permutations=perms, cooperative=not no_coop, faces=not no_faces,
                            reverse_image=not no_reverse, alt_accounts=not no_alts, discover_sites=not no_discovery,
                            darkweb=not no_darkweb, websearch=not no_websearch)
    from panoptes.sources.base import apply_profile
    apply_profile(options, profile)
    if pivot:
        options.pivot_kinds = _split(pivot)
    run_search(entities, options, output, show_all, quiet, verbose, save=not no_save, meta={"case": case} if case else {})


def run_search(entities, options, output, show_all, quiet, verbose, save=True, meta=None):
    console.print(BANNER.format(v=__version__))

    progress = Progress(SpinnerColumn(style="yellow"), TextColumn("{task.description}"), BarColumn(bar_width=30),
                        MofNCompleteColumn(), TimeElapsedColumn(), console=console, transient=True)
    engine = Engine(Config.load(), options, CLIEvents(progress, verbose, quiet))
    interrupted = False
    with progress:
        try:
            asyncio.run(engine.run(entities))
        except KeyboardInterrupt:
            interrupted = True
    report = engine.report
    if report is None:
        raise typer.Exit(1)
    report.meta.update(meta or {})
    if interrupted:
        console.print("[yellow]Interrupted - showing partial results.[/]")
        report.finished = report.finished or dt.datetime.now().timestamp()
    console.print()
    print_summary(report, show_all)
    for path in output:
        try:
            console.print(f"[green]Report written:[/] {export(report, path).resolve()}")
        except ValueError as exc:
            console.print(f"[red]{exc}[/]")
    if save and report.findings:
        from panoptes.storage import save_case
        cid = save_case(report)
        console.print(f"[dim]Saved as case #{cid} - `panoptes cases show {cid}` / `panoptes cases export {cid} out.html`[/]")
    return report


@app.command()
def investigate(
    name: Optional[str] = typer.Option(None, "--name", help="Full name of the person / organisation"),
    username: List[str] = typer.Option([], "--username", "-u", help="Known username (repeatable)"),
    email: List[str] = typer.Option([], "--email", "-e", help="Known email (repeatable)"),
    phone: List[str] = typer.Option([], "--phone", "-p", help="Known phone number (repeatable)"),
    domain: List[str] = typer.Option([], "--domain", help="Website / domain (repeatable)"),
    ip: List[str] = typer.Option([], "--ip", help="IP address (repeatable)"),
    wallet: List[str] = typer.Option([], "--wallet", help="Crypto wallet address (repeatable)"),
    file: List[str] = typer.Option([], "--file", "-f", help="Image/document path or URL (repeatable)"),
    company: List[str] = typer.Option([], "--company", help="Company / organisation (repeatable)"),
    location: List[str] = typer.Option([], "--location", help="Place name or 'lat, lon' (repeatable)"),
    onion: List[str] = typer.Option([], "--onion", help=".onion address (needs tor_proxy)"),
    case: Optional[str] = typer.Option(None, "--case", help="Case name"),
    notes: str = typer.Option("", "--notes", help="Case notes / context"),
    depth: int = typer.Option(2, "--depth", "-d", min=0, max=4, help="Pivot hops (default 2 for investigations)"),
    scope: str = typer.Option("full", "--scope", "-s", help="Username site scope (default full)"),
    nsfw: bool = typer.Option(False, "--nsfw"),
    passive: bool = typer.Option(False, "--passive", help="No active DNS techniques"),
    output: List[Path] = typer.Option([], "--output", "-o", help="Report files (.html .json .csv .stix.json)"),
    show_all: bool = typer.Option(False, "--all", "-a"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Full investigation: everything you know about a subject, every capability, deep pivoting.

    Run with no options for an interactive form."""
    from rich.prompt import Prompt

    fields = {"name": [name] if name else [], "username": username, "email": email, "phone": phone,
              "domain": domain, "ip": ip, "crypto": wallet, "file": file, "company": company, "location": location,
              "onion": onion}
    if not any(fields.values()):
        console.print(Panel("[bold yellow]◉ Full investigation[/]\nFill in whatever you know - leave blank to skip. "
                            "Separate multiple values with commas.", border_style="yellow"))
        case = Prompt.ask("Case name", default="Investigation") if case is None else case
        for key, label in (("name", "Full name"), ("username", "Usernames"), ("email", "Emails"), ("phone", "Phone numbers"),
                           ("domain", "Websites / domains"), ("ip", "IP addresses"), ("crypto", "Crypto wallets"),
                           ("file", "Images / documents (path or URL)"), ("company", "Companies / organisations"),
                           ("location", "Places or coordinates"), ("onion", ".onion addresses")):
            raw = Prompt.ask(label, default="")
            if key == "name":
                fields[key] = [raw.strip()] if raw.strip() else []
            else:
                fields[key] = [v.strip() for v in raw.split(",") if v.strip()]
        notes = notes or Prompt.ask("Notes / context", default="")
    entities = [parse_target(v, kind) for kind, values in fields.items() for v in values]
    if not entities:
        console.print("[red]Nothing to investigate.[/]")
        raise typer.Exit(1)
    options = investigation_options(depth, scope, nsfw, passive, bool(fields["name"]))
    if not output:
        slug = re.sub(r"[^A-Za-z0-9_-]+", "_", case or entities[0].value)[:60]
        output = [Path("reports") / f"{slug}_{dt.datetime.now():%Y%m%d_%H%M}.html"]
    run_search(entities, options, output, show_all, quiet, verbose, save=True,
               meta={"case": case or "Investigation", "notes": notes, "form": {k: v for k, v in fields.items() if v}})


cases_app = typer.Typer(help="Saved investigations (every search is saved automatically).", no_args_is_help=True)
app.add_typer(cases_app, name="cases")


@cases_app.command("list")
def cases_list(limit: int = typer.Option(30, "--limit", "-n")):
    """List saved cases."""
    from panoptes.storage import list_cases
    t = Table(border_style="grey37", header_style="bold yellow")
    for col in ("ID", "Case", "Targets", "Findings", "Date"):
        t.add_column(col, overflow="fold")
    for c in list_cases(limit):
        t.add_row(str(c["id"]), c["name"], ", ".join(c["targets"])[:80], str(c["findings"]),
                  dt.datetime.fromtimestamp(c["created"]).strftime("%Y-%m-%d %H:%M"))
    console.print(t)


@cases_app.command("show")
def cases_show(case_id: int, show_all: bool = typer.Option(False, "--all", "-a")):
    """Print a saved case."""
    from panoptes.storage import load_case
    report = load_case(case_id)
    if not report:
        console.print(f"[red]No case #{case_id}[/]")
        raise typer.Exit(1)
    print_summary(report, show_all)


@cases_app.command("export")
def cases_export(case_id: int, path: Path):
    """Export a saved case (.html .json .csv .stix.json)."""
    from panoptes.storage import load_case
    report = load_case(case_id)
    if not report:
        console.print(f"[red]No case #{case_id}[/]")
        raise typer.Exit(1)
    console.print(f"[green]Written:[/] {export(report, path).resolve()}")


@cases_app.command("delete")
def cases_delete(case_id: int):
    """Delete a saved case."""
    from panoptes.storage import delete_case
    console.print("[green]Deleted[/]" if delete_case(case_id) else f"[red]No case #{case_id}[/]")


@app.command("sources")
def list_sources():
    """List every data source, what it searches, and whether it's ready."""
    cfg = Config.load()
    table = Table(border_style="grey37", header_style="bold yellow")
    for col in ("Source", "Targets", "Status", "Description"):
        table.add_column(col, overflow="fold")
    for s in SOURCES:
        ok, why = s.available(cfg)
        table.add_row(s.name, ", ".join(s.kinds), "[green]ready[/]" if ok else f"[yellow]{why}[/]", s.description)
    console.print(table)


@app.command()
def update(force: bool = typer.Option(True, help="Re-download even if the cache is fresh")):
    """Download the latest Sherlock / WhatsMyName / Maigret site databases and rebuild the catalog."""
    async def go():
        async with make_client(Config.load(), SearchOptions()) as client:
            return await sitedb.update_databases(client, force=force, log=lambda m: console.print(f"  {m}"))
    with console.status("Updating site databases…"):
        counts = asyncio.run(go())
    table = Table(title="Raw databases", border_style="grey37", header_style="bold yellow")
    table.add_column("Database"); table.add_column("Sites", justify="right"); table.add_column("Age")
    for db, n in counts.items():
        age = sitedb.cache_age(db)
        table.add_row(db, str(n), f"{age / 3600:.1f}h" if age is not None else "missing")
    console.print(table)
    with console.status("Merging catalog…"):
        stats = sitedb.catalog_stats()
    table = Table(title="Merged Panoptes catalog", border_style="grey37", header_style="bold yellow")
    for col in ("Scope", "Unique sites", "In 2+ databases", "Detection rules"):
        table.add_column(col, justify="right")
    for scope, s in stats.items():
        table.add_row(scope, str(s["sites"]), str(s["multi_source"]), str(s["rules"]))
    console.print(table)


login_app = typer.Typer(help="Site logins (browser sessions) for sites that block anonymous lookups.", no_args_is_help=True)
app.add_typer(login_app, name="login")


@login_app.command("add")
def login_add(site: str = typer.Argument(..., help="e.g. facebook.com"),
              cookie: str = typer.Argument(..., help="the Cookie header copied from your browser's DevTools")):
    """Save a session: log in with a burner account, copy the Cookie request header from DevTools > Network."""
    from panoptes import sessions
    data = dict(sessions.load())
    data[site] = cookie
    sessions.save(data)
    console.print(f"[green]Saved session for[/] {site} - checks on that site now run logged in")


@login_app.command("list")
def login_list():
    """Show sites with saved sessions."""
    from panoptes import sessions
    for site, cookie in sorted(sessions.load().items()):
        console.print(f"  {site}  [dim]({len(cookie)} characters)[/]")


@login_app.command("remove")
def login_remove(site: str):
    """Forget a site's session."""
    from panoptes import sessions
    data = dict(sessions.load())
    data.pop(site.lower().removeprefix("www."), None)
    sessions.save(data)
    console.print(f"[green]Removed[/] {site}")


@config_app.command("show")
def config_show():
    """Show configured keys (values masked)."""
    cfg = Config.load()
    from panoptes.config import KEY_GROUPS, SECRET_KEYS
    for group, keys in KEY_GROUPS.items():
        table = Table(title=f"{group}  [dim]({CONFIG_FILE})[/]", title_justify="left", border_style="grey37",
                      header_style="bold yellow", expand=True)
        table.add_column("Key", no_wrap=True); table.add_column("Value", no_wrap=True)
        table.add_column("Purpose / how to get it", style="dim", ratio=1)
        for key, (desc, how) in keys.items():
            v = cfg.get(key)
            shown = "[dim]not set[/]" if not v else (v[:4] + "…" + v[-2:] if key in SECRET_KEYS else v)
            table.add_row(key, shown, f"{desc}\n[italic]{how}[/]")
        console.print(table)


@config_app.command("set")
def config_set(key: str, value: str):
    """Set a config value, e.g. `panoptes config set hibp_api_key XXXX`."""
    if key not in KNOWN_KEYS:
        console.print(f"[yellow]Note:[/] '{key}' isn't a known key ({', '.join(KNOWN_KEYS)})")
    cfg = Config.load()
    cfg.set(key, value)
    cfg.save()
    console.print(f"[green]Saved[/] {key}")


@config_app.command("unset")
def config_unset(key: str):
    """Remove a config value."""
    cfg = Config.load()
    cfg.set(key, None)
    cfg.save()
    console.print(f"[green]Removed[/] {key}")


@app.command()
def gui(targets: List[str] = typer.Argument(None, help="Optional targets to search immediately")):
    """Launch the desktop app."""
    try:
        from panoptes.gui.app import main as gui_main
    except ImportError as exc:
        console.print(f"[red]GUI unavailable ({exc}).[/] Install it with: pip install \"panoptes[gui]\"")
        raise typer.Exit(1)
    gui_main(targets or [])


@app.command()
def version():
    """Print the version."""
    console.print(f"panoptes {__version__}")


def main():
    import sys
    for stream in (sys.stdout, sys.stderr):  # legacy Windows consoles default to cp1252 and choke on ◉ / →
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    app()


if __name__ == "__main__":
    main()
