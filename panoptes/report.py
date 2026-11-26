"""Export reports: HTML (with relationship graph), JSON, CSV and STIX 2.1 (OpenCTI / MISP import)."""
from __future__ import annotations

import csv
import datetime as dt
import html
import io
import json
import uuid
from pathlib import Path

from panoptes import __version__
from panoptes.models import Entity, Report

CATEGORY_ORDER = ["summary", "insight", "account", "alt-account", "profile", "person", "face-match", "image-link",
                  "address", "location", "geo", "sun", "weather", "email", "breach", "threat", "darkweb", "onion", "associate",
                  "activity", "relationship", "company", "key", "phone", "wallet", "file", "face", "metadata",
                  "software", "image", "image-match", "registration", "dns", "tls", "subdomain", "related-domain",
                  "lookalike", "web", "url", "network", "geolocation", "exposure", "archive", "lead"]
SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def category_rank(cat: str) -> int:
    return CATEGORY_ORDER.index(cat) if cat in CATEGORY_ORDER else len(CATEGORY_ORDER)


def to_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False, default=str)


def to_csv(report: Report) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["target", "category", "title", "value", "url", "confidence", "sources"])
    for f in report.to_dict()["findings"]:
        w.writerow([f["target"], f["category"], f["title"], f["value"], f["url"] or "", f["confidence"],
                    "; ".join(f["sources"])])
    return buf.getvalue()


# ----------------------------------------------------------------------------- graph

GRAPH_CATEGORIES = {"account": 30, "alt-account": 10, "email": 15, "breach": 15, "related-domain": 10, "lookalike": 10,
                    "person": 10, "location": 6, "wallet": 4, "relationship": 15, "associate": 8, "darkweb": 8,
                    "face-match": 6, "image-match": 6}


def graph_data(report: Report) -> dict:
    """Entities + their most important findings as a node/edge graph."""
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    for ent, depth, via in report.entities.values():
        nid = str(ent)
        label = Path(ent.value.split("?")[0]).name if ent.kind == "file" else ent.value
        nodes[nid] = {"id": nid, "label": label, "group": ent.kind, "entity": True, "depth": depth}
        if via:
            src = via.split(" → ")[0]
            edges.append({"from": src, "to": nid, "label": via.split(" → ", 1)[-1]})
    counts: dict[tuple, int] = {}
    for f in sorted(report.findings.values(), key=lambda f: -f.confidence):
        if f.category not in GRAPH_CATEGORIES:
            continue
        k = (str(f.target), f.category)
        if counts.get(k, 0) >= GRAPH_CATEGORIES[f.category]:
            continue
        counts[k] = counts.get(k, 0) + 1
        piv = next((p for p in f.pivots if str(p) in nodes), None)
        if piv:
            continue  # already an entity node; the pivot edge covers it
        label = f.title if f.category == "account" else f.value
        nid = f"{f.category}:{label}:{f.target}"
        nodes[nid] = {"id": nid, "label": label[:40], "group": f.category, "entity": False, "url": f.url}
        edges.append({"from": str(f.target), "to": nid, "label": ""})
    edges = [e for e in edges if e["from"] in nodes and e["to"] in nodes]
    return {"nodes": list(nodes.values()), "edges": edges}


GRAPH_JS = r"""
(function(){const d=JSON.parse(document.getElementById('gdata').textContent);const c=document.getElementById('graph');
if(!d.nodes.length){c.style.display='none';return}const x=c.getContext('2d');const dpr=window.devicePixelRatio||1;
function size(){c.width=c.clientWidth*dpr;c.height=c.clientHeight*dpr}size();
const col={username:'#3fb950',email:'#d2a8ff',domain:'#79c0ff',ip:'#e3b341',phone:'#58a6ff',name:'#ffa657',crypto:'#f778ba',
file:'#a5d6ff',account:'#2ea04366',breach:'#f85149',location:'#e3b341','related-domain':'#79c0ff99',lookalike:'#f0883e',person:'#ffa657',wallet:'#f778ba'};
const N=d.nodes.map((n,i)=>({...n,x:Math.cos(i)*200+Math.random()*50,y:Math.sin(i)*200+Math.random()*50,vx:0,vy:0}));
const idx=Object.fromEntries(N.map((n,i)=>[n.id,i]));const E=d.edges.map(e=>[idx[e.from],idx[e.to],e.label]).filter(e=>e[0]!=null&&e[1]!=null);
let scale=1,ox=0,oy=0,drag=null,pan=null;
for(let it=0;it<400;it++){for(let i=0;i<N.length;i++)for(let j=i+1;j<N.length;j++){let dx=N[i].x-N[j].x,dy=N[i].y-N[j].y,
dd=dx*dx+dy*dy+.01,f=2200/dd;N[i].vx+=dx*f/Math.sqrt(dd);N[i].vy+=dy*f/Math.sqrt(dd);N[j].vx-=dx*f/Math.sqrt(dd);N[j].vy-=dy*f/Math.sqrt(dd)}
for(const [a,b] of E){let dx=N[b].x-N[a].x,dy=N[b].y-N[a].y,dist=Math.sqrt(dx*dx+dy*dy)+.01,L=N[b].entity&&N[a].entity?160:70,f=(dist-L)*.02;
N[a].vx+=dx/dist*f;N[a].vy+=dy/dist*f;N[b].vx-=dx/dist*f;N[b].vy-=dy/dist*f}
for(const n of N){n.vx-=n.x*.002;n.vy-=n.y*.002;n.x+=Math.max(-20,Math.min(20,n.vx));n.y+=Math.max(-20,Math.min(20,n.vy));n.vx*=.6;n.vy*=.6}}
const dark=matchMedia('(prefers-color-scheme: dark)').matches;
function draw(){x.setTransform(dpr,0,0,dpr,0,0);x.clearRect(0,0,c.width,c.height);x.translate(c.clientWidth/2+ox,c.clientHeight/2+oy);x.scale(scale,scale);
x.strokeStyle=dark?'#30363d':'#d0d7de';x.lineWidth=1/scale;for(const [a,b] of E){x.beginPath();x.moveTo(N[a].x,N[a].y);x.lineTo(N[b].x,N[b].y);x.stroke()}
for(const n of N){const r=n.entity?11:5;x.beginPath();x.arc(n.x,n.y,r,0,7);x.fillStyle=col[n.group]||'#8b949e';x.fill();
if(n.entity){x.lineWidth=2/scale;x.strokeStyle='#d4a017';x.stroke()}
if(n.entity||scale>1.3){x.fillStyle=dark?'#e6edf3':'#1f2328';x.font=(n.entity?'600 12px':'10px')+' system-ui';x.fillText(n.label,n.x+r+3,n.y+4)}}}
draw();function pt(e){const r=c.getBoundingClientRect();return[(e.clientX-r.left-c.clientWidth/2-ox)/scale,(e.clientY-r.top-c.clientHeight/2-oy)/scale]}
c.onmousedown=e=>{const[px,py]=pt(e);drag=N.find(n=>(n.x-px)**2+(n.y-py)**2<150);if(!drag)pan=[e.clientX-ox,e.clientY-oy]};
c.onmousemove=e=>{if(drag){[drag.x,drag.y]=pt(e);draw()}else if(pan){ox=e.clientX-pan[0];oy=e.clientY-pan[1];draw()}};
onmouseup=()=>{drag=null;pan=null};c.onwheel=e=>{e.preventDefault();scale*=e.deltaY<0?1.1:.9;draw()};
c.ondblclick=e=>{const[px,py]=pt(e);const n=N.find(n=>(n.x-px)**2+(n.y-py)**2<150);if(n&&n.url)open(n.url)};
addEventListener('resize',()=>{size();draw()});})();
"""


def to_html(report: Report) -> str:
    e = html.escape
    started = dt.datetime.fromtimestamp(report.started).strftime("%Y-%m-%d %H:%M:%S")
    duration = f"{(report.finished or report.started) - report.started:.1f}s"
    by_entity = report.by_entity()

    # Summary & insights panel
    summary = [f for f in report.findings.values() if f.category == "summary"]
    insights = sorted((f for f in report.findings.values() if f.category == "insight"),
                      key=lambda f: SEV_ORDER.get(f.data.get("severity", "info"), 9))
    summary_rows = "".join(f"<tr><td>{e(f.title)}</td><td>{e(f.value)}</td><td class=src>{e(', '.join(sorted(f.sources)))}</td></tr>"
                           for f in sorted(summary, key=lambda f: (f.title, -f.confidence)))
    insight_rows = "".join(f'<li class="sev-{e(f.data.get("severity", "info"))}"><b>{e(f.title)}</b> - {e(f.value)} '
                           f'<small>{e(str(f.target))}</small></li>' for f in insights)

    sections = []
    for target, cats in by_entity.items():
        rows = []
        for cat in sorted(cats, key=category_rank):
            if cat in ("summary", "insight"):
                continue
            for f in cats[cat]:
                val = e(f.value)
                if f.url:
                    val = f'<a href="{e(f.url)}" target="_blank" rel="noopener noreferrer">{val}</a>'
                pct = int(f.confidence * 100)
                rows.append(
                    f'<tr data-cat="{e(cat)}"><td><span class="cat">{e(cat)}</span></td><td>{e(f.title)}</td><td class="val">{val}</td>'
                    f'<td class="src">{e(", ".join(sorted(f.sources)))}</td>'
                    f'<td><div class="bar"><span style="width:{pct}%"></span></div>{pct}%</td></tr>')
        total = sum(len(v) for k, v in cats.items() if k not in ("summary", "insight"))
        if rows:
            sections.append(f'<section><h2>{e(target)} <small>{total} findings</small></h2>'
                            f'<table><thead><tr><th>Category</th><th>Title</th><th>Value</th><th>Sources</th>'
                            f'<th>Confidence</th></tr></thead><tbody>{"".join(rows)}</tbody></table></section>')
    entities = "".join(f"<li><code>{e(str(ent))}</code> <small>depth {d}{' via ' + e(via) if via else ''}</small></li>"
                       for ent, d, via in report.entities.values())
    errors = "".join(f"<li>{e(x)}</li>" for x in report.errors)
    gjson = json.dumps(graph_data(report)).replace("</", "<\\/")
    case = report.meta.get("case")
    notes = report.meta.get("notes")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Panoptes report - {e(case or ', '.join(map(str, report.targets)))}</title>
<style>
:root{{color-scheme:light dark;--bg:#0d1117;--fg:#e6edf3;--mut:#8b949e;--line:#30363d;--acc:#d4a017;--card:#161b22}}
@media (prefers-color-scheme:light){{:root{{--bg:#f6f8fa;--fg:#1f2328;--mut:#59636e;--line:#d0d7de;--acc:#9a6700;--card:#fff}}}}
body{{margin:0;font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;background:var(--bg);color:var(--fg)}}
header{{padding:24px 32px;border-bottom:1px solid var(--line)}} h1{{margin:0;font-size:22px;letter-spacing:.08em}}
h1 span{{color:var(--acc)}} main{{padding:24px 32px;max-width:1500px}} .meta{{color:var(--mut)}}
section{{background:var(--card);border:1px solid var(--line);border-radius:8px;margin:0 0 24px;overflow:auto}}
h2{{font-size:16px;margin:0;padding:14px 16px;border-bottom:1px solid var(--line)}} h2 small{{color:var(--mut);font-weight:400}}
table{{width:100%;border-collapse:collapse}} th,td{{text-align:left;padding:6px 16px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{color:var(--mut);font-weight:500;font-size:12px;text-transform:uppercase}} td.val{{word-break:break-all;max-width:640px}}
td.src,.src{{color:var(--mut);font-size:12px}} a{{color:var(--acc)}} .cat{{font-size:12px;color:var(--mut)}}
.bar{{display:inline-block;width:50px;height:6px;background:var(--line);border-radius:3px;margin-right:6px;vertical-align:middle}}
.bar span{{display:block;height:100%;background:var(--acc);border-radius:3px}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:24px}} @media(max-width:1000px){{.grid{{grid-template-columns:1fr}}}}
ul.ins{{list-style:none;margin:0;padding:8px 16px}} ul.ins li{{padding:6px 0 6px 12px;border-left:3px solid var(--line);margin:4px 0}}
ul.ins small{{color:var(--mut)}} .sev-high{{border-color:#f85149!important}} .sev-medium{{border-color:#d29922!important}}
.sev-low{{border-color:#58a6ff!important}} #graph{{width:100%;height:520px;display:block;cursor:grab}}
.notes{{padding:12px 16px;white-space:pre-wrap}}
</style></head><body><header><h1><span>◉</span> PANOPTES{' · ' + e(case) if case else ''}</h1>
<div class="meta">Targets: {e(', '.join(map(str, report.targets)))} · {started} · {duration} · {len(report.findings)} findings · {len(report.entities)} entities · v{__version__}</div></header>
<main>
{f'<section><h2>Case notes</h2><div class="notes">{e(notes)}</div></section>' if notes else ''}
<div class="grid">
<section><h2>Identity summary</h2><table><tbody>{summary_rows or '<tr><td>No summary</td></tr>'}</tbody></table></section>
<section><h2>Insights <small>{len(insights)}</small></h2><ul class="ins">{insight_rows or '<li>No notable insights</li>'}</ul></section>
</div>
<section><h2>Relationship graph <small>drag nodes · scroll to zoom · double-click to open</small></h2><canvas id="graph"></canvas></section>
{''.join(sections) or '<p>No findings.</p>'}
<section><h2>Entities searched</h2><ul>{entities}</ul></section>
{f'<section><h2>Errors</h2><ul>{errors}</ul></section>' if errors else ''}</main>
<script type="application/json" id="gdata">{gjson}</script><script>{GRAPH_JS}</script></body></html>"""


# ----------------------------------------------------------------------------- STIX 2.1

def _sid(kind: str, value: str) -> str:
    return f"{kind}--{uuid.uuid5(uuid.NAMESPACE_URL, f'panoptes:{kind}:{value.lower()}')}"


def _sco(ent: Entity) -> dict | None:
    v = ent.value
    if ent.kind == "email":
        return {"type": "email-addr", "id": _sid("email-addr", v), "value": v}
    if ent.kind == "domain":
        return {"type": "domain-name", "id": _sid("domain-name", v), "value": v}
    if ent.kind == "ip":
        t = "ipv6-addr" if ":" in v else "ipv4-addr"
        return {"type": t, "id": _sid(t, v), "value": v}
    if ent.kind == "username":
        return {"type": "user-account", "id": _sid("user-account", v), "account_login": v}
    if ent.kind == "phone":
        return {"type": "phone-number", "id": _sid("phone-number", v), "value": v}            # OpenCTI custom SCO
    if ent.kind == "crypto":
        return {"type": "cryptocurrency-wallet", "id": _sid("cryptocurrency-wallet", v), "value": v}  # OpenCTI
    if ent.kind == "name":
        return {"type": "identity", "id": _sid("identity", v), "name": v, "identity_class": "individual"}
    return None


def to_stix(report: Report) -> str:
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    objs: dict[str, dict] = {}

    def add(o):
        if o is None:
            return None
        o.setdefault("spec_version", "2.1")
        if o["type"] == "identity":
            o.setdefault("created", now)
            o.setdefault("modified", now)
        objs[o["id"]] = o
        return o["id"]

    def rel(a, b, desc=""):
        if a and b and a != b:
            rid = _sid("relationship", f"{a}|{b}")
            objs[rid] = {"type": "relationship", "spec_version": "2.1", "id": rid, "created": now, "modified": now,
                         "relationship_type": "related-to", "source_ref": a, "target_ref": b, "description": desc}

    ent_ids = {}
    for ent, _, via in report.entities.values():
        ent_ids[str(ent)] = add(_sco(ent))
    for ent, _, via in report.entities.values():
        if via:
            rel(ent_ids.get(via.split(" → ")[0]), ent_ids.get(str(ent)), via)
    for f in report.findings.values():
        src = ent_ids.get(str(f.target))
        if f.category == "account" and f.url:
            uid = add({"type": "url", "id": _sid("url", f.url), "value": f.url})
            rel(src, uid, f"account on {f.title}")
        for p in f.pivots:
            pid = ent_ids.get(str(p)) or add(_sco(p))
            rel(src, pid, f"{f.category}: {f.title}")
        if f.category in ("insight", "summary"):
            nid = _sid("note", f"{f.target}|{f.title}|{f.value}")
            objs[nid] = {"type": "note", "spec_version": "2.1", "id": nid, "created": now, "modified": now,
                         "abstract": f.title, "content": f.value, "object_refs": [src] if src else list(ent_ids.values())[:1]}
    rid = _sid("report", f"{report.started}")
    objs[rid] = {"type": "report", "spec_version": "2.1", "id": rid, "created": now, "modified": now,
                 "name": report.meta.get("case") or f"Panoptes: {', '.join(t.value for t in report.targets)}",
                 "description": report.meta.get("notes") or "Generated by Panoptes OSINT", "published": now,
                 "report_types": ["threat-actor", "identity"] if any(t.kind != "domain" for t in report.targets) else ["infrastructure"],
                 "object_refs": [k for k in objs if not k.startswith("report--")] or [rid]}
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": list(objs.values())}
    return json.dumps(bundle, indent=2, ensure_ascii=False)


EXPORTERS = {".json": to_json, ".csv": to_csv, ".html": to_html, ".htm": to_html, ".stix": to_stix}


def export(report: Report, path: str | Path) -> Path:
    path = Path(path)
    name = path.name.lower()
    fn = to_stix if name.endswith((".stix.json", ".stix")) else EXPORTERS.get(path.suffix.lower())
    if fn is None:
        raise ValueError(f"Unsupported report format '{path.suffix}'. Use .html, .json, .csv or .stix.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(fn(report), encoding="utf-8")
    return path
