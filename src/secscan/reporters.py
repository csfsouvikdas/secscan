"""Output formats: console, JSON, SARIF 2.1.0, HTML and Markdown."""
from __future__ import annotations

import html
import json
from typing import Sequence

from . import __version__
from .models import SEV_RANK, SEVERITIES, Rule, ScanResult
from .rules import RULES

INFO_URI = "https://github.com/YOUR_USERNAME/secscan"
COLORS = {"critical": "\033[1;97;41m", "high": "\033[1;91m", "medium": "\033[1;93m",
          "low": "\033[1;94m", "info": "\033[1;90m"}
RESET, DIM, BOLD = "\033[0m", "\033[2m", "\033[1m"
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SARIF_SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}


def _summary(result: ScanResult) -> str:
    c = result.counts()
    return ", ".join(f"{c[s]} {s}" for s in c if c[s]) or "no findings"


# ---------------------------------------------------------------- console
def console(result: ScanResult, color: bool = True) -> str:
    def paint(sev: str, text: str) -> str:
        return f"{COLORS[sev]} {text} {RESET}" if color else f"[{text}]"

    out = [f"{BOLD if color else ''}SecScan {__version__}{RESET if color else ''} - scanned "
           f"{result.files_scanned} file(s) in {result.duration:.2f}s", ""]
    for f in result.findings:
        out.append(f"{paint(f.severity, f.severity.upper())} {f.rule_id}  {f.title}  ({f.cwe})")
        out.append(f"    {f.file}:{f.line}:{f.column}")
        out.append(f"    {DIM if color else ''}> {f.snippet}{RESET if color else ''}")
        out.append(f"    fix: {f.fix}")
        out.append("")
    c = result.counts()
    out.append("-" * 60)
    out.append("Summary: " + _summary(result))
    if result.findings:
        bar = "  ".join(f"{s}:{c[s]}" for s in c)
        out.append(bar)
    for e in result.errors:
        out.append(f"warning: {e}")
    return "\n".join(out) + "\n"


# ------------------------------------------------------------------- json
def to_json(result: ScanResult) -> str:
    return json.dumps({
        "tool": "secscan", "version": __version__,
        "files_scanned": result.files_scanned,
        "duration_seconds": round(result.duration, 3),
        "summary": result.counts(),
        "findings": [f.to_dict() for f in result.findings],
        "errors": result.errors,
    }, indent=2)


# ------------------------------------------------------------------ sarif
def sarif(result: ScanResult, rules: Sequence[Rule] = RULES) -> str:
    used = {f.rule_id for f in result.findings}
    rule_objs = []
    for r in rules:
        if r.id not in used:
            continue
        rule_objs.append({
            "id": r.id, "name": r.title,
            "shortDescription": {"text": r.title},
            "fullDescription": {"text": r.description},
            "help": {"text": r.fix},
            "defaultConfiguration": {"level": SARIF_LEVEL[r.severity]},
            "properties": {"tags": ["security", r.cwe, r.category], "security-severity": SARIF_SCORE[r.severity]},
        })
    results = [{
        "ruleId": f.rule_id, "level": SARIF_LEVEL[f.severity],
        "message": {"text": f"{f.title}. {f.description} Fix: {f.fix}"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": f.file},
            "region": {"startLine": f.line, "startColumn": f.column},
        }}],
    } for f in result.findings]
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "SecScan", "version": __version__,
                                       "informationUri": INFO_URI, "rules": rule_objs}},
                  "results": results}],
    }
    return json.dumps(doc, indent=2)


# --------------------------------------------------------------- markdown
def markdown(result: ScanResult) -> str:
    c = result.counts()
    out = ["# SecScan report", "",
           f"Scanned **{result.files_scanned}** files in {result.duration:.2f}s - "
           f"**{len(result.findings)}** finding(s).", "",
           "| Critical | High | Medium | Low | Info |", "|:-:|:-:|:-:|:-:|:-:|",
           f"| {c['critical']} | {c['high']} | {c['medium']} | {c['low']} | {c['info']} |", ""]
    if result.findings:
        out += ["| Severity | Rule | Location | Issue | CWE |", "|---|---|---|---|---|"]
        for f in result.findings:
            out.append(f"| {f.severity.upper()} | `{f.rule_id}` | `{f.file}:{f.line}` | {f.title} | {f.cwe} |")
        out += ["", "## Details", ""]
        for f in result.findings:
            snippet = f.snippet.replace("`", "'")
            out += [f"### `{f.rule_id}` {f.title} - {f.severity.upper()}",
                    f"`{f.file}:{f.line}` - {f.cwe}", "", "```", snippet, "```",
                    f"**Why it matters:** {f.description}  ", f"**Fix:** {f.fix}", ""]
    return "\n".join(out) + "\n"


# ------------------------------------------------------------------- html
_CSS = """
:root{color-scheme:light dark;--bg:#f5f6fa;--card:#fff;--fg:#1b1f2a;--mut:#667;--bd:#0001;
--critical:#b91c1c;--high:#dc2626;--medium:#d97706;--low:#2563eb;--info:#6b7280}
@media(prefers-color-scheme:dark){:root{--bg:#0e1117;--card:#171b24;--fg:#e8eaf0;--mut:#9aa3b2;--bd:#fff2}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
main{max-width:980px;margin:0 auto;padding:32px 20px}h1{margin:0 0 4px}.sub{color:var(--mut);margin:0 0 24px}
.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:20px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:14px;text-align:center}
.card b{display:block;font-size:28px}.filters{margin:0 0 16px;display:flex;gap:8px;flex-wrap:wrap}
.filters button{border:1px solid var(--bd);background:var(--card);color:var(--fg);padding:6px 12px;border-radius:999px;cursor:pointer}
.filters button.on{outline:2px solid var(--low)}
.f{background:var(--card);border:1px solid var(--bd);border-left:6px solid var(--info);border-radius:10px;padding:14px 16px;margin-bottom:12px}
.f h3{margin:0 0 4px;font-size:16px}.badge{display:inline-block;padding:1px 8px;border-radius:6px;color:#fff;font-size:12px;font-weight:700;margin-right:8px}
.loc{color:var(--mut);font:13px ui-monospace,monospace}pre{background:#0002;padding:10px;border-radius:8px;overflow-x:auto;margin:8px 0}
.fix{color:var(--mut)}
""" + "".join(f".f.{s}{{border-left-color:var(--{s})}}.badge.{s}{{background:var(--{s})}}" for s in SEVERITIES)

_JS = """
const bs=document.querySelectorAll('.filters button');
bs.forEach(b=>b.onclick=()=>{bs.forEach(x=>x.classList.remove('on'));b.classList.add('on');
document.querySelectorAll('.f').forEach(f=>f.hidden=b.dataset.s!=='all'&&!f.classList.contains(b.dataset.s));});
"""


def to_html(result: ScanResult) -> str:
    e = html.escape
    c = result.counts()
    cards = "".join(f'<div class="card"><b style="color:var(--{s})">{c[s]}</b>{s.title()}</div>'
                    for s in ("critical", "high", "medium", "low", "info"))
    filters = '<button data-s="all" class="on">All</button>' + "".join(
        f'<button data-s="{s}">{s.title()}</button>' for s in ("critical", "high", "medium", "low", "info") if c[s])
    items = []
    for f in result.findings:
        items.append(
            f'<div class="f {e(f.severity)}"><h3><span class="badge {e(f.severity)}">{e(f.severity.upper())}</span>'
            f'{e(f.rule_id)} - {e(f.title)} <span class="loc">({e(f.cwe)})</span></h3>'
            f'<div class="loc">{e(f.file)}:{f.line}:{f.column}</div><pre>{e(f.snippet)}</pre>'
            f'<div>{e(f.description)}</div><div class="fix"><b>Fix:</b> {e(f.fix)}</div></div>')
    body = "".join(items) or "<p>No findings. 🎉</p>"
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1"><title>SecScan report</title>'
            f'<style>{_CSS}</style></head><body><main><h1>🛡️ SecScan report</h1>'
            f'<p class="sub">{result.files_scanned} files scanned in {result.duration:.2f}s - '
            f'{len(result.findings)} finding(s) - SecScan {__version__}</p>'
            f'<div class="cards">{cards}</div><div class="filters">{filters}</div>{body}</main>'
            f'<script>{_JS}</script></body></html>')


def render(fmt: str, result: ScanResult, color: bool = False) -> str:
    if fmt == "console":
        return console(result, color)
    return {"json": to_json, "sarif": sarif, "markdown": markdown, "html": to_html}[fmt](result)
