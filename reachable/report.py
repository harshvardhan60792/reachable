"""Phase 5 — write findings.json, report.md and a self-contained report.html.

The HTML has no external assets, no script tags fetching anything, and no server. It opens
from the filesystem. That is a hard requirement, not a convenience: the tool must run in an
air-gapped CI job and produce an artifact anyone can open.
"""

from __future__ import annotations

import html
import json
import os
import re
from typing import Dict, List

from .models import CallGraph, EXACT, REACHABLE, UNKNOWN, UNREACHABLE, Verdict

ORDER = (REACHABLE, UNKNOWN, UNREACHABLE)

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "ERROR": 1, "MEDIUM": 2, "WARNING": 2, "LOW": 3, "INFO": 4}


def _sort_key(v: Verdict):
    return (
        ORDER.index(v.status) if v.status in ORDER else 9,
        SEVERITY_RANK.get(v.finding.severity.upper(), 5),
        v.finding.file,
        v.finding.line,
    )


def _counts(verdicts: List[Verdict]) -> Dict[str, int]:
    counts = {s: 0 for s in ORDER}
    for v in verdicts:
        counts[v.status] = counts.get(v.status, 0) + 1
    return counts


_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
MAX_FIELD = 500


def _clean(value, limit: int = MAX_FIELD) -> str:
    """Flatten untrusted text to a single line before it reaches a report.

    Every field here originates outside the tool: scanner messages, rule IDs, file paths, and
    -- for the built-in credential rule -- an identifier lifted straight out of the scanned
    source. A message containing newlines could inject whole sections into report.md:

        message = "harmless\\n\\n## REACHABLE (999)\\n\\n### `fake.py:1`\\n\\ncritical"

    The GitHub Action posts report.md as a pull request comment, so anyone who can put a
    string in a PR could forge the security report that reviews that same PR -- fabricating
    findings or burying real ones under a fake all-clear. Collapsing whitespace removes the
    line starts that markdown structure depends on.
    """
    text = _CONTROL.sub("", str(value or ""))
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text


def _fmt_path(path: List[str]) -> str:
    return " -> ".join(_clean(p, 200) for p in path) if path else ""


# ----------------------------------------------------------------------------- json

def write_json(verdicts: List[Verdict], graph: CallGraph, path: str) -> None:
    payload = {
        "summary": {
            "findings": len(verdicts),
            **{k.lower(): v for k, v in _counts(verdicts).items()},
            "functions": len(graph.functions),
            "edges": len(graph.edges),
            "entry_points": len(graph.entry_points()),
            "external_calls": graph.external,
            "unresolved_calls": graph.unresolved,
            "files_parsed": graph.files_parsed,
        },
        "verdicts": [v.to_dict() for v in verdicts],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


# ------------------------------------------------------------------------- markdown

def write_markdown(
    verdicts: List[Verdict], graph: CallGraph, path: str, include_unknown: bool = False
) -> None:
    counts = _counts(verdicts)
    lines: List[str] = []
    add = lines.append

    add("# Reachability report")
    add("")
    add(
        "**%d findings -> %d reachable.** %d unreachable, %d unknown."
        % (len(verdicts), counts[REACHABLE], counts[UNREACHABLE], counts[UNKNOWN])
    )
    add("")
    add(
        "Call graph: %d functions, %d edges, %d entry points across %d files. "
        "%d calls go to stdlib or third-party code (correctly outside the graph); "
        "%d could not be resolved statically."
        % (
            len(graph.functions),
            len(graph.edges),
            len(graph.entry_points()),
            graph.files_parsed,
            graph.external,
            graph.unresolved,
        )
    )
    add("")

    shown = [REACHABLE, UNREACHABLE] + ([UNKNOWN] if include_unknown else [])
    for status in ORDER:
        if status not in shown:
            continue
        group = [v for v in verdicts if v.status == status]
        if not group:
            continue
        add("## %s (%d)" % (status, len(group)))
        add("")
        for v in sorted(group, key=_sort_key):
            f = v.finding
            loc = "%s:%d" % (_clean(f.file, 200), f.line) if f.line else _clean(f.package or f.file, 200)
            add("### `%s`" % loc)
            add("")
            add("%s" % _clean(f.message or f.rule_id))
            add("")
            add("- tool: `%s`  severity: `%s`  rule: `%s`"
                % (_clean(f.tool, 40), _clean(f.severity, 40), _clean(f.rule_id, 200)))
            if v.path:
                add("- path: `%s`" % _fmt_path(v.path))
            if v.confidence != EXACT:
                add("- confidence: `%s` — resolved by name match, may be over-approximate" % _clean(v.confidence, 20))
            if v.reason:
                add("- %s" % _clean(v.reason))
            if f.fixed_version:
                add("- fixed in: `%s`" % _clean(f.fixed_version, 60))
            add("")

    if not include_unknown and counts[UNKNOWN]:
        add("---")
        add("")
        add("%d UNKNOWN findings hidden. Re-run with `--include-unknown` to see them." % counts[UNKNOWN])
        add("")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


# ----------------------------------------------------------------------------- html

CSS = """
:root{--bg:#fff;--fg:#16181d;--muted:#666e7a;--line:#e4e7ec;--card:#fafbfc;
--red:#c1332c;--amber:#8a6100;--green:#2f6b3f;--code:#f2f4f7}
@media(prefers-color-scheme:dark){:root{--bg:#0f1115;--fg:#e6e8ec;--muted:#9aa3ae;
--line:#242830;--card:#161920;--red:#ff7b72;--amber:#e3b341;--green:#7ee787;--code:#1c2028}}
*{box-sizing:border-box}
body{margin:0;padding:2.5rem 1.25rem;background:var(--bg);color:var(--fg);
font:15px/1.6 ui-sans-serif,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:60rem;margin:0 auto}
h1{font-size:1.6rem;margin:0 0 .35rem}
h2{font-size:1.05rem;margin:2.5rem 0 .9rem;letter-spacing:.02em;text-transform:uppercase;
color:var(--muted);font-weight:600}
.lede{font-size:1.15rem;margin:0 0 .4rem}
.lede b{font-variant-numeric:tabular-nums}
.sub{color:var(--muted);font-size:.87rem;margin:0 0 2rem}
.stats{display:flex;flex-wrap:wrap;gap:.5rem;margin:0 0 2rem}
.stat{background:var(--card);border:1px solid var(--line);border-radius:8px;
padding:.6rem .85rem;min-width:6.5rem}
.stat b{display:block;font-size:1.35rem;font-variant-numeric:tabular-nums}
.stat span{color:var(--muted);font-size:.72rem;text-transform:uppercase;letter-spacing:.05em}
.f{border:1px solid var(--line);border-left-width:3px;border-radius:8px;background:var(--card);
padding:.9rem 1rem;margin:0 0 .7rem}
.f.REACHABLE{border-left-color:var(--red)}
.f.UNREACHABLE{border-left-color:var(--green)}
.f.UNKNOWN{border-left-color:var(--amber)}
.loc{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.85rem;font-weight:600}
.msg{margin:.35rem 0 .6rem}
.meta{color:var(--muted);font-size:.79rem;display:flex;flex-wrap:wrap;gap:.75rem}
.path{margin-top:.6rem;padding:.5rem .65rem;background:var(--code);border-radius:6px;
font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.78rem;
overflow-x:auto;white-space:nowrap}
.note{color:var(--muted);font-size:.79rem;margin-top:.5rem;font-style:italic}
code{background:var(--code);padding:.1rem .3rem;border-radius:4px;font-size:.85em}
footer{margin-top:3rem;padding-top:1.25rem;border-top:1px solid var(--line);
color:var(--muted);font-size:.8rem}
"""


def _esc(s: str) -> str:
    return html.escape(str(s or ""))


def write_html(verdicts: List[Verdict], graph: CallGraph, path: str) -> None:
    counts = _counts(verdicts)
    parts: List[str] = []
    add = parts.append

    add("<!doctype html><html lang=en><head><meta charset=utf-8>")
    add("<meta name=viewport content='width=device-width,initial-scale=1'>")
    add("<title>Reachability report</title><style>%s</style></head><body><div class=wrap>" % CSS)

    add("<h1>Reachability report</h1>")
    add(
        "<p class=lede><b>%d</b> findings &rarr; <b>%d</b> reachable.</p>"
        % (len(verdicts), counts[REACHABLE])
    )
    add(
        "<p class=sub>%d functions, %d call edges, %d entry points across %d files. "
        "%d external calls, %d unresolved.</p>"
        % (
            len(graph.functions),
            len(graph.edges),
            len(graph.entry_points()),
            graph.files_parsed,
            graph.external,
            graph.unresolved,
        )
    )

    add("<div class=stats>")
    for label, value in (
        ("Reachable", counts[REACHABLE]),
        ("Unknown", counts[UNKNOWN]),
        ("Unreachable", counts[UNREACHABLE]),
        ("Entry points", len(graph.entry_points())),
    ):
        add("<div class=stat><b>%d</b><span>%s</span></div>" % (value, label))
    add("</div>")

    for status in ORDER:
        group = [v for v in verdicts if v.status == status]
        if not group:
            continue
        add("<h2>%s &middot; %d</h2>" % (status.lower(), len(group)))
        for v in sorted(group, key=_sort_key):
            f = v.finding
            loc = "%s:%d" % (_clean(f.file, 200), f.line) if f.line else _clean(f.package or f.file, 200)
            add("<div class='f %s'>" % status)
            add("<div class=loc>%s</div>" % _esc(loc))
            add("<div class=msg>%s</div>" % _esc(_clean(f.message or f.rule_id)))
            add(
                "<div class=meta><span>%s</span><span>%s</span><span>%s</span></div>"
                % (_esc(_clean(f.tool, 40)), _esc(_clean(f.severity, 40)), _esc(_clean(f.rule_id, 200)))
            )
            if v.path:
                add("<div class=path>%s</div>" % _esc(_fmt_path(v.path)))
            notes = []
            if v.confidence != EXACT:
                notes.append("confidence: %s — resolved by name match, may over-approximate"
                             % _clean(v.confidence, 20))
            if v.reason:
                notes.append(_clean(v.reason))
            if f.fixed_version:
                notes.append("fixed in %s" % _clean(f.fixed_version, 60))
            if notes:
                add("<div class=note>%s</div>" % _esc(" · ".join(notes)))
            add("</div>")

    add(
        "<footer>Static analysis over-approximates. UNKNOWN means the analysis could not see "
        "the path, not that the finding is safe. Verify before acting.</footer>"
    )
    add("</div></body></html>")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("".join(parts))


def write(
    verdicts: List[Verdict],
    graph: CallGraph,
    out_dir: str,
    include_unknown: bool = False,
) -> Dict[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    paths = {
        "json": os.path.join(out_dir, "findings.json"),
        "md": os.path.join(out_dir, "report.md"),
        "html": os.path.join(out_dir, "report.html"),
    }
    write_json(verdicts, graph, paths["json"])
    write_markdown(verdicts, graph, paths["md"], include_unknown)
    write_html(verdicts, graph, paths["html"])
    return paths
