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
from typing import Dict, List, Sequence

from . import explain
from .models import CallGraph, EXACT, REACHABLE, ScanFailure, UNKNOWN, UNREACHABLE, Verdict

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


def _add_plain_english(add, v: Verdict) -> None:
    """The part someone can actually read, argue with, and repeat to another person."""
    e = explain.for_finding(v.finding.rule_id, v.finding.message)

    add("<details>")
    add("<summary><b>Explain this in plain English</b></summary>")
    add("")
    add("**What the code is doing:** %s" % e.what)
    add("")
    add("**Why that is a problem:** %s" % e.why)
    add("")

    if v.path:
        story = explain.path_in_words(v.path, v.reason)
        if story:
            add("**How something reaches it:** %s" % story)
            add("")

    add("**How to check this yourself:**")
    add("")
    for i, step in enumerate(e.check, 1):
        add("%d. %s" % (i, step))
    add("")

    if e.fix:
        add("**What a fix looks like:** %s" % e.fix)
        add("")

    add("**If someone asks you to explain it:** \"%s\"" % e.say)
    add("")
    add("</details>")
    add("")


def _fmt_path(path: List[str]) -> str:
    return " -> ".join(_clean(p, 200) for p in path) if path else ""


INCOMPLETE_HEADLINE = "This report is incomplete, not clean"

INCOMPLETE_BODY = (
    "The scanners listed above were installed and did not finish, so whatever they would have found "
    "is missing from the counts on this page. A low number here is not evidence of a healthy "
    "codebase until they run."
)


def _failure_lines(failures) -> List[tuple]:
    """Normalize and clean failures for display.

    The reason is a scanner's own error text, which can carry a path or a rule name lifted
    from the repository under scan -- the same untrusted-input boundary as a finding message,
    and it gets the same treatment.
    """
    return [(_clean(f.scanner, 60), _clean(f.reason, 300)) for f in failures or ()]


# ----------------------------------------------------------------------------- json

def write_json(
    verdicts: List[Verdict], graph: CallGraph, path: str, failures=()
) -> None:
    payload = {
        "summary": {
            # First key on purpose: anything consuming this in CI should be able to gate on
            # "was the scan even complete" before it reads a single count.
            "complete": not failures,
            "findings": len(verdicts),
            **{k.lower(): v for k, v in _counts(verdicts).items()},
            "functions": len(graph.functions),
            "edges": len(graph.edges),
            "entry_points": len(graph.entry_points()),
            "external_calls": graph.external,
            "unresolved_calls": graph.unresolved,
            "files_parsed": graph.files_parsed,
        },
        "scan_failures": [f.to_dict() for f in failures or ()],
        "verdicts": [v.to_dict() for v in verdicts],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


# ------------------------------------------------------------------------- markdown

def write_markdown(
    verdicts: List[Verdict],
    graph: CallGraph,
    path: str,
    include_unknown: bool = False,
    plain: bool = True,
    failures=(),
) -> None:
    counts = _counts(verdicts)
    lines: List[str] = []
    add = lines.append

    add("# Reachability report")
    add("")

    # Above the counts, because the counts are what it qualifies. A reader who stops after the
    # first paragraph must not walk away with a number that a dead scanner made look good.
    broken = _failure_lines(failures)
    if broken:
        add("> **%s.**" % INCOMPLETE_HEADLINE)
        add(">")
        for scanner, reason in broken:
            add("> - `%s` did not complete: %s" % (scanner, reason))
        add(">")
        add("> %s" % INCOMPLETE_BODY)
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

    if plain:
        add("---")
        add("")
        add("## How to read this")
        add("")
        add("Findings are grouped by whether anything can actually reach them.")
        add("")
        for status in ORDER:
            headline, detail = explain.for_verdict(status)
            add("- **%s** — %s %s" % (status, headline, detail))
        add("")
        add("Each finding below explains what the code does, why it matters, and **how to "
            "check it yourself**. Do the checking. This tool points at code; you decide. Its "
            "own audit found eight bugs in itself, so \"the scanner said so\" is not a good "
            "enough reason to open a pull request.")
        add("")

    shown = [REACHABLE, UNREACHABLE] + ([UNKNOWN] if include_unknown else [])
    for status in ORDER:
        if status not in shown:
            continue
        group = [v for v in verdicts if v.status == status]
        if not group:
            continue
        add("---")
        add("")
        headline, detail = explain.for_verdict(status)
        add("## %s (%d)" % (status, len(group)))
        add("")
        if plain:
            add("*%s %s*" % (headline, detail))
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

            if plain:
                _add_plain_english(add, v)

    if plain and verdicts:
        add("---")
        add("")
        add("## Words used above")
        add("")
        for term, meaning in sorted(explain.GLOSSARY.items()):
            add("**%s** — %s" % (term, meaning))
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
.verdicthelp{color:var(--muted);font-size:.85rem;margin:-.4rem 0 1rem;max-width:52rem}
details.plain{margin-top:.7rem;border-top:1px solid var(--line);padding-top:.6rem}
details.plain summary{cursor:pointer;font-size:.82rem;font-weight:600;color:var(--muted);
user-select:none}
details.plain summary:hover{color:var(--fg)}
details.plain p{font-size:.87rem;margin:.7rem 0}
details.plain ol{font-size:.87rem;margin:.4rem 0;padding-left:1.3rem}
details.plain li{margin:.25rem 0}
details.plain .say{background:var(--code);border-radius:6px;padding:.6rem .75rem;
font-style:italic}
code{background:var(--code);padding:.1rem .3rem;border-radius:4px;font-size:.85em}
footer{margin-top:3rem;padding-top:1.25rem;border-top:1px solid var(--line);
color:var(--muted);font-size:.8rem}
.incomplete{border:1px solid var(--red);border-left-width:3px;border-radius:8px;
background:var(--card);padding:.9rem 1rem;margin:0 0 1.5rem}
.incomplete ul{margin:.5rem 0;padding-left:1.2rem}
.incomplete li{margin:.25rem 0}
.incomplete p{margin:.5rem 0 0;color:var(--muted);font-size:.87rem}
"""


def _esc(s: str) -> str:
    return html.escape(str(s or ""))


def write_html(
    verdicts: List[Verdict], graph: CallGraph, path: str, plain: bool = True, failures=()
) -> None:
    counts = _counts(verdicts)
    parts: List[str] = []
    add = parts.append

    add("<!doctype html><html lang=en><head><meta charset=utf-8>")
    add("<meta name=viewport content='width=device-width,initial-scale=1'>")
    add("<title>Reachability report</title><style>%s</style></head><body><div class=wrap>" % CSS)

    add("<h1>Reachability report</h1>")

    lines = _failure_lines(failures)
    if lines:
        add("<div class=incomplete>")
        add("<b>%s.</b>" % _esc(INCOMPLETE_HEADLINE))
        add("<ul>")
        for scanner, reason in lines:
            add("<li><code>%s</code> did not complete: %s</li>" % (_esc(scanner), _esc(reason)))
        add("</ul>")
        add("<p>%s</p>" % _esc(INCOMPLETE_BODY))
        add("</div>")

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
        if plain:
            headline, detail = explain.for_verdict(status)
            add("<p class=verdicthelp><b>%s</b> %s</p>" % (_esc(headline), _esc(detail)))
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

            if plain:
                e = explain.for_finding(f.rule_id, f.message)
                add("<details class=plain>")
                add("<summary>Explain this in plain English</summary>")
                add("<p><b>What the code is doing:</b> %s</p>" % _esc(e.what))
                add("<p><b>Why that is a problem:</b> %s</p>" % _esc(e.why))
                if v.path:
                    story = explain.path_in_words(v.path, v.reason)
                    if story:
                        add("<p><b>How something reaches it:</b> %s</p>"
                            % _esc(story).replace("`", ""))
                add("<p><b>How to check this yourself:</b></p><ol>")
                for step in e.check:
                    add("<li>%s</li>" % _esc(step))
                add("</ol>")
                if e.fix:
                    add("<p><b>What a fix looks like:</b> %s</p>" % _esc(e.fix))
                add("<p class=say><b>If someone asks you to explain it:</b> &ldquo;%s&rdquo;</p>"
                    % _esc(e.say))
                add("</details>")

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
    plain: bool = True,
    failures: Sequence[ScanFailure] = (),
) -> Dict[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    paths = {
        "json": os.path.join(out_dir, "findings.json"),
        "md": os.path.join(out_dir, "report.md"),
        "html": os.path.join(out_dir, "report.html"),
    }
    write_json(verdicts, graph, paths["json"], failures)
    write_markdown(verdicts, graph, paths["md"], include_unknown, plain, failures)
    write_html(verdicts, graph, paths["html"], plain, failures)
    return paths
