"""Command line entry point. Owns all user-facing output; the library modules stay silent."""

from __future__ import annotations

import argparse
import os
import sys
from typing import List

from . import callgraph, entrypoints, reachability, report, scanners
from .models import Finding, REACHABLE


def _make_logger(quiet: bool):
    def log(msg: str) -> None:
        if not quiet:
            print(msg, file=sys.stderr)
    return log


def _collect(args, log) -> List[Finding]:
    if args.findings:
        log("loading cached findings from %s" % args.findings)
        return scanners.load_raw(args.findings)
    if args.no_scan:
        log("--no-scan: skipping all scanners")
        return []
    return scanners.scan(args.repo, log, use_builtin=not args.no_builtin)


def run(args) -> int:
    log = _make_logger(args.quiet)
    repo = os.path.abspath(args.repo)

    if not os.path.isdir(repo):
        print("error: not a directory: %s" % repo, file=sys.stderr)
        return 2

    os.makedirs(args.out, exist_ok=True)

    findings = _collect(args, log)
    if findings and not args.findings:
        scanners.save_raw(findings, os.path.join(args.out, "findings.raw.json"))

    graph = callgraph.build(repo, log)
    if not graph.files_parsed:
        print("error: no Python files found under %s" % repo, file=sys.stderr)
        return 2

    entrypoints.detect(repo, graph, log)

    if not graph.entry_points():
        log(
            "warning: no entry points detected. Everything will come back UNREACHABLE, which "
            "is almost certainly wrong. Check that this repo is an application or library "
            "with a recognizable entry surface."
        )

    verdicts = reachability.analyze(findings, graph, log)
    paths = report.write(verdicts, graph, args.out, args.include_unknown)

    reachable = sum(1 for v in verdicts if v.status == REACHABLE)
    print("")
    print("%d findings -> %d reachable" % (len(verdicts), reachable))
    for kind in ("md", "html", "json"):
        print("  %-5s %s" % (kind, paths[kind]))

    # Non-zero when something is actually reachable, so CI can gate on it.
    return 1 if (reachable and args.fail_on_reachable) else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reachable",
        description="Triage security findings by whether anything can actually reach them.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a repository and write a reachability report")
    scan.add_argument("repo", nargs="?", default=".", help="path to the repository (default: .)")
    scan.add_argument("--out", default="./out", help="output directory (default: ./out)")
    scan.add_argument("--no-scan", action="store_true", help="skip all scanners, graph only")
    scan.add_argument("--no-builtin", action="store_true", help="skip the built-in rules")
    scan.add_argument("--findings", help="reuse a cached raw scanner run")
    scan.add_argument("--include-unknown", action="store_true", help="show UNKNOWN in report.md")
    scan.add_argument("--fail-on-reachable", action="store_true", help="exit 1 if anything is reachable")
    scan.add_argument("--quiet", action="store_true", help="errors only")
    scan.set_defaults(func=run)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
