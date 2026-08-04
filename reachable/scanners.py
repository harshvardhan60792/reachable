"""Phase 1 — run the free scanners, normalize their output to Finding[].

Every scanner is optional. A missing binary is a warning, not an error: the call graph
analysis is still useful on its own, and this keeps the tool runnable on a bare machine.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from .models import Finding, ScanFailure

# Scanners can be slow on large repos; cap them rather than hang forever.
TIMEOUT = 900


def _have(binary: str) -> bool:
    return shutil.which(binary) is not None


class ScannerFailed(Exception):
    """A scanner was installed, started, and produced nothing usable.

    Distinct from "not installed", and it must never be reported as zero findings. An empty
    result that actually means the scanner died is a clean bill of health nobody earned, which
    is the worst thing a security tool can print.
    """


def _run(cmd: List[str], cwd: str) -> Optional[str]:
    """Run a scanner and return stdout.

    Scanners exit non-zero when they find things, so a non-zero code on its own is not a
    failure. A non-zero code *with no stdout at all* is: the scanner never got as far as
    emitting its report.
    """
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        raise ScannerFailed("timed out after %ds" % TIMEOUT)
    except OSError as exc:
        raise ScannerFailed("could not start: %s" % exc)
    if proc.returncode != 0 and not (proc.stdout or "").strip():
        detail = " ".join((proc.stderr or "").split())[:300] or "no output"
        raise ScannerFailed("exit %d: %s" % (proc.returncode, detail))
    return proc.stdout


def _checked(raw: Optional[str], binary: str) -> str:
    """Reject output that is not JSON at all.

    The parsers tolerate odd *shapes* on purpose -- scanner output is untrusted input. Output
    that does not parse at all is a different thing: the scanner printed an error where its
    report should have been, and swallowing that reads as zero findings.
    """
    if not raw or not raw.strip():
        return ""
    try:
        json.loads(raw)
    except json.JSONDecodeError:
        raise ScannerFailed("output was not JSON: %s" % " ".join(raw.split())[:200])
    return raw


def _norm_path(path: str, repo: str) -> str:
    """Scanner output paths vary between absolute and relative. Normalize to repo-relative."""
    if not path:
        return ""
    p = path.replace("\\", "/")
    root = os.path.abspath(repo).replace("\\", "/")
    if p.startswith(root):
        p = p[len(root):]
    return p.lstrip("./")


# --------------------------------------------------------------------------- semgrep

#: Semgrep rulesets, named explicitly. `--config=auto` cannot be used: it is *defined* as
#: "ask the registry what to run for this project", which requires the upload that
#: `--metrics=off` forbids, and Semgrep refuses the combination outright --
#: "Cannot create auto config when metrics are off". Naming the rulesets keeps metrics off,
#: makes the rule set reproducible between runs, and still covers the same ground.
SEMGREP_CONFIGS = ("p/python", "p/security-audit", "p/secrets")


def run_semgrep(repo: str) -> List[Finding]:
    # --metrics=off matters: Semgrep uploads usage metrics by default. This tool promises
    # local-only analysis, and silently phoning home about a codebase someone pointed a
    # security scanner at would break that promise.
    #
    # Fetching the named rulesets is still a network request. That is a deliberate trade for
    # rule coverage, and it is the only outbound request the pipeline makes.
    cmd = ["semgrep"]
    cmd += ["--config=%s" % c for c in SEMGREP_CONFIGS]
    cmd += ["--metrics=off", "--json", "--quiet", "--no-git-ignore", "."]
    out = _checked(_run(cmd, repo), "semgrep")
    if not out:
        return []
    return parse_semgrep(out, repo)


def parse_semgrep(raw: str, repo: str) -> List[Finding]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []

    findings: List[Finding] = []
    for i, r in enumerate(data.get("results", [])):
        extra = r.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        findings.append(
            Finding(
                id="semgrep-%d" % i,
                tool="semgrep",
                severity=str(extra.get("severity", "INFO")).upper(),
                message=(extra.get("message") or "").strip(),
                file=_norm_path(r.get("path", ""), repo),
                line=int((r.get("start", {}) or {}).get("line", 0) or 0),
                end_line=int((r.get("end", {}) or {}).get("line", 0) or 0),
                rule_id=r.get("check_id", "") or ",".join(meta.get("cwe", []) or []),
            )
        )
    return findings


# ------------------------------------------------------------------------ osv-scanner

def run_osv(repo: str) -> List[Finding]:
    out = _checked(_run(["osv-scanner", "--format", "json", "-r", "."], repo), "osv-scanner")
    if not out:
        return []
    return parse_osv(out, repo)


def parse_osv(raw: str, repo: str) -> List[Finding]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []

    findings: List[Finding] = []
    n = 0
    for res in data.get("results", []) or []:
        src = (res.get("source", {}) or {}).get("path", "")
        for pkg in res.get("packages", []) or []:
            info = pkg.get("package", {}) or {}
            name = info.get("name", "")
            for vuln in pkg.get("vulnerabilities", []) or []:
                findings.append(
                    Finding(
                        id="osv-%d" % n,
                        tool="osv",
                        severity=_osv_severity(vuln),
                        message=(vuln.get("summary") or vuln.get("id", "")).strip(),
                        file=_norm_path(src, repo),
                        line=0,
                        rule_id=vuln.get("id", ""),
                        package=name,
                        fixed_version=_osv_fixed(vuln, name),
                    )
                )
                n += 1
    return findings


def _osv_severity(vuln: Dict[str, Any]) -> str:
    """OSV encodes severity inconsistently. Prefer the database_specific label."""
    db = vuln.get("database_specific", {}) or {}
    label = db.get("severity")
    if label:
        return str(label).upper()
    if vuln.get("severity"):
        return "HIGH"
    return "MEDIUM"


def _osv_fixed(vuln: Dict[str, Any], package: str) -> str:
    for aff in vuln.get("affected", []) or []:
        if (aff.get("package", {}) or {}).get("name") not in (package, None):
            continue
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                if ev.get("fixed"):
                    return str(ev["fixed"])
    return ""


# --------------------------------------------------------------------------- gitleaks

def run_gitleaks(repo: str) -> List[Finding]:
    # gitleaks writes the report to a file; "-" sends it to stdout.
    out = _run(
        ["gitleaks", "detect", "--no-banner", "--report-format", "json", "--report-path", "-"],
        repo,
    )
    out = _checked(out, "gitleaks")
    if not out:
        return []
    return parse_gitleaks(out, repo)


def parse_gitleaks(raw: str, repo: str) -> List[Finding]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []

    findings: List[Finding] = []
    for i, r in enumerate(data):
        line = int(r.get("StartLine", 0) or 0)
        findings.append(
            Finding(
                id="gitleaks-%d" % i,
                tool="gitleaks",
                # A committed credential is always high severity — it is already exposed.
                severity="HIGH",
                message="Potential secret: %s" % (r.get("Description", "") or r.get("RuleID", "")),
                file=_norm_path(r.get("File", ""), repo),
                line=line,
                end_line=int(r.get("EndLine", line) or line),
                rule_id=r.get("RuleID", ""),
            )
        )
    return findings


# ------------------------------------------------------------------------------ driver

SCANNERS = (
    ("semgrep", run_semgrep),
    ("osv-scanner", run_osv),
    ("gitleaks", run_gitleaks),
)


def scan(
    repo: str,
    log=None,
    use_builtin: bool = True,
    failures: Optional[List[ScanFailure]] = None,
) -> List[Finding]:
    """Run every available scanner. Missing binaries are skipped with a warning.

    Pass a list as ``failures`` to receive the scanners that died. The return type stays a
    plain finding list so the stage contract in CLAUDE.md holds, but a caller that writes a
    report needs to know the difference between "found nothing" and "never ran".
    """
    log = log or (lambda *_a, **_k: None)
    findings: List[Finding] = []
    ran_any = False

    failed: List[str] = []

    for binary, fn in SCANNERS:
        if not _have(binary):
            log("skip %s (not installed)" % binary)
            continue
        ran_any = True
        log("running %s ..." % binary)
        try:
            got = fn(repo)
        except ScannerFailed as exc:
            # Never fall through to "0 findings". An installed scanner that died leaves a
            # hole in the coverage, and the run has to say so out loud.
            failed.append(binary)
            if failures is not None:
                failures.append(ScanFailure(binary, str(exc)))
            log("  %s FAILED (%s) -- no findings from it, and that is not a clean result"
                % (binary, exc))
            continue
        log("  %s -> %d findings" % (binary, len(got)))
        findings.extend(got)

    # The built-in rules always run: they are cheap, and they keep the tool useful on a
    # machine where nothing else is installed.
    if use_builtin:
        from . import builtin_scan

        log("running builtin rules ...")
        findings.extend(builtin_scan.scan(repo, log))
    elif not ran_any:
        log("warning: no scanner ran; there is nothing to triage")

    if failed:
        log("warning: %s did not complete; this report is incomplete, not clean"
            % ", ".join(failed))

    return findings


def save_raw(findings: List[Finding], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([f.to_dict() for f in findings], fh, indent=2)


_FINDING_FIELDS = set(Finding.__dataclass_fields__)


def load_raw(path: str) -> List[Finding]:
    """Tolerate unknown keys rather than crashing.

    A cached findings file can come from a different version of this tool, or be edited by
    hand. `Finding(**d)` raises TypeError on any extra key, which turns a stale cache into a
    hard failure with a confusing traceback.
    """
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        return []
    out = []
    for d in data:
        if isinstance(d, dict):
            out.append(Finding(**{k: v for k, v in d.items() if k in _FINDING_FIELDS}))
    return out
