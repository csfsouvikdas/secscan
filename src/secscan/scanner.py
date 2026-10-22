"""File discovery and the scanning engine."""
from __future__ import annotations

import fnmatch
import math
import os
import re
import time
from typing import Iterable, List, Optional, Sequence

from .models import SEV_RANK, Finding, Rule, ScanResult
from .pyast import scan_python
from .rules import CODE, RULES

CONFIG_EXTS = {"env", "yml", "yaml", "json", "properties", "ini", "cfg", "conf", "toml", "xml", "sh", "txt"}
SCAN_EXTS = set(CODE) | CONFIG_EXTS
DEFAULT_EXCLUDE_DIRS = {".git", ".hg", ".svn", "node_modules", "venv", ".venv", "env", "__pycache__",
                        "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", "vendor", ".idea", ".vscode"}
MAX_FILE_BYTES = 1_000_000
MAX_LINE_CHARS = 2000

_COMMENT_PREFIXES = ("#", "//", "/*", "*", "--", ";")
_SUPPRESS = re.compile(r"(?:secscan|nosec)\s*:?\s*(?:ignore)?(?:=([A-Z0-9,\s]+))?", re.I)
_PLACEHOLDERS = ("changeme", "change_me", "your_", "your-", "<", ">", "${", "{{", "%s", "xxxx", "****",
                 "placeholder", "example", "dummy", "sample", "todo", "redacted", "enter_", "insert")
_ENTROPY_CANDIDATE = re.compile(r"[\"']([A-Za-z0-9+/=_\-]{32,})[\"']")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in freq.values())


def _ext(path: str) -> str:
    base = os.path.basename(path).lower()
    if base.startswith(".env"):
        return "env"
    return base.rsplit(".", 1)[-1] if "." in base else ""


def _suppressed(line: str, rule_id: str) -> bool:
    if "secscan" not in line.lower() and "nosec" not in line.lower():
        return False
    m = _SUPPRESS.search(line)
    if not m:
        return False
    ids = m.group(1)
    if not ids or not ids.strip():
        return True
    return rule_id in {i.strip().upper() for i in ids.split(",")}


def _redact(line: str, start: int, end: int) -> str:
    secret = line[start:end]
    mask = secret[:4] + "*" * max(4, len(secret) - 4) if len(secret) > 8 else "*" * len(secret)
    return line[:start] + mask + line[end:]


def _placeholder(value: str, key: str) -> bool:
    low = value.lower()
    if any(p in low for p in _PLACEHOLDERS):
        return True
    if re.fullmatch(r"[a-z_.\-]+", value) and not re.search(r"(?i)passw|pwd|secret", key):
        return True  # e.g. token_type = "bearer"
    return False


def iter_files(paths: Sequence[str], excludes: Iterable[str] = ()) -> Iterable[str]:
    excludes = list(excludes)

    def excluded(p: str) -> bool:
        norm = p.replace(os.sep, "/")
        return any(fnmatch.fnmatch(norm, g) or fnmatch.fnmatch(os.path.basename(p), g) for g in excludes)

    for root in paths:
        if os.path.isfile(root):
            yield root
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames
                                 if d not in DEFAULT_EXCLUDE_DIRS and not excluded(os.path.join(dirpath, d)))
            for fn in sorted(filenames):
                full = os.path.join(dirpath, fn)
                if _ext(fn) in SCAN_EXTS and not fn.endswith(".min.js") and not excluded(full):
                    yield full


def scan_text(text: str, path: str, rules: Sequence[Rule], errors: Optional[List[str]] = None) -> List[Finding]:
    """Scan one file's contents and return findings (no file I/O)."""
    ext = _ext(path)
    findings: List[Finding] = []
    seen = set()

    def add(rule: Rule, line_no: int, col: int, snippet: str) -> None:
        key = (rule.id, line_no)
        if key in seen:
            return
        seen.add(key)
        findings.append(Finding(rule.id, rule.title, rule.severity, rule.cwe, path, line_no, col,
                                snippet.strip()[:200], rule.description, rule.fix))

    active = [r for r in rules if r.applies_to(ext)]
    regex_rules = [r for r in active if r.kind == "regex" and r.compiled]
    entropy_rules = [r for r in active if r.kind == "entropy"]
    ast_ids = {r.id for r in active if r.kind == "ast"}

    lines = text.splitlines()
    secret_lines = set()
    for i, raw in enumerate(lines, 1):
        line = raw[:MAX_LINE_CHARS]
        stripped = line.lstrip()
        is_comment = stripped.startswith(_COMMENT_PREFIXES)
        for r in regex_rules:
            if is_comment and r.category != "secrets":
                continue
            m = r.compiled.search(line)  # type: ignore[union-attr]
            if not m:
                continue
            if r.context_compiled and not r.context_compiled.search(line):
                continue
            if r.id == "SEC006" and _placeholder(m.group(2), m.group(1)):
                continue
            if _suppressed(line, r.id):
                continue
            shown = _redact(line, *m.span(r.secret_group)) if r.redact else line
            if r.category == "secrets":
                secret_lines.add(i)
            add(r, i, m.start() + 1, shown)
        for r in entropy_rules:
            if i in secret_lines or _suppressed(line, r.id):
                continue
            for m in _ENTROPY_CANDIDATE.finditer(line):
                s = m.group(1)
                if (shannon_entropy(s) >= 4.5 and re.search(r"[A-Z]", s) and re.search(r"[a-z]", s)
                        and re.search(r"\d", s)):
                    add(r, i, m.start() + 1, _redact(line, *m.span(1)))
                    break

    if ext == "py" and ast_ids:
        try:
            for f in scan_python(text, path):
                if f.rule_id in ast_ids and not _suppressed(lines[f.line - 1] if f.line <= len(lines) else "", f.rule_id):
                    key = (f.rule_id, f.line)
                    if key not in seen:
                        seen.add(key)
                        findings.append(f)
        except SyntaxError as e:
            if errors is not None:
                errors.append(f"{path}:{e.lineno}: syntax error, Python AST rules skipped")
    return findings


def scan_paths(paths: Sequence[str], rules: Optional[Sequence[Rule]] = None, excludes: Iterable[str] = (),
               min_severity: str = "info", base: Optional[str] = None) -> ScanResult:
    """Scan files/directories and return a :class:`ScanResult`."""
    start = time.time()
    rules = list(rules if rules is not None else RULES)
    result = ScanResult()
    floor = SEV_RANK[min_severity]
    for path in iter_files(paths, excludes):
        try:
            if os.path.getsize(path) > MAX_FILE_BYTES:
                result.errors.append(f"{path}: skipped (larger than {MAX_FILE_BYTES // 1000} KB)")
                continue
            with open(path, "rb") as fh:
                data = fh.read()
            if b"\x00" in data[:2048]:
                continue  # binary
            text = data.decode("utf-8", errors="replace")
        except OSError as e:
            result.errors.append(f"{path}: {e.strerror or e}")
            continue
        result.files_scanned += 1
        display = os.path.relpath(path, base) if base else path
        display = display.replace(os.sep, "/")
        for f in scan_text(text, display, rules, result.errors):
            if SEV_RANK[f.severity] >= floor:
                result.findings.append(f)
    result.findings.sort(key=lambda f: (-SEV_RANK[f.severity], f.file, f.line, f.rule_id))
    result.duration = time.time() - start
    return result
