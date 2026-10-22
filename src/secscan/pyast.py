"""AST based checks for Python files (more precise than regex)."""
from __future__ import annotations

import ast
from typing import Dict, List, Optional

from .models import Finding
from .rules import RULES_BY_ID

SQL_METHODS = {"execute", "executemany", "executescript", "mogrify", "raw"}


def _is_dynamic_string(node: ast.AST) -> bool:
    """True for f-strings with values, %/+ formatting with non-constants, and .format() calls."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return not (isinstance(node.left, ast.Constant) and isinstance(node.right, ast.Constant))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return False


class _Visitor(ast.NodeVisitor):
    def __init__(self, path: str, lines: List[str]) -> None:
        self.path = path
        self.lines = lines
        self.aliases: Dict[str, str] = {}
        self.findings: List[Finding] = []

    # -- helpers ---------------------------------------------------------
    def _resolve(self, node: ast.AST) -> Optional[str]:
        parts: List[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(self.aliases.get(node.id, node.id))
            return ".".join(reversed(parts))
        return None

    def _add(self, rule_id: str, node: ast.AST) -> None:
        r = RULES_BY_ID[rule_id]
        line = getattr(node, "lineno", 1)
        snippet = self.lines[line - 1].strip()[:200] if 0 < line <= len(self.lines) else ""
        self.findings.append(Finding(r.id, r.title, r.severity, r.cwe, self.path, line,
                                     getattr(node, "col_offset", 0) + 1, snippet, r.description, r.fix))

    @staticmethod
    def _kw(node: ast.Call, name: str) -> Optional[ast.expr]:
        for k in node.keywords:
            if k.arg == name:
                return k.value
        return None

    # -- imports ---------------------------------------------------------
    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            if a.asname:
                self.aliases[a.asname] = a.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            for a in node.names:
                self.aliases[a.asname or a.name] = f"{node.module}.{a.name}"
        self.generic_visit(node)

    # -- checks ----------------------------------------------------------
    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            self._add("PY109", node)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = self._resolve(node.func) or ""

        if name in ("eval", "exec", "builtins.eval", "builtins.exec"):
            self._add("PY101", node)
        elif name in ("os.system", "os.popen", "commands.getoutput"):
            self._add("PY102", node)
        elif name.startswith("subprocess."):
            shell = self._kw(node, "shell")
            if isinstance(shell, ast.Constant) and shell.value is True:
                self._add("PY102", node)
        elif name in ("pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads", "marshal.load",
                      "marshal.loads", "shelve.open", "dill.load", "dill.loads", "_pickle.loads"):
            self._add("PY103", node)
        elif name in ("yaml.load", "yaml.load_all"):
            loader = self._kw(node, "Loader")
            lname = self._resolve(loader) if loader is not None else ""
            if "Safe" not in (lname or ""):
                self._add("PY104", node)
        elif name in ("hashlib.md5", "hashlib.sha1"):
            flag = self._kw(node, "usedforsecurity")
            if not (isinstance(flag, ast.Constant) and flag.value is False):
                self._add("PY105", node)
        elif name == "hashlib.new" and node.args and isinstance(node.args[0], ast.Constant) \
                and str(node.args[0].value).lower() in ("md5", "sha1"):
            self._add("PY105", node)
        elif name in ("tempfile.mktemp",):
            self._add("PY107", node)
        elif name.endswith("render_template_string") and node.args and _is_dynamic_string(node.args[0]):
            self._add("PY108", node)
        elif name in ("jinja2.Environment", "jinja2.environment.Environment"):
            auto = self._kw(node, "autoescape")
            if isinstance(auto, ast.Constant) and auto.value is False:
                self._add("PY108", node)

        if isinstance(node.func, ast.Attribute) and node.func.attr in SQL_METHODS and node.args \
                and _is_dynamic_string(node.args[0]):
            self._add("PY106", node)
        self.generic_visit(node)


def scan_python(source: str, path: str) -> List[Finding]:
    tree = ast.parse(source, filename=path)
    v = _Visitor(path, source.splitlines())
    v.visit(tree)
    return v.findings
