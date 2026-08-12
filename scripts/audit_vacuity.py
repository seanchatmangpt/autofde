#!/usr/bin/env python3
"""Fail-closed static audit for executable stubs and vacuous standing claims.

The scanner distinguishes interface declarations from executable bodies. Protocol/
ABC/abstract methods may use ``...`` or ``pass``; concrete executable functions may
not. It can enumerate every fetched branch and every tracked executable source file.
Identical blobs shared by branches are scanned once and re-bound to each branch ref.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

CODE_SUFFIXES = {
    ".py", ".rs", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".kt",
    ".cc", ".cpp", ".cxx", ".h", ".hpp", ".lean",
}
IGNORED_PARTS = {".git", ".venv", "node_modules", "target", "vendor"}
STANDING_VALUES = {"ALIVE", "PARTIAL_ALIVE"}


@dataclass(frozen=True, slots=True)
class Finding:
    ref: str
    path: str
    line: int
    kind: str
    symbol: str
    detail: str


class PythonVacuityVisitor(ast.NodeVisitor):
    def __init__(self, ref: str, path: str) -> None:
        self.ref = ref
        self.path = path
        self.findings: list[Finding] = []
        self.class_stack: list[tuple[str, bool]] = []

    @staticmethod
    def _name(node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return ""

    @staticmethod
    def _body_without_docstring(body: list[ast.stmt]) -> list[ast.stmt]:
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            return body[1:]
        return body

    def _finding(self, node: ast.AST, kind: str, symbol: str, detail: str) -> None:
        self.findings.append(
            Finding(self.ref, self.path, getattr(node, "lineno", 1), kind, symbol, detail)
        )

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        interface = any(self._name(base) in {"Protocol", "ABC"} for base in node.bases)
        exception_type = any(self._name(base).endswith(("Error", "Exception")) for base in node.bases)
        self.class_stack.append((node.name, interface or exception_type))
        self.generic_visit(node)
        self.class_stack.pop()

    def _is_abstract(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        if self.class_stack and self.class_stack[-1][1]:
            return True
        return any(self._name(dec) == "abstractmethod" for dec in node.decorator_list)

    def _scan_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        body = self._body_without_docstring(node.body)
        if not self._is_abstract(node) and len(body) == 1:
            statement = body[0]
            if isinstance(statement, ast.Pass):
                self._finding(statement, "PY_PASS_BODY", node.name, "concrete function contains only pass")
            elif (
                isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Constant)
                and statement.value.value is Ellipsis
            ):
                self._finding(statement, "PY_ELLIPSIS_BODY", node.name, "concrete function contains only ellipsis")
            elif isinstance(statement, ast.Raise) and isinstance(statement.exc, ast.Call):
                exc_name = self._name(statement.exc.func)
                message = ""
                if statement.exc.args and isinstance(statement.exc.args[0], ast.Constant):
                    message = str(statement.exc.args[0].value).lower()
                if exc_name == "NotImplementedError" or (
                    exc_name.endswith(("Error", "Exception"))
                    and any(marker in message for marker in ("not implemented", "todo", "stub"))
                ):
                    self._finding(statement, "PY_NOT_IMPLEMENTED", node.name, "concrete function raises a not-implemented exception")
            elif isinstance(statement, ast.Return):
                value = statement.value
                verifier_like = any(token in node.name.lower() for token in ("verify", "check", "admit", "validate"))
                if verifier_like and isinstance(value, ast.Constant) and value.value in {True, False}:
                    self._finding(statement, "PY_VACUOUS_VERIFIER", node.name, "verifier-like function returns a constant")
                if isinstance(value, ast.Name) and value.id == "NotImplemented":
                    self._finding(statement, "PY_NOT_IMPLEMENTED", node.name, "concrete function returns NotImplemented")
                if isinstance(value, ast.Constant) and value.value is Ellipsis:
                    self._finding(statement, "PY_ELLIPSIS_BODY", node.name, "concrete function returns ellipsis")
                if isinstance(value, ast.Dict):
                    literals: dict[str, object] = {}
                    for key, item in zip(value.keys, value.values):
                        if isinstance(key, ast.Constant) and isinstance(key.value, str) and isinstance(item, ast.Constant):
                            literals[key.value] = item.value
                    if literals.get("standing") in STANDING_VALUES:
                        self._finding(statement, "PY_SELF_ASSERTED_STANDING", node.name, "literal standing is returned without observed evidence")
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._scan_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._scan_function(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        test = node.test
        if isinstance(test, ast.Constant) and test.value is True:
            self._finding(node, "PY_CONSTANT_ASSERT", "assert", "assert True cannot falsify behavior")
        elif isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq):
            left = ast.dump(test.left, include_attributes=False)
            right = ast.dump(test.comparators[0], include_attributes=False)
            if left == right:
                self._finding(node, "PY_SELF_EQUALITY_ASSERT", "assert", "assertion compares an expression with itself")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = self._name(node.func)
        if name in {"assertEqual", "assertIs"} and len(node.args) >= 2:
            left = ast.dump(node.args[0], include_attributes=False)
            right = ast.dump(node.args[1], include_attributes=False)
            if left == right:
                self._finding(node, "PY_SELF_EQUALITY_ASSERT", name, "test assertion compares an expression with itself")
        elif name == "assertTrue" and node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value is True:
            self._finding(node, "PY_CONSTANT_ASSERT", name, "assertTrue(True) cannot falsify behavior")
        elif name == "assertFalse" and node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value is False:
            self._finding(node, "PY_CONSTANT_ASSERT", name, "assertFalse(False) cannot falsify behavior")
        self.generic_visit(node)


def scan_python(ref: str, path: str, text: str) -> list[Finding]:
    try:
        tree = ast.parse(text, filename=path)
    except SyntaxError as exc:
        return [Finding(ref, path, exc.lineno or 1, "PY_SYNTAX_ERROR", "<module>", str(exc))]
    visitor = PythonVacuityVisitor(ref, path)
    visitor.visit(tree)
    return visitor.findings


def scan_text(ref: str, path: str, text: str) -> list[Finding]:
    suffix = Path(path).suffix.lower()
    if suffix == ".py":
        return scan_python(ref, path, text)
    findings: list[Finding] = []
    patterns = (
        (r"\btodo!\s*\(", "RS_TODO", "todo! macro in executable source"),
        (r"\bunimplemented!\s*\(", "RS_UNIMPLEMENTED", "unimplemented! macro in executable source"),
        (r"\bpanic!\s*\(\s*['\"][^'\"]*(?:not implemented|todo|stub)", "RS_NOT_IMPLEMENTED_PANIC", "not-implemented panic in Rust source"),
        (r"throw\s+new\s+\w*(?:Error|Exception)\s*\(\s*['\"][^'\"]*(?:not implemented|todo|stub)", "JS_NOT_IMPLEMENTED", "explicit not-implemented exception"),
        (r"\bpanic\s*\(\s*['\"][^'\"]*(?:not implemented|todo|stub)", "GO_NOT_IMPLEMENTED", "explicit not-implemented panic"),
        (r"throw\s+(?:std::)?(?:logic_error|runtime_error)\s*\(\s*['\"][^'\"]*(?:not implemented|todo|stub)", "CPP_NOT_IMPLEMENTED", "explicit not-implemented exception"),
        (r"throw\s+new\s+UnsupportedOperationException\s*\(\s*['\"][^'\"]*(?:not implemented|todo|stub)", "JVM_NOT_IMPLEMENTED", "explicit unsupported placeholder"),
        (r"^\s*(?:by\s+)?sorry\b", "LEAN_SORRY", "Lean proof contains sorry"),
        (r"^\s*(?:by\s+)?admit\b", "LEAN_ADMIT", "Lean proof contains admit"),
    )
    for lineno, line in enumerate(text.splitlines(), 1):
        for pattern, kind, detail in patterns:
            if re.search(pattern, line, flags=re.IGNORECASE):
                findings.append(Finding(ref, path, lineno, kind, "<text>", detail))
    return findings


def _git(*args: str) -> str:
    proc = subprocess.run(["git", *args], check=False, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def tracked_entries(ref: str) -> tuple[tuple[str, str], ...]:
    entries: list[tuple[str, str]] = []
    for line in _git("ls-tree", "-r", ref).splitlines():
        if "\t" not in line:
            continue
        metadata, path = line.split("\t", 1)
        fields = metadata.split()
        if len(fields) < 3 or fields[1] != "blob":
            continue
        candidate = Path(path)
        if candidate.suffix.lower() not in CODE_SUFFIXES:
            continue
        if any(part in IGNORED_PARTS for part in candidate.parts):
            continue
        entries.append((fields[2], path))
    return tuple(entries)


def tracked_paths(ref: str) -> tuple[str, ...]:
    return tuple(path for _, path in tracked_entries(ref))


def _scan_blob(ref: str, blob_sha: str, path: str) -> list[Finding]:
    return scan_text(ref, path, _git("cat-file", "blob", blob_sha))


def scan_ref(ref: str) -> list[Finding]:
    findings: list[Finding] = []
    for blob_sha, path in tracked_entries(ref):
        findings.extend(_scan_blob(ref, blob_sha, path))
    return sorted(findings, key=lambda f: (f.path, f.line, f.kind))


def all_refs() -> tuple[str, ...]:
    """Return every fetched origin branch exactly once, falling back to local heads."""
    remote = tuple(
        sorted(
            ref
            for ref in _git("for-each-ref", "--format=%(refname)", "refs/remotes/origin").splitlines()
            if ref and not ref.endswith("/HEAD")
        )
    )
    if remote:
        return remote
    return tuple(
        sorted(
            ref
            for ref in _git("for-each-ref", "--format=%(refname)", "refs/heads").splitlines()
            if ref
        )
    )


def report(refs: Iterable[str]) -> dict[str, object]:
    entries = []
    cache: dict[tuple[str, str], tuple[Finding, ...]] = {}
    unique_blobs: set[str] = set()
    for ref in refs:
        tracked = tracked_entries(ref)
        findings: list[Finding] = []
        for blob_sha, path in tracked:
            unique_blobs.add(blob_sha)
            key = (blob_sha, path)
            cached = cache.get(key)
            if cached is None:
                cached = tuple(_scan_blob("<blob>", blob_sha, path))
                cache[key] = cached
            findings.extend(
                Finding(ref, item.path, item.line, item.kind, item.symbol, item.detail)
                for item in cached
            )
        findings.sort(key=lambda f: (f.path, f.line, f.kind))
        entries.append(
            {
                "ref": ref,
                "files_scanned": len(tracked),
                "findings": [asdict(finding) for finding in findings],
            }
        )
    return {
        "schema": "autofde.vacuity-audit/1",
        "refs": entries,
        "unique_blobs_scanned": len(unique_blobs),
        "total_findings": sum(len(entry["findings"]) for entry in entries),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ref", default="HEAD")
    parser.add_argument("--all-refs", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--fail-on-findings", action="store_true")
    args = parser.parse_args()

    refs = all_refs() if args.all_refs else (args.ref,)
    result = report(refs)
    if args.json:
        print(json.dumps(result, sort_keys=True, indent=2))
    else:
        for entry in result["refs"]:
            print(f"{entry['ref']}: files={entry['files_scanned']} findings={len(entry['findings'])}")
            for finding in entry["findings"]:
                print(
                    f"  {finding['path']}:{finding['line']} {finding['kind']} "
                    f"{finding['symbol']} — {finding['detail']}"
                )
        print(f"UNIQUE_BLOBS_SCANNED={result['unique_blobs_scanned']}")
        print(f"TOTAL_FINDINGS={result['total_findings']}")
    return 1 if args.fail_on_findings and result["total_findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
