from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts" / "audit_vacuity.py"
spec = importlib.util.spec_from_file_location("audit_vacuity", SCRIPT)
assert spec is not None and spec.loader is not None
audit_vacuity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit_vacuity)
scan_text = audit_vacuity.scan_text


class VacuityAuditTests(unittest.TestCase):
    def kinds(self, source: str, path: str = "sample.py") -> set[str]:
        return {finding.kind for finding in scan_text("HEAD", path, source)}

    def test_concrete_pass_ellipsis_and_not_implemented_are_findings(self) -> None:
        source = """
def a():
    pass

def b():
    ...

def c():
    raise NotImplementedError()
"""
        self.assertEqual(
            self.kinds(source),
            {"PY_PASS_BODY", "PY_ELLIPSIS_BODY", "PY_NOT_IMPLEMENTED"},
        )

    def test_protocol_and_exception_declarations_are_not_false_positive_stubs(self) -> None:
        source = """
from typing import Protocol
class Driver(Protocol):
    def run(self): ...
class DomainError(RuntimeError):
    pass
"""
        self.assertEqual(self.kinds(source), set())

    def test_vacuous_verifier_and_self_asserted_standing_are_refused(self) -> None:
        source = """
def verify_result(value):
    return True

def receipt():
    return {"standing": "PARTIAL_ALIVE", "value": 1}
"""
        self.assertEqual(
            self.kinds(source),
            {"PY_VACUOUS_VERIFIER", "PY_SELF_ASSERTED_STANDING"},
        )

    def test_self_equality_assertion_is_refused(self) -> None:
        self.assertIn("PY_SELF_EQUALITY_ASSERT", self.kinds("value = 1\nassert value == value\n"))

    def test_rust_and_typescript_not_implemented_markers_are_found(self) -> None:
        self.assertEqual(self.kinds("fn x() { todo!() }", "sample.rs"), {"RS_TODO"})
        self.assertEqual(
            self.kinds("function x(){ throw new Error('not implemented') }", "sample.ts"),
            {"JS_NOT_IMPLEMENTED"},
        )


if __name__ == "__main__":
    unittest.main()
