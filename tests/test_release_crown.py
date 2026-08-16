from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from verify_release_crown import verify  # noqa: E402


class ReleaseCrownTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = ROOT / "release" / "v26.9.1.toml"

    def _write(self, text: str) -> Path:
        handle = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
        handle.write(text)
        handle.close()
        return Path(handle.name)

    def test_current_crown_is_partial_and_names_runtime_seams(self) -> None:
        receipt = verify(self.source)
        self.assertEqual(receipt["standing"], "PARTIAL_ALIVE")
        self.assertEqual(receipt["unresolved_required_roles"], ["orchestration"])
        self.assertFalse(receipt["do_authority"])

    def test_world_execution_is_bound_to_executed_gymact_subject(self) -> None:
        data = tomllib.loads(self.source.read_text())
        world = next(component for component in data["components"] if component["role"] == "world_execution")
        self.assertEqual(world["repository"], "seanchatmangpt/gymact")
        self.assertEqual(world["revision"], "8bf5c15766705b5ebc1dacf3492d57d8a46af5e4")
        self.assertEqual(world["standing"], "ALIVE")
        self.assertEqual(world["execution_receipt"], "github-actions:31954771109")
        self.assertEqual(world["authority"], "BRCE_GATED_DO")
        self.assertNotIn("blocker", world)

    def test_alive_without_execution_is_refused(self) -> None:
        text = self.source.read_text().replace(
            'standing = "BLOCKED"\nrequired = true\nblocker = "GITHUB_ACTIONS_BILLING_OR_SPENDING_LIMIT"',
            'standing = "ALIVE"\nrequired = true',
            1,
        )
        with self.assertRaisesRegex(ValueError, "ALIVE_WITHOUT_VALID_EXECUTION_RECEIPT"):
            verify(self._write(text))

    def test_malformed_execution_receipt_is_refused(self) -> None:
        text = self.source.read_text().replace(
            'execution_receipt = "github-actions:31676713680"',
            'execution_receipt = "trust-me"',
            1,
        )
        with self.assertRaisesRegex(ValueError, "ALIVE_WITHOUT_VALID_EXECUTION_RECEIPT"):
            verify(self._write(text))

    def test_blocked_component_cannot_carry_execution_receipt(self) -> None:
        text = self.source.read_text().replace(
            'blocker = "GITHUB_ACTIONS_BILLING_OR_SPENDING_LIMIT"',
            'blocker = "GITHUB_ACTIONS_BILLING_OR_SPENDING_LIMIT"\nexecution_receipt = "github-actions:zero-step"',
            1,
        )
        with self.assertRaisesRegex(ValueError, "BLOCKED_WITH_EXECUTION_RECEIPT"):
            verify(self._write(text))

    def test_mandatory_role_cannot_opt_out_of_required_closure(self) -> None:
        text = self.source.read_text().replace('required = true', 'required = false', 1)
        with self.assertRaisesRegex(ValueError, "MANDATORY_ROLE_NOT_REQUIRED"):
            verify(self._write(text))

    def test_role_authority_drift_is_refused(self) -> None:
        text = self.source.read_text().replace('authority = "ORCHESTRATION_ONLY"', 'authority = "EVIDENCE_ONLY"')
        with self.assertRaisesRegex(ValueError, "ROLE_AUTHORITY_DRIFT"):
            verify(self._write(text))

    def test_ambient_do_is_refused(self) -> None:
        text = self.source.read_text().replace('authority = "ORCHESTRATION_ONLY"', 'authority = "AMBIENT_DO"')
        with self.assertRaisesRegex(ValueError, "ROLE_AUTHORITY_DRIFT"):
            verify(self._write(text))

    def test_invalid_revision_is_refused(self) -> None:
        text = self.source.read_text().replace("2cb59841c9842efe21d386b184bd1e8bace58411", "main", 1)
        with self.assertRaisesRegex(ValueError, "INVALID_REVISION"):
            verify(self._write(text))


if __name__ == "__main__":
    unittest.main()
