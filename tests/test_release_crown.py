from __future__ import annotations

from pathlib import Path
import sys
import tempfile
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
        self.assertEqual(receipt["unresolved_required_roles"], ["orchestration", "world_execution"])
        self.assertFalse(receipt["do_authority"])

    def test_alive_without_execution_is_refused(self) -> None:
        text = self.source.read_text().replace(
            'standing = "BLOCKED"\nrequired = true\nblocker = "GITHUB_ACTIONS_BILLING_OR_SPENDING_LIMIT"',
            'standing = "ALIVE"\nrequired = true',
            1,
        )
        with self.assertRaisesRegex(ValueError, "ALIVE_WITHOUT_EXECUTION"):
            verify(self._write(text))

    def test_ambient_do_is_refused(self) -> None:
        text = self.source.read_text().replace('authority = "ORCHESTRATION_ONLY"', 'authority = "AMBIENT_DO"')
        with self.assertRaisesRegex(ValueError, "AMBIENT_DO"):
            verify(self._write(text))

    def test_invalid_revision_is_refused(self) -> None:
        text = self.source.read_text().replace("2cb59841c9842efe21d386b184bd1e8bace58411", "main", 1)
        with self.assertRaisesRegex(ValueError, "INVALID_REVISION"):
            verify(self._write(text))


if __name__ == "__main__":
    unittest.main()
