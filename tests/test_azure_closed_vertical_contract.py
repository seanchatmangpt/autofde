from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from verify_azure_closed_vertical import ContractError, verify  # noqa: E402


class AzureClosedVerticalContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        shutil.copytree(ROOT / "cloud", self.root / "cloud")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def mutate(self, old: str, new: str) -> None:
        path = self.root / "cloud" / "azure" / "sentinel.tf"
        text = path.read_text()
        self.assertIn(old, text)
        path.write_text(text.replace(old, new, 1))

    def test_admitted_contract(self) -> None:
        verify(self.root)

    def test_refuses_owner_role(self) -> None:
        self.mutate('role_definition_name = "Microsoft Sentinel Reader"', 'role_definition_name = "Owner"')
        with self.assertRaisesRegex(ContractError, "REFUSED"):
            verify(self.root)

    def test_refuses_subscription_scope_rbac(self) -> None:
        self.mutate('scope                = azurerm_log_analytics_workspace.sentinel.id', 'scope                = "/subscriptions/${var.subscription_id}"')
        with self.assertRaisesRegex(ContractError, "REFUSED"):
            verify(self.root)

    def test_refuses_missing_managed_identity(self) -> None:
        self.mutate('type = "SystemAssigned"', 'type = "None"')
        with self.assertRaisesRegex(ContractError, "REFUSED"):
            verify(self.root)

    def test_refuses_missing_incident_timestamp(self) -> None:
        self.mutate('"lastModifiedTimeUtc"', '"timestamp"')
        with self.assertRaisesRegex(ContractError, "REFUSED"):
            verify(self.root)


if __name__ == "__main__":
    unittest.main()
