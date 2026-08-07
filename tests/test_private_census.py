from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from verify_private_census import (  # noqa: E402
    PrivateCensusRefusal,
    SEMANTIC_EXTENSIONS,
    validate_private_census,
)


class PrivateSemanticCensusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.receipt = json.loads(
            (ROOT / "corpus/private-semantic-census-receipt.json").read_text(encoding="utf-8")
        )
        cls.profile = json.loads(
            (ROOT / "corpus/admission-profile.json").read_text(encoding="utf-8")
        )

    def refused(self, mutate) -> None:
        receipt = copy.deepcopy(self.receipt)
        profile = copy.deepcopy(self.profile)
        mutate(receipt, profile)
        with self.assertRaises(PrivateCensusRefusal):
            validate_private_census(receipt, profile)

    def test_exact_private_census_is_alive(self) -> None:
        verified = validate_private_census(self.receipt, self.profile)
        self.assertEqual(verified["standing"], "ALIVE")
        self.assertEqual(verified["repositories"], 75)
        self.assertEqual(verified["recursive_trees"], 71)
        self.assertEqual(verified["empty_repositories"], 4)

    def test_repository_count_drift_is_refused(self) -> None:
        self.refused(lambda receipt, profile: receipt.__setitem__("repository_inventory", 74))

    def test_tree_count_drift_is_refused(self) -> None:
        self.refused(lambda receipt, profile: receipt.__setitem__("materialized_recursive_trees", 70))

    def test_truncated_tree_is_refused(self) -> None:
        self.refused(lambda receipt, profile: receipt.__setitem__("truncated_trees", 1))

    def test_repository_failure_is_refused(self) -> None:
        self.refused(lambda receipt, profile: receipt.__setitem__("repository_failures", 1))

    def test_incomplete_file_level_scan_is_refused(self) -> None:
        self.refused(lambda receipt, profile: receipt.__setitem__("file_level_complete", False))

    def test_semantic_extension_drift_is_refused(self) -> None:
        self.refused(lambda receipt, profile: receipt.__setitem__("semantic_extensions", SEMANTIC_EXTENSIONS[:-1]))

    def test_authority_escalation_is_refused(self) -> None:
        self.refused(lambda receipt, profile: receipt.__setitem__("authority_ceiling", "DO"))

    def test_non_alive_standing_is_refused(self) -> None:
        self.refused(lambda receipt, profile: receipt.__setitem__("standing", "PARTIAL_ALIVE"))

    def test_private_identifier_leak_is_refused(self) -> None:
        self.refused(lambda receipt, profile: receipt.__setitem__("repositories", ["seanchatmangpt/private-example"]))

    def test_commitment_drift_is_refused(self) -> None:
        self.refused(lambda receipt, profile: receipt.__setitem__("repository_tree_commitment_sha256", "not-a-sha256"))

    def test_owner_partition_drift_is_refused(self) -> None:
        self.refused(lambda receipt, profile: profile["census"].__setitem__("public_repository_rows", 264))


if __name__ == "__main__":
    unittest.main()
