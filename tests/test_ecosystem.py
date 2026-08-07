from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from rdflib import Dataset, Namespace, RDF

ROOT = Path(__file__).resolve().parents[1]
AUTOFDE = Namespace("https://seanchatmangpt.github.io/autofde/ontology#")
sys.path.insert(0, str(ROOT / "scripts"))

from census_semantic_assets import FixtureClient, scan  # noqa: E402


class AutoFDEEcosystemTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixture = json.loads(
            (ROOT / "tests/fixtures/semantic-census.json").read_text(encoding="utf-8")
        )
        cls.corpus, cls.receipt = scan(
            FixtureClient(fixture),
            owner="seanchatmangpt",
            hydrate="all",
            expected_repositories=5,
        )

    def test_fixture_census_is_alive_and_complete(self) -> None:
        self.assertEqual(self.receipt["standing"], "ALIVE")
        self.assertTrue(self.receipt["repository_inventory_complete"])
        self.assertEqual(self.receipt["observed_repositories"], 5)
        self.assertEqual(self.receipt["semantic_assets"], 5)

    def test_census_is_byte_deterministic(self) -> None:
        fixture = json.loads(
            (ROOT / "tests/fixtures/semantic-census.json").read_text(encoding="utf-8")
        )
        second, second_receipt = scan(
            FixtureClient(fixture),
            owner="seanchatmangpt",
            hydrate="all",
            expected_repositories=5,
        )
        first_bytes = json.dumps(self.corpus, sort_keys=True, separators=(",", ":"))
        second_bytes = json.dumps(second, sort_keys=True, separators=(",", ":"))
        self.assertEqual(first_bytes, second_bytes)
        self.assertEqual(
            self.receipt["corpus_sha256"], second_receipt["corpus_sha256"]
        )

    def test_duplicate_fixture_is_eliminated(self) -> None:
        duplicate = next(
            asset for asset in self.corpus["assets"]
            if asset["repository"] == "seanchatmangpt/duplicate-fixture"
        )
        self.assertEqual(duplicate["disposition"], "VALIDATION_FIXTURE")
        self.assertEqual(duplicate["errc_action"], "ELIMINATE")
        self.assertIn("duplicate_of", duplicate)

    def test_broken_unlicensed_canonical_source_is_raised(self) -> None:
        broken = next(
            asset for asset in self.corpus["assets"]
            if asset["repository"] == "seanchatmangpt/broken-ontology"
        )
        self.assertEqual(broken["disposition"], "CANONICAL_CANDIDATE")
        self.assertEqual(broken["errc_action"], "RAISE")
        self.assertIn(
            broken["admission_issue"],
            {"REFUSED:LICENSE_NOT_ADMITTED", "REFUSED:SEMANTIC_PARSE_FAILED"},
        )

    def test_generated_projection_is_eliminated(self) -> None:
        generated = next(
            asset for asset in self.corpus["assets"]
            if asset["repository"] == "seanchatmangpt/generated-copy"
        )
        self.assertEqual(generated["disposition"], "GENERATED_PROJECTION")
        self.assertEqual(generated["errc_action"], "ELIMINATE")
        self.assertEqual(generated["authority_ceiling"], "CONSTRUCT")

    def test_sparql_query_is_parsed(self) -> None:
        query = next(
            asset for asset in self.corpus["assets"]
            if asset["repository"] == "seanchatmangpt/query-pack"
        )
        self.assertEqual(query["parse"]["standing"], "ALIVE")
        self.assertEqual(query["parse"]["kind"], "query")

    def test_canonical_graph_has_one_corpus_and_closed_gate(self) -> None:
        dataset = Dataset()
        for raw in (ROOT / "ontology/source-bundle.txt").read_text(
            encoding="utf-8"
        ).splitlines():
            path = raw.strip()
            if path and not path.startswith("#"):
                dataset.parse(ROOT / path, format="turtle")
        self.assertEqual(
            set(dataset.subjects(RDF.type, AUTOFDE.RepositoryCorpus)),
            {AUTOFDE.ChatmanEcosystemCorpus},
        )
        query = (ROOT / "queries/gates/ecosystem-admission.rq").read_text(
            encoding="utf-8"
        )
        self.assertFalse(bool(dataset.query(query).askAnswer))

    def test_cli_fixture_replay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "census.json"
            receipt = Path(directory) / "receipt.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/census_semantic_assets.py"),
                    "--fixture",
                    str(ROOT / "tests/fixtures/semantic-census.json"),
                    "--owner",
                    "seanchatmangpt",
                    "--expected-repositories",
                    "5",
                    "--hydrate",
                    "all",
                    "--output",
                    str(output),
                    "--receipt",
                    str(receipt),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("AUTOFDE_SEMANTIC_CENSUS_ALIVE", completed.stdout)
            self.assertEqual(json.loads(receipt.read_text())["standing"], "ALIVE")


if __name__ == "__main__":
    unittest.main()
