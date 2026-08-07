from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

from rdflib import Graph, Namespace, RDF

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from admit_semantic_corpus import (  # noqa: E402
    AdmissionRefusal,
    manufacture,
    validate_profile,
)

AUTOFDE = Namespace("https://seanchatmangpt.github.io/autofde/ontology#")
CONTENT_A = b"@prefix owl: <http://www.w3.org/2002/07/owl#> . <https://example.com/a> a owl:Ontology ."
CONTENT_B = b"@prefix owl: <http://www.w3.org/2002/07/owl#> . <https://example.com/b> a owl:Ontology ."


def source(path: str, *, action: str = "CREATE", content: bytes = CONTENT_A) -> dict:
    return {
        "repository": "seanchatmangpt/example",
        "path": path,
        "visibility": "public",
        "commit_sha": "1" * 40,
        "tree_sha": "2" * 40,
        "blob_sha": "3" * 40,
        "license_id": "MIT",
        "role": "fixture",
        "errc_action": action,
        "authority_ceiling": "CONSTRUCT",
        "expected_sha256": hashlib.sha256(content).hexdigest(),
        "observed_parse_standing": "UNKNOWN",
        "observed_ontology_iris": [],
        "source_census_sha256": "4" * 64,
    }


def profile(sources: list[dict]) -> dict:
    return {
        "schema": "autofde.ecosystem-admission-profile.v1",
        "owner": "seanchatmangpt",
        "mode": "EXPLOIT_ONLY",
        "authority_ceiling": "CONSTRUCT",
        "census": {"owned_repository_count": 1},
        "errc_law": {},
        "sources": sources,
    }


class SemanticAdmissionTests(unittest.TestCase):
    def test_create_source_executes_and_is_receipted(self) -> None:
        p = profile([source("ontology/a.ttl")])
        ttl, federation, receipt = manufacture(
            p,
            hydrate_create=True,
            fetch=lambda _: CONTENT_A,
        )
        self.assertEqual(receipt["standing"], "ALIVE")
        self.assertEqual(receipt["create_alive"], 1)
        self.assertEqual(federation["sources"][0]["standing"], "ALIVE")
        graph = Graph().parse(data=ttl, format="turtle")
        assets = set(graph.subjects(RDF.type, AUTOFDE.SemanticAsset))
        self.assertEqual(len(assets), 1)
        self.assertNotIn("\"DO\"", ttl)

    def test_generated_federation_is_deterministic(self) -> None:
        p = profile([source("ontology/a.ttl")])
        first = manufacture(p, hydrate_create=True, fetch=lambda _: CONTENT_A)
        second = manufacture(p, hydrate_create=True, fetch=lambda _: CONTENT_A)
        self.assertEqual(first, second)

    def test_digest_drift_is_refused(self) -> None:
        p = profile([source("ontology/a.ttl")])
        with self.assertRaisesRegex(AdmissionRefusal, "IDENTITY_DRIFT"):
            manufacture(p, hydrate_create=True, fetch=lambda _: CONTENT_B)

    def test_non_exploit_mode_is_refused(self) -> None:
        p = profile([source("ontology/a.ttl")])
        p["mode"] = "EXPLORE"
        with self.assertRaisesRegex(AdmissionRefusal, "NON_EXPLOIT_MODE"):
            validate_profile(p)

    def test_private_create_is_refused(self) -> None:
        item = source("ontology/a.ttl")
        item["visibility"] = "private"
        with self.assertRaisesRegex(AdmissionRefusal, "PRIVATE_CREATE"):
            validate_profile(profile([item]))

    def test_raise_source_is_quarantined_without_fetch(self) -> None:
        item = source("ontology/a.ttl", action="RAISE")
        item["visibility"] = "private"
        item["license_id"] = "NOASSERTION"
        item["expected_sha256"] = None
        called = False

        def forbidden_fetch(_: dict) -> bytes:
            nonlocal called
            called = True
            raise AssertionError("RAISE source must not be fetched")

        ttl, federation, receipt = manufacture(
            profile([item]),
            hydrate_create=True,
            fetch=forbidden_fetch,
        )
        self.assertFalse(called)
        self.assertEqual(receipt["standing"], "ALIVE")
        self.assertEqual(receipt["raised_sources"], 1)
        self.assertIn("QuarantineDisposition", ttl)
        self.assertEqual(federation["sources"][0]["standing"], "PARTIAL_ALIVE")

    def test_namespace_collision_is_refused(self) -> None:
        first = source("ontology/a.ttl", content=CONTENT_A)
        second = source("ontology/b.ttl", content=CONTENT_B)
        second["blob_sha"] = "5" * 40
        colliding_b = b"@prefix owl: <http://www.w3.org/2002/07/owl#> . <https://example.com/a> a owl:Ontology ; <https://example.com/p> <https://example.com/o> ."
        second["expected_sha256"] = hashlib.sha256(colliding_b).hexdigest()

        def fetch(item: dict) -> bytes:
            return CONTENT_A if item["path"].endswith("a.ttl") else colliding_b

        with self.assertRaisesRegex(AdmissionRefusal, "NAMESPACE_COLLISION"):
            manufacture(profile([first, second]), hydrate_create=True, fetch=fetch)

    def test_real_profile_has_80_20_closure(self) -> None:
        p = json.loads((ROOT / "corpus/admission-profile.json").read_text())
        validate_profile(p)
        actions = [item["errc_action"] for item in p["sources"]]
        self.assertEqual(actions.count("CREATE"), 17)
        self.assertEqual(actions.count("RAISE"), 14)
        self.assertEqual(p["census"]["owned_repository_count"], 342)
        self.assertEqual(p["authority_ceiling"], "CONSTRUCT")


if __name__ == "__main__":
    unittest.main()
