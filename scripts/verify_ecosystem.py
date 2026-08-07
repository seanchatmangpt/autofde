#!/usr/bin/env python3
"""Verify the AutoFDE ecosystem corpus and ERRC federation laws."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from rdflib import Dataset, Namespace, RDF

ROOT = Path(__file__).resolve().parents[1]
AUTOFDE = Namespace("https://seanchatmangpt.github.io/autofde/ontology#")
OWL = Namespace("http://www.w3.org/2002/07/owl#")


def load_graph() -> Dataset:
    dataset = Dataset()
    for raw in (ROOT / "ontology/source-bundle.txt").read_text(encoding="utf-8").splitlines():
        path = raw.strip()
        if not path or path.startswith("#"):
            continue
        dataset.parse(ROOT / path, format="turtle")
    return dataset


def catalog_count(catalog: str, surface: str) -> int:
    match = re.search(rf"^\| {re.escape(surface)} \| ([0-9]+) \|$", catalog, re.MULTILINE)
    if not match:
        raise SystemExit(f"ECOSYSTEM_REFUSED missing_catalog_surface={surface}")
    return int(match.group(1))


def main() -> int:
    dataset = load_graph()
    corpus = list(dataset.subjects(RDF.type, AUTOFDE.RepositoryCorpus))
    if corpus != [AUTOFDE.ChatmanEcosystemCorpus]:
        raise SystemExit(f"ECOSYSTEM_REFUSED corpus={corpus!r}")

    dispositions = set(dataset.subjects(RDF.type, AUTOFDE.SourceDisposition))
    actions = set(dataset.subjects(RDF.type, AUTOFDE.ERRCAction))
    dialects = set(dataset.subjects(RDF.type, AUTOFDE.SemanticDialect))
    repositories = set(dataset.subjects(RDF.type, AUTOFDE.SemanticRepository))
    decisions = set(dataset.subjects(RDF.type, AUTOFDE.ERRCDecision))

    if len(dispositions) != 7:
        raise SystemExit(f"ECOSYSTEM_REFUSED dispositions={len(dispositions)}")
    if len(actions) != 4:
        raise SystemExit(f"ECOSYSTEM_REFUSED errc_actions={len(actions)}")
    if len(dialects) < 12:
        raise SystemExit(f"ECOSYSTEM_REFUSED dialects={len(dialects)}")
    if len(repositories) < 10:
        raise SystemExit(f"ECOSYSTEM_REFUSED repositories={len(repositories)}")
    if not decisions:
        raise SystemExit("ECOSYSTEM_REFUSED missing_errc_decision")

    gate_path = ROOT / "queries/gates/ecosystem-admission.rq"
    if bool(dataset.query(gate_path.read_text(encoding="utf-8")).askAnswer):
        raise SystemExit("ECOSYSTEM_REFUSED admission_gate_open")

    expected = int(next(dataset.objects(AUTOFDE.ChatmanEcosystemCorpus, AUTOFDE.expectedRepositoryCount)))
    observed = int(next(dataset.objects(AUTOFDE.ChatmanEcosystemCorpus, AUTOFDE.observedRepositoryCount)))
    if expected != 342 or observed != 342:
        raise SystemExit(f"ECOSYSTEM_REFUSED repository_inventory expected={expected} observed={observed}")

    catalog_path = ROOT / "generated/ONTOLOGY_CATALOG.md"
    catalog = catalog_path.read_text(encoding="utf-8")
    class_count = len(set(dataset.subjects(RDF.type, OWL.Class)))
    object_property_count = len(set(dataset.subjects(RDF.type, OWL.ObjectProperty)))
    datatype_property_count = len(set(dataset.subjects(RDF.type, OWL.DatatypeProperty)))
    if catalog_count(catalog, "Classes") != class_count:
        raise SystemExit("ECOSYSTEM_REFUSED generated_class_count")
    if catalog_count(catalog, "Object properties") != object_property_count:
        raise SystemExit("ECOSYSTEM_REFUSED generated_object_property_count")
    if catalog_count(catalog, "Datatype properties") != datatype_property_count:
        raise SystemExit("ECOSYSTEM_REFUSED generated_datatype_property_count")

    receipt = {
        "schema": "autofde.ecosystem-verifier-receipt.v1",
        "subject": "ontology/ecosystem-corpus.ttl@0.1.0",
        "standing": "ALIVE",
        "metrics": {
            "repository_inventory": observed,
            "semantic_repositories": len(repositories),
            "source_dispositions": len(dispositions),
            "errc_actions": len(actions),
            "semantic_dialects": len(dialects),
            "errc_decisions": len(decisions),
            "classes": class_count,
            "object_properties": object_property_count,
            "datatype_properties": datatype_property_count,
        },
        "artifact": {
            "path": str(catalog_path.relative_to(ROOT)),
            "sha256": hashlib.sha256(catalog_path.read_bytes()).hexdigest(),
            "bytes": catalog_path.stat().st_size,
        },
        "authority_ceiling": "CONSTRUCT",
    }
    print(json.dumps(receipt, indent=2, sort_keys=True))
    print("AUTOFDE_ECOSYSTEM_ALIVE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
