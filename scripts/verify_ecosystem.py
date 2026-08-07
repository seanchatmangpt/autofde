#!/usr/bin/env python3
"""Verify the AutoFDE ecosystem corpus, ERRC profile, and federation receipts."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from rdflib import Dataset, Namespace, RDF

ROOT = Path(__file__).resolve().parents[1]
AUTOFDE = Namespace("https://seanchatmangpt.github.io/autofde/ontology#")
OWL = Namespace("http://www.w3.org/2002/07/owl#")


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


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
    assets = set(dataset.subjects(RDF.type, AUTOFDE.SemanticAsset))

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
    if len(assets) != 31:
        raise SystemExit(f"ECOSYSTEM_REFUSED semantic_assets={len(assets)}")

    canonical = {
        asset for asset in assets
        if (asset, AUTOFDE.sourceDisposition, AUTOFDE.CanonicalSourceDisposition) in dataset
    }
    quarantined = {
        asset for asset in assets
        if (asset, AUTOFDE.sourceDisposition, AUTOFDE.QuarantineDisposition) in dataset
    }
    if len(canonical) != 17 or len(quarantined) != 14:
        raise SystemExit(
            f"ECOSYSTEM_REFUSED federation_partition canonical={len(canonical)} "
            f"quarantined={len(quarantined)}"
        )
    for asset in assets:
        ceilings = {str(value) for value in dataset.objects(asset, AUTOFDE.authorityCeiling)}
        if ceilings != {"CONSTRUCT"}:
            raise SystemExit(f"ECOSYSTEM_REFUSED authority_ceiling asset={asset} values={ceilings}")
    for asset in canonical:
        if not list(dataset.objects(asset, AUTOFDE.hasDigest)):
            raise SystemExit(f"ECOSYSTEM_REFUSED canonical_digest asset={asset}")
        if not list(dataset.objects(asset, AUTOFDE.licenseId)):
            raise SystemExit(f"ECOSYSTEM_REFUSED canonical_license asset={asset}")
        if not list(dataset.objects(asset, AUTOFDE.namespaceIRI)):
            raise SystemExit(f"ECOSYSTEM_REFUSED canonical_namespace asset={asset}")
        if {str(value) for value in dataset.objects(asset, AUTOFDE.parseStanding)} != {"ALIVE"}:
            raise SystemExit(f"ECOSYSTEM_REFUSED canonical_parse asset={asset}")

    gate_path = ROOT / "queries/gates/ecosystem-admission.rq"
    if bool(dataset.query(gate_path.read_text(encoding="utf-8")).askAnswer):
        raise SystemExit("ECOSYSTEM_REFUSED admission_gate_open")

    expected = int(next(dataset.objects(AUTOFDE.ChatmanEcosystemCorpus, AUTOFDE.expectedRepositoryCount)))
    observed = int(next(dataset.objects(AUTOFDE.ChatmanEcosystemCorpus, AUTOFDE.observedRepositoryCount)))
    if expected != 340 or observed != 340:
        raise SystemExit(f"ECOSYSTEM_REFUSED repository_inventory expected={expected} observed={observed}")

    profile_path = ROOT / "corpus/admission-profile.json"
    admitted_path = ROOT / "corpus/admitted-sources.json"
    federation_receipt_path = ROOT / "corpus/semantic-federation-receipt.json"
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    admitted = json.loads(admitted_path.read_text(encoding="utf-8"))
    federation_receipt = json.loads(federation_receipt_path.read_text(encoding="utf-8"))
    if profile["mode"] != "EXPLOIT_ONLY" or profile["authority_ceiling"] != "CONSTRUCT":
        raise SystemExit("ECOSYSTEM_REFUSED profile_authority")
    if profile["census"]["owned_repository_count"] != 340:
        raise SystemExit("ECOSYSTEM_REFUSED profile_inventory")
    if len(admitted["sources"]) != 31:
        raise SystemExit("ECOSYSTEM_REFUSED admitted_source_count")
    if federation_receipt["standing"] != "ALIVE":
        raise SystemExit("ECOSYSTEM_REFUSED federation_receipt")
    if federation_receipt["create_sources"] != 17 or federation_receipt["create_alive"] != 17:
        raise SystemExit("ECOSYSTEM_REFUSED create_receipt")
    profile_sha = hashlib.sha256(canonical_json(profile)).hexdigest()
    if federation_receipt["profile_sha256"] != profile_sha:
        raise SystemExit("ECOSYSTEM_REFUSED profile_digest")
    ttl_path = ROOT / "ontology/ecosystem-sources.ttl"
    if federation_receipt["ttl_sha256"] != hashlib.sha256(ttl_path.read_bytes()).hexdigest():
        raise SystemExit("ECOSYSTEM_REFUSED ttl_digest")
    if federation_receipt["federation_sha256"] != hashlib.sha256(canonical_json(admitted)).hexdigest():
        raise SystemExit("ECOSYSTEM_REFUSED federation_digest")

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
        "schema": "autofde.ecosystem-verifier-receipt.v2",
        "subject": "ontology/ecosystem-sources.ttl@0.1.0",
        "standing": "ALIVE",
        "metrics": {
            "repository_inventory": observed,
            "semantic_repositories": len(repositories),
            "semantic_assets": len(assets),
            "canonical_sources": len(canonical),
            "quarantined_sources": len(quarantined),
            "source_dispositions": len(dispositions),
            "errc_actions": len(actions),
            "semantic_dialects": len(dialects),
            "errc_decisions": len(decisions),
            "classes": class_count,
            "object_properties": object_property_count,
            "datatype_properties": datatype_property_count,
        },
        "artifacts": [
            {
                "path": str(catalog_path.relative_to(ROOT)),
                "sha256": hashlib.sha256(catalog_path.read_bytes()).hexdigest(),
                "bytes": catalog_path.stat().st_size,
            },
            {
                "path": str(ttl_path.relative_to(ROOT)),
                "sha256": hashlib.sha256(ttl_path.read_bytes()).hexdigest(),
                "bytes": ttl_path.stat().st_size,
            },
        ],
        "authority_ceiling": "CONSTRUCT",
    }
    print(json.dumps(receipt, indent=2, sort_keys=True))
    print("AUTOFDE_ECOSYSTEM_ALIVE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
