#!/usr/bin/env python3
"""Verify the privacy-preserving exact private semantic census receipt."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RECEIPT_PATH = ROOT / "corpus/private-semantic-census-receipt.json"
PROFILE_PATH = ROOT / "corpus/admission-profile.json"

SEMANTIC_EXTENSIONS = [
    ".json-ld", ".jsonld", ".n3", ".nq", ".nt", ".owl", ".rdf",
    ".rq", ".shacl", ".sparql", ".trig", ".trix", ".ttl",
]
CLASSIFICATION_ORDER = [
    "ARCHIVE:ELIMINATE",
    "VENDOR:ELIMINATE",
    "GENERATED_PROJECTION:ELIMINATE",
    "VALIDATION_FIXTURE:REDUCE",
    "EXAMPLE:REDUCE",
    "CANONICAL_CANDIDATE:CREATE",
    "COMPATIBILITY_REFERENCE:REDUCE",
]
FORBIDDEN_PRIVATE_KEYS = {
    "repositories", "repository_names", "repository_name", "paths", "path",
    "tree_shas", "tree_sha", "default_branches", "default_branch",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class PrivateCensusRefusal(ValueError):
    """Typed refusal for an invalid private-census standing claim."""


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def scan_profile() -> dict[str, Any]:
    return {
        "semantic_extensions": SEMANTIC_EXTENSIONS,
        "classification_order": CLASSIFICATION_ORDER,
        "truncation_policy": "recursive_walk_or_refuse",
        "evidence_model": "recursive_git_tree_commitment",
    }


def _refuse(reason: str) -> None:
    raise PrivateCensusRefusal(f"PRIVATE_CENSUS_REFUSED:{reason}")


def _walk_keys(value: object) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            keys.add(str(key))
            keys.update(_walk_keys(child))
    elif isinstance(value, list):
        for child in value:
            keys.update(_walk_keys(child))
    return keys


def validate_private_census(
    receipt: dict[str, Any], admission_profile: dict[str, Any]
) -> dict[str, Any]:
    if receipt.get("schema") != "autofde.private-semantic-census-receipt.v1":
        _refuse("SCHEMA")
    if receipt.get("standing") != "ALIVE":
        _refuse("STANDING")
    if receipt.get("owner") != "seanchatmangpt":
        _refuse("OWNER")
    if receipt.get("visibility") != "private":
        _refuse("VISIBILITY")
    if receipt.get("authority_ceiling") != "SELECT":
        _refuse("AUTHORITY_CEILING")
    if receipt.get("source_transport") != "github_connector_git_tree":
        _refuse("SOURCE_TRANSPORT")
    if receipt.get("evidence_model") != "recursive_git_tree_commitment":
        _refuse("EVIDENCE_MODEL")

    expected_counts = {
        "repository_inventory": 75,
        "repositories_scanned": 75,
        "materialized_recursive_trees": 71,
        "empty_repositories": 4,
        "truncated_trees": 0,
        "repository_failures": 0,
    }
    for key, expected in expected_counts.items():
        if receipt.get(key) != expected:
            _refuse(f"{key.upper()} expected={expected} observed={receipt.get(key)!r}")

    if receipt.get("file_level_complete") is not True:
        _refuse("FILE_LEVEL_INCOMPLETE")
    if receipt.get("names_redacted") is not True:
        _refuse("NAMES_NOT_REDACTED")
    if receipt.get("paths_redacted") is not True:
        _refuse("PATHS_NOT_REDACTED")
    if receipt.get("semantic_extensions") != SEMANTIC_EXTENSIONS:
        _refuse("SEMANTIC_EXTENSION_DRIFT")

    leaked = sorted(_walk_keys(receipt) & FORBIDDEN_PRIVATE_KEYS)
    if leaked:
        _refuse(f"PRIVATE_IDENTIFIERS_EXPOSED keys={leaked}")

    repository_commitment = receipt.get("repository_tree_commitment_sha256")
    if not isinstance(repository_commitment, str) or not SHA256_RE.fullmatch(repository_commitment):
        _refuse("REPOSITORY_TREE_COMMITMENT")

    expected_scan_profile_sha = hashlib.sha256(canonical_json(scan_profile())).hexdigest()
    if receipt.get("scan_profile_sha256") != expected_scan_profile_sha:
        _refuse("SCAN_PROFILE_DIGEST")

    census = admission_profile.get("census", {})
    if census.get("owned_repository_count") != 340:
        _refuse("OWNED_REPOSITORY_COUNT")
    if census.get("public_repository_rows") != 265:
        _refuse("PUBLIC_REPOSITORY_COUNT")
    if census.get("private_repository_count") != 75:
        _refuse("PRIVATE_REPOSITORY_COUNT")
    if census["public_repository_rows"] + receipt["repository_inventory"] != census["owned_repository_count"]:
        _refuse("OWNER_PARTITION")

    return {
        "schema": "autofde.private-semantic-census-verifier-receipt.v1",
        "standing": "ALIVE",
        "repositories": receipt["repository_inventory"],
        "recursive_trees": receipt["materialized_recursive_trees"],
        "empty_repositories": receipt["empty_repositories"],
        "truncated_trees": receipt["truncated_trees"],
        "repository_failures": receipt["repository_failures"],
        "repository_tree_commitment_sha256": repository_commitment,
        "scan_profile_sha256": expected_scan_profile_sha,
        "authority_ceiling": "SELECT",
    }


def main() -> int:
    receipt = json.loads(RECEIPT_PATH.read_text(encoding="utf-8"))
    profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    verified = validate_private_census(receipt, profile)
    print(json.dumps(verified, indent=2, sort_keys=True))
    print(
        "AUTOFDE_PRIVATE_CENSUS_ALIVE "
        f"repositories={verified['repositories']} "
        f"trees={verified['recursive_trees']} "
        f"empty={verified['empty_repositories']} "
        f"commitment={verified['repository_tree_commitment_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
