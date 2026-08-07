#!/usr/bin/env python3
"""Bounded concurrent GitHub transport for the canonical semantic census.

Classification and parse laws remain imported from census_semantic_assets.py.
This adapter only changes transport topology: repository and blob reads execute
concurrently, then all results are deterministically sorted before receipting.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

try:
    from census_semantic_assets import (
        CensusRefusal,
        DISPOSITION_RANK,
        GitHubClient,
        SEMANTIC_EXTENSIONS,
        classify_path,
        parse_semantic_asset,
        semantic_extension,
        should_hydrate,
        write_json,
    )
except ModuleNotFoundError:  # imported as scripts.census_semantic_assets_fast
    from scripts.census_semantic_assets import (
        CensusRefusal,
        DISPOSITION_RANK,
        GitHubClient,
        SEMANTIC_EXTENSIONS,
        classify_path,
        parse_semantic_asset,
        semantic_extension,
        should_hydrate,
        write_json,
    )


def scan_fast(
    client: GitHubClient,
    owner: str,
    *,
    hydrate: str,
    expected_repositories: int | None,
    workers: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if workers < 1 or workers > 32:
        raise CensusRefusal(f"REFUSED:INVALID_WORKER_COUNT workers={workers}")
    started = time.monotonic()
    rows = client.list_owner_repositories(owner)
    resolved = []
    failures: list[dict[str, str]] = []

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(client.resolve_repository, row): row for row in rows}
        for future in as_completed(futures):
            row = futures[future]
            try:
                resolved.append(future.result())
            except Exception as exc:
                failures.append({
                    "repository": row.get("full_name", "UNKNOWN"),
                    "failure": str(exc),
                })

    repositories = []
    assets: list[dict[str, Any]] = []
    for repository in sorted(resolved, key=lambda item: item.full_name):
        repositories.append({
            "full_name": repository.full_name,
            "visibility": repository.visibility,
            "archived": repository.archived,
            "default_branch": repository.default_branch,
            "head_sha": repository.head_sha,
            "tree_sha": repository.tree_sha,
            "license_id": repository.license_id,
            "semantic_asset_count": len(repository.files),
        })
        for entry in sorted(repository.files, key=lambda item: item["path"]):
            extension = semantic_extension(entry["path"])
            if extension is None:
                continue
            disposition, action = classify_path(entry["path"], repository.archived)
            assets.append({
                "repository": repository.full_name,
                "visibility": repository.visibility,
                "default_branch": repository.default_branch,
                "head_sha": repository.head_sha,
                "tree_sha": repository.tree_sha,
                "path": entry["path"],
                "blob_sha": entry["sha"],
                "size": int(entry.get("size") or 0),
                "extension": extension,
                "media_type": SEMANTIC_EXTENSIONS[extension],
                "license_id": repository.license_id,
                "disposition": disposition,
                "errc_action": action,
                "authority_ceiling": "CONSTRUCT",
                "parse": {"standing": "UNKNOWN", "namespaces": []},
            })

    def hydrate_asset(index: int) -> tuple[int, dict[str, Any]]:
        asset = assets[index]
        try:
            content = client.blob_content(asset["repository"], asset["blob_sha"])
            return index, {
                "sha256": hashlib.sha256(content).hexdigest(),
                "parse": parse_semantic_asset(asset["extension"], content),
            }
        except Exception as exc:
            return index, {
                "parse": {
                    "standing": "BLOCKED",
                    "error": str(exc)[:1000],
                    "namespaces": [],
                }
            }

    indexes = [
        index for index, asset in enumerate(assets)
        if should_hydrate(asset["disposition"], hydrate)
    ]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for index, update in pool.map(hydrate_asset, indexes):
            assets[index].update(update)

    for asset in assets:
        if (
            asset["disposition"] == "CANONICAL_CANDIDATE"
            and asset["license_id"] in {"", "NOASSERTION", "OTHER", None}
        ):
            asset["errc_action"] = "RAISE"
            asset["admission_issue"] = "REFUSED:LICENSE_NOT_ADMITTED"
        if (
            asset["disposition"] == "CANONICAL_CANDIDATE"
            and asset["parse"]["standing"] == "BUILD_BROKEN"
        ):
            asset["errc_action"] = "RAISE"
            asset["admission_issue"] = "REFUSED:SEMANTIC_PARSE_FAILED"

    assets.sort(key=lambda item: (item["repository"], item["path"]))
    failures.sort(key=lambda item: item["repository"])
    digest_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for asset in assets:
        if asset.get("sha256"):
            digest_groups[asset["sha256"]].append(asset)

    duplicate_groups = []
    for digest, group in sorted(digest_groups.items()):
        if len(group) < 2:
            continue
        preferred = min(group, key=lambda item: (
            DISPOSITION_RANK.get(item["disposition"], 99),
            item["repository"],
            item["path"],
        ))
        duplicates = []
        for asset in group:
            if asset is preferred:
                continue
            asset["duplicate_of"] = f"{preferred['repository']}:{preferred['path']}"
            if asset["disposition"] != "CANONICAL_CANDIDATE":
                asset["errc_action"] = "ELIMINATE"
            duplicates.append(f"{asset['repository']}:{asset['path']}")
        duplicate_groups.append({
            "sha256": digest,
            "preferred": f"{preferred['repository']}:{preferred['path']}",
            "duplicates": sorted(duplicates),
        })

    claims: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for asset in assets:
        if asset["disposition"] == "CANONICAL_CANDIDATE":
            for iri in asset["parse"].get("ontology_iris", []):
                claims[iri].append(asset)
    collisions = []
    for iri, group in sorted(claims.items()):
        digests = {asset.get("sha256") for asset in group} - {None}
        if len(digests) <= 1:
            continue
        members = sorted(f"{asset['repository']}:{asset['path']}" for asset in group)
        collisions.append({"namespace": iri, "assets": members})
        for asset in group:
            asset["errc_action"] = "RAISE"
            asset["admission_issue"] = "REFUSED:NAMESPACE_COLLISION"

    observed = len(repositories)
    complete = expected_repositories is None or observed == expected_repositories
    standing = "ALIVE"
    if failures or not complete or any(
        asset["parse"]["standing"] == "BLOCKED" for asset in assets
    ):
        standing = "PARTIAL_ALIVE"
    corpus = {
        "schema": "autofde.semantic-census.v1",
        "owner": owner,
        "extensions": sorted(SEMANTIC_EXTENSIONS),
        "repositories": repositories,
        "assets": assets,
        "duplicate_groups": duplicate_groups,
        "namespace_collisions": collisions,
    }
    encoded = json.dumps(corpus, sort_keys=True, separators=(",", ":")).encode()
    receipt = {
        "schema": "autofde.semantic-census-receipt.v1",
        "standing": standing,
        "owner": owner,
        "expected_repositories": expected_repositories,
        "observed_repositories": observed,
        "listed_repositories": len(rows),
        "repository_inventory_complete": complete,
        "repository_failures": failures,
        "semantic_assets": len(assets),
        "hydrated_assets": sum(
            asset["parse"]["standing"] != "UNKNOWN" for asset in assets
        ),
        "parse_failures": sum(
            asset["parse"]["standing"] == "BUILD_BROKEN" for asset in assets
        ),
        "canonical_candidates": sum(
            asset["disposition"] == "CANONICAL_CANDIDATE" for asset in assets
        ),
        "errc": {
            action: sum(asset["errc_action"] == action for asset in assets)
            for action in ("ELIMINATE", "REDUCE", "RAISE", "CREATE")
        },
        "duplicate_groups": len(duplicate_groups),
        "namespace_collisions": len(collisions),
        "github_api_calls": client.calls,
        "workers": workers,
        "corpus_sha256": hashlib.sha256(encoded).hexdigest(),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "authority_ceiling": "SELECT",
    }
    return corpus, receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--owner", default="seanchatmangpt")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--hydrate", choices=("none", "source", "all"), default="source")
    parser.add_argument("--expected-repositories", type=int)
    parser.add_argument("--workers", type=int, default=20)
    parser.add_argument("--api-url", default=os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    args = parser.parse_args(argv)
    try:
        corpus, receipt = scan_fast(
            GitHubClient(os.environ.get("GITHUB_TOKEN"), args.api_url),
            args.owner,
            hydrate=args.hydrate,
            expected_repositories=args.expected_repositories,
            workers=args.workers,
        )
        write_json(args.output, corpus)
        write_json(args.receipt, receipt)
        print(json.dumps(receipt, sort_keys=True))
        print(f"AUTOFDE_SEMANTIC_CENSUS_{receipt['standing']}")
        return 0
    except CensusRefusal as exc:
        refusal = {
            "schema": "autofde.semantic-census-receipt.v1",
            "standing": str(exc).split()[0],
            "error": str(exc),
        }
        write_json(args.receipt, refusal)
        print(json.dumps(refusal, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
