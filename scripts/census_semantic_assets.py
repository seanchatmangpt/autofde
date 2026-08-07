#!/usr/bin/env python3
"""Deterministic GitHub semantic-asset census for the AutoFDE corpus.

The scanner observes repository metadata and Git trees. It has no actuation path.
It emits a JSON corpus plus a machine-readable receipt. Live mode uses GitHub REST;
fixture mode is dependency-free and is the unit-test/replay boundary.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from rdflib import Graph, OWL, RDF, URIRef
from rdflib.plugins.sparql.parser import parseQuery, parseUpdate

SEMANTIC_EXTENSIONS = {
    ".ttl": "text/turtle",
    ".rq": "application/sparql-query",
    ".sparql": "application/sparql-query",
    ".nt": "application/n-triples",
    ".nq": "application/n-quads",
    ".trig": "application/trig",
    ".rdf": "application/rdf+xml",
    ".owl": "application/rdf+xml",
    ".jsonld": "application/ld+json",
    ".json-ld": "application/ld+json",
    ".n3": "text/n3",
    ".shacl": "text/turtle",
    ".trix": "application/trix",
}
RDF_FORMATS = {
    ".ttl": "turtle",
    ".nt": "nt",
    ".nq": "nquads",
    ".trig": "trig",
    ".rdf": "xml",
    ".owl": "xml",
    ".jsonld": "json-ld",
    ".json-ld": "json-ld",
    ".n3": "n3",
    ".shacl": "turtle",
    ".trix": "trix",
}
GENERATED_SEGMENTS = {"generated", "dist", "build", "target", "coverage", ".cache"}
VENDOR_SEGMENTS = {"vendor", "vendors", "third_party", "third-party", "node_modules"}
FIXTURE_SEGMENTS = {"fixture", "fixtures", "testdata", "test-data", "golden", "snapshots"}
TEST_SEGMENTS = {"test", "tests", "testing", "__tests__"}
EXAMPLE_SEGMENTS = {"example", "examples", "demo", "demos", "sample", "samples"}
ARCHIVE_SEGMENTS = {"archive", "archives", "legacy", "deprecated", "attic"}
CANONICAL_SEGMENTS = {
    "ontology", "ontologies", "vocabulary", "vocabularies", "vocab",
    "schema", "schemas", "semantic", "semantics", "rdf", "shapes",
}
DISPOSITION_RANK = {
    "CANONICAL_CANDIDATE": 0,
    "COMPATIBILITY_REFERENCE": 1,
    "VALIDATION_FIXTURE": 2,
    "EXAMPLE": 3,
    "GENERATED_PROJECTION": 4,
    "VENDOR": 5,
    "ARCHIVE": 6,
    "QUARANTINE": 7,
}


class CensusRefusal(RuntimeError):
    """Typed refusal for malformed or inadmissible scanner inputs."""


@dataclass(frozen=True)
class Repository:
    full_name: str
    visibility: str
    archived: bool
    default_branch: str
    head_sha: str
    tree_sha: str
    license_id: str
    files: tuple[dict[str, Any], ...] = field(default_factory=tuple)


class GitHubClient:
    def __init__(self, token: str | None, api_url: str = "https://api.github.com") -> None:
        self.token = token
        self.api_url = api_url.rstrip("/")
        self.calls = 0

    def get(self, path: str) -> Any:
        url = path if path.startswith("http") else f"{self.api_url}{path}"
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "autofde-semantic-census/0.1",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(url, headers=headers)
        self.calls += 1
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            raise CensusRefusal(
                f"REFUSED:GITHUB_HTTP status={exc.code} url={url} body={body[:500]}"
            ) from exc
        except urllib.error.URLError as exc:
            raise CensusRefusal(f"REFUSED:GITHUB_TRANSPORT url={url} reason={exc}") from exc

    def pages(self, path: str) -> Iterable[Any]:
        page = 1
        separator = "&" if "?" in path else "?"
        while True:
            batch = self.get(f"{path}{separator}per_page=100&page={page}")
            if not isinstance(batch, list):
                raise CensusRefusal(f"REFUSED:GITHUB_SCHEMA path={path}")
            yield from batch
            if len(batch) < 100:
                return
            page += 1

    def list_owner_repositories(self, owner: str) -> list[dict[str, Any]]:
        repositories: dict[str, dict[str, Any]] = {}
        authenticated_error: str | None = None
        if self.token:
            try:
                for repo in self.pages("/user/repos?affiliation=owner&visibility=all&sort=full_name"):
                    if repo.get("owner", {}).get("login", "").lower() == owner.lower():
                        repositories[repo["full_name"]] = repo
            except CensusRefusal as exc:
                authenticated_error = str(exc)
        for repo in self.pages(f"/users/{urllib.parse.quote(owner)}/repos?type=owner&sort=full_name"):
            repositories.setdefault(repo["full_name"], repo)
        result = [repositories[key] for key in sorted(repositories)]
        if not result:
            suffix = f" authenticated={authenticated_error}" if authenticated_error else ""
            raise CensusRefusal(f"REFUSED:NO_REPOSITORIES owner={owner}{suffix}")
        return result

    def resolve_repository(self, repo: dict[str, Any]) -> Repository:
        full_name = repo["full_name"]
        default_branch = repo.get("default_branch")
        if not default_branch:
            raise CensusRefusal(f"REFUSED:NO_DEFAULT_BRANCH repository={full_name}")
        commit = self.get(
            f"/repos/{full_name}/commits/{urllib.parse.quote(default_branch, safe='')}"
        )
        head_sha = commit["sha"]
        tree_sha = commit["commit"]["tree"]["sha"]
        license_id = (repo.get("license") or {}).get("spdx_id") or "NOASSERTION"
        tree = self.get(f"/repos/{full_name}/git/trees/{tree_sha}?recursive=1")
        entries = tree.get("tree", [])
        if tree.get("truncated"):
            entries = list(self.walk_tree(full_name, tree_sha))
        files = tuple(
            entry for entry in entries
            if entry.get("type") == "blob" and semantic_extension(entry.get("path", ""))
        )
        return Repository(
            full_name=full_name,
            visibility=repo.get("visibility") or ("private" if repo.get("private") else "public"),
            archived=bool(repo.get("archived")),
            default_branch=default_branch,
            head_sha=head_sha,
            tree_sha=tree_sha,
            license_id=license_id,
            files=files,
        )

    def walk_tree(self, full_name: str, tree_sha: str, prefix: str = "") -> Iterable[dict[str, Any]]:
        tree = self.get(f"/repos/{full_name}/git/trees/{tree_sha}")
        for entry in tree.get("tree", []):
            path = f"{prefix}/{entry['path']}" if prefix else entry["path"]
            normalized = {**entry, "path": path}
            if entry.get("type") == "tree":
                yield from self.walk_tree(full_name, entry["sha"], path)
            else:
                yield normalized

    def blob_content(self, full_name: str, blob_sha: str) -> bytes:
        blob = self.get(f"/repos/{full_name}/git/blobs/{blob_sha}")
        if blob.get("encoding") != "base64":
            raise CensusRefusal(
                f"REFUSED:BLOB_ENCODING repository={full_name} blob={blob_sha}"
            )
        return base64.b64decode(blob.get("content", ""), validate=False)


class FixtureClient:
    def __init__(self, fixture: dict[str, Any]) -> None:
        self.fixture = fixture
        self.calls = 0
        self._blobs: dict[tuple[str, str], bytes] = {}

    def list_owner_repositories(self, owner: str) -> list[dict[str, Any]]:
        repos = []
        for repo in self.fixture.get("repositories", []):
            if not repo["full_name"].startswith(f"{owner}/"):
                continue
            repos.append({
                "full_name": repo["full_name"],
                "owner": {"login": owner},
                "default_branch": repo.get("default_branch", "main"),
                "visibility": repo.get("visibility", "public"),
                "private": repo.get("visibility") == "private",
                "archived": repo.get("archived", False),
                "license": {"spdx_id": repo.get("license_id", "NOASSERTION")},
                "_fixture": repo,
            })
        return sorted(repos, key=lambda item: item["full_name"])

    def resolve_repository(self, repo: dict[str, Any]) -> Repository:
        source = repo["_fixture"]
        files = []
        for file in source.get("files", []):
            content = file["content"].encode("utf-8")
            blob_sha = file.get("blob_sha") or hashlib.sha1(
                f"blob {len(content)}\0".encode() + content
            ).hexdigest()
            self._blobs[(repo["full_name"], blob_sha)] = content
            files.append({
                "path": file["path"],
                "sha": blob_sha,
                "size": len(content),
                "type": "blob",
            })
        return Repository(
            full_name=repo["full_name"],
            visibility=repo["visibility"],
            archived=bool(repo["archived"]),
            default_branch=repo["default_branch"],
            head_sha=source.get("head_sha", "f" * 40),
            tree_sha=source.get("tree_sha", "e" * 40),
            license_id=(repo.get("license") or {}).get("spdx_id") or "NOASSERTION",
            files=tuple(files),
        )

    def blob_content(self, full_name: str, blob_sha: str) -> bytes:
        return self._blobs[(full_name, blob_sha)]


def semantic_extension(path: str) -> str | None:
    lowered = path.lower()
    for extension in sorted(SEMANTIC_EXTENSIONS, key=len, reverse=True):
        if lowered.endswith(extension):
            return extension
    return None


def classify_path(path: str, archived_repo: bool) -> tuple[str, str]:
    segments = {segment.lower() for segment in PurePosixPath(path).parts[:-1]}
    if archived_repo or segments & ARCHIVE_SEGMENTS:
        return "ARCHIVE", "ELIMINATE"
    if segments & VENDOR_SEGMENTS:
        return "VENDOR", "ELIMINATE"
    if segments & GENERATED_SEGMENTS:
        return "GENERATED_PROJECTION", "ELIMINATE"
    if segments & FIXTURE_SEGMENTS or segments & TEST_SEGMENTS:
        return "VALIDATION_FIXTURE", "REDUCE"
    if segments & EXAMPLE_SEGMENTS:
        return "EXAMPLE", "REDUCE"
    if segments & CANONICAL_SEGMENTS:
        return "CANONICAL_CANDIDATE", "CREATE"
    return "COMPATIBILITY_REFERENCE", "REDUCE"


def parse_semantic_asset(extension: str, content: bytes) -> dict[str, Any]:
    text = content.decode("utf-8", "replace")
    if extension in {".rq", ".sparql"}:
        try:
            parseQuery(text)
            return {"standing": "ALIVE", "kind": "query", "namespaces": []}
        except Exception as query_error:
            try:
                parseUpdate(text)
                return {"standing": "ALIVE", "kind": "update", "namespaces": []}
            except Exception as update_error:
                return {
                    "standing": "BUILD_BROKEN",
                    "kind": "sparql",
                    "error": f"query={query_error}; update={update_error}"[:1000],
                    "namespaces": [],
                }
    rdf_format = RDF_FORMATS.get(extension)
    if not rdf_format:
        return {"standing": "UNKNOWN", "kind": "unknown", "namespaces": []}
    graph = Graph()
    try:
        graph.parse(data=content, format=rdf_format)
    except Exception as exc:
        if extension == ".owl":
            try:
                graph.parse(data=content, format="turtle")
            except Exception:
                return {
                    "standing": "BUILD_BROKEN",
                    "kind": "rdf",
                    "error": str(exc)[:1000],
                    "namespaces": [],
                }
        else:
            return {
                "standing": "BUILD_BROKEN",
                "kind": "rdf",
                "error": str(exc)[:1000],
                "namespaces": [],
            }
    ontology_iris = sorted(
        str(subject) for subject in graph.subjects(RDF.type, OWL.Ontology)
        if isinstance(subject, URIRef)
    )
    namespaces = sorted(
        {str(namespace) for _, namespace in graph.namespaces() if str(namespace)}
    )
    return {
        "standing": "ALIVE",
        "kind": "rdf",
        "triples": len(graph),
        "ontology_iris": ontology_iris,
        "namespaces": namespaces,
    }


def should_hydrate(disposition: str, mode: str) -> bool:
    if mode == "all":
        return True
    if mode == "none":
        return False
    return disposition in {"CANONICAL_CANDIDATE", "COMPATIBILITY_REFERENCE"}


def scan(
    client: GitHubClient | FixtureClient,
    owner: str,
    hydrate: str = "source",
    expected_repositories: int | None = None,
    repository_limit: int | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    repository_rows = client.list_owner_repositories(owner)
    if repository_limit is not None:
        repository_rows = repository_rows[:repository_limit]
    repositories = []
    assets: list[dict[str, Any]] = []
    repository_failures: list[dict[str, str]] = []
    started = time.monotonic()

    for repository_row in repository_rows:
        try:
            repository = client.resolve_repository(repository_row)
        except CensusRefusal as exc:
            repository_failures.append({
                "repository": repository_row.get("full_name", "UNKNOWN"),
                "failure": str(exc),
            })
            continue
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
        for entry in repository.files:
            path = entry["path"]
            extension = semantic_extension(path)
            if extension is None:
                continue
            disposition, errc_action = classify_path(path, repository.archived)
            asset = {
                "repository": repository.full_name,
                "visibility": repository.visibility,
                "default_branch": repository.default_branch,
                "head_sha": repository.head_sha,
                "tree_sha": repository.tree_sha,
                "path": path,
                "blob_sha": entry["sha"],
                "size": int(entry.get("size") or 0),
                "extension": extension,
                "media_type": SEMANTIC_EXTENSIONS[extension],
                "license_id": repository.license_id,
                "disposition": disposition,
                "errc_action": errc_action,
                "authority_ceiling": "CONSTRUCT",
                "parse": {"standing": "UNKNOWN", "namespaces": []},
            }
            if should_hydrate(disposition, hydrate):
                try:
                    content = client.blob_content(repository.full_name, entry["sha"])
                    asset["sha256"] = hashlib.sha256(content).hexdigest()
                    asset["parse"] = parse_semantic_asset(extension, content)
                except CensusRefusal as exc:
                    asset["parse"] = {
                        "standing": "BLOCKED",
                        "error": str(exc),
                        "namespaces": [],
                    }
            if asset["license_id"] in {"", "NOASSERTION", "OTHER", None} and disposition == "CANONICAL_CANDIDATE":
                asset["errc_action"] = "RAISE"
                asset["admission_issue"] = "REFUSED:LICENSE_NOT_ADMITTED"
            if asset["parse"]["standing"] == "BUILD_BROKEN" and disposition == "CANONICAL_CANDIDATE":
                asset["errc_action"] = "RAISE"
                asset["admission_issue"] = "REFUSED:SEMANTIC_PARSE_FAILED"
            assets.append(asset)

    assets.sort(key=lambda item: (item["repository"], item["path"]))
    digest_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for asset in assets:
        if asset.get("sha256"):
            digest_groups[asset["sha256"]].append(asset)
    duplicate_groups = []
    for digest, group in sorted(digest_groups.items()):
        if len(group) < 2:
            continue
        preferred = min(
            group,
            key=lambda item: (
                DISPOSITION_RANK.get(item["disposition"], 99),
                item["repository"],
                item["path"],
            ),
        )
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
            "duplicates": duplicates,
        })

    namespace_claims: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for asset in assets:
        if asset["disposition"] != "CANONICAL_CANDIDATE":
            continue
        for namespace in asset["parse"].get("ontology_iris", []):
            namespace_claims[namespace].append(asset)
    namespace_collisions = []
    for namespace, group in sorted(namespace_claims.items()):
        digests = {asset.get("sha256") for asset in group}
        digests.discard(None)
        if len(digests) <= 1:
            continue
        members = [f"{asset['repository']}:{asset['path']}" for asset in group]
        namespace_collisions.append({"namespace": namespace, "assets": members})
        for asset in group:
            asset["errc_action"] = "RAISE"
            asset["admission_issue"] = "REFUSED:NAMESPACE_COLLISION"

    observed_repositories = len(repositories)
    repository_inventory_complete = (
        expected_repositories is None or observed_repositories == expected_repositories
    )
    hydrated = sum(1 for asset in assets if asset["parse"]["standing"] != "UNKNOWN")
    parse_failures = sum(
        1 for asset in assets if asset["parse"]["standing"] == "BUILD_BROKEN"
    )
    standing = "ALIVE"
    if (
        repository_failures
        or not repository_inventory_complete
        or any(asset["parse"]["standing"] == "BLOCKED" for asset in assets)
    ):
        standing = "PARTIAL_ALIVE"

    corpus = {
        "schema": "autofde.semantic-census.v1",
        "owner": owner,
        "extensions": sorted(SEMANTIC_EXTENSIONS),
        "repositories": repositories,
        "assets": assets,
        "duplicate_groups": duplicate_groups,
        "namespace_collisions": namespace_collisions,
    }
    canonical_json = json.dumps(corpus, sort_keys=True, separators=(",", ":")).encode()
    receipt = {
        "schema": "autofde.semantic-census-receipt.v1",
        "standing": standing,
        "owner": owner,
        "expected_repositories": expected_repositories,
        "observed_repositories": observed_repositories,
        "listed_repositories": len(repository_rows),
        "repository_inventory_complete": repository_inventory_complete,
        "repository_failures": repository_failures,
        "semantic_assets": len(assets),
        "hydrated_assets": hydrated,
        "parse_failures": parse_failures,
        "canonical_candidates": sum(
            1 for asset in assets if asset["disposition"] == "CANONICAL_CANDIDATE"
        ),
        "errc": {
            action: sum(1 for asset in assets if asset["errc_action"] == action)
            for action in ("ELIMINATE", "REDUCE", "RAISE", "CREATE")
        },
        "duplicate_groups": len(duplicate_groups),
        "namespace_collisions": len(namespace_collisions),
        "github_api_calls": getattr(client, "calls", 0),
        "corpus_sha256": hashlib.sha256(canonical_json).hexdigest(),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "authority_ceiling": "SELECT",
    }
    return corpus, receipt


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--owner", default="seanchatmangpt")
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--hydrate", choices=("none", "source", "all"), default="source")
    parser.add_argument("--expected-repositories", type=int)
    parser.add_argument("--repository-limit", type=int)
    parser.add_argument("--api-url", default=os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        if args.fixture:
            fixture = json.loads(args.fixture.read_text(encoding="utf-8"))
            client: GitHubClient | FixtureClient = FixtureClient(fixture)
        else:
            client = GitHubClient(os.environ.get("GITHUB_TOKEN"), args.api_url)
        corpus, receipt = scan(
            client,
            owner=args.owner,
            hydrate=args.hydrate,
            expected_repositories=args.expected_repositories,
            repository_limit=args.repository_limit,
        )
        write_json(args.output, corpus)
        write_json(args.receipt, receipt)
        print(json.dumps(receipt, sort_keys=True))
        print(f"AUTOFDE_SEMANTIC_CENSUS_{receipt['standing']}")
        return 0 if receipt["standing"] in {"ALIVE", "PARTIAL_ALIVE"} else 1
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
