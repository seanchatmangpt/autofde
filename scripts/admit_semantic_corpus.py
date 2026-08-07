#!/usr/bin/env python3
"""Manufacture the admitted AutoFDE semantic federation from an ERRC profile.

The profile is the bounded O* selection over the account-wide census. CREATE
sources are fetched from exact public commit identities, parsed, hashed, and
federated. RAISE sources remain provenance-preserving quarantine records.
No source receives DO authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from rdflib import Graph, OWL, RDF, URIRef
from rdflib.plugins.sparql.parser import parseQuery, parseUpdate

ADMITTED_LICENSES = {
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "CC0-1.0",
    "MPL-2.0", "EPL-2.0", "LGPL-2.1-only", "LGPL-3.0-only",
}
RDF_FORMATS = {
    ".ttl": "turtle", ".nt": "nt", ".nq": "nquads", ".trig": "trig",
    ".rdf": "xml", ".owl": "xml", ".jsonld": "json-ld",
    ".json-ld": "json-ld", ".n3": "n3", ".shacl": "turtle",
    ".trix": "trix",
}
SPARQL_EXTENSIONS = {".rq", ".sparql"}
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
AUTOFDE = "https://seanchatmangpt.github.io/autofde/ontology#"


class AdmissionRefusal(RuntimeError):
    pass


@dataclass(frozen=True)
class MaterializedSource:
    profile: dict[str, Any]
    sha256: str | None
    parse_standing: str
    ontology_iris: tuple[str, ...]
    triple_count: int | None
    error: str | None = None


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def exact_raw_url(source: dict[str, Any]) -> str:
    owner, repo = source["repository"].split("/", 1)
    path = "/".join(urllib.parse.quote(part, safe="") for part in source["path"].split("/"))
    return (
        f"https://raw.githubusercontent.com/{urllib.parse.quote(owner, safe='')}/"
        f"{urllib.parse.quote(repo, safe='')}/{source['commit_sha']}/{path}"
    )


def default_fetch(source: dict[str, Any]) -> bytes:
    request = urllib.request.Request(
        exact_raw_url(source),
        headers={"User-Agent": "autofde-semantic-admission/0.1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        raise AdmissionRefusal(
            f"REFUSED:SOURCE_HTTP repository={source['repository']} path={source['path']} "
            f"status={exc.code} body={body[:300]}"
        ) from exc
    except urllib.error.URLError as exc:
        raise AdmissionRefusal(
            f"REFUSED:SOURCE_TRANSPORT repository={source['repository']} "
            f"path={source['path']} reason={exc}"
        ) from exc


def parse_source(path: str, content: bytes) -> tuple[str, tuple[str, ...], int | None]:
    lowered = path.lower()
    extension = next(
        (ext for ext in sorted((*RDF_FORMATS, *SPARQL_EXTENSIONS), key=len, reverse=True)
         if lowered.endswith(ext)),
        None,
    )
    if extension is None:
        raise AdmissionRefusal(f"REFUSED:UNKNOWN_SEMANTIC_DIALECT path={path}")
    text = content.decode("utf-8", "strict")
    if extension in SPARQL_EXTENSIONS:
        try:
            parseQuery(text)
        except Exception as query_error:
            try:
                parseUpdate(text)
            except Exception as update_error:
                raise AdmissionRefusal(
                    f"REFUSED:SEMANTIC_PARSE_FAILED path={path} "
                    f"query={query_error} update={update_error}"
                ) from update_error
        return "ALIVE", (), None
    graph = Graph()
    formats = [RDF_FORMATS[extension]]
    if extension == ".owl":
        formats.append("turtle")
    last_error: Exception | None = None
    for rdf_format in formats:
        try:
            graph.parse(data=content, format=rdf_format)
            ontology_iris = tuple(sorted(
                str(subject) for subject in graph.subjects(RDF.type, OWL.Ontology)
                if isinstance(subject, URIRef)
            ))
            return "ALIVE", ontology_iris, len(graph)
        except Exception as exc:
            last_error = exc
    raise AdmissionRefusal(
        f"REFUSED:SEMANTIC_PARSE_FAILED path={path} reason={last_error}"
    )


def validate_profile(profile: dict[str, Any]) -> None:
    if profile.get("schema") != "autofde.ecosystem-admission-profile.v1":
        raise AdmissionRefusal("REFUSED:PROFILE_SCHEMA")
    if profile.get("mode") != "EXPLOIT_ONLY":
        raise AdmissionRefusal("REFUSED:NON_EXPLOIT_MODE")
    if profile.get("authority_ceiling") != "CONSTRUCT":
        raise AdmissionRefusal("REFUSED:AMBIENT_AUTHORITY")
    seen: set[tuple[str, str]] = set()
    for source in profile.get("sources", []):
        key = (source.get("repository", ""), source.get("path", ""))
        if not all(key) or key in seen:
            raise AdmissionRefusal(f"REFUSED:DUPLICATE_OR_EMPTY_SOURCE identity={key!r}")
        seen.add(key)
        if source.get("errc_action") not in {"CREATE", "RAISE"}:
            raise AdmissionRefusal(f"REFUSED:INVALID_ERRC_ACTION identity={key!r}")
        if source.get("authority_ceiling") != "CONSTRUCT":
            raise AdmissionRefusal(f"REFUSED:AMBIENT_AUTHORITY identity={key!r}")
        for field in ("commit_sha", "tree_sha", "blob_sha"):
            if not SHA1_RE.fullmatch(str(source.get(field, ""))):
                raise AdmissionRefusal(
                    f"REFUSED:IDENTITY_DRIFT identity={key!r} field={field}"
                )
        expected = source.get("expected_sha256")
        if expected is not None and not SHA256_RE.fullmatch(str(expected)):
            raise AdmissionRefusal(f"REFUSED:DIGEST_FORMAT identity={key!r}")
        if source["errc_action"] == "CREATE":
            if source.get("visibility") != "public":
                raise AdmissionRefusal(f"REFUSED:PRIVATE_CREATE identity={key!r}")
            if source.get("license_id") not in ADMITTED_LICENSES:
                raise AdmissionRefusal(f"REFUSED:LICENSE_NOT_ADMITTED identity={key!r}")


def materialize(
    profile: dict[str, Any],
    fetch: Callable[[dict[str, Any]], bytes] = default_fetch,
    *,
    hydrate_create: bool,
) -> list[MaterializedSource]:
    validate_profile(profile)
    result: list[MaterializedSource] = []
    for source in sorted(profile["sources"], key=lambda item: (item["repository"], item["path"])):
        if source["errc_action"] != "CREATE" or not hydrate_create:
            result.append(MaterializedSource(
                profile=source,
                sha256=source.get("expected_sha256"),
                parse_standing=source.get("observed_parse_standing", "UNKNOWN"),
                ontology_iris=tuple(source.get("observed_ontology_iris", [])),
                triple_count=None,
            ))
            continue
        content = fetch(source)
        digest = hashlib.sha256(content).hexdigest()
        expected = source.get("expected_sha256")
        if expected is not None and digest != expected:
            raise AdmissionRefusal(
                f"REFUSED:IDENTITY_DRIFT repository={source['repository']} "
                f"path={source['path']} expected={expected} observed={digest}"
            )
        standing, ontology_iris, triple_count = parse_source(source["path"], content)
        result.append(MaterializedSource(
            profile=source,
            sha256=digest,
            parse_standing=standing,
            ontology_iris=ontology_iris,
            triple_count=triple_count,
        ))
    return result


def safe_fragment(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", value).strip("-").lower()


def source_iri(source: dict[str, Any]) -> str:
    key = hashlib.sha256(
        f"{source['repository']}\0{source['path']}\0{source['blob_sha']}".encode()
    ).hexdigest()[:20]
    return f"{AUTOFDE}FederatedSource-{key}"


def repository_iri(repository: str) -> str:
    return f"{AUTOFDE}Repository-{safe_fragment(repository)}"


def ttl_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def render_ttl(profile: dict[str, Any], materialized: list[MaterializedSource]) -> str:
    lines = [
        "@prefix autofde: <https://seanchatmangpt.github.io/autofde/ontology#> .",
        "@prefix dcat: <http://www.w3.org/ns/dcat#> .",
        "@prefix dcterms: <http://purl.org/dc/terms/> .",
        "@prefix owl: <http://www.w3.org/2002/07/owl#> .",
        "@prefix prov: <http://www.w3.org/ns/prov#> .",
        "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .",
        "@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .",
        "",
        "<https://seanchatmangpt.github.io/autofde/ontology/ecosystem-sources>",
        "    a owl:Ontology ;",
        "    dcterms:title \"AutoFDE admitted ecosystem source federation\" ;",
        "    dcterms:description \"Generated from corpus/admission-profile.json; CREATE sources are exact, licensed, parsed, and digest-bound. RAISE sources remain quarantined.\" ;",
        "    owl:versionInfo \"0.1.0\" ;",
    ]
    create_imports = [exact_raw_url(item.profile) for item in materialized if item.profile["errc_action"] == "CREATE"]
    if create_imports:
        imports = sorted(create_imports)
        for index, url in enumerate(imports):
            if index == 0:
                lines.append(f"    owl:imports <{url}>")
            else:
                lines.append(f"        , <{url}>")
        lines[-1] += " ."
    else:
        lines[-1] = lines[-1].rstrip(" ;") + " ."
    lines.append("")

    repositories = sorted({item.profile["repository"] for item in materialized})
    for repository in repositories:
        visibility = next(item.profile["visibility"] for item in materialized if item.profile["repository"] == repository)
        lines.extend([
            f"<{repository_iri(repository)}>",
            "    a autofde:SemanticRepository ;",
            f"    autofde:repositoryFullName {ttl_string(repository)} ;",
            f"    autofde:visibility {ttl_string(visibility)} .",
            "",
        ])

    namespace_claims: dict[str, list[MaterializedSource]] = {}
    for item in materialized:
        source = item.profile
        iri = source_iri(source)
        disposition = (
            "autofde:CanonicalSourceDisposition"
            if source["errc_action"] == "CREATE" and item.parse_standing == "ALIVE" and item.sha256
            else "autofde:QuarantineDisposition"
        )
        action = f"autofde:{source['errc_action'].title()}"
        exact_url = exact_raw_url(source)
        namespace_iris = item.ontology_iris or ((exact_url,) if source["errc_action"] == "CREATE" else ())
        lines.extend([
            f"<{iri}>",
            "    a autofde:SemanticAsset, prov:Entity, dcat:Distribution ;",
            f"    autofde:sourceRepository <{repository_iri(source['repository'])}> ;",
            f"    autofde:assetPath {ttl_string(source['path'])} ;",
            f"    autofde:resolvedCommit {ttl_string(source['commit_sha'])} ;",
            f"    autofde:treeIdentity {ttl_string(source['tree_sha'])} ;",
            f"    autofde:blobIdentity {ttl_string(source['blob_sha'])} ;",
            f"    autofde:licenseId {ttl_string(source['license_id'])} ;",
            f"    autofde:sourceDisposition {disposition} ;",
            f"    autofde:errcAction {action} ;",
            f"    autofde:authorityCeiling {ttl_string('CONSTRUCT')} ;",
            f"    autofde:parseStanding {ttl_string(item.parse_standing)} ;",
            f"    dcat:accessURL <{exact_url}> ;",
        ])
        if item.sha256:
            digest_iri = f"{iri}-Digest"
            lines.extend([
                f"    autofde:digest {ttl_string(item.sha256)} ;",
                f"    autofde:hasDigest <{digest_iri}> ;",
            ])
        for namespace in namespace_iris:
            lines.append(f"    autofde:namespaceIRI <{namespace}> ;")
            namespace_claims.setdefault(namespace, []).append(item)
        if source["errc_action"] == "CREATE" and item.parse_standing == "ALIVE":
            lines.append("    autofde:admissionRationale \"Exact public commit, tree, blob, admitted license, successful parse, and digest closure.\" .")
        else:
            lines.append("    autofde:admissionRationale \"Quarantined until license, parse, namespace, and authority evidence close.\" .")
        if item.sha256:
            lines.extend([
                "",
                f"<{digest_iri}>",
                "    a autofde:ArtifactDigest ;",
                "    autofde:digestAlgorithm \"sha256\" ;",
                f"    autofde:digestValue {ttl_string(item.sha256)} .",
            ])
        lines.append("")

    for namespace, items in sorted(namespace_claims.items()):
        digests = {item.sha256 for item in items}
        if len(digests) > 1:
            identities = [f"{item.profile['repository']}:{item.profile['path']}" for item in items]
            raise AdmissionRefusal(
                f"REFUSED:NAMESPACE_COLLISION namespace={namespace} assets={identities}"
            )
    return "\n".join(lines).rstrip() + "\n"


def render_json(profile: dict[str, Any], materialized: list[MaterializedSource]) -> dict[str, Any]:
    sources = []
    for item in materialized:
        source = dict(item.profile)
        source.update({
            "observed_sha256": item.sha256,
            "parse_standing": item.parse_standing,
            "ontology_iris": list(item.ontology_iris),
            "triple_count": item.triple_count,
            "source_iri": source_iri(source),
            "exact_url": exact_raw_url(source),
            "standing": (
                "ALIVE" if source["errc_action"] == "CREATE" and item.parse_standing == "ALIVE" and item.sha256
                else "PARTIAL_ALIVE"
            ),
        })
        sources.append(source)
    return {
        "schema": "autofde.admitted-semantic-federation.v1",
        "mode": profile["mode"],
        "authority_ceiling": profile["authority_ceiling"],
        "profile_sha256": hashlib.sha256(canonical_json(profile)).hexdigest(),
        "census": profile["census"],
        "sources": sources,
    }


def manufacture(
    profile: dict[str, Any],
    *,
    hydrate_create: bool,
    fetch: Callable[[dict[str, Any]], bytes] = default_fetch,
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    materialized = materialize(profile, fetch, hydrate_create=hydrate_create)
    federation = render_json(profile, materialized)
    ttl = render_ttl(profile, materialized)
    create = [item for item in materialized if item.profile["errc_action"] == "CREATE"]
    raised = [item for item in materialized if item.profile["errc_action"] == "RAISE"]
    create_alive = all(item.parse_standing == "ALIVE" and item.sha256 for item in create)
    standing = "ALIVE" if hydrate_create and create_alive else "PARTIAL_ALIVE"
    receipt = {
        "schema": "autofde.semantic-federation-receipt.v1",
        "standing": standing,
        "subject": "ontology/ecosystem-sources.ttl@0.1.0",
        "profile_sha256": federation["profile_sha256"],
        "ttl_sha256": hashlib.sha256(ttl.encode()).hexdigest(),
        "federation_sha256": hashlib.sha256(canonical_json(federation)).hexdigest(),
        "sources": len(materialized),
        "create_sources": len(create),
        "create_alive": sum(item.parse_standing == "ALIVE" and bool(item.sha256) for item in create),
        "raised_sources": len(raised),
        "authority_ceiling": "CONSTRUCT",
        "mode": "EXPLOIT_ONLY",
    }
    if hydrate_create and not create_alive:
        raise AdmissionRefusal("REFUSED:CREATE_SOURCE_NOT_ALIVE")
    return ttl, federation, receipt


def write_or_check(path: Path, content: str, check: bool) -> None:
    if check:
        if not path.exists() or path.read_text(encoding="utf-8") != content:
            raise AdmissionRefusal(f"REFUSED:GENERATED_DRIFT path={path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", type=Path, default=Path("corpus/admission-profile.json"))
    parser.add_argument("--output-ttl", type=Path, required=True)
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--hydrate-create", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    try:
        profile = json.loads(args.profile.read_text(encoding="utf-8"))
        ttl, federation, receipt = manufacture(profile, hydrate_create=args.hydrate_create)
        write_or_check(args.output_ttl, ttl, args.check)
        federation_text = json.dumps(federation, indent=2, sort_keys=True) + "\n"
        write_or_check(args.output_json, federation_text, args.check)
        receipt_text = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        write_or_check(args.receipt, receipt_text, args.check)
        print(json.dumps(receipt, sort_keys=True))
        print(f"AUTOFDE_SEMANTIC_FEDERATION_{receipt['standing']}")
        return 0
    except (AdmissionRefusal, OSError, ValueError, UnicodeError) as exc:
        print(f"AUTOFDE_SEMANTIC_FEDERATION_REFUSED {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
