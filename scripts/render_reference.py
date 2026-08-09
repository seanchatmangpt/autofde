#!/usr/bin/env python3
"""Independent correspondence verifier for AutoFDE's ggen projections.

`ggen` is the sole manufacturer. This module never replaces ggen in the
v26.8.8 frontmatter/pack architecture: it independently re-reads the admitted
RDF and checks the generated clap noun-verb artifacts already on disk. The
legacy declarative-generation mode remains supported for older exact subjects.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from jinja2 import Environment, FileSystemLoader, StrictUndefined
from rdflib import BNode, Graph, Literal, Namespace, RDF, RDFS, URIRef

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "ggen.toml"
CNV = Namespace("http://seanchatmangpt.github.io/packs/clap-noun-verb#")


class Row(dict[str, Any]):
    """Dictionary with attribute access, matching Tera row ergonomics."""

    def __getattr__(self, key: str) -> Any:
        try:
            return self[key]
        except KeyError as exc:
            raise AttributeError(key) from exc


def term_value(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, Literal):
        native = value.toPython()
        return native if isinstance(native, (bool, int, float)) else str(native)
    if isinstance(value, (URIRef, BNode)):
        return str(value)
    return value


def query_rows(graph: Graph, query: str) -> list[Row]:
    result = graph.query(query)
    variables = [str(variable) for variable in result.vars]
    return [
        Row({name: term_value(value) for name, value in zip(variables, result_row)})
        for result_row in result
    ]


def load_config() -> dict[str, Any]:
    with CONFIG.open("rb") as handle:
        return tomllib.load(handle)


def _parse_once(graph: Graph, seen: set[Path], path: Path) -> None:
    resolved = path.resolve()
    if resolved in seen:
        return
    graph.parse(resolved, format="turtle")
    seen.add(resolved)


def load_graph(config: dict[str, Any]) -> Graph:
    graph = Graph()
    seen: set[Path] = set()
    ontology = config["ontology"]
    for relative in [ontology["source"], *ontology.get("imports", [])]:
        _parse_once(graph, seen, ROOT / relative)

    # v26.8.8 frontmatter mode: independently materialize the same semantic
    # inputs declared by the single pack reference. The workflow has already
    # checked out the exact pack revision beside this repository.
    for pack in config.get("packs", {}).values():
        pack_root = (ROOT / pack["path"]).resolve()
        pack_ontology = pack_root / "ontology.ttl"
        if pack_ontology.exists():
            _parse_once(graph, seen, pack_ontology)
        for relative in pack.get("extra_ontologies", []):
            _parse_once(graph, seen, ROOT / relative)
    return graph


@dataclass(frozen=True)
class RenderedArtifact:
    rule: str
    output_file: str
    content: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()


def render_legacy(graph: Graph, config: dict[str, Any]) -> list[RenderedArtifact]:
    environment = Environment(
        loader=FileSystemLoader(str(ROOT)),
        undefined=StrictUndefined,
        autoescape=False,
        keep_trailing_newline=True,
        trim_blocks=False,
        lstrip_blocks=False,
    )
    environment.globals["sparql"] = lambda query: query_rows(graph, query)

    rendered: list[RenderedArtifact] = []
    for rule in config["generation"]["rules"]:
        query_spec = rule["query"]
        query_text = (
            (ROOT / query_spec["file"]).read_text(encoding="utf-8")
            if "file" in query_spec
            else query_spec["inline"]
        )
        anchor_rows = query_rows(graph, query_text)
        if not anchor_rows and not rule.get("skip_empty", True):
            raise RuntimeError(f"generation rule {rule['name']} has an empty anchor query")
        if not anchor_rows and rule.get("skip_empty", True):
            continue
        template = environment.get_template(rule["template"]["file"])
        rendered.append(
            RenderedArtifact(
                rule=rule["name"],
                output_file=rule["output_file"],
                content=template.render(rows=anchor_rows).encode("utf-8"),
            )
        )
    return rendered


def write_artifacts(artifacts: Iterable[RenderedArtifact], root: Path = ROOT) -> None:
    for artifact in artifacts:
        destination = root / artifact.output_file
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(artifact.content)


def check_artifacts(artifacts: Iterable[RenderedArtifact], root: Path = ROOT) -> list[str]:
    return [
        artifact.output_file
        for artifact in artifacts
        if not (root / artifact.output_file).exists()
        or (root / artifact.output_file).read_bytes() != artifact.content
    ]


def _snake(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9]+", "_", value)
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return value.strip("_").lower()


def _compact(value: str) -> str:
    return "".join(value.split())


def check_pack_projection(graph: Graph, config: dict[str, Any]) -> list[str]:
    packs = config.get("packs", {})
    if list(packs) != ["clap-noun-verb-pack"]:
        return [f"pack-set:{','.join(packs)}"]

    routes_path = ROOT / "src/clap_noun_verb_routes.rs"
    docs_path = ROOT / "docs/clap_noun_verb_routes.md"
    proof_path = ROOT / "tests/clap_noun_verb_sparql_derived_proof.rs"
    for path in (routes_path, docs_path, proof_path, ROOT / "ggen.lock"):
        if not path.is_file() or path.stat().st_size == 0:
            return [str(path.relative_to(ROOT))]

    routes = routes_path.read_text(encoding="utf-8")
    docs = docs_path.read_text(encoding="utf-8")
    compact_routes = _compact(routes)
    drift: list[str] = []

    commands: list[tuple[str, str, str, str, str, str, str | None]] = []
    for subject in graph.subjects(RDF.type, CNV.Command):
        noun = str(graph.value(subject, CNV.noun) or "")
        verb = str(graph.value(subject, CNV.verb) or "")
        handler = str(graph.value(subject, CNV.handler) or "")
        doc = str(graph.value(subject, CNV.doc) or "")
        return_type = str(graph.value(subject, CNV.returnType) or "")
        args = str(graph.value(subject, CNV.args) or "")
        static = graph.value(subject, CNV.staticResponse)
        commands.append(
            (noun, verb, handler, doc, return_type, args, None if static is None else str(static))
        )

    for noun, verb, handler, doc, return_type, args, static in sorted(commands):
        key = f"{noun}:{verb}"
        expected = [
            f'#[verb("{verb}", "{noun}")]',
            f"fn {_snake(noun)}_{_snake(verb)}(",
            f"/// {doc}",
            f") -> Result<{return_type}> ",
        ]
        for needle in expected:
            if needle not in routes:
                drift.append(f"route:{key}:{needle}")

        for spec in filter(None, args.split("@@")):
            parts = spec.split("|", 3)
            if len(parts) < 3:
                drift.append(f"args:{key}:malformed:{spec}")
                continue
            field, rust_type, required = parts[:3]
            semantic = (
                f"{field}:{rust_type}"
                if required == "true"
                else f"{field}:Option<{rust_type}>"
            )
            if _compact(semantic) not in compact_routes:
                drift.append(f"args:{key}:{semantic}")

        if static is None:
            if f"crate::verbs::handlers::{handler}(" not in routes:
                drift.append(f"handler:{key}:{handler}")
        elif _compact(f"Ok({static})") not in compact_routes:
            drift.append(f"static:{key}")

        row = f"| `{noun}` | `{verb}` | `{handler}` | {doc} |"
        if row not in docs:
            drift.append(f"docs:{key}")

    for subject in graph.subjects(RDF.type, CNV.Noun):
        noun = str(graph.value(subject, RDFS.label) or "")
        about = str(graph.value(subject, RDFS.comment) or "")
        if f"REGISTER_{noun.upper()}_NOUN" not in routes:
            drift.append(f"noun:{noun}:registration")
        if about and f'"{about}"' not in routes:
            drift.append(f"noun:{noun}:about")

    return drift


def pack_receipt(config: dict[str, Any]) -> dict[str, Any]:
    paths = [
        "src/clap_noun_verb_routes.rs",
        "docs/clap_noun_verb_routes.md",
        "tests/clap_noun_verb_sparql_derived_proof.rs",
        "ggen.lock",
    ]
    return {
        "schema": "autofde.reference-correspondence-receipt.v2",
        "mode": "independent-pack-verifier",
        "packs": sorted(config.get("packs", {})),
        "artifacts": [
            {
                "path": path,
                "sha256": hashlib.sha256((ROOT / path).read_bytes()).hexdigest(),
                "bytes": (ROOT / path).stat().st_size,
            }
            for path in paths
        ],
    }


def deterministic_receipt(graph: Graph, config: dict[str, Any]) -> dict[str, Any]:
    first = render_legacy(graph, config)
    second = render_legacy(graph, config)
    if {x.output_file: x.content for x in first} != {x.output_file: x.content for x in second}:
        raise RuntimeError("reference generation is nondeterministic")
    return {
        "schema": "autofde.reference-generation-receipt.v1",
        "artifacts": [
            {
                "rule": artifact.rule,
                "path": artifact.output_file,
                "sha256": artifact.sha256,
                "bytes": len(artifact.content),
            }
            for artifact in first
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--receipt", action="store_true")
    args = parser.parse_args()

    config = load_config()
    graph = load_graph(config)

    if "generation" in config:
        artifacts = render_legacy(graph, config)
        if args.write:
            write_artifacts(artifacts)
        elif args.check:
            drift = check_artifacts(artifacts)
            if drift:
                print("REFUSED:GENERATED_DRIFT " + ",".join(drift))
                return 2
        else:
            print(json.dumps(deterministic_receipt(graph, config), indent=2, sort_keys=True))
        for artifact in artifacts:
            print(
                f"GENERATED {artifact.output_file} sha256={artifact.sha256} "
                f"bytes={len(artifact.content)}"
            )
        return 0

    # v26.8.8: ggen is the sole manufacturer; this independent verifier may
    # check or receipt its consequences, but refuses to manufacture them.
    if args.write:
        print("REFUSED:REFERENCE_RENDERER_NOT_MANUFACTURER")
        return 3
    drift = check_pack_projection(graph, config)
    if drift:
        print("REFUSED:PACK_PROJECTION_DRIFT " + ",".join(drift))
        return 2
    if args.receipt:
        print(json.dumps(pack_receipt(config), indent=2, sort_keys=True))
    else:
        print("REFERENCE_CORRESPONDENCE_ALIVE mode=independent-pack-verifier")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
