#!/usr/bin/env python3
"""Bounded verifier for the canonical AutoFDE ontology and ggen contract."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

from rdflib import Graph, Literal, Namespace, RDF, RDFS, URIRef
from rdflib.namespace import OWL

ROOT = Path(__file__).resolve().parents[1]
AUTOFDE = Namespace("https://seanchatmangpt.github.io/autofde/ontology#")

sys.path.insert(0, str(ROOT / "scripts"))
from render_reference import check_artifacts, load_config, load_graph, render_all  # noqa: E402


class VerificationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def count(graph: Graph, rdf_type: URIRef) -> int:
    return sum(1 for _ in graph.subjects(RDF.type, rdf_type))


def source_bundle_paths() -> list[str]:
    manifest = ROOT / "ontology/source-bundle.txt"
    return [line.strip() for line in manifest.read_text(encoding="utf-8").splitlines() if line.strip()]


def verify_files(config: dict[str, Any]) -> None:
    required = [
        "README.md",
        "AGENTS.md",
        "ontology/source-bundle.txt",
        *source_bundle_paths(),
        "ontology/shapes.ttl",
        "ontology/bootstrap-to-breach.ttl",
        "ontology/bootstrap-project.ttl",
        "ontology/bootstrap-runtime.ttl",
        "ggen.toml",
    ]
    for relative in required:
        require((ROOT / relative).is_file(), f"missing required file: {relative}")

    for gate in config["validation"]["gates"]:
        require((ROOT / gate).is_file(), f"missing law gate: {gate}")
    for rule in config["generation"]["rules"]:
        require(rule.get("mode") == "Overwrite", f"rule {rule['name']} must use Overwrite")
        require((ROOT / rule["query"]["file"]).is_file(), f"missing query for {rule['name']}")
        require((ROOT / rule["template"]["file"]).is_file(), f"missing template for {rule['name']}")
        require(rule["output_file"].startswith("generated/"), f"output escapes generated/: {rule['output_file']}")


def verify_identity(graph: Graph) -> None:
    ontology = URIRef("https://seanchatmangpt.github.io/autofde/ontology")
    require((ontology, RDF.type, OWL.Ontology) in graph, "canonical ontology IRI missing")
    require((ontology, OWL.versionInfo, Literal("0.1.0")) in graph, "ontology version mismatch")
    require((ontology, AUTOFDE.executionMode, AUTOFDE.ExploitOnly) in graph, "ontology is not ExploitOnly")
    require((AUTOFDE.AutoFDE, AUTOFDE.executionMode, AUTOFDE.ExploitOnly) in graph, "product is not ExploitOnly")

    forbidden = re.compile(r"explor", re.IGNORECASE)
    for subject, predicate, obj in graph:
        for term in (subject, predicate):
            if isinstance(term, URIRef) and str(term).startswith(str(AUTOFDE)):
                require(not forbidden.search(str(term).split("#")[-1]), f"forbidden mode term: {term}")
        if predicate in {RDFS.label, AUTOFDE.identifier} and isinstance(obj, Literal):
            require(not forbidden.search(str(obj)), f"forbidden mode label: {obj}")


def verify_coverage(graph: Graph) -> dict[str, int]:
    metrics = {
        "classes": count(graph, OWL.Class),
        "object_properties": count(graph, OWL.ObjectProperty),
        "datatype_properties": count(graph, OWL.DatatypeProperty),
        "annotation_properties": count(graph, OWL.AnnotationProperty),
        "modules": count(graph, AUTOFDE.CapabilityModule),
        "phases": count(graph, AUTOFDE.Phase),
        "standing_codes": count(graph, AUTOFDE.StandingCode),
        "refusal_codes": count(graph, AUTOFDE.RefusalCode),
        "generation_rules": count(graph, AUTOFDE.GenerationRule),
        "competency_questions": count(graph, AUTOFDE.CompetencyQuestion),
    }
    minimums = {
        "classes": 80,
        "object_properties": 65,
        "datatype_properties": 25,
        "annotation_properties": 6,
        "modules": 9,
        "phases": 9,
        "standing_codes": 7,
        "refusal_codes": 10,
        "generation_rules": 4,
        "competency_questions": 10,
    }
    for key, expected in minimums.items():
        require(metrics[key] >= expected, f"ontology surface too small: {key}={metrics[key]} < {expected}")
    return metrics


def gate_has_violation(graph: Graph, path: Path) -> bool:
    query = path.read_text(encoding="utf-8")
    result = graph.query(query)
    answer = getattr(result, "askAnswer", None)
    if answer is None:
        raise VerificationError(f"gate is not ASK: {path.relative_to(ROOT)}")
    return bool(answer)


def verify_gates(graph: Graph, config: dict[str, Any]) -> None:
    for relative in config["validation"]["gates"]:
        path = ROOT / relative
        require(not gate_has_violation(graph, path), f"law gate found violation: {relative}")


def verify_query_determinism(config: dict[str, Any], graph: Graph) -> None:
    for rule in config["generation"]["rules"]:
        query_path = ROOT / rule["query"]["file"]
        query = query_path.read_text(encoding="utf-8")
        require("ORDER BY" in query.upper(), f"query lacks deterministic ORDER BY: {query_path}")
        rows = list(graph.query(query))
        require(bool(rows), f"generation anchor query is empty: {query_path}")


def verify_config_matches_ontology(graph: Graph, config: dict[str, Any]) -> None:
    graph_rules = {
        str(identifier): {
            "query": str(next(graph.objects(rule, AUTOFDE.hasQuery))),
            "template": str(next(graph.objects(rule, AUTOFDE.hasTemplate))),
            "output": str(next(graph.objects(rule, AUTOFDE.hasOutput))),
            "mode": str(next(graph.objects(rule, AUTOFDE.generationMode))),
        }
        for rule in graph.subjects(RDF.type, AUTOFDE.GenerationRule)
        for identifier in graph.objects(rule, AUTOFDE.identifier)
    }
    config_rules = {rule["name"]: rule for rule in config["generation"]["rules"]}
    require(set(graph_rules) == set(config_rules), "ggen.toml and ontology generation-rule identities differ")
    for name, rule in config_rules.items():
        require(graph_rules[name]["mode"] == rule["mode"], f"generation mode mismatch: {name}")


def source_bundle_digest(config: dict[str, Any]) -> str:
    digest = hashlib.sha256()
    for relative in source_bundle_paths():
        encoded_path = relative.encode("utf-8")
        content = (ROOT / relative).read_bytes()
        digest.update(len(encoded_path).to_bytes(4, "big"))
        digest.update(encoded_path)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def verify_exact_internal_digest(graph: Graph, config: dict[str, Any]) -> None:
    actual = source_bundle_digest(config)
    values = [str(value) for value in graph.objects(AUTOFDE.AutoFDEOntologyDigest, AUTOFDE.digestValue)]
    require(values == [actual], f"internal source-bundle digest mismatch: graph={values} actual={actual}")


def verify_shape_contract(graph: Graph) -> None:
    # Directly enforce the high-consequence subset even when pySHACL is absent.
    for hook in graph.subjects(RDF.type, AUTOFDE.KnowledgeHook):
        require(list(graph.objects(hook, AUTOFDE.mayActuate)) == [Literal(False)], f"hook may actuate: {hook}")
        require(any(graph.objects(hook, AUTOFDE.manufacturesIntent)), f"hook has no manufactured intent: {hook}")
    for action in graph.subjects(RDF.type, AUTOFDE.Actuation):
        require(any(graph.objects(action, AUTOFDE.routedThroughBroker)), f"actuation has no broker: {action}")
        require(any(graph.objects(action, AUTOFDE.hasPreActuationReceipt)), f"actuation has no open receipt: {action}")
        require(any(graph.subjects(AUTOFDE.authorizes, action)), f"actuation has no authority intersection: {action}")
    orders = [int(value) for phase in graph.subjects(RDF.type, AUTOFDE.Phase) for value in graph.objects(phase, AUTOFDE.order)]
    require(len(orders) == len(set(orders)), "phase orders are not unique")


def verify_generated(config: dict[str, Any], graph: Graph) -> list[dict[str, Any]]:
    first = render_all(graph, config)
    second = render_all(graph, config)
    require(
        {item.output_file: item.content for item in first} == {item.output_file: item.content for item in second},
        "reference render is nondeterministic",
    )
    drift = check_artifacts(first)
    require(not drift, "generated drift: " + ", ".join(drift))
    return [
        {
            "path": item.output_file,
            "sha256": hashlib.sha256(item.content).hexdigest(),
            "bytes": len(item.content),
        }
        for item in first
    ]


def verify_generated_artifact_syntax() -> None:
    json.loads((ROOT / "generated/autofde-modules.json").read_text(encoding="utf-8"))
    subprocess.run(
        [sys.executable, "-m", "py_compile", str(ROOT / "generated/autofde_standing.py")],
        check=True,
        cwd=ROOT,
    )
    phase_text = (ROOT / "generated/autofde-phases.yaml").read_text(encoding="utf-8")
    require(phase_text.count("  - order:") == 9, "phase projection does not contain nine phases")


def verify_shapes_parse() -> None:
    shapes = Graph()
    shapes.parse(ROOT / "ontology/shapes.ttl", format="turtle")
    SH = Namespace("http://www.w3.org/ns/shacl#")
    targets = list(shapes.triples((None, SH.targetClass, None)))
    require(len(targets) >= 12, f"insufficient SHACL targets: {len(targets)}")


def main() -> int:
    try:
        config = load_config()
        verify_files(config)
        graph = load_graph(config)
        verify_identity(graph)
        metrics = verify_coverage(graph)
        verify_gates(graph, config)
        verify_query_determinism(config, graph)
        verify_config_matches_ontology(graph, config)
        verify_exact_internal_digest(graph, config)
        verify_shape_contract(graph)
        verify_shapes_parse()
        artifacts = verify_generated(config, graph)
        verify_generated_artifact_syntax()
    except (VerificationError, Exception) as exc:
        print(f"AUTOFDE_ONTOLOGY_REFUSED:{type(exc).__name__}:{exc}", file=sys.stderr)
        return 1

    receipt = {
        "schema": "autofde.ontology-verifier-receipt.v1",
        "standing": "ALIVE",
        "subject": "ontology/autofde.ttl@0.1.0",
        "metrics": metrics,
        "artifacts": artifacts,
        "gates": config["validation"]["gates"],
    }
    print(json.dumps(receipt, indent=2, sort_keys=True))
    print("AUTOFDE_ONTOLOGY_ALIVE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
