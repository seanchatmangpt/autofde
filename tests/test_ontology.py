from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

from rdflib import Graph, Literal, Namespace, RDF, URIRef

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from render_reference import load_config, load_graph, render_all  # noqa: E402
from verify_ontology import gate_has_violation, verify_coverage, verify_identity  # noqa: E402

AUTOFDE = Namespace("https://seanchatmangpt.github.io/autofde/ontology#")


class AutoFDEOntologyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = load_config()
        cls.graph = load_graph(cls.config)
        cls.gates = {Path(path).stem: ROOT / path for path in cls.config["validation"]["gates"]}

    def clone_graph(self) -> Graph:
        clone = Graph()
        for triple in self.graph:
            clone.add(triple)
        return clone

    def test_identity_and_surface(self) -> None:
        verify_identity(self.graph)
        metrics = verify_coverage(self.graph)
        self.assertGreaterEqual(metrics["classes"], 100)
        self.assertEqual(metrics["modules"], 9)
        self.assertEqual(metrics["phases"], 9)

    def test_all_law_gates_are_closed(self) -> None:
        for name, path in self.gates.items():
            with self.subTest(gate=name):
                self.assertFalse(gate_has_violation(self.graph, path))

    def test_direct_actuation_is_refused(self) -> None:
        graph = self.clone_graph()
        graph.add((AUTOFDE.UnreceiptedMutation, RDF.type, AUTOFDE.Actuation))
        self.assertTrue(gate_has_violation(graph, self.gates["actuation-through-brce"]))

    def test_hook_actuation_is_refused(self) -> None:
        graph = self.clone_graph()
        graph.set((AUTOFDE.BreachHook, AUTOFDE.mayActuate, Literal(True)))
        self.assertTrue(gate_has_violation(graph, self.gates["hooks-never-actuate"]))

    def test_second_runtime_mode_is_refused(self) -> None:
        graph = self.clone_graph()
        graph.add((AUTOFDE.AlternateMode, RDF.type, AUTOFDE.ExecutionMode))
        graph.add((AUTOFDE.AutoFDE, AUTOFDE.executionMode, AUTOFDE.AlternateMode))
        self.assertTrue(gate_has_violation(graph, self.gates["no-non-exploit-mode"]))

    def test_work_edge_cannot_become_provisioning_edge(self) -> None:
        graph = self.clone_graph()
        graph.add((AUTOFDE.WD001, AUTOFDE.provisioningPredecessor, AUTOFDE.RepositoryResource))
        self.assertTrue(gate_has_violation(graph, self.gates["work-provisioning-separated"]))

    def test_unpinned_source_is_refused(self) -> None:
        graph = self.clone_graph()
        graph.add((AUTOFDE.UnpinnedSource, RDF.type, AUTOFDE.SemanticSource))
        self.assertTrue(gate_has_violation(graph, self.gates["every-source-is-pinned"]))

    def test_unreceipted_standing_is_refused(self) -> None:
        graph = self.clone_graph()
        graph.add((AUTOFDE.BadStanding, RDF.type, AUTOFDE.StandingAssertion))
        graph.add((AUTOFDE.BadStanding, AUTOFDE.assertsStanding, AUTOFDE.ALIVE))
        self.assertTrue(gate_has_violation(graph, self.gates["every-standing-is-receipted"]))

    def test_incomplete_generation_rule_is_refused(self) -> None:
        graph = self.clone_graph()
        graph.add((AUTOFDE.BadGenerationRule, RDF.type, AUTOFDE.GenerationRule))
        graph.add((AUTOFDE.BadGenerationRule, AUTOFDE.identifier, Literal("bad")))
        self.assertTrue(gate_has_violation(graph, self.gates["every-generation-rule-is-closed"]))

    def test_reference_generation_is_byte_deterministic(self) -> None:
        first = {item.output_file: item.content for item in render_all(self.graph, self.config)}
        second = {item.output_file: item.content for item in render_all(self.graph, self.config)}
        self.assertEqual(first, second)
        self.assertEqual(set(first), {
            "generated/ONTOLOGY_CATALOG.md",
            "generated/autofde-modules.json",
            "generated/autofde_standing.py",
            "generated/autofde-phases.yaml",
        })

    def test_module_projection_is_valid_json(self) -> None:
        data = json.loads((ROOT / "generated/autofde-modules.json").read_text())
        self.assertEqual(data["execution_mode"], "EXPLOIT")
        self.assertEqual(len(data["modules"]), 9)
        self.assertEqual(data["modules"][0]["id"], "core")

    def test_projects_v2_is_not_claimed(self) -> None:
        ontology_text = (ROOT / "ontology/autofde.ttl").read_text()
        case_text = "".join(
            (ROOT / path).read_text()
            for path in (
                "ontology/bootstrap-to-breach.ttl",
                "ontology/bootstrap-project.ttl",
                "ontology/bootstrap-runtime.ttl",
            )
        )
        self.assertNotIn("ProjectsV2", ontology_text)
        self.assertNotIn("ProjectsV2", case_text)


if __name__ == "__main__":
    unittest.main()
