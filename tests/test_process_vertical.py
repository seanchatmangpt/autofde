from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from autofde.process import AzureClosedVertical, ConformanceChecker
from autofde.runtime import AuthorityEnvelope, OccurrenceState, RuntimeStore, Standing

BUNDLE = Path(__file__).parents[1] / "capabilities" / "azure-closed-vertical.json"


class Clock:
    def __init__(self): self.n = 0
    def __call__(self):
        self.n += 1
        return f"2026-08-07T20:00:{self.n:02d}+00:00"


class World:
    def __init__(self):
        self.resources: set[str] = set(); self.apply_calls = 0; self.destroy_calls = 0


class Apply:
    def __init__(self, world: World, uncertain=False): self.world, self.uncertain = world, uncertain
    def actuate(self, payload):
        self.world.apply_calls += 1; self.world.resources.add(payload["resource_id"])
        if self.uncertain: raise RuntimeError("response lost after create")
        return {"resource_id": payload["resource_id"], "state": "present"}


class ObservePresent:
    def __init__(self, world: World): self.world = world
    def verify(self, payload, result):
        return payload["resource_id"] in self.world.resources and result["resource_id"] == payload["resource_id"]


class Destroy:
    def __init__(self, world: World): self.world = world
    def actuate(self, payload):
        self.world.destroy_calls += 1; self.world.resources.discard(payload["resource_id"])
        return {"resource_id": payload["resource_id"], "state": "absent"}


class ObserveAbsent:
    def __init__(self, world: World): self.world = world
    def verify(self, payload, result):
        return payload["resource_id"] not in self.world.resources and result["state"] == "absent"


class Sweep:
    def __init__(self, world: World, force_orphan=False): self.world, self.force_orphan = world, force_orphan
    def verify_absent(self, resource_id): return not self.force_orphan and resource_id not in self.world.resources


class ClosedVerticalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.bundle = BUNDLE.read_bytes()
        digest = hashlib.sha256(self.bundle).hexdigest()
        self.subscription = "azure:test-subscription"
        self.resource = "/subscriptions/test/resourceGroups/autofde/providers/Microsoft.Resources/deployments/closed-vertical"
        self.authority = AuthorityEnvelope(
            "authority:azure-closed-vertical-test", self.subscription,
            frozenset({"azure:terraform-apply", "azure:terraform-destroy"}), digest,
        )

    def tearDown(self): self.tmp.cleanup()

    def vertical(self):
        return AzureClosedVertical(
            store=RuntimeStore(Path(self.tmp.name) / "runtime.db"), bundle_bytes=self.bundle,
            source_repo="seanchatmangpt/autofde-lab", source_sha="6d58eb96a249182a5c54b245e219ec45032dd212",
            generator_repo="seanchatmangpt/ggen", generator_sha="a9fce3c1db64d3e6dff72f61e5dabf4d0af45e73",
            authority=self.authority, clock=Clock(),
        )

    def run_success(self):
        world, vertical = World(), self.vertical()
        result = vertical.run(
            signal_id="sentinel-001", subscription_id=self.subscription, resource_id=self.resource,
            apply_actuator=Apply(world), apply_verifier=ObservePresent(world),
            destroy_actuator=Destroy(world), destroy_verifier=ObserveAbsent(world), orphan_verifier=Sweep(world),
        )
        return world, vertical, result

    def test_episode_closes_with_ocel_conformance_replay_and_zero_orphans(self):
        world, vertical, result = self.run_success()
        self.assertEqual(result.standing, Standing.ALIVE)
        self.assertEqual((world.apply_calls, world.destroy_calls, world.resources), (1, 1, set()))
        self.assertTrue(result.conformance and result.conformance.conforms)
        self.assertEqual(len(result.ocel.events), 12)
        self.assertTrue(result.receipt and result.receipt.replay(vertical.model, result.ocel).conforms)
        self.assertEqual(vertical.store.receipt_kinds(result.apply.occurrence_id), ["PRE_ACTUATION", "POSTCONDITION_VERIFIED"])
        self.assertEqual(vertical.store.receipt_kinds(result.destroy.occurrence_id), ["PRE_ACTUATION", "POSTCONDITION_VERIFIED"])
        path = Path(self.tmp.name) / "episode.ocel.json"
        self.assertEqual(result.ocel.write(path), result.receipt.ocel_sha256)

    def test_process_mining_falsifies_out_of_order_trace(self):
        _, vertical, result = self.run_success()
        result.ocel.events[1], result.ocel.events[2] = result.ocel.events[2], result.ocel.events[1]
        check = ConformanceChecker(vertical.model).check(result.ocel)
        self.assertFalse(check.conforms)
        self.assertTrue(any(v.startswith("PREDECESSOR_VIOLATION") for v in check.violations))

    def test_uncertain_apply_is_preserved_then_independently_reconciled(self):
        world, vertical = World(), self.vertical()
        result = vertical.run(
            signal_id="sentinel-unknown", subscription_id=self.subscription, resource_id=self.resource,
            apply_actuator=Apply(world, uncertain=True), apply_verifier=ObservePresent(world),
            destroy_actuator=Destroy(world), destroy_verifier=ObserveAbsent(world), orphan_verifier=Sweep(world),
        )
        self.assertEqual(result.apply.state, OccurrenceState.UNKNOWN_RECONCILIATION)
        self.assertEqual((world.apply_calls, world.destroy_calls), (1, 0))
        observed = {"resource_id": self.resource, "state": "present"}
        reconciled = vertical.broker.reconcile("sentinel-unknown:apply", observed_result=observed, verifier=ObservePresent(world))
        self.assertEqual(reconciled.standing, Standing.ALIVE)
        self.assertEqual(world.apply_calls, 1)
        self.assertIn("RECONCILIATION_VERIFIED", vertical.store.receipt_kinds(reconciled.occurrence_id))

    def test_orphan_sweep_refuses_final_standing(self):
        world, vertical = World(), self.vertical()
        result = vertical.run(
            signal_id="sentinel-orphan", subscription_id=self.subscription, resource_id=self.resource,
            apply_actuator=Apply(world), apply_verifier=ObservePresent(world),
            destroy_actuator=Destroy(world), destroy_verifier=ObserveAbsent(world), orphan_verifier=Sweep(world, True),
        )
        self.assertEqual(result.standing, Standing.REFUSED)
        self.assertEqual(result.refusal, "REFUSED:ORPHAN_SWEEP")
        self.assertIsNone(result.receipt)


if __name__ == "__main__": unittest.main()
