from __future__ import annotations

import hashlib
import json
import tempfile
import unittest

from autofde.observations import (
    Observation,
    ObservationLedger,
    ObservationRefusal,
    ObservationRefusalCode,
)


def digest(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


class ObservationLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.ledger = ObservationLedger(f"{self.tmp.name}/observations.db")
        self.scope = "/subscriptions/sub-1/resourceGroups/rg-1"
        self.subject = self.scope + "/providers/Microsoft.Web/sites/app-1"
        self.now = "2026-08-11T05:30:00+00:00"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def obs(
        self,
        sensor: str,
        value: object,
        *,
        at: str = "2026-08-11T05:29:50+00:00",
    ) -> Observation:
        evidence = {"sensor": sensor, "value": value, "at": at}
        return Observation(
            sensor_id=sensor,
            subject=self.subject,
            property_iri="urn:autofde:cloud:public-access",
            value=value,
            observed_at=at,
            scope=self.scope,
            evidence_digest=digest(evidence),
        )

    def test_arm_resource_projection_preserves_source_identity(self) -> None:
        raw = {
            "id": self.subject,
            "type": "Microsoft.Web/sites",
            "location": "westus2",
            "properties": {"provisioningState": "Succeeded"},
        }
        observations = Observation.from_arm_resource(
            sensor_id="azure-arm",
            resource=raw,
            observed_at="2026-08-11T05:29:50Z",
            scope=self.scope,
            evidence_digest=digest(raw),
        )
        self.assertEqual(3, len(observations))
        self.assertEqual({self.subject}, {o.subject for o in observations})
        self.assertEqual({digest(raw)}, {o.evidence_digest for o in observations})

    def test_duplicate_observation_is_idempotent_and_raw_o_is_preserved(self) -> None:
        observation = self.obs("arm", False)
        first = self.ledger.append(observation)
        second = self.ledger.append(observation)
        self.assertEqual(first, second)
        self.assertEqual(1, self.ledger.raw_count())

    def test_matching_independent_sensors_admit_o_star_and_bind_both_receipts(self) -> None:
        self.ledger.append(self.obs("arm", False))
        self.ledger.append(self.obs("network-probe", False))
        claim = self.ledger.admit_current(
            subject=self.subject,
            property_iri="urn:autofde:cloud:public-access",
            scope=self.scope,
            now=self.now,
            max_age_seconds=30,
            required_sensors=("arm", "network-probe"),
        )
        self.assertFalse(claim.value)
        self.assertEqual(2, len(claim.observation_ids))
        self.assertEqual(2, self.ledger.raw_count())
        self.assertEqual(1, self.ledger.admitted_count())

    def test_conflicting_control_and_data_plane_observations_refuse_without_overwrite(self) -> None:
        self.ledger.append(self.obs("arm", False))
        self.ledger.append(self.obs("network-probe", True))
        with self.assertRaises(ObservationRefusal) as ctx:
            self.ledger.admit_current(
                subject=self.subject,
                property_iri="urn:autofde:cloud:public-access",
                scope=self.scope,
                now=self.now,
                max_age_seconds=30,
                required_sensors=("arm", "network-probe"),
            )
        self.assertEqual(ObservationRefusalCode.OBSERVATION_CONFLICT, ctx.exception.code)
        self.assertEqual(2, self.ledger.raw_count())
        self.assertEqual(0, self.ledger.admitted_count())
        payloads = self.ledger.observation_payloads(
            subject=self.subject,
            property_iri="urn:autofde:cloud:public-access",
            scope=self.scope,
        )
        self.assertEqual({False, True}, {p["value"] for p in payloads})

    def test_absence_requires_closed_world_complete_enumeration(self) -> None:
        bad = Observation(
            sensor_id="arg-enumeration",
            subject=self.subject,
            property_iri="urn:autofde:cloud:exists",
            value=None,
            observed_at="2026-08-11T05:29:50+00:00",
            scope=self.scope,
            evidence_digest=digest({"enumerated": []}),
            absent=True,
            closed_world=False,
            coverage_complete=False,
        )
        with self.assertRaises(ObservationRefusal) as ctx:
            self.ledger.append(bad)
        self.assertEqual(ObservationRefusalCode.ABSENCE_NOT_CLOSED_WORLD, ctx.exception.code)
        self.assertEqual(0, self.ledger.raw_count())

    def test_complete_closed_world_absence_is_admissible(self) -> None:
        absence = Observation.closed_world_absence(
            sensor_id="arm-resource-group-enumeration",
            subject=self.subject,
            property_iri="urn:autofde:cloud:exists",
            observed_at="2026-08-11T05:29:50+00:00",
            scope=self.scope,
            evidence_digest=digest({"complete": True, "resources": []}),
            coverage_complete=True,
        )
        self.ledger.append(absence)
        claim = self.ledger.admit_current(
            subject=self.subject,
            property_iri="urn:autofde:cloud:exists",
            scope=self.scope,
            now=self.now,
            max_age_seconds=30,
            required_sensors=("arm-resource-group-enumeration",),
        )
        self.assertTrue(claim.absent)
        self.assertIsNone(claim.value)

    def test_stale_observation_refuses_current_state_claim(self) -> None:
        self.ledger.append(self.obs("arm", False, at="2026-08-11T05:00:00+00:00"))
        with self.assertRaises(ObservationRefusal) as ctx:
            self.ledger.admit_current(
                subject=self.subject,
                property_iri="urn:autofde:cloud:public-access",
                scope=self.scope,
                now=self.now,
                max_age_seconds=30,
            )
        self.assertEqual(ObservationRefusalCode.STALE_OBSERVATION, ctx.exception.code)

    def test_required_sensor_coverage_refuses_single_source_truth(self) -> None:
        self.ledger.append(self.obs("arm", False))
        with self.assertRaises(ObservationRefusal) as ctx:
            self.ledger.admit_current(
                subject=self.subject,
                property_iri="urn:autofde:cloud:public-access",
                scope=self.scope,
                now=self.now,
                max_age_seconds=30,
                required_sensors=("arm", "network-probe"),
            )
        self.assertEqual(ObservationRefusalCode.INSUFFICIENT_COVERAGE, ctx.exception.code)

    def test_rdfdelta_is_deterministic_and_replayable_without_withdrawing_o(self) -> None:
        self.ledger.append(self.obs("arm", False))
        claim = self.ledger.admit_current(
            subject=self.subject,
            property_iri="urn:autofde:cloud:public-access",
            scope=self.scope,
            now=self.now,
            max_age_seconds=30,
        )
        first = ObservationLedger.rdfdelta(claim)
        second = ObservationLedger.rdfdelta(claim)
        self.assertEqual(first, second)
        self.assertEqual([], first["removes"])
        replayed = ObservationLedger.replay_rdfdelta(first)
        self.assertEqual(tuple(first["adds"]), replayed)

    def test_rdfdelta_replay_refuses_attempt_to_delete_raw_observation_graph(self) -> None:
        malicious = {
            "schema": "autofde.rdfdelta/1",
            "adds": [],
            "removes": [
                {"subject": self.subject, "predicate": "x", "object": {"json": True}}
            ],
        }
        with self.assertRaises(ObservationRefusal) as ctx:
            ObservationLedger.replay_rdfdelta(malicious)
        self.assertEqual(ObservationRefusalCode.INVALID_OBSERVATION, ctx.exception.code)


if __name__ == "__main__":
    unittest.main()
