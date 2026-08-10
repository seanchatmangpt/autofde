from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from autofde.autonomic import (
    AutonomicFastPath,
    AutonomicRefusal,
    PromotedHookAdmission,
)
from autofde.runtime import AuthorityEnvelope, BRCEBroker, OccurrenceState, RuntimeStore, Standing

LAB_REVISION = "a06c30f634c15aa574d0e31f0753d9361cfd01d1"
GGEN_REVISION = "b63492ef4e415f25d8fc990c003d79b7f261bfb2"


def canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def promotion() -> dict[str, object]:
    return {
        "schema": "urn:autofde-lab:knowledge-hook-promotion:v1",
        "standing": "CANDIDATE",
        "hook_id": "urn:hook:sentinel-known-incident",
        "hook_class": "ACTUATION",
        "implementation_digest": "sha256:" + "1" * 64,
        "promotion_digest": "sha256:" + "2" * 64,
        "requires_brce": True,
        "direct_do_authority": False,
        "envelope": {
            "subjects": ["azure:subscription:test"],
            "scopes": ["azure:resource-group:rg-test"],
            "action": "azure:incident.close-known-benign",
            "policy": "urn:policy:sentinel-known-benign-v1",
            "verifier": "urn:verifier:sentinel-incident-state",
            "max_age_ticks": 5,
            "compensation": None,
        },
    }


def capability() -> dict[str, object]:
    return {
        "schema": "autofde.compiled-capability/1",
        "capability": "sentinel-known-benign-close",
        "match_all": {
            "incident_type": "KnownBenignScanner",
            "severity": "Informational",
        },
        "consequence": "azure:incident.close-known-benign",
        "program": {"kind": "noop"},
        "verifier": {"kind": "noop"},
    }


def receipt(payload: dict[str, object]) -> dict[str, object]:
    return {
        "schema": "autofde.manufacture-receipt/1",
        "standing": "ALIVE",
        "authority_class": "CONSTRUCT",
        "do_authority": False,
        "requirement_id": "req-known-benign",
        "admission_digest": "sha256:admission",
        "powl_digest": "sha256:powl",
        "lab_revision": LAB_REVISION,
        "ggen_revision": GGEN_REVISION,
        "bundle_digest": canonical_digest(payload),
        "payload_schema": "autofde.compiled-capability/1",
        "validator": "ggen:autofde-capability-bundle/1",
    }


def observation(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "observation_id": "sentinel:incident:123",
        "subject": "azure:subscription:test",
        "scope": "azure:resource-group:rg-test",
        "policy": "urn:policy:sentinel-known-benign-v1",
        "age_ticks": 1,
        "facts": {
            "incident_type": "KnownBenignScanner",
            "severity": "Informational",
        },
    }
    value.update(changes)
    return value


class RecordingActuator:
    def __init__(self) -> None:
        self.calls = 0

    def actuate(self, payload: dict[str, object]) -> dict[str, object]:
        self.calls += 1
        return {
            "incident_id": payload["observation_id"],
            "state": "Closed",
        }


class IncidentClosedVerifier:
    def verify(self, payload: dict[str, object], result: dict[str, object]) -> bool:
        return (
            result.get("incident_id") == payload.get("observation_id")
            and result.get("state") == "Closed"
        )


class AutonomicFastPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = RuntimeStore(Path(self.temp.name) / "runtime.sqlite")
        self.admission = PromotedHookAdmission(
            self.store,
            admitted_lab_revision=LAB_REVISION,
            admitted_ggen_revision=GGEN_REVISION,
        )
        self.payload = capability()
        self.hook = self.admission.admit(
            promotion(),
            self.payload,
            receipt(self.payload),
        )
        self.broker = BRCEBroker(self.store)
        self.fast_path = AutonomicFastPath(self.broker)

    def authority(self, **changes: object) -> AuthorityEnvelope:
        values: dict[str, object] = {
            "envelope_id": "authority:test-sentinel",
            "subject": "azure:subscription:test",
            "allowed_consequences": frozenset({"azure:incident.close-known-benign"}),
            "capability_digest": self.hook.capability_digest,
        }
        values.update(changes)
        return AuthorityEnvelope(**values)  # type: ignore[arg-type]

    def test_known_pattern_executes_once_through_brce_and_replays_idempotently(self) -> None:
        actuator = RecordingActuator()
        verifier = IncidentClosedVerifier()

        first = self.fast_path.execute(
            self.hook,
            observation(),
            authority=self.authority(),
            actuator=actuator,
            verifier=verifier,
        )
        second = self.fast_path.execute(
            self.hook,
            observation(),
            authority=self.authority(),
            actuator=actuator,
            verifier=verifier,
        )

        self.assertEqual(OccurrenceState.VERIFIED, first.state)
        self.assertEqual(Standing.ALIVE, first.standing)
        self.assertEqual(first, second)
        self.assertEqual(1, actuator.calls)
        self.assertEqual(
            ["PRE_ACTUATION", "POSTCONDITION_VERIFIED"],
            self.store.receipt_kinds(first.occurrence_id),
        )

    def test_no_live_authority_means_no_actuation(self) -> None:
        actuator = RecordingActuator()
        result = self.fast_path.execute(
            self.hook,
            observation(),
            authority=self.authority(allowed_consequences=frozenset()),
            actuator=actuator,
            verifier=IncidentClosedVerifier(),
        )
        self.assertEqual(OccurrenceState.REFUSED, result.state)
        self.assertEqual(Standing.REFUSED, result.standing)
        self.assertIn("REFUSED:AUTHORITY", result.refusal or "")
        self.assertEqual(0, actuator.calls)

    def test_out_of_envelope_and_near_miss_patterns_never_reach_brce(self) -> None:
        attacks = [
            observation(subject="azure:subscription:other"),
            observation(scope="azure:resource-group:other"),
            observation(policy="urn:policy:other"),
            observation(age_ticks=6),
            observation(facts={"incident_type": "KnownBenignScanner", "severity": "High"}),
        ]
        for attack in attacks:
            with self.subTest(attack=attack), self.assertRaisesRegex(
                AutonomicRefusal,
                "REFUSED:OUTSIDE_PROMOTED_ENVELOPE",
            ):
                self.fast_path.construct(self.hook, attack)

    def test_lab_and_ggen_revision_drift_are_refused_before_pinning(self) -> None:
        cases = [
            ("lab_revision", "wrong"),
            ("ggen_revision", "wrong"),
        ]
        for field, wrong in cases:
            manufactured = receipt(self.payload)
            manufactured[field] = wrong
            with self.subTest(field=field), self.assertRaises(AutonomicRefusal):
                self.admission.admit(promotion(), self.payload, manufactured)

    def test_bundle_tamper_is_refused_before_pinning(self) -> None:
        manufactured = receipt(self.payload)
        tampered = copy.deepcopy(self.payload)
        tampered["consequence"] = "azure:subscription.delete"
        with self.assertRaisesRegex(AutonomicRefusal, "REFUSED:BUNDLE_DIGEST_MISMATCH"):
            self.admission.admit(promotion(), tampered, manufactured)

    def test_promotion_cannot_smuggle_do_or_bypass_brce(self) -> None:
        for field, value, refusal in [
            ("direct_do_authority", True, "REFUSED:DIRECT_DO_AUTHORITY"),
            ("requires_brce", False, "REFUSED:BRCE_BYPASS"),
            ("hook_class", "CONSTRUCT", "REFUSED:HOOK_CLASS"),
        ]:
            candidate = promotion()
            candidate[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(AutonomicRefusal, refusal):
                self.admission.admit(candidate, self.payload, receipt(self.payload))

    def test_manufacturer_cannot_smuggle_do_authority(self) -> None:
        manufactured = receipt(self.payload)
        manufactured["do_authority"] = True
        with self.assertRaisesRegex(AutonomicRefusal, "REFUSED:MANUFACTURE_AUTHORITY"):
            self.admission.admit(promotion(), self.payload, manufactured)

    def test_consequence_drift_between_promotion_and_bundle_is_refused(self) -> None:
        changed = capability()
        changed["consequence"] = "azure:incident.delete"
        with self.assertRaisesRegex(AutonomicRefusal, "REFUSED:CONSEQUENCE_DRIFT"):
            self.admission.admit(promotion(), changed, receipt(changed))


if __name__ == "__main__":
    unittest.main()
