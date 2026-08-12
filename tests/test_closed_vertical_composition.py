from __future__ import annotations

import hashlib
import json
import tempfile
import unittest

from autofde.manufacturing import (
    MANUFACTURE_RECEIPT_SCHEMA,
    MANUFACTURE_VALIDATOR,
    REQUIRED_MANUFACTURE_COURTS,
    CapabilityRequirement,
    ManufactureRequest,
    ManufacturerReceipt,
    admit_manufactured_bundle,
    manifest_for_payloads,
)
from autofde.observations import AdmittedClaim, Observation, ObservationLedger
from autofde.reflex import CompiledReflex, ManufacturedFastPath, ReflexRefusal, ReflexRefusalCode
from autofde.runtime import (
    AuthorityEnvelope,
    BRCEBroker,
    OccurrenceState,
    RuntimeStore,
    Standing,
)


LAB_SHA = "d6951f863613ed8840638801b0411549ffce9601"
GGEN_SHA = "2aed979b92e4b68226208988420173154c663539"
SUBJECT = "/subscriptions/test/resourceGroups/rg/providers/Microsoft.SecurityInsights/incidents/42"
SCOPE = "subscription:test/resource-group:rg"
PROPERTY = "urn:autofde:sentinel:classification"
VALUE = {"classification": "BenignPositive"}
CONSEQUENCE = "sentinel.incident.close"


def _canonical_json(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()


def _sha256_json(value) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value)).hexdigest()


def _admit_o_star(path: str) -> AdmittedClaim:
    ledger = ObservationLedger(path)
    for sensor, digest in (("arm-read", "a" * 64), ("sentinel-read", "b" * 64)):
        ledger.append(
            Observation(
                sensor_id=sensor,
                subject=SUBJECT,
                property_iri=PROPERTY,
                value=VALUE,
                observed_at="2026-08-11T20:00:00+00:00",
                scope=SCOPE,
                evidence_digest=digest,
            )
        )
    return ledger.admit_current(
        subject=SUBJECT,
        property_iri=PROPERTY,
        scope=SCOPE,
        now="2026-08-11T20:00:05+00:00",
        max_age_seconds=30,
        required_sensors=("arm-read", "sentinel-read"),
    )


def _requirement() -> CapabilityRequirement:
    return CapabilityRequirement(
        name="sentinel-benign-close",
        subject="sentinel-incident",
        consequence=CONSEQUENCE,
        verifier="independent-sentinel-postcondition",
        target_environment="azure",
        semantic_types=("urn:autofde:Capability", "urn:autofde:AzureConsequence"),
    )


def _request(claim: AdmittedClaim) -> ManufactureRequest:
    return ManufactureRequest.from_admitted_claim(
        claim,
        requirement=_requirement(),
        lab_revision=LAB_SHA,
        ggen_revision=GGEN_SHA,
    )


def _receipt(request: ManufactureRequest, manifest) -> ManufacturerReceipt:
    payload = {
        "schema": MANUFACTURE_RECEIPT_SCHEMA,
        "standing": "ALIVE",
        "authority_class": "CONSTRUCT",
        "do_authority": False,
        "validator": MANUFACTURE_VALIDATOR,
        "request_id": request.request_id,
        "request_digest": request.request_digest,
        "manifest_digest": manifest.manifest_digest,
        "artifact_set_digest": manifest.artifact_set_digest,
        "lab_revision": request.lab_revision,
        "ggen_revision": request.ggen_revision,
        "courts": list(REQUIRED_MANUFACTURE_COURTS),
    }
    payload["receipt_digest"] = _sha256_json(payload)
    return ManufacturerReceipt.from_payload(payload)


def _match_payload(claim: AdmittedClaim, **extra) -> bytes:
    payload = {
        "schema": "autofde.compiled-reflex/1",
        "subject": claim.subject,
        "scope": claim.scope,
        "property_iri": claim.property_iri,
        "equals": claim.value,
        "consequence": CONSEQUENCE,
        **extra,
    }
    return _canonical_json(payload)


def _manufacture_and_pin(store: RuntimeStore, claim: AdmittedClaim, *, match: bytes | None = None):
    request = _request(claim)
    match = _match_payload(claim) if match is None else match
    payloads = {
        "bundle/match.json": match,
        "bundle/authority.json": b'{"mode":"external-only","do_authority":false}',
        "bundle/verifier.json": b'{"kind":"independent-sentinel-postcondition"}',
    }
    manifest = manifest_for_payloads(
        request,
        artifacts=tuple((path, "application/json", body) for path, body in payloads.items()),
    )
    bundle = admit_manufactured_bundle(
        request,
        manifest,
        _receipt(request, manifest),
        artifact_payloads=payloads,
        store=store,
    )
    return request, manifest, match, bundle


class _World:
    def __init__(self) -> None:
        self.status = "Active"


class _Actuator:
    def __init__(self, world: _World) -> None:
        self.world = world
        self.calls = 0

    def actuate(self, payload):
        self.calls += 1
        self.world.status = "Closed"
        return {"accepted": True, "claim_id": payload["claim_id"]}


class _IndependentVerifier:
    def __init__(self, world: _World) -> None:
        self.world = world
        self.calls = 0

    def verify(self, _payload, _result) -> bool:
        self.calls += 1
        return self.world.status == "Closed"


class ClosedVerticalCompositionTests(unittest.TestCase):
    def test_o_to_o_star_to_manufacture_pin_to_brce_verify_and_replay(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            claim = _admit_o_star(f"{tmp}/observations.db")
            store = RuntimeStore(f"{tmp}/runtime.db")
            request, manifest, match, bundle = _manufacture_and_pin(store, claim)
            reflex = CompiledReflex.from_verified_bundle(
                request=request,
                manifest=manifest,
                match_artifact=match,
                bundle=bundle,
                store=store,
            )

            world = _World()
            actuator = _Actuator(world)
            verifier = _IndependentVerifier(world)
            authority = AuthorityEnvelope(
                envelope_id="test-authority",
                subject=claim.subject,
                allowed_consequences=frozenset({CONSEQUENCE}),
                capability_digest=bundle.digest,
            )
            fast_path = ManufacturedFastPath(BRCEBroker(store))

            first = fast_path.execute(
                reflex,
                claim,
                authority=authority,
                actuator=actuator,
                verifier=verifier,
            )
            self.assertEqual(first.state, OccurrenceState.VERIFIED)
            self.assertEqual(first.standing, Standing.ALIVE)
            self.assertEqual(world.status, "Closed")
            self.assertEqual(actuator.calls, 1)
            self.assertEqual(verifier.calls, 1)
            self.assertEqual(
                store.receipt_kinds(first.occurrence_id),
                ["PRE_ACTUATION", "POSTCONDITION_VERIFIED"],
            )

            replay = fast_path.execute(
                reflex,
                claim,
                authority=authority,
                actuator=actuator,
                verifier=verifier,
            )
            self.assertEqual(replay.occurrence_id, first.occurrence_id)
            self.assertEqual(replay.state, OccurrenceState.VERIFIED)
            self.assertEqual(actuator.calls, 1, "replay must not re-actuate")
            self.assertEqual(verifier.calls, 1, "terminal replay must not manufacture new evidence")

    def test_wrong_authority_refuses_before_zero_actuation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            claim = _admit_o_star(f"{tmp}/observations.db")
            store = RuntimeStore(f"{tmp}/runtime.db")
            request, manifest, match, bundle = _manufacture_and_pin(store, claim)
            reflex = CompiledReflex.from_verified_bundle(
                request=request,
                manifest=manifest,
                match_artifact=match,
                bundle=bundle,
                store=store,
            )
            world = _World()
            actuator = _Actuator(world)
            verifier = _IndependentVerifier(world)
            result = ManufacturedFastPath(BRCEBroker(store)).execute(
                reflex,
                claim,
                authority=AuthorityEnvelope(
                    envelope_id="wrong-authority",
                    subject=claim.subject,
                    allowed_consequences=frozenset(),
                    capability_digest=bundle.digest,
                ),
                actuator=actuator,
                verifier=verifier,
            )
            self.assertEqual(result.state, OccurrenceState.REFUSED)
            self.assertEqual(result.standing, Standing.REFUSED)
            self.assertIn("REFUSED:AUTHORITY", result.refusal or "")
            self.assertEqual(actuator.calls, 0)
            self.assertEqual(verifier.calls, 0)
            self.assertEqual(world.status, "Active")

    def test_match_artifact_tamper_and_authority_smuggling_refuse(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            claim = _admit_o_star(f"{tmp}/observations.db")
            store = RuntimeStore(f"{tmp}/runtime.db")
            request, manifest, match, bundle = _manufacture_and_pin(store, claim)

            with self.assertRaises(ReflexRefusal) as tamper:
                CompiledReflex.from_verified_bundle(
                    request=request,
                    manifest=manifest,
                    match_artifact=match + b" ",
                    bundle=bundle,
                    store=store,
                )
            self.assertEqual(tamper.exception.code, ReflexRefusalCode.ARTIFACT_TAMPER)

        with tempfile.TemporaryDirectory() as tmp:
            claim = _admit_o_star(f"{tmp}/observations.db")
            store = RuntimeStore(f"{tmp}/runtime.db")
            smuggled = _match_payload(claim, authority_ref="ambient-admin")
            request, manifest, match, bundle = _manufacture_and_pin(store, claim, match=smuggled)
            with self.assertRaises(ReflexRefusal) as caught:
                CompiledReflex.from_verified_bundle(
                    request=request,
                    manifest=manifest,
                    match_artifact=match,
                    bundle=bundle,
                    store=store,
                )
            self.assertEqual(caught.exception.code, ReflexRefusalCode.AUTHORITY_SMUGGLING)

    def test_near_miss_claim_refuses_before_work_item_or_brce(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            claim = _admit_o_star(f"{tmp}/observations.db")
            store = RuntimeStore(f"{tmp}/runtime.db")
            request, manifest, match, bundle = _manufacture_and_pin(store, claim)
            reflex = CompiledReflex.from_verified_bundle(
                request=request,
                manifest=manifest,
                match_artifact=match,
                bundle=bundle,
                store=store,
            )
            near_miss = AdmittedClaim(
                subject=claim.subject,
                property_iri=claim.property_iri,
                value={"classification": "TruePositive"},
                scope=claim.scope,
                observation_ids=("c" * 64,),
                admitted_at=claim.admitted_at,
            )
            with self.assertRaises(ReflexRefusal) as caught:
                reflex.work_item(near_miss)
            self.assertEqual(caught.exception.code, ReflexRefusalCode.OUTSIDE_ENVELOPE)
            self.assertIsNone(store.get_by_key("reflex:" + "0" * 64))


if __name__ == "__main__":
    unittest.main()
