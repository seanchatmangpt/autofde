from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest

from autofde.manufacturing import (
    MANUFACTURE_RECEIPT_SCHEMA,
    MANUFACTURE_VALIDATOR,
    REQUIRED_MANUFACTURE_COURTS,
    CapabilityRequirement,
    ManufactureRefusal,
    ManufactureRefusalCode,
    ManufacturerReceipt,
    ManufacturedBundleManifest,
    admit_manufactured_bundle,
    manifest_for_payloads,
)
from autofde.observations import AdmittedClaim
from autofde.runtime import RuntimeStore


LAB_SHA = "1db599aa38e2655f96e9dd766e5d7dcae5b1542d"
GGEN_SHA = "b757db714d617dc2a82aac021589cbe57b2a85ed"


def canonical_json(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()


def sha256_json(value) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def admitted_claim() -> AdmittedClaim:
    return AdmittedClaim(
        subject="/subscriptions/test/resourceGroups/rg/providers/Microsoft.SecurityInsights/incidents/42",
        property_iri="urn:autofde:sentinel:classification",
        value={"classification": "BenignPositive"},
        scope="subscription:test/resource-group:rg",
        observation_ids=("a" * 64, "b" * 64),
        admitted_at="2026-08-11T20:00:00+00:00",
    )


def requirement() -> CapabilityRequirement:
    return CapabilityRequirement(
        name="sentinel-benign-close",
        subject="sentinel-incident",
        consequence="sentinel.incident.close",
        verifier="azure-arm-postcondition",
        target_environment="azure",
        semantic_types=("urn:autofde:Capability", "urn:autofde:AzureConsequence"),
    )


def make_request():
    from autofde.manufacturing import ManufactureRequest

    return ManufactureRequest.from_admitted_claim(
        admitted_claim(),
        requirement=requirement(),
        lab_revision=LAB_SHA,
        ggen_revision=GGEN_SHA,
    )


def receipt_for(request, manifest) -> ManufacturerReceipt:
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
    payload["receipt_digest"] = sha256_json(payload)
    return ManufacturerReceipt.from_payload(payload)


class ManufactureBridgeTests(unittest.TestCase):
    def payloads_and_manifest(self):
        request = make_request()
        payloads = {
            "bundle/match.json": b'{"predicate":"classification=BenignPositive"}',
            "bundle/authority.json": b'{"mode":"external-only","do_authority":false}',
            "bundle/verifier.json": b'{"kind":"azure-arm-postcondition"}',
        }
        manifest = manifest_for_payloads(
            request,
            artifacts=tuple((path, "application/json", body) for path, body in payloads.items()),
        )
        return request, payloads, manifest

    def test_request_is_deterministic_structured_and_pins_exact_hardened_ggen(self) -> None:
        first = make_request()
        second = make_request()
        self.assertEqual(first.request_id, second.request_id)
        self.assertEqual(first.request_digest, second.request_digest)
        self.assertEqual(first.to_bytes(), second.to_bytes())
        payload = first.canonical_payload()
        self.assertEqual(payload["rdfdelta"]["schema"], "autofde.rdfdelta/1")
        self.assertEqual(payload["authority"], {"mode": "external-only", "do_authority": False})
        self.assertEqual(payload["manufacturer"]["revision"], GGEN_SHA)
        self.assertNotIn("hcl", first.to_bytes().decode().lower())

    def test_candidate_manifest_has_no_standing_or_authority(self) -> None:
        _, _, manifest = self.payloads_and_manifest()
        payload = manifest.canonical_payload()
        self.assertNotIn("standing", payload)
        self.assertNotIn("authority", payload)
        self.assertFalse(hasattr(manifest, "standing"))
        self.assertFalse(hasattr(manifest, "do_authority"))

    def test_valid_external_manufacturer_receipt_is_replayed_before_pin(self) -> None:
        request, payloads, manifest = self.payloads_and_manifest()
        receipt = receipt_for(request, manifest)
        with tempfile.TemporaryDirectory() as tmp:
            store = RuntimeStore(f"{tmp}/runtime.db")
            bundle = admit_manufactured_bundle(
                request,
                manifest,
                receipt,
                artifact_payloads=payloads,
                store=store,
            )
            self.assertTrue(store.is_pinned(bundle.digest))
            self.assertEqual(bundle.source_repo, "seanchatmangpt/autofde-lab")
            self.assertEqual(bundle.source_sha, LAB_SHA)
            self.assertEqual(bundle.generated_by, "seanchatmangpt/ggen")
            self.assertEqual(bundle.generator_sha, GGEN_SHA)

    def test_receipt_is_mandatory(self) -> None:
        request, payloads, manifest = self.payloads_and_manifest()
        with tempfile.TemporaryDirectory() as tmp:
            store = RuntimeStore(f"{tmp}/runtime.db")
            with self.assertRaises((TypeError, ManufactureRefusal)):
                admit_manufactured_bundle(
                    request,
                    manifest,
                    None,
                    artifact_payloads=payloads,
                    store=store,
                )

    def test_artifact_order_does_not_change_manifest_or_bundle_identity(self) -> None:
        request = make_request()
        a = ("bundle/a.json", "application/json", b"a")
        b = ("bundle/b.json", "application/json", b"b")
        m1 = manifest_for_payloads(request, artifacts=(a, b))
        m2 = manifest_for_payloads(request, artifacts=(b, a))
        self.assertEqual(m1.manifest_digest, m2.manifest_digest)
        self.assertEqual(m1.artifact_set_digest, m2.artifact_set_digest)
        r1 = receipt_for(request, m1)
        r2 = receipt_for(request, m2)
        self.assertEqual(r1.receipt_digest, r2.receipt_digest)
        with tempfile.TemporaryDirectory() as tmp:
            s1 = RuntimeStore(f"{tmp}/one.db")
            s2 = RuntimeStore(f"{tmp}/two.db")
            payloads = {a[0]: a[2], b[0]: b[2]}
            d1 = admit_manufactured_bundle(request, m1, r1, artifact_payloads=payloads, store=s1).digest
            d2 = admit_manufactured_bundle(request, m2, r2, artifact_payloads=payloads, store=s2).digest
            self.assertEqual(d1, d2)

    def test_tampered_artifact_refuses_without_pin(self) -> None:
        request, payloads, manifest = self.payloads_and_manifest()
        receipt = receipt_for(request, manifest)
        changed = dict(payloads)
        changed["bundle/verifier.json"] = b"tampered"
        with tempfile.TemporaryDirectory() as tmp:
            store = RuntimeStore(f"{tmp}/runtime.db")
            with self.assertRaises(ManufactureRefusal) as caught:
                admit_manufactured_bundle(request, manifest, receipt, artifact_payloads=changed, store=store)
            self.assertEqual(caught.exception.code, ManufactureRefusalCode.BUNDLE_TAMPER)

    def test_revision_manifest_request_and_receipt_tamper_all_refuse(self) -> None:
        request, payloads, manifest = self.payloads_and_manifest()
        receipt = receipt_for(request, manifest)
        base_payload = receipt.canonical_payload()

        cases = []
        for field, bad in (
            ("ggen_revision", "0" * 40),
            ("lab_revision", "f" * 40),
            ("manifest_digest", "sha256:" + "0" * 64),
            ("artifact_set_digest", "sha256:" + "1" * 64),
            ("request_digest", "sha256:" + "2" * 64),
            ("validator", "forged"),
            ("standing", "UNKNOWN"),
            ("authority_class", "DO"),
            ("do_authority", True),
        ):
            forged = dict(base_payload)
            forged[field] = bad
            forged["receipt_digest"] = sha256_json({k: v for k, v in forged.items() if k != "receipt_digest"})
            cases.append((field, forged))

        forged = dict(base_payload)
        forged["courts"] = ["request_binding"]
        forged["receipt_digest"] = sha256_json({k: v for k, v in forged.items() if k != "receipt_digest"})
        cases.append(("courts", forged))

        forged = dict(base_payload)
        forged["receipt_digest"] = "sha256:" + "9" * 64
        cases.append(("receipt_digest", forged))

        for field, forged in cases:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                store = RuntimeStore(f"{tmp}/runtime.db")
                with self.assertRaises(ManufactureRefusal):
                    admit_manufactured_bundle(
                        request,
                        manifest,
                        forged,
                        artifact_payloads=payloads,
                        store=store,
                    )

    def test_local_parent_and_incomplete_artifact_sets_refuse(self) -> None:
        request = make_request()
        for path in ("/tmp/action.json", "../action.json", "C:\\temp\\action.json"):
            with self.subTest(path=path):
                manifest = manifest_for_payloads(
                    request,
                    artifacts=((path, "application/json", b"ok"),),
                )
                with self.assertRaises(ManufactureRefusal) as caught:
                    manifest.canonical_payload()
                self.assertEqual(caught.exception.code, ManufactureRefusalCode.LOCAL_PATH_DEPENDENCY)

        _, payloads, manifest = self.payloads_and_manifest()
        receipt = receipt_for(request, manifest)
        incomplete = dict(payloads)
        incomplete.pop("bundle/verifier.json")
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ManufactureRefusal) as caught:
                admit_manufactured_bundle(
                    request,
                    manifest,
                    receipt,
                    artifact_payloads=incomplete,
                    store=RuntimeStore(f"{tmp}/runtime.db"),
                )
            self.assertEqual(caught.exception.code, ManufactureRefusalCode.INCOMPLETE_BUNDLE)


if __name__ == "__main__":
    unittest.main()
