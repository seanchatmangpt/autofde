from __future__ import annotations

import hashlib
import tempfile
import unittest

from autofde.manufacturing import (
    CapabilityRequirement,
    ManufactureRefusal,
    ManufactureRefusalCode,
    ManufacturedBundleManifest,
    admit_manufactured_bundle,
    manifest_for_payloads,
)
from autofde.observations import AdmittedClaim
from autofde.runtime import RuntimeStore


LAB_SHA = "1db599aa38e2655f96e9dd766e5d7dcae5b1542d"
GGEN_SHA = "41cd378c6f55de6ed3991fdba60a7c25b68546b9"


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
        semantic_types=(
            "urn:autofde:Capability",
            "urn:autofde:AzureConsequence",
        ),
    )


class ManufactureBridgeTests(unittest.TestCase):
    def make_request(self):
        from autofde.manufacturing import ManufactureRequest

        return ManufactureRequest.from_admitted_claim(
            admitted_claim(),
            requirement=requirement(),
            lab_revision=LAB_SHA,
            ggen_revision=GGEN_SHA,
        )

    def test_request_is_deterministic_and_structured(self) -> None:
        first = self.make_request()
        second = self.make_request()
        self.assertEqual(first.request_id, second.request_id)
        self.assertEqual(first.to_bytes(), second.to_bytes())
        payload = first.canonical_payload()
        self.assertEqual(payload["rdfdelta"]["schema"], "autofde.rdfdelta/1")
        self.assertEqual(payload["authority"], {"mode": "external-only", "do_authority": False})
        self.assertEqual(payload["manufacturer"]["revision"], GGEN_SHA)
        self.assertNotIn("hcl", first.to_bytes().decode().lower())

    def test_valid_manufactured_bundle_is_content_verified_and_pinned(self) -> None:
        request = self.make_request()
        payloads = {
            "bundle/match.json": b'{"predicate":"classification=BenignPositive"}',
            "bundle/authority.json": b'{"mode":"external-only","do_authority":false}',
            "bundle/verifier.json": b'{"kind":"azure-arm-postcondition"}',
        }
        manifest = manifest_for_payloads(
            request,
            artifacts=tuple(
                (path, "application/json", body) for path, body in payloads.items()
            ),
        )
        with tempfile.TemporaryDirectory() as tmp:
            store = RuntimeStore(f"{tmp}/runtime.db")
            bundle = admit_manufactured_bundle(
                request,
                manifest,
                artifact_payloads=payloads,
                store=store,
            )
            self.assertTrue(store.is_pinned(bundle.digest))
            self.assertEqual(bundle.source_repo, "seanchatmangpt/autofde-lab")
            self.assertEqual(bundle.source_sha, LAB_SHA)
            self.assertEqual(bundle.generated_by, "seanchatmangpt/ggen")
            self.assertEqual(bundle.generator_sha, GGEN_SHA)

    def test_artifact_order_does_not_change_bundle_identity(self) -> None:
        request = self.make_request()
        a = ("bundle/a.json", "application/json", b"a")
        b = ("bundle/b.json", "application/json", b"b")
        m1 = manifest_for_payloads(request, artifacts=(a, b))
        m2 = manifest_for_payloads(request, artifacts=(b, a))
        with tempfile.TemporaryDirectory() as tmp:
            s1 = RuntimeStore(f"{tmp}/one.db")
            s2 = RuntimeStore(f"{tmp}/two.db")
            p = {a[0]: a[2], b[0]: b[2]}
            d1 = admit_manufactured_bundle(request, m1, artifact_payloads=p, store=s1).digest
            d2 = admit_manufactured_bundle(request, m2, artifact_payloads=p, store=s2).digest
            self.assertEqual(d1, d2)

    def test_tampered_artifact_refuses_without_pin(self) -> None:
        request = self.make_request()
        original = b"admitted"
        manifest = manifest_for_payloads(
            request,
            artifacts=(("bundle/action.json", "application/json", original),),
        )
        with tempfile.TemporaryDirectory() as tmp:
            store = RuntimeStore(f"{tmp}/runtime.db")
            with self.assertRaises(ManufactureRefusal) as caught:
                admit_manufactured_bundle(
                    request,
                    manifest,
                    artifact_payloads={"bundle/action.json": b"tampered"},
                    store=store,
                )
            self.assertEqual(caught.exception.code, ManufactureRefusalCode.BUNDLE_TAMPER)
            digest = hashlib.sha256(original).hexdigest()
            self.assertFalse(store.is_pinned(digest))

    def test_generator_revision_drift_refuses(self) -> None:
        request = self.make_request()
        payload = b"ok"
        manifest = ManufacturedBundleManifest(
            name=request.requirement.name,
            request_id=request.request_id,
            lab_revision=LAB_SHA,
            ggen_revision="0" * 40,
            consequence=request.requirement.consequence,
            artifacts=manifest_for_payloads(
                request,
                artifacts=(("bundle/action.json", "application/json", payload),),
            ).artifacts,
        )
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ManufactureRefusal) as caught:
                admit_manufactured_bundle(
                    request,
                    manifest,
                    artifact_payloads={"bundle/action.json": payload},
                    store=RuntimeStore(f"{tmp}/runtime.db"),
                )
            self.assertEqual(caught.exception.code, ManufactureRefusalCode.GENERATOR_DRIFT)

    def test_do_authority_smuggling_refuses(self) -> None:
        request = self.make_request()
        payload = b"ok"
        base = manifest_for_payloads(
            request,
            artifacts=(("bundle/action.json", "application/json", payload),),
        )
        malicious = ManufacturedBundleManifest(
            name=base.name,
            request_id=base.request_id,
            lab_revision=base.lab_revision,
            ggen_revision=base.ggen_revision,
            consequence=base.consequence,
            artifacts=base.artifacts,
            do_authority=True,
        )
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ManufactureRefusal) as caught:
                admit_manufactured_bundle(
                    request,
                    malicious,
                    artifact_payloads={"bundle/action.json": payload},
                    store=RuntimeStore(f"{tmp}/runtime.db"),
                )
            self.assertEqual(caught.exception.code, ManufactureRefusalCode.AUTHORITY_SMUGGLING)

    def test_local_or_parent_paths_refuse(self) -> None:
        request = self.make_request()
        for path in ("/tmp/action.json", "../action.json", "C:\\temp\\action.json"):
            with self.subTest(path=path):
                manifest = manifest_for_payloads(
                    request,
                    artifacts=((path, "application/json", b"ok"),),
                )
                with tempfile.TemporaryDirectory() as tmp:
                    with self.assertRaises(ManufactureRefusal) as caught:
                        admit_manufactured_bundle(
                            request,
                            manifest,
                            artifact_payloads={path: b"ok"},
                            store=RuntimeStore(f"{tmp}/runtime.db"),
                        )
                    self.assertEqual(
                        caught.exception.code,
                        ManufactureRefusalCode.LOCAL_PATH_DEPENDENCY,
                    )

    def test_missing_or_extra_artifact_refuses(self) -> None:
        request = self.make_request()
        manifest = manifest_for_payloads(
            request,
            artifacts=(("bundle/action.json", "application/json", b"ok"),),
        )
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ManufactureRefusal) as caught:
                admit_manufactured_bundle(
                    request,
                    manifest,
                    artifact_payloads={"bundle/extra.json": b"ok"},
                    store=RuntimeStore(f"{tmp}/runtime.db"),
                )
            self.assertEqual(caught.exception.code, ManufactureRefusalCode.INCOMPLETE_BUNDLE)


if __name__ == "__main__":
    unittest.main()
