from __future__ import annotations

import json
import unittest

from autofde.compiled_runtime import AdmissionRefused, admit_execution_bundle, sha256_hex


def document() -> dict[str, object]:
    return {
        "schema": "urn:autofde:execution-profile:v1",
        "generated_by": "ggen:autofde-execution-profile-pack",
        "authority_mode": "external-only",
        "profiles": [{
            "profile_id": "memory-counter",
            "source_ref": "urn:test:benchmark-source",
            "derived_from": "urn:test:experiment-plan",
            "provider": "memory",
            "benchmark_revision": "0123456789abcdef0123456789abcdef01234567",
            "scenario": None,
            "config_json": json.dumps({"initial": {"counter": 0}, "requires_authority": True}, sort_keys=True),
            "capability_ref": None,
            "capability_binding": "increment",
            "payload_json": json.dumps({"key": "counter", "amount": 1}, sort_keys=True),
            "expected_json": json.dumps({"counter": 1}, sort_keys=True),
            "input_schema_json": json.dumps({"type": "object"}, sort_keys=True),
            "authority_ref": "urn:test:authority:compiled-runtime",
            "action_ref": "urn:test:action:memory-counter-increment",
        }],
    }


def bundle_bytes(value: dict[str, object]) -> bytes:
    return json.dumps(value, indent=2, sort_keys=True).encode()


class CompiledRuntimeAdmissionTest(unittest.TestCase):
    def test_exact_digest_and_profile_are_admitted(self) -> None:
        raw = bundle_bytes(document())
        bundle = admit_execution_bundle(raw, expected_sha256=sha256_hex(raw))
        profile = bundle.profile("memory-counter")
        self.assertEqual(bundle.sha256, sha256_hex(raw))
        self.assertEqual(profile.authority_ref, "urn:test:authority:compiled-runtime")
        self.assertEqual(profile.action_ref, "urn:test:action:memory-counter-increment")

    def test_digest_drift_is_refused(self) -> None:
        raw = bundle_bytes(document())
        with self.assertRaisesRegex(AdmissionRefused, "EXECUTION_BUNDLE_DIGEST_MISMATCH"):
            admit_execution_bundle(raw, expected_sha256="0" * 64)

    def test_embedded_authority_token_is_refused(self) -> None:
        value = document()
        value["profiles"][0]["nonce"] = "must-never-enter-production-artifact"  # type: ignore[index]
        raw = bundle_bytes(value)
        with self.assertRaisesRegex(AdmissionRefused, "AUTHORITY_TOKEN_FIELD_REFUSED:nonce"):
            admit_execution_bundle(raw, expected_sha256=sha256_hex(raw))

    def test_authority_and_verification_contracts_are_non_vacuous(self) -> None:
        value = document()
        value["profiles"][0]["authority_ref"] = None  # type: ignore[index]
        raw = bundle_bytes(value)
        with self.assertRaisesRegex(AdmissionRefused, "PROFILE_FIELD_REQUIRED:authority_ref"):
            admit_execution_bundle(raw, expected_sha256=sha256_hex(raw))

        value = document()
        value["profiles"][0]["expected_json"] = "{}"  # type: ignore[index]
        raw = bundle_bytes(value)
        with self.assertRaisesRegex(AdmissionRefused, "PROFILE_OBJECT_REQUIRED:expected_json"):
            admit_execution_bundle(raw, expected_sha256=sha256_hex(raw))

    def test_duplicate_json_keys_are_refused(self) -> None:
        raw = b'{"schema":"urn:autofde:execution-profile:v1","schema":"x","generated_by":"ggen:autofde-execution-profile-pack","authority_mode":"external-only","profiles":[]}'
        with self.assertRaisesRegex(AdmissionRefused, "DUPLICATE_JSON_KEY_REFUSED:schema"):
            admit_execution_bundle(raw, expected_sha256=sha256_hex(raw))


if __name__ == "__main__":
    unittest.main()
