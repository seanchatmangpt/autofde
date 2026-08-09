from __future__ import annotations

import asyncio
import json

import pytest

from autofde.compiled_runtime import (
    AdmissionRefused,
    CompiledProfileExploitRuntime,
    admit_execution_bundle,
    sha256_hex,
)
from gymact.authority import AllowListAuthorityResolver
from gymact.autonomic import AutonomicController, BoundedGrantIssuer
from gymact.providers import MemoryProvider
from gymact.runtime import ProductionGymAct

AUTHORITY = "urn:test:authority:compiled-runtime"


def _document() -> dict[str, object]:
    return {
        "schema": "urn:autofde:execution-profile:v1",
        "generated_by": "ggen:autofde-execution-profile-pack",
        "authority_mode": "external-only",
        "profiles": [
            {
                "profile_id": "memory-counter",
                "source_ref": "urn:test:benchmark-source",
                "derived_from": "urn:test:experiment-plan",
                "provider": "memory",
                "benchmark_revision": "0123456789abcdef0123456789abcdef01234567",
                "scenario": None,
                "config_json": json.dumps(
                    {"initial": {"counter": 0}, "requires_authority": True},
                    sort_keys=True,
                ),
                "capability_ref": None,
                "capability_binding": "increment",
                "payload_json": json.dumps(
                    {"key": "counter", "amount": 1}, sort_keys=True
                ),
                "expected_json": json.dumps({"counter": 1}, sort_keys=True),
                "input_schema_json": json.dumps({"type": "object"}, sort_keys=True),
                "authority_ref": AUTHORITY,
                "action_ref": "urn:test:action:memory-counter-increment",
            }
        ],
    }


def _bundle_bytes(document: dict[str, object] | None = None) -> bytes:
    return json.dumps(document or _document(), indent=2, sort_keys=True).encode("utf-8")


def _admit(document: dict[str, object] | None = None):
    raw = _bundle_bytes(document)
    return admit_execution_bundle(raw, expected_sha256=sha256_hex(raw))


def _controller(*, grant: bool = True) -> AutonomicController:
    runtime = ProductionGymAct(authority_resolver=AllowListAuthorityResolver({AUTHORITY}))
    runtime.register_provider(MemoryProvider())
    issuer = BoundedGrantIssuer({AUTHORITY}) if grant else None
    return AutonomicController(runtime, grant_issuer=issuer)


def test_compiled_profile_executes_only_through_real_gymact_brce_and_is_receipted() -> None:
    bundle = _admit()
    runtime = CompiledProfileExploitRuntime(_controller(), bundle)

    assert not hasattr(runtime, "act")
    outcome = asyncio.run(runtime.execute("memory-counter"))

    assert outcome.standing == "ALIVE"
    assert outcome.verified is True
    assert outcome.receipt.bundle_sha256 == bundle.sha256
    assert outcome.receipt.profile_id == "memory-counter"
    assert outcome.receipt.downstream_receipt_ids
    assert outcome.receipt.receipt_id.startswith("blake3:")
    assert runtime.receipts() == (outcome.receipt,)

    # Exact compiled profile identity is exactly-once. Re-entry returns the
    # already-receipted outcome instead of rematerializing a torn-down episode.
    replay = asyncio.run(runtime.execute("memory-counter"))
    assert replay is outcome
    assert runtime.receipts() == (outcome.receipt,)
    assert runtime.outcomes() == (outcome,)


def test_missing_grant_issuer_is_a_receipted_refusal_not_a_bypass() -> None:
    bundle = _admit()
    runtime = CompiledProfileExploitRuntime(_controller(grant=False), bundle)

    outcome = asyncio.run(runtime.execute("memory-counter"))

    assert outcome.standing == "REFUSED"
    assert "GRANT" in outcome.reason
    assert outcome.verified is False
    assert outcome.receipt.downstream_receipt_ids
    assert outcome.receipt.receipt_id.startswith("blake3:")


def test_digest_mismatch_refuses_before_runtime_construction() -> None:
    raw = _bundle_bytes()
    with pytest.raises(AdmissionRefused, match="EXECUTION_BUNDLE_DIGEST_MISMATCH"):
        admit_execution_bundle(raw, expected_sha256="0" * 64)


def test_embedded_authority_token_is_refused_even_with_valid_digest() -> None:
    document = _document()
    profile = document["profiles"][0]  # type: ignore[index]
    profile["nonce"] = "must-never-enter-production-artifact"  # type: ignore[index]
    raw = _bundle_bytes(document)
    with pytest.raises(AdmissionRefused, match="AUTHORITY_TOKEN_FIELD_REFUSED:nonce"):
        admit_execution_bundle(raw, expected_sha256=sha256_hex(raw))


def test_production_requires_authority_oracle_and_valid_inner_json() -> None:
    no_authority = _document()
    no_authority["profiles"][0]["authority_ref"] = None  # type: ignore[index]
    raw = _bundle_bytes(no_authority)
    with pytest.raises(AdmissionRefused, match="PROFILE_FIELD_REQUIRED:authority_ref"):
        admit_execution_bundle(raw, expected_sha256=sha256_hex(raw))

    vacuous = _document()
    vacuous["profiles"][0]["expected_json"] = "{}"  # type: ignore[index]
    raw = _bundle_bytes(vacuous)
    with pytest.raises(AdmissionRefused, match="PROFILE_OBJECT_REQUIRED:expected_json"):
        admit_execution_bundle(raw, expected_sha256=sha256_hex(raw))

    malformed = _document()
    malformed["profiles"][0]["config_json"] = "{not-json}"  # type: ignore[index]
    raw = _bundle_bytes(malformed)
    with pytest.raises(AdmissionRefused, match="PROFILE_JSON_INVALID:config_json"):
        admit_execution_bundle(raw, expected_sha256=sha256_hex(raw))


def test_provider_payload_may_contain_nonce_without_becoming_an_execution_grant() -> None:
    document = _document()
    document["profiles"][0]["payload_json"] = json.dumps(  # type: ignore[index]
        {"key": "counter", "amount": 1, "nonce": "provider-data"}, sort_keys=True
    )
    bundle = _admit(document)
    assert bundle.profile("memory-counter").payload["nonce"] == "provider-data"
