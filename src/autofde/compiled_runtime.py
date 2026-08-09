"""Tiny EXPLOIT-only runtime for digest-pinned compiled execution profiles.

AutoFDE does not plan, optimize, or discover here. Lab/ggen manufacture a powerless
profile bundle; this module admits its exact bytes and delegates the selected profile
to GymAct's AutonomicController. The controller is the only accepted consequence
controller because its EXECUTE phase is BRCE-exclusive.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

_SCHEMA = "urn:autofde:execution-profile:v1"
_GENERATOR = "ggen:autofde-execution-profile-pack"
_AUTHORITY_MODE = "external-only"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TOP_KEYS = {"schema", "generated_by", "authority_mode", "profiles"}
_PROFILE_KEYS = {
    "profile_id",
    "source_ref",
    "derived_from",
    "provider",
    "benchmark_revision",
    "scenario",
    "config",
    "capability_ref",
    "capability_binding",
    "payload",
    "expected",
    "input_schema",
    "authority_ref",
    "action_ref",
}
_FORBIDDEN_AUTHORITY_KEYS = {
    "principal",
    "delegated_principal",
    "nonce",
    "expires_at",
    "execution_grant",
    "permission_token",
}


class AdmissionRefused(ValueError):
    """Typed refusal before a compiled artifact can reach the consequence boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise AdmissionRefused(f"DUPLICATE_JSON_KEY_REFUSED:{key}")
        value[key] = item
    return value


def _reject_authority_tokens(value: Any) -> None:
    if isinstance(value, dict):
        forbidden = _FORBIDDEN_AUTHORITY_KEYS.intersection(value)
        if forbidden:
            raise AdmissionRefused(f"AUTHORITY_TOKEN_FIELD_REFUSED:{sorted(forbidden)[0]}")
        for child in value.values():
            _reject_authority_tokens(child)
    elif isinstance(value, list):
        for child in value:
            _reject_authority_tokens(child)


def _required_string(profile: dict[str, Any], key: str) -> str:
    value = profile.get(key)
    if not isinstance(value, str) or not value.strip():
        raise AdmissionRefused(f"PROFILE_FIELD_REQUIRED:{key}")
    return value


def _nullable_string(profile: dict[str, Any], key: str) -> str | None:
    value = profile.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise AdmissionRefused(f"PROFILE_FIELD_TYPE_REFUSED:{key}")
    return value or None


def _required_object(profile: dict[str, Any], key: str, *, nonempty: bool = False) -> dict[str, Any]:
    value = profile.get(key)
    if not isinstance(value, dict) or (nonempty and not value):
        raise AdmissionRefused(f"PROFILE_OBJECT_REQUIRED:{key}")
    return value


@dataclass(frozen=True, slots=True)
class CompiledExecutionProfile:
    profile_id: str
    source_ref: str
    derived_from: str
    provider: str
    benchmark_revision: str
    scenario: str | None
    config: dict[str, Any]
    capability_ref: str | None
    capability_binding: str | None
    payload: dict[str, Any]
    expected: dict[str, Any]
    input_schema: dict[str, Any]
    authority_ref: str
    action_ref: str


@dataclass(frozen=True, slots=True)
class AdmittedExecutionBundle:
    sha256: str
    profiles: tuple[CompiledExecutionProfile, ...]

    def profile(self, profile_id: str) -> CompiledExecutionProfile:
        for profile in self.profiles:
            if profile.profile_id == profile_id:
                return profile
        raise AdmissionRefused(f"UNKNOWN_EXECUTION_PROFILE:{profile_id}")


def admit_execution_bundle(raw: bytes, *, expected_sha256: str) -> AdmittedExecutionBundle:
    """Admit exact bundle bytes; no authority or actuation occurs here."""

    expected = expected_sha256.lower()
    if not _SHA256_RE.fullmatch(expected):
        raise AdmissionRefused("EXPECTED_SHA256_INVALID")
    observed = sha256_hex(raw)
    if observed != expected:
        raise AdmissionRefused("EXECUTION_BUNDLE_DIGEST_MISMATCH")
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AdmissionRefused("EXECUTION_BUNDLE_UTF8_REFUSED") from exc
    try:
        document = json.loads(decoded, object_pairs_hook=_object_without_duplicate_keys)
    except AdmissionRefused:
        raise
    except (json.JSONDecodeError, TypeError) as exc:
        raise AdmissionRefused("EXECUTION_BUNDLE_JSON_REFUSED") from exc
    if not isinstance(document, dict):
        raise AdmissionRefused("EXECUTION_BUNDLE_OBJECT_REQUIRED")

    _reject_authority_tokens(document)
    if set(document) != _TOP_KEYS:
        raise AdmissionRefused("EXECUTION_BUNDLE_TOP_LEVEL_SHAPE_REFUSED")
    if document.get("schema") != _SCHEMA:
        raise AdmissionRefused("EXECUTION_BUNDLE_SCHEMA_REFUSED")
    if document.get("generated_by") != _GENERATOR:
        raise AdmissionRefused("EXECUTION_BUNDLE_GENERATOR_REFUSED")
    if document.get("authority_mode") != _AUTHORITY_MODE:
        raise AdmissionRefused("EXECUTION_BUNDLE_AUTHORITY_MODE_REFUSED")
    rows = document.get("profiles")
    if not isinstance(rows, list) or not rows:
        raise AdmissionRefused("EXECUTION_BUNDLE_PROFILES_REQUIRED")

    profiles: list[CompiledExecutionProfile] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != _PROFILE_KEYS:
            raise AdmissionRefused("EXECUTION_PROFILE_SHAPE_REFUSED")
        profile_id = _required_string(row, "profile_id")
        if profile_id in seen:
            raise AdmissionRefused(f"DUPLICATE_EXECUTION_PROFILE:{profile_id}")
        seen.add(profile_id)

        capability_ref = _nullable_string(row, "capability_ref")
        capability_binding = _nullable_string(row, "capability_binding")
        if (capability_ref is None) == (capability_binding is None):
            raise AdmissionRefused("EXECUTION_PROFILE_CAPABILITY_SELECTOR_REFUSED")

        # Production is stricter than manufacture: every DO profile must name the
        # external authority reference and compiled action identity. Neither field
        # is itself an ExecutionGrant.
        authority_ref = _required_string(row, "authority_ref")
        action_ref = _required_string(row, "action_ref")
        profiles.append(
            CompiledExecutionProfile(
                profile_id=profile_id,
                source_ref=_required_string(row, "source_ref"),
                derived_from=_required_string(row, "derived_from"),
                provider=_required_string(row, "provider"),
                benchmark_revision=_required_string(row, "benchmark_revision"),
                scenario=_nullable_string(row, "scenario"),
                config=_required_object(row, "config"),
                capability_ref=capability_ref,
                capability_binding=capability_binding,
                payload=_required_object(row, "payload"),
                expected=_required_object(row, "expected", nonempty=True),
                input_schema=_required_object(row, "input_schema", nonempty=True),
                authority_ref=authority_ref,
                action_ref=action_ref,
            )
        )
    return AdmittedExecutionBundle(sha256=observed, profiles=tuple(profiles))


@dataclass(frozen=True, slots=True)
class ExploitReceipt:
    receipt_id: str
    bundle_sha256: str
    profile_id: str
    request_id: str
    standing: str
    verified: bool
    downstream_receipt_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ExploitOutcome:
    standing: str
    verified: bool
    reason: str
    receipt: ExploitReceipt


class CompiledProfileExploitRuntime:
    """No planner, no learner, no raw actuation: compiled profile -> GymAct MAPE-K/BRCE."""

    def __init__(self, controller: object, bundle: AdmittedExecutionBundle) -> None:
        from gymact.autonomic import AutonomicController

        if not isinstance(controller, AutonomicController):
            raise TypeError("AutoFDE production requires gymact.autonomic.AutonomicController")
        self._controller = controller
        self.bundle = bundle
        self._receipts: list[ExploitReceipt] = []
        self._outcomes: dict[str, ExploitOutcome] = {}

    def receipts(self) -> tuple[ExploitReceipt, ...]:
        return tuple(self._receipts)

    def outcomes(self) -> tuple[ExploitOutcome, ...]:
        return tuple(self._outcomes[key] for key in sorted(self._outcomes))

    async def execute(self, profile_id: str) -> ExploitOutcome:
        from gymact.autonomic import AutonomicPhase, ConsequenceRequest

        cached = self._outcomes.get(profile_id)
        if cached is not None:
            return cached

        profile = self.bundle.profile(profile_id)
        request_id = f"urn:autofde:execution:{self.bundle.sha256}:{profile.profile_id}"
        idempotency_key = sha256_hex(
            f"{self.bundle.sha256}:{profile.profile_id}".encode("utf-8")
        )
        result = await self._controller.run(
            ConsequenceRequest(
                request_id=request_id,
                provider=profile.provider,
                scenario=profile.scenario,
                config=profile.config,
                capability_ref=profile.capability_ref,
                capability_binding=profile.capability_binding,
                payload=profile.payload,
                expected=profile.expected,
                authority_ref=profile.authority_ref,
                subject_revision=profile.benchmark_revision,
                action_ref=profile.action_ref,
                input_schema=profile.input_schema,
                idempotency_key=idempotency_key,
                require_verification=True,
            )
        )

        evidence: list[str] = list(result.receipt_ids)
        execute_evidence: list[str] = []
        for phase in result.phase_records:
            for ref in phase.evidence_refs:
                if ref not in evidence:
                    evidence.append(ref)
                if phase.phase is AutonomicPhase.EXECUTE:
                    execute_evidence.append(ref)
        if not evidence:
            raise RuntimeError("ZERO_UNRECEIPTED_RESULT_REFUSED")
        standing = str(result.standing)
        if standing == "ALIVE" and (not result.verified or not execute_evidence):
            raise RuntimeError("UNVERIFIED_OR_UNRECEIPTED_ALIVE_REFUSED")

        receipt_payload = {
            "bundle_sha256": self.bundle.sha256,
            "profile_id": profile.profile_id,
            "request_id": request_id,
            "standing": standing,
            "verified": bool(result.verified),
            "downstream_receipt_ids": evidence,
        }
        receipt_id = "sha256:" + sha256_hex(
            json.dumps(receipt_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        receipt = ExploitReceipt(
            receipt_id=receipt_id,
            bundle_sha256=self.bundle.sha256,
            profile_id=profile.profile_id,
            request_id=request_id,
            standing=standing,
            verified=bool(result.verified),
            downstream_receipt_ids=tuple(evidence),
        )
        outcome = ExploitOutcome(
            standing=standing,
            verified=bool(result.verified),
            reason=str(result.reason),
            receipt=receipt,
        )
        self._receipts.append(receipt)
        self._outcomes[profile.profile_id] = outcome
        return outcome
