from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from .manufacturing import ManufactureRequest, ManufacturedBundleManifest
from .observations import AdmittedClaim
from .runtime import (
    Actuator,
    AuthorityEnvelope,
    BRCEBroker,
    CapabilityBundle,
    ExecutionResult,
    PostconditionVerifier,
    RuntimeStore,
    WorkItem,
)


class ReflexRefusalCode(StrEnum):
    BUNDLE_NOT_PINNED = "REFUSED:BUNDLE_NOT_PINNED"
    PROVENANCE_DRIFT = "REFUSED:REFLEX_PROVENANCE_DRIFT"
    ARTIFACT_MISSING = "REFUSED:REFLEX_ARTIFACT_MISSING"
    ARTIFACT_TAMPER = "REFUSED:REFLEX_ARTIFACT_TAMPER"
    ARTIFACT_SCHEMA = "REFUSED:REFLEX_ARTIFACT_SCHEMA"
    AUTHORITY_SMUGGLING = "REFUSED:REFLEX_AUTHORITY_SMUGGLING"
    OUTSIDE_ENVELOPE = "REFUSED:OUTSIDE_COMPILED_REFLEX_ENVELOPE"


class ReflexRefusal(ValueError):
    def __init__(self, code: ReflexRefusalCode, detail: str) -> None:
        super().__init__(f"{code}:{detail}")
        self.code = code
        self.detail = detail


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReflexRefusal(ReflexRefusalCode.ARTIFACT_SCHEMA, label)
    return value


@dataclass(frozen=True, slots=True)
class CompiledReflex:
    """Powerless deterministic SELECT projection from a verified bundle.

    Possession of this object grants no authority. It can only construct a
    `WorkItem`; consequential execution remains exclusively behind BRCE.
    """

    reflex_digest: str
    capability_digest: str
    subject: str
    scope: str
    property_iri: str
    expected_value: Any
    consequence: str
    request_id: str
    lab_revision: str
    ggen_revision: str

    @classmethod
    def from_verified_bundle(
        cls,
        *,
        request: ManufactureRequest,
        manifest: ManufacturedBundleManifest,
        match_artifact: bytes,
        bundle: CapabilityBundle,
        store: RuntimeStore,
        artifact_path: str = "bundle/match.json",
    ) -> "CompiledReflex":
        if not store.is_pinned(bundle.digest):
            raise ReflexRefusal(ReflexRefusalCode.BUNDLE_NOT_PINNED, bundle.digest)
        if (
            bundle.source_repo != request.lab_repository
            or bundle.source_sha != request.lab_revision
            or bundle.generated_by != request.generator_repository
            or bundle.generator_sha != request.ggen_revision
            or manifest.request_id != request.request_id
            or manifest.lab_revision != request.lab_revision
            or manifest.ggen_revision != request.ggen_revision
        ):
            raise ReflexRefusal(ReflexRefusalCode.PROVENANCE_DRIFT, request.request_id)

        manifest_rows = {
            str(row["path"]): str(row["sha256"])
            for row in manifest.canonical_payload()["artifacts"]
        }
        expected_digest = manifest_rows.get(artifact_path)
        if expected_digest is None:
            raise ReflexRefusal(ReflexRefusalCode.ARTIFACT_MISSING, artifact_path)
        if _sha256(match_artifact) != expected_digest:
            raise ReflexRefusal(ReflexRefusalCode.ARTIFACT_TAMPER, artifact_path)

        try:
            payload = json.loads(match_artifact)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReflexRefusal(ReflexRefusalCode.ARTIFACT_SCHEMA, "INVALID_JSON") from exc
        if not isinstance(payload, dict):
            raise ReflexRefusal(ReflexRefusalCode.ARTIFACT_SCHEMA, "ROOT_NOT_OBJECT")

        allowed = {
            "schema",
            "subject",
            "scope",
            "property_iri",
            "equals",
            "consequence",
        }
        extra = sorted(set(payload) - allowed)
        forbidden = {
            "authority",
            "authority_ref",
            "do_authority",
            "grant",
            "principal",
            "nonce",
            "expiry",
            "token",
            "command",
            "executable",
        }
        if forbidden & set(payload):
            raise ReflexRefusal(
                ReflexRefusalCode.AUTHORITY_SMUGGLING,
                ",".join(sorted(forbidden & set(payload))),
            )
        if extra:
            raise ReflexRefusal(ReflexRefusalCode.ARTIFACT_SCHEMA, "EXTRA_FIELDS:" + ",".join(extra))
        if payload.get("schema") != "autofde.compiled-reflex/1":
            raise ReflexRefusal(ReflexRefusalCode.ARTIFACT_SCHEMA, "SCHEMA")

        subject = _require_text(payload.get("subject"), "SUBJECT")
        scope = _require_text(payload.get("scope"), "SCOPE")
        property_iri = _require_text(payload.get("property_iri"), "PROPERTY_IRI")
        consequence = _require_text(payload.get("consequence"), "CONSEQUENCE")
        if consequence != request.requirement.consequence or consequence != manifest.consequence:
            raise ReflexRefusal(ReflexRefusalCode.PROVENANCE_DRIFT, "CONSEQUENCE")

        delta = request.rdfdelta
        adds = delta.get("adds")
        if not isinstance(adds, list) or len(adds) != 1 or not isinstance(adds[0], Mapping):
            raise ReflexRefusal(ReflexRefusalCode.PROVENANCE_DRIFT, "RDFDELTA")
        statement = adds[0]
        expected_object = statement.get("object")
        if not isinstance(expected_object, Mapping) or "json" not in expected_object:
            raise ReflexRefusal(ReflexRefusalCode.PROVENANCE_DRIFT, "RDFDELTA_OBJECT")
        if (
            subject != statement.get("subject")
            or scope != delta.get("scope")
            or property_iri != statement.get("predicate")
            or payload.get("equals") != expected_object.get("json")
        ):
            raise ReflexRefusal(ReflexRefusalCode.PROVENANCE_DRIFT, "MATCH_NOT_BOUND_TO_O_STAR")

        return cls(
            reflex_digest=_sha256(match_artifact),
            capability_digest=bundle.digest,
            subject=subject,
            scope=scope,
            property_iri=property_iri,
            expected_value=payload.get("equals"),
            consequence=consequence,
            request_id=request.request_id,
            lab_revision=request.lab_revision,
            ggen_revision=request.ggen_revision,
        )

    def matches(self, claim: AdmittedClaim) -> bool:
        return (
            not claim.absent
            and claim.subject == self.subject
            and claim.scope == self.scope
            and claim.property_iri == self.property_iri
            and claim.value == self.expected_value
        )

    def work_item(self, claim: AdmittedClaim) -> WorkItem:
        if not self.matches(claim):
            raise ReflexRefusal(ReflexRefusalCode.OUTSIDE_ENVELOPE, claim.claim_id)
        payload = {
            "claim_id": claim.claim_id,
            "observation_ids": list(claim.observation_ids),
            "subject": claim.subject,
            "scope": claim.scope,
            "property_iri": claim.property_iri,
            "observed_value": claim.value,
            "compiled_reflex_digest": self.reflex_digest,
            "manufacture_request_id": self.request_id,
        }
        key = "reflex:" + _sha256(
            _canonical_json(
                {
                    "capability_digest": self.capability_digest,
                    "claim_id": claim.claim_id,
                    "reflex_digest": self.reflex_digest,
                }
            )
        )
        return WorkItem(
            idempotency_key=key,
            subject=claim.subject,
            consequence=self.consequence,
            capability_digest=self.capability_digest,
            payload=payload,
        )


class ManufacturedFastPath:
    """Deterministic known-pattern fast path. BRCE remains the only DO edge."""

    def __init__(self, broker: BRCEBroker) -> None:
        self.broker = broker

    def execute(
        self,
        reflex: CompiledReflex,
        claim: AdmittedClaim,
        *,
        authority: AuthorityEnvelope,
        actuator: Actuator,
        verifier: PostconditionVerifier,
    ) -> ExecutionResult:
        item = reflex.work_item(claim)
        return self.broker.do(
            item,
            authority=authority,
            actuator=actuator,
            verifier=verifier,
        )
