from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any, Mapping, Sequence

from .observations import AdmittedClaim, ObservationLedger
from .runtime import CapabilityBundle, RuntimeStore


MANUFACTURE_RECEIPT_SCHEMA = "autofde.manufacture-receipt/2"
MANUFACTURE_VALIDATOR = "ggen:autofde-capability-bundle/2"
REQUIRED_MANUFACTURE_COURTS = (
    "artifact_set_integrity",
    "authority_non_escalation",
    "manifest_binding",
    "provenance_binding",
    "receipt_self_integrity",
    "request_binding",
)


class ManufactureRefusalCode(StrEnum):
    INVALID_REQUEST = "REFUSED:INVALID_MANUFACTURE_REQUEST"
    SOURCE_IDENTITY = "REFUSED:SOURCE_IDENTITY"
    AUTHORITY_SMUGGLING = "REFUSED:AUTHORITY_SMUGGLING"
    REQUEST_MISMATCH = "REFUSED:MANUFACTURE_REQUEST_MISMATCH"
    GENERATOR_DRIFT = "REFUSED:GENERATOR_DRIFT"
    BUNDLE_TAMPER = "REFUSED:BUNDLE_TAMPER"
    LOCAL_PATH_DEPENDENCY = "REFUSED:LOCAL_PATH_DEPENDENCY"
    INCOMPLETE_BUNDLE = "REFUSED:INCOMPLETE_BUNDLE"
    MANUFACTURER_RECEIPT = "REFUSED:MANUFACTURER_RECEIPT"


class ManufactureRefusal(ValueError):
    def __init__(self, code: ManufactureRefusalCode, detail: str) -> None:
        super().__init__(f"{code}:{detail}")
        self.code = code
        self.detail = detail


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: Any) -> str:
    return "sha256:" + _sha256(_canonical_json(value))


def _require_sha(value: str, label: str) -> None:
    if len(value) != 40 or any(ch not in "0123456789abcdef" for ch in value):
        raise ManufactureRefusal(
            ManufactureRefusalCode.SOURCE_IDENTITY,
            f"{label}_MUST_BE_EXACT_GIT_SHA1",
        )


def _require_text(value: str, label: str) -> None:
    if not value.strip():
        raise ManufactureRefusal(
            ManufactureRefusalCode.INVALID_REQUEST,
            f"{label}_MISSING",
        )


def _portable_artifact_path(value: str) -> str:
    _require_text(value, "ARTIFACT_PATH")
    if "\\" in value or value.startswith(("/", "~")):
        raise ManufactureRefusal(
            ManufactureRefusalCode.LOCAL_PATH_DEPENDENCY,
            value,
        )
    path = PurePosixPath(value)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ManufactureRefusal(
            ManufactureRefusalCode.LOCAL_PATH_DEPENDENCY,
            value,
        )
    return path.as_posix()


def _artifact_set_digest(rows: Sequence[Mapping[str, str]]) -> str:
    material = [{"path": row["path"], "sha256": row["sha256"]} for row in rows]
    return _sha256_json(sorted(material, key=lambda row: row["path"]))


def _receipt_digest(payload: Mapping[str, Any]) -> str:
    unsigned = dict(payload)
    unsigned.pop("receipt_digest", None)
    return _sha256_json(unsigned)


@dataclass(frozen=True, slots=True)
class CapabilityRequirement:
    name: str
    subject: str
    consequence: str
    verifier: str
    target_environment: str
    semantic_types: tuple[str, ...] = ()

    def canonical_payload(self) -> Mapping[str, Any]:
        for value, label in (
            (self.name, "NAME"),
            (self.subject, "SUBJECT"),
            (self.consequence, "CONSEQUENCE"),
            (self.verifier, "VERIFIER"),
            (self.target_environment, "TARGET_ENVIRONMENT"),
        ):
            _require_text(value, label)
        return {
            "name": self.name,
            "subject": self.subject,
            "consequence": self.consequence,
            "verifier": self.verifier,
            "target_environment": self.target_environment,
            "semantic_types": sorted(set(self.semantic_types)),
        }


@dataclass(frozen=True, slots=True)
class ManufactureRequest:
    claim_id: str
    rdfdelta: Mapping[str, Any]
    requirement: CapabilityRequirement
    lab_revision: str
    ggen_revision: str
    lab_repository: str = "seanchatmangpt/autofde-lab"
    generator_repository: str = "seanchatmangpt/ggen"
    authority_mode: str = "external-only"
    do_authority: bool = False
    schema: str = "autofde.manufacture-request/1"

    @classmethod
    def from_admitted_claim(
        cls,
        claim: AdmittedClaim,
        *,
        requirement: CapabilityRequirement,
        lab_revision: str,
        ggen_revision: str,
    ) -> "ManufactureRequest":
        return cls(
            claim_id=claim.claim_id,
            rdfdelta=ObservationLedger.rdfdelta(claim),
            requirement=requirement,
            lab_revision=lab_revision,
            ggen_revision=ggen_revision,
        )

    def canonical_payload(self) -> Mapping[str, Any]:
        _require_sha(self.lab_revision, "LAB_REVISION")
        _require_sha(self.ggen_revision, "GGEN_REVISION")
        _require_text(self.claim_id, "CLAIM_ID")
        if self.schema != "autofde.manufacture-request/1":
            raise ManufactureRefusal(ManufactureRefusalCode.INVALID_REQUEST, "REQUEST_SCHEMA")
        if self.authority_mode != "external-only" or self.do_authority:
            raise ManufactureRefusal(
                ManufactureRefusalCode.AUTHORITY_SMUGGLING,
                "MANUFACTURE_REQUEST_MUST_BE_CONSTRUCT_ONLY",
            )
        if self.rdfdelta.get("schema") != "autofde.rdfdelta/1":
            raise ManufactureRefusal(ManufactureRefusalCode.INVALID_REQUEST, "RDFDELTA_SCHEMA")
        if self.rdfdelta.get("claim_id") != self.claim_id:
            raise ManufactureRefusal(ManufactureRefusalCode.REQUEST_MISMATCH, "RDFDELTA_CLAIM_ID")
        if self.rdfdelta.get("removes") not in ([], ()):
            raise ManufactureRefusal(
                ManufactureRefusalCode.INVALID_REQUEST,
                "RDFDELTA_REMOVALS_FORBIDDEN",
            )
        return {
            "schema": self.schema,
            "claim_id": self.claim_id,
            "rdfdelta": self.rdfdelta,
            "requirement": self.requirement.canonical_payload(),
            "source": {
                "lab_repository": self.lab_repository,
                "lab_revision": self.lab_revision,
            },
            "manufacturer": {
                "repository": self.generator_repository,
                "revision": self.ggen_revision,
            },
            "authority": {
                "mode": self.authority_mode,
                "do_authority": self.do_authority,
            },
        }

    @property
    def request_id(self) -> str:
        return _sha256(_canonical_json(self.canonical_payload()))

    @property
    def request_digest(self) -> str:
        return _sha256_json(self.canonical_payload())

    def to_bytes(self) -> bytes:
        payload = dict(self.canonical_payload())
        payload["request_id"] = self.request_id
        return _canonical_json(payload)


@dataclass(frozen=True, slots=True)
class ManufacturedArtifact:
    path: str
    sha256: str
    media_type: str

    def canonical_payload(self) -> Mapping[str, str]:
        path = _portable_artifact_path(self.path)
        _require_text(self.media_type, "MEDIA_TYPE")
        if len(self.sha256) != 64 or any(ch not in "0123456789abcdef" for ch in self.sha256):
            raise ManufactureRefusal(
                ManufactureRefusalCode.BUNDLE_TAMPER,
                f"INVALID_ARTIFACT_DIGEST:{path}",
            )
        return {"path": path, "sha256": self.sha256, "media_type": self.media_type}


@dataclass(frozen=True, slots=True)
class ManufacturedBundleManifest:
    """Candidate artifact inventory. It deliberately carries no standing or authority."""

    name: str
    request_id: str
    lab_revision: str
    ggen_revision: str
    consequence: str
    artifacts: tuple[ManufacturedArtifact, ...]
    schema: str = "autofde.capability-bundle-manifest/2"

    def canonical_payload(self) -> Mapping[str, Any]:
        _require_text(self.name, "BUNDLE_NAME")
        _require_text(self.request_id, "REQUEST_ID")
        _require_text(self.consequence, "CONSEQUENCE")
        _require_sha(self.lab_revision, "LAB_REVISION")
        _require_sha(self.ggen_revision, "GGEN_REVISION")
        if self.schema != "autofde.capability-bundle-manifest/2":
            raise ManufactureRefusal(ManufactureRefusalCode.INCOMPLETE_BUNDLE, "BUNDLE_SCHEMA")
        rows = [artifact.canonical_payload() for artifact in self.artifacts]
        if not rows:
            raise ManufactureRefusal(ManufactureRefusalCode.INCOMPLETE_BUNDLE, "NO_ARTIFACTS")
        paths = [row["path"] for row in rows]
        if len(paths) != len(set(paths)):
            raise ManufactureRefusal(
                ManufactureRefusalCode.INCOMPLETE_BUNDLE,
                "DUPLICATE_ARTIFACT_PATH",
            )
        return {
            "schema": self.schema,
            "name": self.name,
            "request_id": self.request_id,
            "lab_revision": self.lab_revision,
            "ggen_revision": self.ggen_revision,
            "consequence": self.consequence,
            "artifacts": sorted(rows, key=lambda row: row["path"]),
        }

    @property
    def manifest_digest(self) -> str:
        return _sha256_json(self.canonical_payload())

    @property
    def artifact_set_digest(self) -> str:
        return _artifact_set_digest(self.canonical_payload()["artifacts"])


@dataclass(frozen=True, slots=True)
class ManufacturerReceipt:
    request_id: str
    request_digest: str
    manifest_digest: str
    artifact_set_digest: str
    lab_revision: str
    ggen_revision: str
    receipt_digest: str
    courts: tuple[str, ...]
    standing: str = "ALIVE"
    authority_class: str = "CONSTRUCT"
    do_authority: bool = False
    validator: str = MANUFACTURE_VALIDATOR
    schema: str = MANUFACTURE_RECEIPT_SCHEMA

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ManufacturerReceipt":
        try:
            return cls(
                request_id=str(payload["request_id"]),
                request_digest=str(payload["request_digest"]),
                manifest_digest=str(payload["manifest_digest"]),
                artifact_set_digest=str(payload["artifact_set_digest"]),
                lab_revision=str(payload["lab_revision"]),
                ggen_revision=str(payload["ggen_revision"]),
                receipt_digest=str(payload["receipt_digest"]),
                courts=tuple(str(value) for value in payload["courts"]),
                standing=str(payload.get("standing", "")),
                authority_class=str(payload.get("authority_class", "")),
                do_authority=bool(payload.get("do_authority", True)),
                validator=str(payload.get("validator", "")),
                schema=str(payload.get("schema", "")),
            )
        except (KeyError, TypeError) as exc:
            raise ManufactureRefusal(
                ManufactureRefusalCode.MANUFACTURER_RECEIPT,
                "RECEIPT_FIELDS_MISSING",
            ) from exc

    def canonical_payload(self, *, include_digest: bool = True) -> Mapping[str, Any]:
        payload: dict[str, Any] = {
            "schema": self.schema,
            "standing": self.standing,
            "authority_class": self.authority_class,
            "do_authority": self.do_authority,
            "validator": self.validator,
            "request_id": self.request_id,
            "request_digest": self.request_digest,
            "manifest_digest": self.manifest_digest,
            "artifact_set_digest": self.artifact_set_digest,
            "lab_revision": self.lab_revision,
            "ggen_revision": self.ggen_revision,
            "courts": list(self.courts),
        }
        if include_digest:
            payload["receipt_digest"] = self.receipt_digest
        return payload

    def verify(self, request: ManufactureRequest, manifest: ManufacturedBundleManifest) -> None:
        if self.schema != MANUFACTURE_RECEIPT_SCHEMA:
            raise ManufactureRefusal(ManufactureRefusalCode.MANUFACTURER_RECEIPT, "RECEIPT_SCHEMA")
        if self.standing != "ALIVE":
            raise ManufactureRefusal(ManufactureRefusalCode.MANUFACTURER_RECEIPT, "MANUFACTURER_NOT_ALIVE")
        if self.authority_class != "CONSTRUCT" or self.do_authority:
            raise ManufactureRefusal(
                ManufactureRefusalCode.AUTHORITY_SMUGGLING,
                "MANUFACTURER_RECEIPT_MUST_BE_CONSTRUCT_ONLY",
            )
        if self.validator != MANUFACTURE_VALIDATOR:
            raise ManufactureRefusal(ManufactureRefusalCode.MANUFACTURER_RECEIPT, "VALIDATOR_IDENTITY")
        _require_sha(self.lab_revision, "RECEIPT_LAB_REVISION")
        _require_sha(self.ggen_revision, "RECEIPT_GGEN_REVISION")
        if self.request_id != request.request_id or self.request_digest != request.request_digest:
            raise ManufactureRefusal(ManufactureRefusalCode.REQUEST_MISMATCH, "RECEIPT_REQUEST_BINDING")
        if self.lab_revision != request.lab_revision or self.lab_revision != manifest.lab_revision:
            raise ManufactureRefusal(ManufactureRefusalCode.SOURCE_IDENTITY, "RECEIPT_LAB_REVISION_DRIFT")
        if self.ggen_revision != request.ggen_revision or self.ggen_revision != manifest.ggen_revision:
            raise ManufactureRefusal(ManufactureRefusalCode.GENERATOR_DRIFT, "RECEIPT_GGEN_REVISION_DRIFT")
        if self.manifest_digest != manifest.manifest_digest:
            raise ManufactureRefusal(ManufactureRefusalCode.BUNDLE_TAMPER, "RECEIPT_MANIFEST_DIGEST")
        if self.artifact_set_digest != manifest.artifact_set_digest:
            raise ManufactureRefusal(ManufactureRefusalCode.BUNDLE_TAMPER, "RECEIPT_ARTIFACT_SET_DIGEST")
        if tuple(sorted(self.courts)) != tuple(sorted(REQUIRED_MANUFACTURE_COURTS)):
            raise ManufactureRefusal(ManufactureRefusalCode.MANUFACTURER_RECEIPT, "COURTS_INCOMPLETE")
        expected_digest = _receipt_digest(self.canonical_payload(include_digest=False))
        if self.receipt_digest != expected_digest:
            raise ManufactureRefusal(ManufactureRefusalCode.MANUFACTURER_RECEIPT, "RECEIPT_DIGEST_MISMATCH")


def admit_manufactured_bundle(
    request: ManufactureRequest,
    manifest: ManufacturedBundleManifest,
    manufacturer_receipt: ManufacturerReceipt | Mapping[str, Any],
    *,
    artifact_payloads: Mapping[str, bytes],
    store: RuntimeStore,
) -> CapabilityBundle:
    request_payload = request.canonical_payload()
    manifest_payload = manifest.canonical_payload()

    if manifest.request_id != request.request_id:
        raise ManufactureRefusal(ManufactureRefusalCode.REQUEST_MISMATCH, "BUNDLE_REQUEST_ID")
    if manifest.lab_revision != request.lab_revision:
        raise ManufactureRefusal(ManufactureRefusalCode.SOURCE_IDENTITY, "LAB_REVISION_DRIFT")
    if manifest.ggen_revision != request.ggen_revision:
        raise ManufactureRefusal(ManufactureRefusalCode.GENERATOR_DRIFT, "GGEN_REVISION_DRIFT")
    if manifest.name != request.requirement.name or manifest.consequence != request.requirement.consequence:
        raise ManufactureRefusal(ManufactureRefusalCode.REQUEST_MISMATCH, "BUNDLE_REQUIREMENT_DRIFT")

    expected = {row["path"]: row["sha256"] for row in manifest_payload["artifacts"]}
    observed = {_portable_artifact_path(path): payload for path, payload in artifact_payloads.items()}
    if set(observed) != set(expected):
        missing = sorted(set(expected) - set(observed))
        extra = sorted(set(observed) - set(expected))
        raise ManufactureRefusal(
            ManufactureRefusalCode.INCOMPLETE_BUNDLE,
            f"ARTIFACT_SET_MISMATCH:missing={missing}:extra={extra}",
        )
    for path, digest in expected.items():
        if _sha256(observed[path]) != digest:
            raise ManufactureRefusal(ManufactureRefusalCode.BUNDLE_TAMPER, path)

    receipt = (
        manufacturer_receipt
        if isinstance(manufacturer_receipt, ManufacturerReceipt)
        else ManufacturerReceipt.from_payload(manufacturer_receipt)
    )
    receipt.verify(request, manifest)

    bundle_identity = {
        "request": request_payload,
        "manifest": manifest_payload,
        "artifact_digests": expected,
        "manufacturer_receipt_digest": receipt.receipt_digest,
    }
    bundle_digest = _sha256(_canonical_json(bundle_identity))
    bundle = CapabilityBundle(
        name=manifest.name,
        digest=bundle_digest,
        source_repo=request.lab_repository,
        source_sha=request.lab_revision,
        generated_by=request.generator_repository,
        generator_sha=request.ggen_revision,
    )
    store.pin_bundle(bundle)
    return bundle


def manifest_for_payloads(
    request: ManufactureRequest,
    *,
    artifacts: Sequence[tuple[str, str, bytes]],
) -> ManufacturedBundleManifest:
    """Build a powerless candidate manifest. This function never confers ALIVE standing."""
    material = tuple(
        ManufacturedArtifact(path=path, media_type=media_type, sha256=_sha256(payload))
        for path, media_type, payload in artifacts
    )
    return ManufacturedBundleManifest(
        name=request.requirement.name,
        request_id=request.request_id,
        lab_revision=request.lab_revision,
        ggen_revision=request.ggen_revision,
        consequence=request.requirement.consequence,
        artifacts=material,
    )
