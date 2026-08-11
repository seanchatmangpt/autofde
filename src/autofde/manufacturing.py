from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any, Mapping, Sequence

from .observations import AdmittedClaim, ObservationLedger
from .runtime import CapabilityBundle, RuntimeStore


class ManufactureRefusalCode(StrEnum):
    INVALID_REQUEST = "REFUSED:INVALID_MANUFACTURE_REQUEST"
    SOURCE_IDENTITY = "REFUSED:SOURCE_IDENTITY"
    AUTHORITY_SMUGGLING = "REFUSED:AUTHORITY_SMUGGLING"
    REQUEST_MISMATCH = "REFUSED:MANUFACTURE_REQUEST_MISMATCH"
    GENERATOR_DRIFT = "REFUSED:GENERATOR_DRIFT"
    BUNDLE_TAMPER = "REFUSED:BUNDLE_TAMPER"
    LOCAL_PATH_DEPENDENCY = "REFUSED:LOCAL_PATH_DEPENDENCY"
    INCOMPLETE_BUNDLE = "REFUSED:INCOMPLETE_BUNDLE"


class ManufactureRefusal(ValueError):
    def __init__(self, code: ManufactureRefusalCode, detail: str) -> None:
        super().__init__(f"{code}:{detail}")
        self.code = code
        self.detail = detail


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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
            raise ManufactureRefusal(
                ManufactureRefusalCode.INVALID_REQUEST,
                "REQUEST_SCHEMA",
            )
        if self.authority_mode != "external-only" or self.do_authority:
            raise ManufactureRefusal(
                ManufactureRefusalCode.AUTHORITY_SMUGGLING,
                "MANUFACTURE_REQUEST_MUST_BE_CONSTRUCT_ONLY",
            )
        if self.rdfdelta.get("schema") != "autofde.rdfdelta/1":
            raise ManufactureRefusal(
                ManufactureRefusalCode.INVALID_REQUEST,
                "RDFDELTA_SCHEMA",
            )
        if self.rdfdelta.get("claim_id") != self.claim_id:
            raise ManufactureRefusal(
                ManufactureRefusalCode.REQUEST_MISMATCH,
                "RDFDELTA_CLAIM_ID",
            )
        if self.rdfdelta.get("removes") not in ([], ()):  # manufacturing never rewrites raw O
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
    name: str
    request_id: str
    lab_revision: str
    ggen_revision: str
    consequence: str
    artifacts: tuple[ManufacturedArtifact, ...]
    standing: str = "ALIVE"
    authority_mode: str = "external-only"
    do_authority: bool = False
    schema: str = "autofde.capability-bundle/1"

    def canonical_payload(self) -> Mapping[str, Any]:
        _require_text(self.name, "BUNDLE_NAME")
        _require_text(self.request_id, "REQUEST_ID")
        _require_text(self.consequence, "CONSEQUENCE")
        _require_sha(self.lab_revision, "LAB_REVISION")
        _require_sha(self.ggen_revision, "GGEN_REVISION")
        if self.schema != "autofde.capability-bundle/1":
            raise ManufactureRefusal(
                ManufactureRefusalCode.INCOMPLETE_BUNDLE,
                "BUNDLE_SCHEMA",
            )
        if self.standing != "ALIVE":
            raise ManufactureRefusal(
                ManufactureRefusalCode.INCOMPLETE_BUNDLE,
                f"MANUFACTURER_STANDING:{self.standing}",
            )
        if self.authority_mode != "external-only" or self.do_authority:
            raise ManufactureRefusal(
                ManufactureRefusalCode.AUTHORITY_SMUGGLING,
                "MANUFACTURED_BUNDLE_MUST_NOT_CARRY_DO_AUTHORITY",
            )
        rows = [artifact.canonical_payload() for artifact in self.artifacts]
        if not rows:
            raise ManufactureRefusal(
                ManufactureRefusalCode.INCOMPLETE_BUNDLE,
                "NO_ARTIFACTS",
            )
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
            "standing": self.standing,
            "authority": {
                "mode": self.authority_mode,
                "do_authority": self.do_authority,
            },
            "artifacts": sorted(rows, key=lambda row: row["path"]),
        }


def admit_manufactured_bundle(
    request: ManufactureRequest,
    manifest: ManufacturedBundleManifest,
    *,
    artifact_payloads: Mapping[str, bytes],
    store: RuntimeStore,
) -> CapabilityBundle:
    request_payload = request.canonical_payload()
    manifest_payload = manifest.canonical_payload()

    if manifest.request_id != request.request_id:
        raise ManufactureRefusal(
            ManufactureRefusalCode.REQUEST_MISMATCH,
            "BUNDLE_REQUEST_ID",
        )
    if manifest.lab_revision != request.lab_revision:
        raise ManufactureRefusal(
            ManufactureRefusalCode.SOURCE_IDENTITY,
            "LAB_REVISION_DRIFT",
        )
    if manifest.ggen_revision != request.ggen_revision:
        raise ManufactureRefusal(
            ManufactureRefusalCode.GENERATOR_DRIFT,
            "GGEN_REVISION_DRIFT",
        )
    if manifest.name != request.requirement.name or manifest.consequence != request.requirement.consequence:
        raise ManufactureRefusal(
            ManufactureRefusalCode.REQUEST_MISMATCH,
            "BUNDLE_REQUIREMENT_DRIFT",
        )

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
            raise ManufactureRefusal(
                ManufactureRefusalCode.BUNDLE_TAMPER,
                path,
            )

    bundle_identity = {
        "request": request_payload,
        "manifest": manifest_payload,
        "artifact_digests": expected,
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
    """Small deterministic adapter for ggen outputs: (path, media type, bytes)."""
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
