from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from importlib import metadata
from typing import Iterable


@dataclass(frozen=True, slots=True)
class IntegrationManifest:
    name: str
    role: str
    coordinate: str
    identity: str
    authority: str
    runtime_required: bool = False

    def __post_init__(self) -> None:
        if any(not value.strip() for value in (self.name, self.role, self.coordinate, self.identity, self.authority)):
            raise ValueError("REFUSED:INCOMPLETE_INTEGRATION_MANIFEST")
        if self.authority == "DO":
            raise ValueError("REFUSED:INTEGRATION_MANIFEST_DO_AUTHORITY")


@dataclass(frozen=True, slots=True)
class IntegrationObservation:
    name: str
    coordinate: str
    configured_identity: str
    observed_identity: str | None
    observed: bool


_MANIFEST = (
    IntegrationManifest(
        "substrate",
        "project scaffold",
        "superlinear-ai/substrate",
        "ec640e3d6e0d18ddfc7123e67580ffdc7af80889",
        "CONSTRUCT",
    ),
    IntegrationManifest("fastmcp", "MCP transport", "PyPI:fastmcp", ">=2.12,<3", "ROUTE", True),
    IntegrationManifest("dspy", "bounded program optimization", "PyPI:dspy", ">=3,<4", "CONSTRUCT"),
    IntegrationManifest(
        "autofde-lab",
        "exploration and capability admission source",
        "seanchatmangpt/autofde-lab",
        "d6951f863613ed8840638801b0411549ffce9601",
        "SELECT",
    ),
)


def admitted_integrations() -> tuple[IntegrationManifest, ...]:
    """Return the immutable integration constitution; this is not execution evidence."""
    return _MANIFEST


def _manifest_payload(integrations: Iterable[IntegrationManifest]) -> dict[str, object]:
    rows = [asdict(item) for item in integrations]
    return {
        "schema": "autofde.integration-manifest/1",
        "kind": "MANIFEST",
        "authority_ceiling": "CONSTRUCT",
        "integrations": rows,
    }


def integration_manifest_digest() -> str:
    payload = _manifest_payload(_MANIFEST)
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def integration_receipt() -> dict[str, object]:
    """Return a content-addressed integration manifest without manufacturing standing.

    The historical implementation returned ``standing=PARTIAL_ALIVE`` unconditionally.
    That was not an observation and therefore was not a receipt. This surface now binds
    only identities and authority ceilings. Runtime observations are separate.
    """
    payload = _manifest_payload(_MANIFEST)
    return {**payload, "manifest_digest": integration_manifest_digest()}


def observe_runtime_integrations() -> tuple[IntegrationObservation, ...]:
    """Observe installed PyPI identities without promoting installation to capability standing."""
    observations: list[IntegrationObservation] = []
    for item in _MANIFEST:
        if not item.coordinate.startswith("PyPI:"):
            observations.append(
                IntegrationObservation(
                    item.name,
                    item.coordinate,
                    item.identity,
                    None,
                    False,
                )
            )
            continue
        distribution = item.coordinate.removeprefix("PyPI:")
        try:
            observed_identity = metadata.version(distribution)
        except metadata.PackageNotFoundError:
            observed_identity = None
        observations.append(
            IntegrationObservation(
                item.name,
                item.coordinate,
                item.identity,
                observed_identity,
                observed_identity is not None,
            )
        )
    return tuple(observations)
