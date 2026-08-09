from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True, slots=True)
class IntegrationManifest:
    name: str
    role: str
    coordinate: str
    identity: str
    authority: str
    runtime_resident: bool


_MANIFEST = (
    IntegrationManifest(
        "substrate",
        "project scaffold provenance",
        "superlinear-ai/substrate",
        "ec640e3d6e0d18ddfc7123e67580ffdc7af80889",
        "CONSTRUCT",
        False,
    ),
    IntegrationManifest(
        "fastmcp",
        "MCP transport",
        "PyPI:fastmcp",
        ">=3.4.1,<4",
        "ROUTE",
        True,
    ),
    IntegrationManifest(
        "dspy",
        "design-time bounded program optimization",
        "PyPI:dspy",
        ">=3,<4",
        "CONSTRUCT",
        False,
    ),
    IntegrationManifest(
        "autofde-lab",
        "external exploration, experiment selection, and learning control plane",
        "seanchatmangpt/autofde-lab",
        "582277151fd07ea831f6217e43ddf764f61b723f",
        "SELECT_LEARN",
        False,
    ),
    IntegrationManifest(
        "ggen",
        "ontology-driven execution-profile manufacture",
        "seanchatmangpt/ggen",
        "37daece2a026efc6168c6ea715a1747bb934a898",
        "CONSTRUCT",
        False,
    ),
    IntegrationManifest(
        "gymact",
        "governed consequence substrate",
        "seanchatmangpt/gymact",
        "24bd68a8c9e59ee42a4a2eeea9fc12d79fe75f5b",
        "DO_BRCE_ONLY",
        True,
    ),
)


def admitted_integrations() -> tuple[IntegrationManifest, ...]:
    return _MANIFEST


def integration_receipt() -> dict[str, object]:
    return {
        "standing": "PARTIAL_ALIVE",
        "production_rule": "EXPLOIT_ONLY_COMPILED_PROFILE_TO_GYMACT_BRCE",
        "integrations": [asdict(item) for item in _MANIFEST],
    }
