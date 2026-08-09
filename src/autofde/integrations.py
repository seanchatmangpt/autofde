from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True, slots=True)
class IntegrationManifest:
    name: str
    role: str
    coordinate: str
    identity: str
    authority: str


_MANIFEST = (
    IntegrationManifest("substrate", "project scaffold", "superlinear-ai/substrate", "ec640e3d6e0d18ddfc7123e67580ffdc7af80889", "CONSTRUCT"),
    IntegrationManifest("fastmcp", "MCP transport", "PyPI:fastmcp", ">=2.12,<3", "ROUTE"),
    IntegrationManifest("dspy", "bounded program optimization", "PyPI:dspy", ">=3,<4", "CONSTRUCT"),
    IntegrationManifest("autofde-lab", "exploration and admission", "seanchatmangpt/autofde-lab", "8d8e8ae6c995abbe89f2ede4f8aaea1f02ae52f2", "SELECT"),
)


def admitted_integrations() -> tuple[IntegrationManifest, ...]:
    return _MANIFEST


def integration_receipt() -> dict[str, object]:
    return {"standing": "PARTIAL_ALIVE", "integrations": [asdict(item) for item in _MANIFEST]}
