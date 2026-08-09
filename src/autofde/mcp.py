from __future__ import annotations

from fastmcp import FastMCP

from .integrations import integration_receipt

mcp = FastMCP("AutoFDE")


@mcp.tool
def get_integration_receipt() -> dict[str, object]:
    """Return the admitted integration identities without granting DO authority."""
    return integration_receipt()


def main() -> None:
    mcp.run()
