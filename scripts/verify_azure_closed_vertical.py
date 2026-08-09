from __future__ import annotations

import argparse
from pathlib import Path


class ContractError(RuntimeError):
    pass


def require(text: str, token: str, reason: str) -> None:
    if token not in text:
        raise ContractError(reason)


def refuse(text: str, token: str, reason: str) -> None:
    if token in text:
        raise ContractError(reason)


def verify(root: Path) -> None:
    azure = root / "cloud" / "azure"
    main = (azure / "main.tf").read_text()
    sentinel = (azure / "sentinel.tf").read_text()
    variables = (azure / "variables.tf").read_text()
    outputs = (azure / "outputs.tf").read_text()

    require(main, 'subscription_id = var.subscription_id', "REFUSED:UNPINNED_SUBSCRIPTION")
    require(main, '"autofde:managed-by" = "brce"', "REFUSED:BRCE_TAG_ABSENT")
    require(sentinel, 'azurerm_sentinel_log_analytics_workspace_onboarding', "REFUSED:SENTINEL_ONBOARDING_ABSENT")
    require(sentinel, 'type = "SystemAssigned"', "REFUSED:MANAGED_IDENTITY_ABSENT")
    require(sentinel, 'azurerm_logic_app_trigger_http_request', "REFUSED:INCIDENT_TRIGGER_ABSENT")
    require(sentinel, '"lastModifiedTimeUtc"', "REFUSED:INGRESS_SCHEMA_INCOMPLETE")
    require(sentinel, 'role_definition_name = "Microsoft Sentinel Reader"', "REFUSED:SENTINEL_RBAC_ABSENT")
    require(sentinel, 'role_definition_name = "Log Analytics Reader"', "REFUSED:LOG_RBAC_ABSENT")
    require(sentinel, 'scope                = azurerm_log_analytics_workspace.sentinel.id', "REFUSED:RBAC_SCOPE_BROADENED")
    refuse(sentinel, 'role_definition_name = "Owner"', "REFUSED:OWNER_ROLE")
    refuse(sentinel, 'role_definition_name = "Contributor"', "REFUSED:CONTRIBUTOR_ROLE")
    refuse(sentinel, 'scope                = "/subscriptions/${var.subscription_id}"', "REFUSED:SUBSCRIPTION_SCOPE_RBAC")
    require(variables, 'variable "subscription_id"', "REFUSED:SUBSCRIPTION_ADMISSION_ABSENT")
    require(variables, 'variable "log_analytics_workspace_name"', "REFUSED:WORKSPACE_ADMISSION_ABSENT")
    require(variables, 'variable "logic_app_name"', "REFUSED:LOGIC_APP_ADMISSION_ABSENT")
    require(outputs, 'output "sentinel_workspace_id"', "REFUSED:WORKSPACE_POSTCONDITION_ID_ABSENT")
    require(outputs, 'output "sentinel_ingress_logic_app_id"', "REFUSED:LOGIC_APP_POSTCONDITION_ID_ABSENT")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    args = parser.parse_args()
    try:
        verify(Path(args.root))
    except (OSError, ContractError) as exc:
        print(exc)
        return 1
    print("AUTOFDE_AZURE_CLOSED_VERTICAL_CONTRACT_ALIVE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
