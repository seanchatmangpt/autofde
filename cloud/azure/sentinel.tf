resource "azurerm_log_analytics_workspace" "sentinel" {
  name                = var.log_analytics_workspace_name
  location            = azurerm_resource_group.closed_vertical.location
  resource_group_name = azurerm_resource_group.closed_vertical.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = var.tags
}

resource "azurerm_sentinel_log_analytics_workspace_onboarding" "sentinel" {
  workspace_id = azurerm_log_analytics_workspace.sentinel.id
}

resource "azurerm_logic_app_workflow" "sentinel_ingress" {
  name                = var.logic_app_name
  location            = azurerm_resource_group.closed_vertical.location
  resource_group_name = azurerm_resource_group.closed_vertical.name
  enabled             = true
  tags                = var.tags

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_logic_app_trigger_http_request" "sentinel_incident" {
  name         = "sentinel-incident"
  logic_app_id = azurerm_logic_app_workflow.sentinel_ingress.id

  schema = jsonencode({
    type = "object"
    required = ["id", "name", "properties"]
    properties = {
      id = { type = "string" }
      name = { type = "string" }
      properties = {
        type = "object"
        required = ["lastModifiedTimeUtc", "status", "title"]
      }
    }
  })
}

resource "azurerm_role_assignment" "sentinel_reader" {
  scope                = azurerm_log_analytics_workspace.sentinel.id
  role_definition_name = "Microsoft Sentinel Reader"
  principal_id         = azurerm_logic_app_workflow.sentinel_ingress.identity[0].principal_id
}

resource "azurerm_role_assignment" "log_analytics_reader" {
  scope                = azurerm_log_analytics_workspace.sentinel.id
  role_definition_name = "Log Analytics Reader"
  principal_id         = azurerm_logic_app_workflow.sentinel_ingress.identity[0].principal_id
}
