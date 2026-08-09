output "resource_id" {
  description = "Independent ARM-verifiable consequence identity."
  value       = azurerm_resource_group.closed_vertical.id
}

output "resource_group_name" {
  value = azurerm_resource_group.closed_vertical.name
}

output "sentinel_workspace_id" {
  description = "ARM identity used for independent postcondition verification."
  value       = azurerm_log_analytics_workspace.sentinel.id
}

output "sentinel_ingress_logic_app_id" {
  description = "ARM identity of the managed-identity ingress workflow."
  value       = azurerm_logic_app_workflow.sentinel_ingress.id
}

output "sentinel_ingress_principal_id" {
  description = "System-assigned principal bound only to workspace read roles."
  value       = azurerm_logic_app_workflow.sentinel_ingress.identity[0].principal_id
}
