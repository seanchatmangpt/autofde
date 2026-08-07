output "resource_id" {
  description = "Independent ARM-verifiable consequence identity."
  value       = azurerm_resource_group.closed_vertical.id
}

output "resource_group_name" {
  value = azurerm_resource_group.closed_vertical.name
}
