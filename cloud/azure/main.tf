terraform {
  required_version = ">= 1.8.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

resource "azurerm_resource_group" "closed_vertical" {
  name     = var.resource_group_name
  location = var.location
  tags = merge(var.tags, {
    "autofde:purpose"    = "closed-vertical"
    "autofde:disposable" = "true"
    "autofde:managed-by" = "brce"
  })
}
