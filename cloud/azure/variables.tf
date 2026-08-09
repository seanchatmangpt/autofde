variable "subscription_id" {
  description = "Exact allowlisted disposable Azure subscription admitted by AutoFDE authority."
  type        = string
  nullable    = false

  validation {
    condition     = length(trimspace(var.subscription_id)) > 0
    error_message = "subscription_id must be explicitly admitted"
  }
}

variable "resource_group_name" {
  description = "Disposable resource group forming the orphan-sweep boundary."
  type        = string
  default     = "autofde-closed-vertical-test"
}

variable "location" {
  description = "Azure region for the bounded closed vertical."
  type        = string
  default     = "westus2"
}

variable "tags" {
  description = "Additional admitted tags."
  type        = map(string)
  default     = {}
}

variable "log_analytics_workspace_name" {
  description = "Exact Sentinel Log Analytics workspace admitted for the closed vertical."
  type        = string
  default     = "autofde-sentinel-test"

  validation {
    condition     = length(trimspace(var.log_analytics_workspace_name)) > 0
    error_message = "log_analytics_workspace_name must be explicit"
  }
}

variable "logic_app_name" {
  description = "Logic App receiving admitted Sentinel incident payloads."
  type        = string
  default     = "autofde-sentinel-ingress"

  validation {
    condition     = length(trimspace(var.logic_app_name)) > 0
    error_message = "logic_app_name must be explicit"
  }
}
