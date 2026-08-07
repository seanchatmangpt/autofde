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
