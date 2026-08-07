# Azure closed-vertical groundwork

This directory is a disposable Azure consequence boundary for the AutoFDE closed vertical. It is not an ambient deployment surface.

`TerraformToolchain.prepare()` performs only `init -backend=false` and `validate`; it is CONSTRUCT, not DO. `apply` and `destroy` remain consequential and may only be called as actuators behind the BRCE broker after the exact capability digest and authority envelope are admitted.

Authority is admitted through `AUTOFDE_AZURE_SUBSCRIPTION_ID` plus either a short-lived `AUTOFDE_AZURE_ACCESS_TOKEN` for independent ARM observation or a service-principal tuple (`AUTOFDE_AZURE_TENANT_ID`, `AUTOFDE_AZURE_CLIENT_ID`, `AUTOFDE_AZURE_CLIENT_SECRET`) for both ARM observation and Terraform/OpenTofu. Existing `ARM_*` service-principal variables are also recognized. Tokens and secrets are never written to receipts by this adapter.

Independent postconditions use Azure Resource Manager REST directly; Azure CLI is not required. Final cleanup enumerates every resource in the admitted resource group and requires the enumeration to be empty. A single-resource 404 is not sufficient for crown standing.

The IaC engine is resolved in this order: explicit `AUTOFDE_IAC_ENGINE`, `terraform`, then `tofu`. `toolchain.lock.json` records an observed OpenTofu release identity as a capability-equivalent fallback. It intentionally does not claim exact Terraform brand parity.

Live standing remains `BLOCKED:LIVE_CLOUD_AUTHORITY` until a named disposable subscription and scoped short-lived credential are supplied. Only after real BRCE apply, independent ARM verification, BRCE destroy, whole-resource-group orphan sweep, OCEL conformance, and replay may the live Azure episode become `ALIVE`.
