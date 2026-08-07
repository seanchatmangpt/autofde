from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class AzurePreflight:
    terraform: str | None
    az: str | None
    subscription_id: str | None

    @property
    def standing(self) -> str:
        if self.terraform is None:
            return "BLOCKED:TERRAFORM_CLI_UNAVAILABLE"
        if self.az is None:
            return "BLOCKED:AZURE_CLI_UNAVAILABLE"
        if not self.subscription_id:
            return "BLOCKED:AZURE_SUBSCRIPTION_NOT_ADMITTED"
        return "PARTIAL_ALIVE"


def azure_preflight() -> AzurePreflight:
    return AzurePreflight(
        terraform=shutil.which("terraform"),
        az=shutil.which("az"),
        subscription_id=os.environ.get("AUTOFDE_AZURE_SUBSCRIPTION_ID"),
    )


class TerraformCLIActuator:
    """Real Terraform subprocess adapter. Consequential calls must be invoked through BRCE."""

    def __init__(self, workdir: str | Path, operation: str) -> None:
        if operation not in {"apply", "destroy"}:
            raise ValueError("operation must be apply or destroy")
        self.workdir = Path(workdir)
        self.operation = operation

    def actuate(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        binary = shutil.which("terraform")
        if binary is None:
            raise RuntimeError("TERRAFORM_CLI_UNAVAILABLE")
        subscription_id = payload.get("subscription_id")
        admitted = os.environ.get("AUTOFDE_AZURE_SUBSCRIPTION_ID")
        if not admitted or subscription_id != admitted:
            raise RuntimeError("AZURE_SUBSCRIPTION_NOT_ADMITTED")
        env = os.environ.copy()
        env["TF_IN_AUTOMATION"] = "1"
        command = [binary, self.operation, "-input=false", "-auto-approve", "-no-color"]
        proc = subprocess.run(
            command,
            cwd=self.workdir,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"TERRAFORM_{self.operation.upper()}_FAILED:{proc.returncode}:{proc.stderr[-1000:]}")
        return {
            "operation": self.operation,
            "resource_id": payload["resource_id"],
            "returncode": proc.returncode,
        }


class AzureCLIResourceVerifier:
    """Independent Azure CLI observer; it does not read Terraform state."""

    def __init__(self, *, expect_present: bool) -> None:
        self.expect_present = expect_present

    def verify(self, payload: Mapping[str, Any], result: Mapping[str, Any]) -> bool:
        binary = shutil.which("az")
        if binary is None:
            return False
        subscription_id = payload.get("subscription_id")
        admitted = os.environ.get("AUTOFDE_AZURE_SUBSCRIPTION_ID")
        if not admitted or subscription_id != admitted:
            return False
        proc = subprocess.run(
            [binary, "resource", "show", "--ids", str(payload["resource_id"]), "--subscription", admitted, "--output", "json"],
            capture_output=True,
            text=True,
            check=False,
        )
        if self.expect_present:
            if proc.returncode != 0:
                return False
            try:
                observed = json.loads(proc.stdout)
            except json.JSONDecodeError:
                return False
            return str(observed.get("id", "")).lower() == str(payload["resource_id"]).lower()
        return proc.returncode != 0


class AzureCLIOrphanVerifier:
    def verify_absent(self, resource_id: str) -> bool:
        binary = shutil.which("az")
        admitted = os.environ.get("AUTOFDE_AZURE_SUBSCRIPTION_ID")
        if binary is None or not admitted:
            return False
        proc = subprocess.run(
            [binary, "resource", "show", "--ids", resource_id, "--subscription", admitted, "--output", "none"],
            capture_output=True,
            text=True,
            check=False,
        )
        return proc.returncode != 0
