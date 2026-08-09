from __future__ import annotations

import json
import os
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

ARM_ENDPOINT = "https://management.azure.com"
ARM_RESOURCE_API = "2021-04-01"
ARM_SUBSCRIPTION_API = "2020-01-01"
AZURE_SCOPE = "https://management.azure.com/.default"


class AzureAuthorityError(RuntimeError):
    pass


class AzureObservationError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class AzureAuthority:
    subscription_id: str
    access_token: str | None = None
    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    arm_endpoint: str = ARM_ENDPOINT

    @property
    def credential_source(self) -> str | None:
        if self.access_token:
            return "bearer"
        if self.tenant_id and self.client_id and self.client_secret:
            return "service-principal"
        return None

    @classmethod
    def from_env(cls) -> "AzureAuthority | None":
        subscription_id = os.environ.get("AUTOFDE_AZURE_SUBSCRIPTION_ID") or os.environ.get(
            "ARM_SUBSCRIPTION_ID"
        )
        if not subscription_id:
            return None
        return cls(
            subscription_id=subscription_id,
            access_token=os.environ.get("AUTOFDE_AZURE_ACCESS_TOKEN"),
            tenant_id=os.environ.get("AUTOFDE_AZURE_TENANT_ID") or os.environ.get("ARM_TENANT_ID"),
            client_id=os.environ.get("AUTOFDE_AZURE_CLIENT_ID") or os.environ.get("ARM_CLIENT_ID"),
            client_secret=os.environ.get("AUTOFDE_AZURE_CLIENT_SECRET")
            or os.environ.get("ARM_CLIENT_SECRET"),
            arm_endpoint=os.environ.get("AUTOFDE_AZURE_ARM_ENDPOINT", ARM_ENDPOINT).rstrip("/"),
        )

    def iac_environment(self) -> dict[str, str]:
        """Return engine-native Azure auth without exposing a bearer token to Terraform/OpenTofu."""
        if not (self.tenant_id and self.client_id and self.client_secret):
            raise AzureAuthorityError("IAC_SERVICE_PRINCIPAL_NOT_ADMITTED")
        return {
            "ARM_SUBSCRIPTION_ID": self.subscription_id,
            "ARM_TENANT_ID": self.tenant_id,
            "ARM_CLIENT_ID": self.client_id,
            "ARM_CLIENT_SECRET": self.client_secret,
        }


@dataclass(frozen=True, slots=True)
class AzurePreflight:
    engine: str | None
    engine_kind: str | None
    subscription_id: str | None
    credential_source: str | None

    @property
    def standing(self) -> str:
        if not self.subscription_id or not self.credential_source:
            return "BLOCKED:LIVE_CLOUD_AUTHORITY"
        if self.engine is None:
            return "BLOCKED:CLOUD_ENGINE_UNAVAILABLE"
        return "PARTIAL_ALIVE"


def resolve_iac_engine() -> tuple[str | None, str | None]:
    override = os.environ.get("AUTOFDE_IAC_ENGINE")
    if override:
        path = shutil.which(override) if os.path.sep not in override else override
        if path and Path(path).is_file():
            return str(path), Path(path).name
    for name in ("terraform", "tofu"):
        path = shutil.which(name)
        if path:
            return path, name
    return None, None


def azure_preflight() -> AzurePreflight:
    engine, kind = resolve_iac_engine()
    authority = AzureAuthority.from_env()
    return AzurePreflight(
        engine=engine,
        engine_kind=kind,
        subscription_id=None if authority is None else authority.subscription_id,
        credential_source=None if authority is None else authority.credential_source,
    )


class HTTPResponse(Protocol):
    status: int

    def read(self) -> bytes: ...


URLOpener = Callable[[urllib.request.Request, float], HTTPResponse]


def _default_open(request: urllib.request.Request, timeout: float) -> HTTPResponse:
    return urllib.request.urlopen(request, timeout=timeout)  # type: ignore[return-value]


class AzureARMClient:
    """Independent ARM observer. It never reads Terraform/OpenTofu state."""

    def __init__(
        self,
        authority: AzureAuthority,
        *,
        opener: URLOpener = _default_open,
        timeout: float = 20.0,
    ) -> None:
        self.authority = authority
        self.opener = opener
        self.timeout = timeout
        self._token: str | None = authority.access_token

    def _service_principal_token(self) -> str:
        a = self.authority
        if not (a.tenant_id and a.client_id and a.client_secret):
            raise AzureAuthorityError("AZURE_CREDENTIAL_NOT_ADMITTED")
        body = urllib.parse.urlencode(
            {
                "client_id": a.client_id,
                "client_secret": a.client_secret,
                "grant_type": "client_credentials",
                "scope": AZURE_SCOPE,
            }
        ).encode()
        request = urllib.request.Request(
            f"https://login.microsoftonline.com/{urllib.parse.quote(a.tenant_id, safe='')}/oauth2/v2.0/token",
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        response = self.opener(request, self.timeout)
        payload = json.loads(response.read())
        token = payload.get("access_token")
        if not isinstance(token, str) or not token:
            raise AzureAuthorityError("AZURE_TOKEN_ACQUISITION_FAILED")
        return token

    def token(self) -> str:
        if self._token is None:
            self._token = self._service_principal_token()
        return self._token

    def _url(self, path: str, api_version: str) -> str:
        endpoint = self.authority.arm_endpoint.rstrip("/")
        normalized = "/" + path.lstrip("/")
        separator = "&" if "?" in normalized else "?"
        return f"{endpoint}{normalized}{separator}api-version={urllib.parse.quote(api_version)}"

    def get(self, path: str, *, api_version: str = ARM_RESOURCE_API) -> tuple[int, Mapping[str, Any] | None]:
        request = urllib.request.Request(
            self._url(path, api_version),
            headers={"Authorization": f"Bearer {self.token()}", "Accept": "application/json"},
            method="GET",
        )
        try:
            response = self.opener(request, self.timeout)
            raw = response.read()
            return response.status, None if not raw else json.loads(raw)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return 404, None
            detail = exc.read().decode(errors="replace")[-1000:]
            raise AzureObservationError(f"ARM_HTTP_{exc.code}:{detail}") from exc

    def verify_subscription(self) -> bool:
        status, body = self.get(
            f"/subscriptions/{urllib.parse.quote(self.authority.subscription_id, safe='')}",
            api_version=ARM_SUBSCRIPTION_API,
        )
        return status == 200 and bool(body) and str(body.get("subscriptionId")) == self.authority.subscription_id

    def resource(self, resource_id: str) -> tuple[int, Mapping[str, Any] | None]:
        return self.get(resource_id)

    def resource_group_resources(self, resource_group: str) -> tuple[Mapping[str, Any], ...]:
        sub = urllib.parse.quote(self.authority.subscription_id, safe="")
        rg = urllib.parse.quote(resource_group, safe="")
        status, body = self.get(f"/subscriptions/{sub}/resourceGroups/{rg}/resources")
        if status != 200 or body is None:
            raise AzureObservationError(f"RESOURCE_GROUP_ENUMERATION_FAILED:{status}")
        values = body.get("value", [])
        if not isinstance(values, list):
            raise AzureObservationError("RESOURCE_GROUP_ENUMERATION_INVALID")
        return tuple(item for item in values if isinstance(item, Mapping))


class TerraformToolchain:
    """Non-consequential construction checks. `prepare` is not a BRCE DO operation."""

    def __init__(
        self,
        workdir: str | Path,
        *,
        engine: str | None = None,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        resolved, _ = resolve_iac_engine()
        self.engine = engine or resolved
        self.workdir = Path(workdir)
        self.runner = runner

    def prepare(self, authority: AzureAuthority) -> Mapping[str, Any]:
        if self.engine is None:
            raise RuntimeError("CLOUD_ENGINE_UNAVAILABLE")
        env = os.environ.copy()
        env.update(authority.iac_environment())
        env["TF_IN_AUTOMATION"] = "1"
        commands = (
            [self.engine, "init", "-backend=false", "-input=false", "-no-color"],
            [self.engine, "validate", "-no-color"],
        )
        for command in commands:
            proc = self.runner(
                command,
                cwd=self.workdir,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            if proc.returncode != 0:
                raise RuntimeError(
                    f"IAC_PREPARE_FAILED:{Path(self.engine).name}:{command[1]}:{proc.returncode}:{proc.stderr[-1000:]}"
                )
        return {"engine": Path(self.engine).name, "prepared": True}


class TerraformCLIActuator:
    """Terraform/OpenTofu subprocess adapter. Consequential calls must be invoked through BRCE."""

    def __init__(
        self,
        workdir: str | Path,
        operation: str,
        *,
        engine: str | None = None,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        if operation not in {"apply", "destroy"}:
            raise ValueError("operation must be apply or destroy")
        resolved, _ = resolve_iac_engine()
        self.engine = engine or resolved
        self.workdir = Path(workdir)
        self.operation = operation
        self.runner = runner

    def actuate(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        if self.engine is None:
            raise RuntimeError("CLOUD_ENGINE_UNAVAILABLE")
        authority = AzureAuthority.from_env()
        if authority is None or payload.get("subscription_id") != authority.subscription_id:
            raise RuntimeError("AZURE_SUBSCRIPTION_NOT_ADMITTED")
        env = os.environ.copy()
        env.update(authority.iac_environment())
        env["TF_IN_AUTOMATION"] = "1"
        command = [self.engine, self.operation, "-input=false", "-auto-approve", "-no-color"]
        proc = self.runner(
            command,
            cwd=self.workdir,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"IAC_{self.operation.upper()}_FAILED:{Path(self.engine).name}:{proc.returncode}:{proc.stderr[-1000:]}"
            )
        return {
            "operation": self.operation,
            "engine": Path(self.engine).name,
            "resource_id": payload["resource_id"],
            "returncode": proc.returncode,
        }


class AzureARMResourceVerifier:
    def __init__(self, client: AzureARMClient, *, expect_present: bool) -> None:
        self.client = client
        self.expect_present = expect_present

    def verify(self, payload: Mapping[str, Any], result: Mapping[str, Any]) -> bool:
        if payload.get("subscription_id") != self.client.authority.subscription_id:
            return False
        status, body = self.client.resource(str(payload["resource_id"]))
        if self.expect_present:
            return (
                status == 200
                and body is not None
                and str(body.get("id", "")).lower() == str(payload["resource_id"]).lower()
            )
        return status == 404


class AzureResourceGroupOrphanVerifier:
    """Crown absence proof: enumerate the whole admitted test resource group, not one resource ID."""

    def __init__(self, client: AzureARMClient, resource_group: str) -> None:
        self.client = client
        self.resource_group = resource_group

    def verify_absent(self, resource_id: str) -> bool:
        expected_fragment = f"/resourceGroups/{self.resource_group}/".lower()
        if expected_fragment not in resource_id.lower():
            return False
        return not self.client.resource_group_resources(self.resource_group)


# Compatibility names retained while the process surface migrates from Azure CLI to raw ARM observation.
class AzureCLIResourceVerifier:
    def __init__(self, *, expect_present: bool) -> None:
        self.expect_present = expect_present

    def verify(self, payload: Mapping[str, Any], result: Mapping[str, Any]) -> bool:
        authority = AzureAuthority.from_env()
        if authority is None or authority.credential_source is None:
            return False
        return AzureARMResourceVerifier(
            AzureARMClient(authority), expect_present=self.expect_present
        ).verify(payload, result)


class AzureCLIOrphanVerifier:
    def verify_absent(self, resource_id: str) -> bool:
        authority = AzureAuthority.from_env()
        if authority is None or authority.credential_source is None:
            return False
        parts = resource_id.strip('/').split('/')
        try:
            rg_index = next(i for i, part in enumerate(parts) if part.lower() == 'resourcegroups')
            resource_group = parts[rg_index + 1]
        except (StopIteration, IndexError):
            return False
        return AzureResourceGroupOrphanVerifier(
            AzureARMClient(authority), resource_group
        ).verify_absent(resource_id)
