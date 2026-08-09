from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

from autofde.azure import (
    AzureARMClient,
    AzureARMResourceVerifier,
    AzureAuthority,
    AzureAuthorityError,
    AzureResourceGroupOrphanVerifier,
    TerraformCLIActuator,
    TerraformToolchain,
    azure_preflight,
)


class Response:
    def __init__(self, body, status=200):
        self.status = status
        self._body = json.dumps(body).encode()

    def read(self):
        return self._body


class AzureGroundworkTests(unittest.TestCase):
    def clean_env(self):
        return patch.dict(
            os.environ,
            {
                "AUTOFDE_AZURE_SUBSCRIPTION_ID": "",
                "AUTOFDE_AZURE_ACCESS_TOKEN": "",
                "AUTOFDE_AZURE_TENANT_ID": "",
                "AUTOFDE_AZURE_CLIENT_ID": "",
                "AUTOFDE_AZURE_CLIENT_SECRET": "",
                "ARM_SUBSCRIPTION_ID": "",
                "ARM_TENANT_ID": "",
                "ARM_CLIENT_ID": "",
                "ARM_CLIENT_SECRET": "",
            },
            clear=False,
        )

    def test_preflight_collapses_missing_subscription_or_credential_to_live_authority(self):
        with self.clean_env(), patch("autofde.azure.resolve_iac_engine", return_value=("/bin/tofu", "tofu")):
            self.assertEqual(azure_preflight().standing, "BLOCKED:LIVE_CLOUD_AUTHORITY")

    def test_service_principal_is_admitted_for_iac_without_azure_cli(self):
        authority = AzureAuthority("sub", tenant_id="tenant", client_id="client", client_secret="secret")
        self.assertEqual(authority.credential_source, "service-principal")
        self.assertEqual(authority.iac_environment()["ARM_SUBSCRIPTION_ID"], "sub")

    def test_bearer_can_observe_arm_but_cannot_implicitly_authorize_iac(self):
        authority = AzureAuthority("sub", access_token="short-lived")
        self.assertEqual(authority.credential_source, "bearer")
        with self.assertRaisesRegex(AzureAuthorityError, "IAC_SERVICE_PRINCIPAL_NOT_ADMITTED"):
            authority.iac_environment()

    def test_arm_client_acquires_token_and_verifies_exact_subscription(self):
        calls = []

        def opener(request, timeout):
            calls.append((request.full_url, request.method, timeout))
            if "login.microsoftonline.com" in request.full_url:
                return Response({"access_token": "token"})
            return Response({"subscriptionId": "sub"})

        authority = AzureAuthority("sub", tenant_id="tenant", client_id="client", client_secret="secret")
        client = AzureARMClient(authority, opener=opener)
        self.assertTrue(client.verify_subscription())
        self.assertEqual(calls[0][1], "POST")
        self.assertIn("/subscriptions/sub?api-version=2020-01-01", calls[1][0])

    def test_resource_verifier_uses_arm_not_iac_state(self):
        rid = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a"

        def opener(request, timeout):
            return Response({"id": rid})

        client = AzureARMClient(AzureAuthority("sub", access_token="token"), opener=opener)
        verifier = AzureARMResourceVerifier(client, expect_present=True)
        self.assertTrue(verifier.verify({"subscription_id": "sub", "resource_id": rid}, {"resource_id": rid}))

    def test_absence_is_only_404_not_arbitrary_arm_failure(self):
        rid = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a"

        def opener(request, timeout):
            raise urllib.error.HTTPError(request.full_url, 404, "not found", {}, None)

        client = AzureARMClient(AzureAuthority("sub", access_token="token"), opener=opener)
        self.assertTrue(AzureARMResourceVerifier(client, expect_present=False).verify(
            {"subscription_id": "sub", "resource_id": rid}, {"resource_id": rid}
        ))

    def test_orphan_sweep_enumerates_entire_resource_group(self):
        rid = "/subscriptions/sub/resourceGroups/autofde-test/providers/Microsoft.Resources/deployments/x"
        client = AzureARMClient(
            AzureAuthority("sub", access_token="token"),
            opener=lambda request, timeout: Response({"value": []}),
        )
        self.assertTrue(AzureResourceGroupOrphanVerifier(client, "autofde-test").verify_absent(rid))

    def test_orphan_sweep_fails_when_any_resource_remains(self):
        rid = "/subscriptions/sub/resourceGroups/autofde-test/providers/Microsoft.Resources/deployments/x"
        client = AzureARMClient(
            AzureAuthority("sub", access_token="token"),
            opener=lambda request, timeout: Response({"value": [{"id": "orphan"}]}),
        )
        self.assertFalse(AzureResourceGroupOrphanVerifier(client, "autofde-test").verify_absent(rid))

    def test_prepare_is_init_and_validate_only(self):
        calls = []

        def runner(command, **kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, "", "")

        authority = AzureAuthority("sub", tenant_id="tenant", client_id="client", client_secret="secret")
        with tempfile.TemporaryDirectory() as tmp:
            result = TerraformToolchain(tmp, engine="/usr/bin/tofu", runner=runner).prepare(authority)
        self.assertEqual([c[1] for c in calls], ["init", "validate"])
        self.assertTrue(result["prepared"])

    def test_actuator_accepts_tofu_but_still_requires_admitted_subscription_and_sp(self):
        calls = []

        def runner(command, **kwargs):
            calls.append((command, kwargs["env"]))
            return subprocess.CompletedProcess(command, 0, "", "")

        env = {
            "AUTOFDE_AZURE_SUBSCRIPTION_ID": "sub",
            "AUTOFDE_AZURE_TENANT_ID": "tenant",
            "AUTOFDE_AZURE_CLIENT_ID": "client",
            "AUTOFDE_AZURE_CLIENT_SECRET": "secret",
        }
        with patch.dict(os.environ, env, clear=False), tempfile.TemporaryDirectory() as tmp:
            result = TerraformCLIActuator(tmp, "apply", engine="/usr/bin/tofu", runner=runner).actuate(
                {"subscription_id": "sub", "resource_id": "/subscriptions/sub/resourceGroups/rg"}
            )
        self.assertEqual(result["engine"], "tofu")
        self.assertEqual(calls[0][0][1], "apply")
        self.assertEqual(calls[0][1]["ARM_SUBSCRIPTION_ID"], "sub")


if __name__ == "__main__":
    unittest.main()
