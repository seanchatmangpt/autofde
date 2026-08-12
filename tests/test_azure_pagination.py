from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from autofde.azure import (
    AzureARMClient,
    AzureAuthority,
    AzureObservationError,
    AzureResourceGroupOrphanVerifier,
)
from autofde.azure_sensing import AzureARMObservationSensor
from autofde.observations import ObservationLedger

SUBSCRIPTION = "sub"
RESOURCE_GROUP = "autofde-test"
PAGE_ONE_RESOURCE = (
    "/subscriptions/sub/resourceGroups/autofde-test/providers/"
    "Microsoft.Storage/storageAccounts/one"
)
PAGE_TWO_RESOURCE = (
    "/subscriptions/sub/resourceGroups/autofde-test/providers/"
    "Microsoft.Storage/storageAccounts/two"
)
ABSENT_RESOURCE = (
    "/subscriptions/sub/resourceGroups/autofde-test/providers/"
    "Microsoft.Storage/storageAccounts/missing"
)


class PaginationState:
    def __init__(self) -> None:
        self.requests: list[str] = []
        self.next_link_mode = "valid"


class PaginationHandler(BaseHTTPRequestHandler):
    server: ThreadingHTTPServer

    @property
    def state(self) -> PaginationState:
        return getattr(self.server, "state")

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        self.state.requests.append(self.path)
        if self.headers.get("Authorization") != "Bearer local-token":
            self._send(401, {"error": "unauthorized"})
            return
        parsed = urlsplit(self.path)
        expected = f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{RESOURCE_GROUP}/resources"
        if parsed.path != expected:
            self._send(404, {"error": "not-found"})
            return
        page = parse_qs(parsed.query).get("$skiptoken", [""])[0]
        if page == "page2":
            self._send(200, {"value": [{"id": PAGE_TWO_RESOURCE, "type": "Microsoft.Storage/storageAccounts"}]})
            return

        if self.state.next_link_mode == "external":
            next_link = (
                "https://example.invalid/subscriptions/sub/resourceGroups/"
                "autofde-test/resources?$skiptoken=page2"
            )
        elif self.state.next_link_mode == "cycle":
            host, port = self.server.server_address
            next_link = (
                f"http://{host}:{port}{expected}?api-version=2021-04-01"
                "&$skiptoken=cycle"
            )
        else:
            host, port = self.server.server_address
            next_link = (
                f"http://{host}:{port}{expected}?api-version=2021-04-01"
                "&$skiptoken=page2"
            )
        self._send(
            200,
            {
                "value": [{"id": PAGE_ONE_RESOURCE, "type": "Microsoft.Storage/storageAccounts"}],
                "nextLink": next_link,
            },
        )


class AzurePaginationCourt(unittest.TestCase):
    def setUp(self) -> None:
        self.state = PaginationState()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), PaginationHandler)
        setattr(self.server, "state", self.state)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        authority = AzureAuthority(
            SUBSCRIPTION,
            access_token="local-token",
            arm_endpoint=f"http://{host}:{port}",
        )
        self.client = AzureARMClient(authority)
        self.tmp = tempfile.TemporaryDirectory()
        self.ledger = ObservationLedger(Path(self.tmp.name) / "observations.db")

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tmp.cleanup()

    def test_resource_group_enumeration_follows_all_pages(self) -> None:
        resources = self.client.resource_group_resources(RESOURCE_GROUP)
        self.assertEqual([row["id"] for row in resources], [PAGE_ONE_RESOURCE, PAGE_TWO_RESOURCE])
        self.assertEqual(len(self.state.requests), 2)

    def test_orphan_verifier_does_not_miss_resource_on_second_page(self) -> None:
        verifier = AzureResourceGroupOrphanVerifier(self.client, RESOURCE_GROUP)
        self.assertFalse(verifier.verify_absent(PAGE_TWO_RESOURCE))
        self.assertEqual(len(self.state.requests), 2)

    def test_closed_world_absence_is_only_issued_after_complete_pagination(self) -> None:
        sensor = AzureARMObservationSensor(self.client, self.ledger)
        receipt = sensor.sense_absence(ABSENT_RESOURCE, resource_group=RESOURCE_GROUP)
        self.assertTrue(receipt.complete_enumeration)
        self.assertEqual(len(receipt.observation_ids), 1)
        self.assertEqual(len(self.state.requests), 2)

    def test_next_link_cannot_escape_admitted_arm_endpoint(self) -> None:
        self.state.next_link_mode = "external"
        with self.assertRaisesRegex(AzureObservationError, "ARM_PAGINATION_ENDPOINT_DRIFT"):
            self.client.resource_group_resources(RESOURCE_GROUP)
        self.assertEqual(len(self.state.requests), 1)


if __name__ == "__main__":
    unittest.main()
