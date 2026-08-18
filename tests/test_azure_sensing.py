from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from autofde.azure import AzureARMClient, AzureAuthority
from autofde.azure_sensing import AzureARMObservationSensor
from autofde.observations import ObservationLedger, ObservationRefusal, ObservationRefusalCode


RESOURCE_ID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Web/sites/app-1"
OTHER_ID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/data1"


class ARMHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path.lower() == RESOURCE_ID.lower():
            self._json(200, {
                "id": RESOURCE_ID,
                "type": "Microsoft.Web/sites",
                "location": "westus2",
                "properties": {"provisioningState": "Succeeded"},
            })
            return
        if path == "/subscriptions/sub-1/resourceGroups/rg-1/resources":
            self._json(200, {"value": [
                {
                    "id": OTHER_ID,
                    "type": "Microsoft.Storage/storageAccounts",
                    "location": "westus2",
                    "properties": {"provisioningState": "Succeeded"},
                }
            ]})
            return
        self._json(404, {"error": {"code": "ResourceNotFound"}})

    def _json(self, status: int, payload: object) -> None:
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class AzureSensingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), ARMHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.endpoint = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.ledger = ObservationLedger(f"{self.tmp.name}/observations.db")
        authority = AzureAuthority(
            subscription_id="sub-1",
            access_token="test-read-only-token",
            arm_endpoint=self.endpoint,
        )
        self.client = AzureARMClient(authority)
        self.sensor = AzureARMObservationSensor(self.client, self.ledger)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_real_http_arm_get_populates_raw_observation_graph(self) -> None:
        receipt = self.sensor.sense_resource(
            RESOURCE_ID,
            scope="/subscriptions/sub-1/resourceGroups/rg-1",
            observed_at="2026-08-11T05:29:50Z",
        )
        self.assertFalse(receipt.complete_enumeration)
        self.assertEqual(4, len(receipt.observation_ids))
        self.assertEqual(4, self.ledger.raw_count())

    def test_point_404_cannot_masquerade_as_absence_proof(self) -> None:
        missing = RESOURCE_ID + "-missing"
        with self.assertRaises(ObservationRefusal) as ctx:
            self.sensor.sense_resource(
                missing,
                scope="/subscriptions/sub-1/resourceGroups/rg-1",
                observed_at="2026-08-11T05:29:50Z",
            )
        self.assertEqual(ObservationRefusalCode.ABSENCE_NOT_CLOSED_WORLD, ctx.exception.code)
        self.assertEqual(0, self.ledger.raw_count())

    def test_complete_enumeration_proves_absence_and_admits_o_star(self) -> None:
        receipt = self.sensor.sense_absence(
            RESOURCE_ID,
            resource_group="rg-1",
            observed_at="2026-08-11T05:29:50Z",
        )
        self.assertTrue(receipt.complete_enumeration)
        claim = self.ledger.admit_current(
            subject=RESOURCE_ID,
            property_iri="urn:autofde:cloud:exists",
            scope=receipt.scope,
            now="2026-08-11T05:30:00Z",
            max_age_seconds=30,
            required_sensors=(receipt.sensor_id,),
        )
        self.assertTrue(claim.absent)

    def test_complete_enumeration_refuses_false_absence_when_resource_is_present(self) -> None:
        with self.assertRaises(ObservationRefusal) as ctx:
            self.sensor.sense_absence(
                OTHER_ID,
                resource_group="rg-1",
                observed_at="2026-08-11T05:29:50Z",
            )
        self.assertEqual(ObservationRefusalCode.OBSERVATION_CONFLICT, ctx.exception.code)


if __name__ == "__main__":
    unittest.main()
