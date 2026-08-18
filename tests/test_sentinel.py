from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from autofde.azure import AzureARMClient, AzureAuthority
from autofde.runtime import AuthorityEnvelope, BRCEBroker, CapabilityBundle, OccurrenceState, RuntimeStore, Standing, WorkItem
from autofde.sentinel import (
    SentinelIncidentClient,
    SentinelIncidentCloseActuator,
    SentinelIncidentClosedVerifier,
    SentinelRefusal,
)

SUBSCRIPTION = "11111111-2222-3333-4444-555555555555"
RESOURCE_GROUP = "rg-autofde-court"
WORKSPACE = "sentinel-court"
INCIDENT = "73e01a99-5cd7-4139-a149-9f2736ff2ab5"
RESOURCE_ID = (
    f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{RESOURCE_GROUP}"
    f"/providers/Microsoft.OperationalInsights/workspaces/{WORKSPACE}"
    f"/providers/Microsoft.SecurityInsights/incidents/{INCIDENT}"
)


class SentinelCourtState:
    def __init__(self) -> None:
        self.get_count = 0
        self.put_count = 0
        self.persist_updates = True
        self.incident: dict[str, Any] = {
            "id": RESOURCE_ID,
            "name": INCIDENT,
            "type": "Microsoft.SecurityInsights/incidents",
            "etag": '"court-etag-1"',
            "properties": {
                "title": "Known benign automation noise",
                "severity": "Medium",
                "status": "Active",
                "description": "bounded local protocol court",
                "labels": [{"labelName": "autofde-court", "labelType": "User"}],
            },
        }


class SentinelCourtHandler(BaseHTTPRequestHandler):
    server: ThreadingHTTPServer

    @property
    def court(self) -> SentinelCourtState:
        return getattr(self.server, "court")

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def _send(self, status: int, body: dict[str, Any]) -> None:
        raw = json.dumps(body, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _authorized(self) -> bool:
        return self.headers.get("Authorization") == "Bearer local-court-token"

    def _matches_incident(self) -> bool:
        return urlsplit(self.path).path.lower() == RESOURCE_ID.lower()

    def do_GET(self) -> None:  # noqa: N802
        self.court.get_count += 1
        if not self._authorized():
            self._send(401, {"error": {"code": "Unauthorized"}})
            return
        if not self._matches_incident():
            self._send(404, {"error": {"code": "NotFound"}})
            return
        self._send(200, self.court.incident)

    def do_PUT(self) -> None:  # noqa: N802
        self.court.put_count += 1
        if not self._authorized():
            self._send(401, {"error": {"code": "Unauthorized"}})
            return
        if not self._matches_incident():
            self._send(404, {"error": {"code": "NotFound"}})
            return
        if self.headers.get("If-Match") != self.court.incident["etag"]:
            self._send(412, {"error": {"code": "PreconditionFailed"}})
            return
        length = int(self.headers.get("Content-Length", "0"))
        request_body = json.loads(self.rfile.read(length))
        if request_body.get("etag") != self.court.incident["etag"]:
            self._send(412, {"error": {"code": "PreconditionFailed"}})
            return
        updated = {
            "id": RESOURCE_ID,
            "name": INCIDENT,
            "type": "Microsoft.SecurityInsights/incidents",
            "etag": '"court-etag-2"',
            "properties": request_body["properties"],
        }
        if self.court.persist_updates:
            self.court.incident = updated
        self._send(200, updated)


class SentinelBRCEIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.court = SentinelCourtState()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), SentinelCourtHandler)
        setattr(self.server, "court", self.court)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        endpoint = f"http://127.0.0.1:{self.server.server_address[1]}"
        authority = AzureAuthority(
            subscription_id=SUBSCRIPTION,
            access_token="local-court-token",
            arm_endpoint=endpoint,
        )
        # Separate clients make the postcondition observation independent of the actuator object.
        self.actuator_client = SentinelIncidentClient(AzureARMClient(authority))
        self.verifier_client = SentinelIncidentClient(AzureARMClient(authority))
        self.tmp = tempfile.TemporaryDirectory()
        self.store = RuntimeStore(Path(self.tmp.name) / "runtime.db")
        self.bundle = CapabilityBundle.from_bytes(
            name="sentinel-close-known-benign",
            payload=b"sentinel-close-known-benign/v2",
            source_repo="seanchatmangpt/autofde-lab",
            source_sha="d6951f863613ed8840638801b0411549ffce9601",
            generated_by="seanchatmangpt/ggen",
            generator_sha="2aed979b92e4b68226208988420173154c663539",
        )
        self.store.pin_bundle(self.bundle)
        self.subject = f"azure:{RESOURCE_ID}"
        self.authority = AuthorityEnvelope(
            envelope_id="authority:sentinel-court-close",
            subject=self.subject,
            allowed_consequences=frozenset({"azure:sentinel:close-incident"}),
            capability_digest=self.bundle.digest,
        )

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tmp.cleanup()

    def payload(self) -> dict[str, str]:
        return {
            "subscription_id": SUBSCRIPTION,
            "resource_group": RESOURCE_GROUP,
            "workspace_name": WORKSPACE,
            "incident_id": INCIDENT,
            "expected_etag": '"court-etag-1"',
            "target_status": "Closed",
            "classification": "BenignPositive",
            "classification_reason": "SuspiciousButExpected",
            "classification_comment": "Verified known-benign pattern in bounded AutoFDE court",
        }

    def item(self, key: str = "sentinel-close-1") -> WorkItem:
        return WorkItem(
            idempotency_key=key,
            subject=self.subject,
            consequence="azure:sentinel:close-incident",
            capability_digest=self.bundle.digest,
            payload=self.payload(),
        )

    def actuator(self) -> SentinelIncidentCloseActuator:
        return SentinelIncidentCloseActuator(self.actuator_client)

    def verifier(self) -> SentinelIncidentClosedVerifier:
        return SentinelIncidentClosedVerifier(self.verifier_client)

    def test_real_http_close_runs_only_through_brce_and_is_independently_verified(self) -> None:
        result = BRCEBroker(self.store).do(
            self.item(), authority=self.authority, actuator=self.actuator(), verifier=self.verifier()
        )
        self.assertEqual(result.state, OccurrenceState.VERIFIED)
        self.assertEqual(result.standing, Standing.ALIVE)
        self.assertEqual(self.court.put_count, 1)
        self.assertEqual(self.court.get_count, 2)
        self.assertEqual(self.court.incident["properties"]["status"], "Closed")
        self.assertEqual(
            self.store.receipt_kinds(result.occurrence_id),
            ["PRE_ACTUATION", "POSTCONDITION_VERIFIED"],
        )

    def test_replay_returns_terminal_receipt_without_second_http_consequence(self) -> None:
        broker = BRCEBroker(self.store)
        actuator = self.actuator()
        verifier = self.verifier()
        first = broker.do(self.item(), authority=self.authority, actuator=actuator, verifier=verifier)
        counts = (self.court.get_count, self.court.put_count)
        second = broker.do(self.item(), authority=self.authority, actuator=actuator, verifier=verifier)
        self.assertEqual(first, second)
        self.assertEqual((self.court.get_count, self.court.put_count), counts)
        self.assertEqual(self.court.put_count, 1)

    def test_authority_refusal_produces_zero_network_consequence(self) -> None:
        denied = AuthorityEnvelope(
            envelope_id="authority:sentinel-denied",
            subject=self.subject,
            allowed_consequences=frozenset(),
            capability_digest=self.bundle.digest,
        )
        result = BRCEBroker(self.store).do(
            self.item(), authority=denied, actuator=self.actuator(), verifier=self.verifier()
        )
        self.assertEqual(result.standing, Standing.REFUSED)
        self.assertEqual(self.court.get_count, 0)
        self.assertEqual(self.court.put_count, 0)

    def test_etag_drift_refuses_before_put(self) -> None:
        payload = self.payload()
        payload["expected_etag"] = '"stale-etag"'
        with self.assertRaisesRegex(SentinelRefusal, "SENTINEL_ETAG_DRIFT"):
            self.actuator().actuate(payload)
        self.assertEqual(self.court.get_count, 1)
        self.assertEqual(self.court.put_count, 0)

    def test_near_miss_incident_identity_never_puts(self) -> None:
        payload = self.payload()
        payload["incident_id"] = "wrong-incident"
        with self.assertRaisesRegex(SentinelRefusal, "INCIDENT_NOT_OBSERVED"):
            self.actuator().actuate(payload)
        self.assertEqual(self.court.put_count, 0)

    def test_actuator_ack_is_not_postcondition_evidence(self) -> None:
        self.court.persist_updates = False
        result = BRCEBroker(self.store).do(
            self.item("lying-ack"),
            authority=self.authority,
            actuator=self.actuator(),
            verifier=self.verifier(),
        )
        self.assertEqual(self.court.put_count, 1)
        self.assertEqual(result.state, OccurrenceState.REFUSED)
        self.assertEqual(result.standing, Standing.REFUSED)
        self.assertEqual(self.court.incident["properties"]["status"], "Active")

    def test_payload_cannot_escape_incident_path_segment(self) -> None:
        payload = self.payload()
        payload["incident_id"] = "../other"
        with self.assertRaisesRegex(SentinelRefusal, "PATH_SEGMENT_INVALID"):
            self.actuator().actuate(payload)
        self.assertEqual(self.court.get_count, 0)
        self.assertEqual(self.court.put_count, 0)


if __name__ == "__main__":
    unittest.main()
