from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from autofde.runtime import (
    AuthorityEnvelope,
    BRCEBroker,
    CapabilityBundle,
    OccurrenceState,
    RefusalCode,
    RuntimeStore,
    Standing,
    Supervisor,
    WorkItem,
)


class CountingActuator:
    def __init__(self, store: RuntimeStore | None = None, *, fail: bool = False) -> None:
        self.calls = 0
        self.store = store
        self.fail = fail

    def actuate(self, payload):
        self.calls += 1
        if self.store is not None:
            row = self.store.get_by_key(payload["key"])
            assert row is not None
            assert "PRE_ACTUATION" in self.store.receipt_kinds(int(row["id"]))
        if self.fail:
            raise RuntimeError("transport dropped after dispatch")
        return {"resource_id": payload["resource_id"], "state": "disabled"}


class ResourceDisabledVerifier:
    def __init__(self, *, accept: bool = True) -> None:
        self.accept = accept
        self.calls = 0

    def verify(self, payload, result):
        self.calls += 1
        return (
            self.accept
            and result.get("resource_id") == payload["resource_id"]
            and result.get("state") == "disabled"
        )


class RuntimeKernelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = RuntimeStore(Path(self.tmp.name) / "runtime.db")
        self.bundle = CapabilityBundle.from_bytes(
            name="azure-disable-public-access",
            payload=b"admitted capability bundle v1",
            source_repo="seanchatmangpt/autofde-lab",
            source_sha="8d8e8ae6c995abbe89f2ede4f8aaea1f02ae52f2",
            generated_by="seanchatmangpt/ggen",
            generator_sha="c36d72161b847b13555c24132819281f17e40e40",
        )
        self.store.pin_bundle(self.bundle)
        self.authority = AuthorityEnvelope(
            envelope_id="authority:test-subscription",
            subject="azure:test-subscription",
            allowed_consequences=frozenset({"azure:disable-public-access"}),
            capability_digest=self.bundle.digest,
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def item(self, key: str = "incident-1") -> WorkItem:
        return WorkItem(
            idempotency_key=key,
            subject="azure:test-subscription",
            consequence="azure:disable-public-access",
            capability_digest=self.bundle.digest,
            payload={
                "key": key,
                "resource_id": "/subscriptions/test/resourceGroups/rg/providers/X/y",
            },
        )

    def test_sqlite_wal_is_enabled(self) -> None:
        self.assertEqual(self.store.journal_mode(), "wal")

    def test_pre_actuation_receipt_exists_before_do_and_success_is_verified(self) -> None:
        actuator = CountingActuator(self.store)
        verifier = ResourceDisabledVerifier()
        result = BRCEBroker(self.store).do(
            self.item(), authority=self.authority, actuator=actuator, verifier=verifier
        )
        self.assertEqual(result.state, OccurrenceState.VERIFIED)
        self.assertEqual(result.standing, Standing.ALIVE)
        self.assertEqual(actuator.calls, 1)
        self.assertEqual(verifier.calls, 1)
        self.assertEqual(
            self.store.receipt_kinds(result.occurrence_id),
            ["PRE_ACTUATION", "POSTCONDITION_VERIFIED"],
        )

    def test_replay_is_idempotent_and_does_not_reactuate(self) -> None:
        actuator = CountingActuator()
        verifier = ResourceDisabledVerifier()
        broker = BRCEBroker(self.store)
        first = broker.do(self.item(), authority=self.authority, actuator=actuator, verifier=verifier)
        second = broker.do(self.item(), authority=self.authority, actuator=actuator, verifier=verifier)
        self.assertEqual(first, second)
        self.assertEqual(actuator.calls, 1)

    def test_same_idempotency_key_with_different_request_is_refused(self) -> None:
        actuator = CountingActuator()
        verifier = ResourceDisabledVerifier()
        broker = BRCEBroker(self.store)
        broker.do(self.item(), authority=self.authority, actuator=actuator, verifier=verifier)
        changed = WorkItem(
            idempotency_key="incident-1",
            subject="azure:test-subscription",
            consequence="azure:disable-public-access",
            capability_digest=self.bundle.digest,
            payload={"key": "incident-1", "resource_id": "different"},
        )
        result = broker.do(changed, authority=self.authority, actuator=actuator, verifier=verifier)
        self.assertEqual(result.standing, Standing.REFUSED)
        self.assertTrue(result.refusal.startswith(str(RefusalCode.IDEMPOTENCY_CONFLICT)))
        original = self.store.get_by_key("incident-1")
        assert original is not None
        self.assertEqual(original["state"], OccurrenceState.VERIFIED)
        self.assertIn(
            "IDEMPOTENCY_CONFLICT_REFUSAL",
            self.store.receipt_kinds(int(original["id"])),
        )
        self.assertEqual(actuator.calls, 1)

    def test_unpinned_capability_refuses_before_actuation(self) -> None:
        item = self.item()
        item = WorkItem(item.idempotency_key, item.subject, item.consequence, "0" * 64, item.payload)
        actuator = CountingActuator()
        result = BRCEBroker(self.store).do(
            item, authority=self.authority, actuator=actuator, verifier=ResourceDisabledVerifier()
        )
        self.assertEqual(result.state, OccurrenceState.REFUSED)
        self.assertTrue(result.refusal.startswith(str(RefusalCode.CAPABILITY_NOT_PINNED)))
        self.assertEqual(actuator.calls, 0)

    def test_authority_refusal_prevents_actuation(self) -> None:
        denied = AuthorityEnvelope(
            envelope_id="authority:denied",
            subject="azure:test-subscription",
            allowed_consequences=frozenset(),
            capability_digest=self.bundle.digest,
        )
        actuator = CountingActuator()
        result = BRCEBroker(self.store).do(
            self.item(), authority=denied, actuator=actuator, verifier=ResourceDisabledVerifier()
        )
        self.assertEqual(result.standing, Standing.REFUSED)
        self.assertTrue(result.refusal.startswith(str(RefusalCode.AUTHORITY)))
        self.assertEqual(actuator.calls, 0)

    def test_failed_postcondition_is_not_alive(self) -> None:
        actuator = CountingActuator()
        result = BRCEBroker(self.store).do(
            self.item(),
            authority=self.authority,
            actuator=actuator,
            verifier=ResourceDisabledVerifier(accept=False),
        )
        self.assertEqual(result.state, OccurrenceState.REFUSED)
        self.assertEqual(result.standing, Standing.REFUSED)
        self.assertEqual(result.refusal, str(RefusalCode.POSTCONDITION))

    def test_uncertain_actuation_never_automatically_retries(self) -> None:
        actuator = CountingActuator(fail=True)
        verifier = ResourceDisabledVerifier()
        broker = BRCEBroker(self.store)
        first = broker.do(self.item(), authority=self.authority, actuator=actuator, verifier=verifier)
        second = broker.do(self.item(), authority=self.authority, actuator=actuator, verifier=verifier)
        self.assertEqual(first.state, OccurrenceState.UNKNOWN_RECONCILIATION)
        self.assertEqual(first.standing, Standing.UNKNOWN)
        self.assertEqual(second.state, OccurrenceState.UNKNOWN_RECONCILIATION)
        self.assertEqual(actuator.calls, 1)

    def test_restart_preserves_unknown_and_prevents_reactuation(self) -> None:
        db_path = Path(self.tmp.name) / "runtime.db"
        actuator = CountingActuator(fail=True)
        broker = BRCEBroker(self.store)
        first = broker.do(
            self.item(),
            authority=self.authority,
            actuator=actuator,
            verifier=ResourceDisabledVerifier(),
        )
        self.assertEqual(first.state, OccurrenceState.UNKNOWN_RECONCILIATION)
        reopened = RuntimeStore(db_path)
        second = BRCEBroker(reopened).do(
            self.item(),
            authority=self.authority,
            actuator=actuator,
            verifier=ResourceDisabledVerifier(),
        )
        self.assertEqual(second.state, OccurrenceState.UNKNOWN_RECONCILIATION)
        self.assertEqual(actuator.calls, 1)

    def test_reconcile_unknown_with_independent_observation(self) -> None:
        actuator = CountingActuator(fail=True)
        broker = BRCEBroker(self.store)
        broker.do(
            self.item(), authority=self.authority, actuator=actuator, verifier=ResourceDisabledVerifier()
        )
        observed = {
            "resource_id": "/subscriptions/test/resourceGroups/rg/providers/X/y",
            "state": "disabled",
        }
        result = broker.reconcile(
            "incident-1", observed_result=observed, verifier=ResourceDisabledVerifier()
        )
        self.assertEqual(result.state, OccurrenceState.VERIFIED)
        self.assertEqual(result.standing, Standing.ALIVE)
        self.assertEqual(actuator.calls, 1)
        self.assertIn("RECONCILIATION_VERIFIED", self.store.receipt_kinds(result.occurrence_id))

    def test_supervisor_routes_each_item_through_broker(self) -> None:
        actuator = CountingActuator()
        verifier = ResourceDisabledVerifier()
        results = Supervisor(BRCEBroker(self.store)).run(
            [self.item("incident-1"), self.item("incident-2")],
            authority=self.authority,
            actuator=actuator,
            verifier=verifier,
        )
        self.assertEqual([r.standing for r in results], [Standing.ALIVE, Standing.ALIVE])
        self.assertEqual(actuator.calls, 2)


if __name__ == "__main__":
    unittest.main()
