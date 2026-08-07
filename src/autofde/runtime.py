from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Iterable, Mapping, Protocol


class Standing(StrEnum):
    UNKNOWN = "UNKNOWN"
    PARTIAL_ALIVE = "PARTIAL_ALIVE"
    ALIVE = "ALIVE"
    REFUSED = "REFUSED"


class OccurrenceState(StrEnum):
    PREPARED = "PREPARED"
    ACTUATING = "ACTUATING"
    VERIFIED = "VERIFIED"
    REFUSED = "REFUSED"
    UNKNOWN_RECONCILIATION = "UNKNOWN_RECONCILIATION"


class RefusalCode(StrEnum):
    AUTHORITY = "REFUSED:AUTHORITY"
    CAPABILITY_NOT_PINNED = "REFUSED:CAPABILITY_NOT_PINNED"
    IDEMPOTENCY_CONFLICT = "REFUSED:IDEMPOTENCY_CONFLICT"
    POSTCONDITION = "REFUSED:POSTCONDITION"


@dataclass(frozen=True, slots=True)
class CapabilityBundle:
    name: str
    digest: str
    source_repo: str
    source_sha: str
    generated_by: str
    generator_sha: str

    @classmethod
    def from_bytes(
        cls,
        *,
        name: str,
        payload: bytes,
        source_repo: str,
        source_sha: str,
        generated_by: str,
        generator_sha: str,
    ) -> "CapabilityBundle":
        return cls(
            name=name,
            digest=hashlib.sha256(payload).hexdigest(),
            source_repo=source_repo,
            source_sha=source_sha,
            generated_by=generated_by,
            generator_sha=generator_sha,
        )


@dataclass(frozen=True, slots=True)
class AuthorityEnvelope:
    envelope_id: str
    subject: str
    allowed_consequences: frozenset[str]
    capability_digest: str

    def admits(self, *, subject: str, consequence: str, capability_digest: str) -> bool:
        return (
            self.subject == subject
            and consequence in self.allowed_consequences
            and self.capability_digest == capability_digest
        )


@dataclass(frozen=True, slots=True)
class WorkItem:
    idempotency_key: str
    subject: str
    consequence: str
    capability_digest: str
    payload: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    occurrence_id: int
    state: OccurrenceState
    standing: Standing
    result: Any = None
    refusal: str | None = None


class Actuator(Protocol):
    def actuate(self, payload: Mapping[str, Any]) -> Any: ...


class PostconditionVerifier(Protocol):
    def verify(self, payload: Mapping[str, Any], result: Any) -> bool: ...


class RuntimeStore:
    """Durable occurrence, receipt, and capability-pin store using SQLite WAL."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._conn:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS capability_bundles (
                    digest TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    source_repo TEXT NOT NULL,
                    source_sha TEXT NOT NULL,
                    generated_by TEXT NOT NULL,
                    generator_sha TEXT NOT NULL,
                    pinned_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS occurrences (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    subject TEXT NOT NULL,
                    consequence TEXT NOT NULL,
                    capability_digest TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    state TEXT NOT NULL,
                    standing TEXT NOT NULL,
                    result_json TEXT,
                    refusal TEXT,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS receipts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    occurrence_id INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    body_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(occurrence_id) REFERENCES occurrences(id)
                );
                """
            )

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _json(value: Any) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)

    @staticmethod
    def _decode(value: str | None) -> Any:
        return None if value is None else json.loads(value)

    def journal_mode(self) -> str:
        return str(self._conn.execute("PRAGMA journal_mode").fetchone()[0]).lower()

    def pin_bundle(self, bundle: CapabilityBundle) -> None:
        if len(bundle.digest) != 64 or any(c not in "0123456789abcdef" for c in bundle.digest):
            raise ValueError("capability digest must be lowercase SHA-256 hex")
        provenance = (bundle.source_repo, bundle.source_sha, bundle.generated_by, bundle.generator_sha)
        if any(not item.strip() for item in provenance):
            raise ValueError("capability provenance must be complete")
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO capability_bundles
                    (digest, name, source_repo, source_sha, generated_by, generator_sha, pinned_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(digest) DO UPDATE SET
                    name=excluded.name,
                    source_repo=excluded.source_repo,
                    source_sha=excluded.source_sha,
                    generated_by=excluded.generated_by,
                    generator_sha=excluded.generator_sha
                """,
                (
                    bundle.digest,
                    bundle.name,
                    bundle.source_repo,
                    bundle.source_sha,
                    bundle.generated_by,
                    bundle.generator_sha,
                    self._now(),
                ),
            )

    def is_pinned(self, digest: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM capability_bundles WHERE digest = ?", (digest,)
        ).fetchone()
        return row is not None

    def get_by_key(self, key: str) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM occurrences WHERE idempotency_key = ?", (key,)
        ).fetchone()

    def create_occurrence(self, item: WorkItem) -> sqlite3.Row:
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO occurrences
                    (idempotency_key, subject, consequence, capability_digest, payload_json,
                     state, standing, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item.idempotency_key,
                    item.subject,
                    item.consequence,
                    item.capability_digest,
                    self._json(item.payload),
                    OccurrenceState.PREPARED,
                    Standing.PARTIAL_ALIVE,
                    self._now(),
                ),
            )
        row = self.get_by_key(item.idempotency_key)
        assert row is not None
        return row

    def write_receipt(self, occurrence_id: int, kind: str, body: Mapping[str, Any]) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO receipts (occurrence_id, kind, body_json, created_at) VALUES (?, ?, ?, ?)",
                (occurrence_id, kind, self._json(body), self._now()),
            )

    def receipt_kinds(self, occurrence_id: int) -> list[str]:
        return [
            str(row[0])
            for row in self._conn.execute(
                "SELECT kind FROM receipts WHERE occurrence_id = ? ORDER BY id", (occurrence_id,)
            ).fetchall()
        ]

    def transition(
        self,
        occurrence_id: int,
        *,
        state: OccurrenceState,
        standing: Standing,
        result: Any = None,
        refusal: str | None = None,
    ) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                UPDATE occurrences
                SET state = ?, standing = ?, result_json = ?, refusal = ?, updated_at = ?
                WHERE id = ?
                """,
                (state, standing, None if result is None else self._json(result), refusal, self._now(), occurrence_id),
            )

    def as_result(self, row: sqlite3.Row) -> ExecutionResult:
        return ExecutionResult(
            occurrence_id=int(row["id"]),
            state=OccurrenceState(row["state"]),
            standing=Standing(row["standing"]),
            result=self._decode(row["result_json"]),
            refusal=row["refusal"],
        )


class BRCEBroker:
    """Exclusive DO boundary for AutoFDE production consequences."""

    def __init__(self, store: RuntimeStore) -> None:
        self.store = store

    @staticmethod
    def _same_request(row: sqlite3.Row, item: WorkItem) -> bool:
        return (
            row["subject"] == item.subject
            and row["consequence"] == item.consequence
            and row["capability_digest"] == item.capability_digest
            and row["payload_json"] == RuntimeStore._json(item.payload)
        )

    def _refuse(self, item: WorkItem, code: RefusalCode, detail: str) -> ExecutionResult:
        row = self.store.get_by_key(item.idempotency_key)
        if row is None:
            row = self.store.create_occurrence(item)
        occurrence_id = int(row["id"])
        self.store.transition(
            occurrence_id,
            state=OccurrenceState.REFUSED,
            standing=Standing.REFUSED,
            refusal=f"{code}:{detail}",
        )
        self.store.write_receipt(
            occurrence_id,
            "REFUSAL",
            {"code": str(code), "detail": detail, "capability_digest": item.capability_digest},
        )
        current = self.store.get_by_key(item.idempotency_key)
        assert current is not None
        return self.store.as_result(current)

    def do(
        self,
        item: WorkItem,
        *,
        authority: AuthorityEnvelope,
        actuator: Actuator,
        verifier: PostconditionVerifier,
    ) -> ExecutionResult:
        existing = self.store.get_by_key(item.idempotency_key)
        if existing is not None:
            if not self._same_request(existing, item):
                occurrence_id = int(existing["id"])
                detail = "key reused for different request"
                self.store.write_receipt(
                    occurrence_id,
                    "IDEMPOTENCY_CONFLICT_REFUSAL",
                    {
                        "code": str(RefusalCode.IDEMPOTENCY_CONFLICT),
                        "detail": detail,
                        "attempted_subject": item.subject,
                        "attempted_consequence": item.consequence,
                        "attempted_capability_digest": item.capability_digest,
                        "attempted_payload": dict(item.payload),
                    },
                )
                return ExecutionResult(
                    occurrence_id=occurrence_id,
                    state=OccurrenceState.REFUSED,
                    standing=Standing.REFUSED,
                    refusal=f"{RefusalCode.IDEMPOTENCY_CONFLICT}:{detail}",
                )
            state = OccurrenceState(existing["state"])
            if state in {
                OccurrenceState.VERIFIED,
                OccurrenceState.REFUSED,
                OccurrenceState.UNKNOWN_RECONCILIATION,
                OccurrenceState.ACTUATING,
            }:
                return self.store.as_result(existing)

        if not self.store.is_pinned(item.capability_digest):
            return self._refuse(item, RefusalCode.CAPABILITY_NOT_PINNED, "digest absent from production pins")
        if not authority.admits(
            subject=item.subject,
            consequence=item.consequence,
            capability_digest=item.capability_digest,
        ):
            return self._refuse(item, RefusalCode.AUTHORITY, authority.envelope_id)

        row = existing if existing is not None else self.store.create_occurrence(item)
        occurrence_id = int(row["id"])
        self.store.write_receipt(
            occurrence_id,
            "PRE_ACTUATION",
            {
                "authority_envelope": authority.envelope_id,
                "subject": item.subject,
                "consequence": item.consequence,
                "capability_digest": item.capability_digest,
                "idempotency_key": item.idempotency_key,
            },
        )
        self.store.transition(
            occurrence_id,
            state=OccurrenceState.ACTUATING,
            standing=Standing.PARTIAL_ALIVE,
        )

        try:
            result = actuator.actuate(item.payload)
        except Exception as exc:  # uncertain side effect: never retry automatically
            self.store.transition(
                occurrence_id,
                state=OccurrenceState.UNKNOWN_RECONCILIATION,
                standing=Standing.UNKNOWN,
                refusal=f"ACTUATION_EXCEPTION:{type(exc).__name__}:{exc}",
            )
            self.store.write_receipt(
                occurrence_id,
                "ACTUATION_UNKNOWN",
                {"error_type": type(exc).__name__, "error": str(exc)},
            )
            current = self.store.get_by_key(item.idempotency_key)
            assert current is not None
            return self.store.as_result(current)

        if not verifier.verify(item.payload, result):
            self.store.transition(
                occurrence_id,
                state=OccurrenceState.REFUSED,
                standing=Standing.REFUSED,
                result=result,
                refusal=str(RefusalCode.POSTCONDITION),
            )
            self.store.write_receipt(
                occurrence_id,
                "POSTCONDITION_REFUSAL",
                {"result": result, "refusal": str(RefusalCode.POSTCONDITION)},
            )
        else:
            self.store.transition(
                occurrence_id,
                state=OccurrenceState.VERIFIED,
                standing=Standing.ALIVE,
                result=result,
            )
            self.store.write_receipt(
                occurrence_id,
                "POSTCONDITION_VERIFIED",
                {"result": result},
            )

        current = self.store.get_by_key(item.idempotency_key)
        assert current is not None
        return self.store.as_result(current)

    def reconcile(
        self,
        idempotency_key: str,
        *,
        observed_result: Any,
        verifier: PostconditionVerifier,
    ) -> ExecutionResult:
        row = self.store.get_by_key(idempotency_key)
        if row is None:
            raise KeyError(idempotency_key)
        if OccurrenceState(row["state"]) != OccurrenceState.UNKNOWN_RECONCILIATION:
            return self.store.as_result(row)
        payload = json.loads(row["payload_json"])
        occurrence_id = int(row["id"])
        if verifier.verify(payload, observed_result):
            self.store.transition(
                occurrence_id,
                state=OccurrenceState.VERIFIED,
                standing=Standing.ALIVE,
                result=observed_result,
            )
            self.store.write_receipt(
                occurrence_id,
                "RECONCILIATION_VERIFIED",
                {"observed_result": observed_result},
            )
        else:
            self.store.write_receipt(
                occurrence_id,
                "RECONCILIATION_INCONCLUSIVE",
                {"observed_result": observed_result},
            )
        current = self.store.get_by_key(idempotency_key)
        assert current is not None
        return self.store.as_result(current)


class Supervisor:
    """Minimal deterministic event loop over the BRCE DO boundary."""

    def __init__(self, broker: BRCEBroker) -> None:
        self.broker = broker

    def run(
        self,
        work: Iterable[WorkItem],
        *,
        authority: AuthorityEnvelope,
        actuator: Actuator,
        verifier: PostconditionVerifier,
    ) -> list[ExecutionResult]:
        return [
            self.broker.do(item, authority=authority, actuator=actuator, verifier=verifier)
            for item in work
        ]
