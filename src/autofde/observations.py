from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Iterable, Mapping


class ObservationRefusalCode(StrEnum):
    INVALID_OBSERVATION = "REFUSED:INVALID_OBSERVATION"
    INSUFFICIENT_COVERAGE = "REFUSED:INSUFFICIENT_OBSERVATION_COVERAGE"
    OBSERVATION_CONFLICT = "REFUSED:OBSERVATION_CONFLICT"
    STALE_OBSERVATION = "REFUSED:STALE_OBSERVATION"
    ABSENCE_NOT_CLOSED_WORLD = "REFUSED:ABSENCE_NOT_CLOSED_WORLD"


class ObservationRefusal(ValueError):
    def __init__(self, code: ObservationRefusalCode, detail: str) -> None:
        super().__init__(f"{code}:{detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True, slots=True)
class Observation:
    sensor_id: str
    subject: str
    property_iri: str
    value: Any
    observed_at: str
    scope: str
    evidence_digest: str
    method: str = "direct"
    absent: bool = False
    closed_world: bool = False
    coverage_complete: bool = False

    def canonical_payload(self) -> Mapping[str, Any]:
        return {
            "sensor_id": self.sensor_id,
            "subject": self.subject,
            "property_iri": self.property_iri,
            "value": self.value,
            "observed_at": self.observed_at,
            "scope": self.scope,
            "evidence_digest": self.evidence_digest,
            "method": self.method,
            "absent": self.absent,
            "closed_world": self.closed_world,
            "coverage_complete": self.coverage_complete,
        }

    @property
    def observation_id(self) -> str:
        raw = json.dumps(
            self.canonical_payload(), sort_keys=True, separators=(",", ":"), default=str
        ).encode()
        return hashlib.sha256(raw).hexdigest()

    @classmethod
    def from_arm_resource(
        cls,
        *,
        sensor_id: str,
        resource: Mapping[str, Any],
        observed_at: str,
        scope: str,
        evidence_digest: str,
    ) -> tuple["Observation", ...]:
        resource_id = str(resource.get("id", "")).strip()
        if not resource_id:
            raise ObservationRefusal(
                ObservationRefusalCode.INVALID_OBSERVATION, "ARM_RESOURCE_ID_MISSING"
            )
        values: list[Observation] = []
        for property_iri, value in (
            ("urn:autofde:cloud:resource-type", resource.get("type")),
            ("urn:autofde:cloud:location", resource.get("location")),
            (
                "urn:autofde:cloud:provisioning-state",
                _nested(resource, "properties", "provisioningState"),
            ),
        ):
            if value is None:
                continue
            values.append(
                cls(
                    sensor_id=sensor_id,
                    subject=resource_id,
                    property_iri=property_iri,
                    value=value,
                    observed_at=observed_at,
                    scope=scope,
                    evidence_digest=evidence_digest,
                )
            )
        return tuple(values)

    @classmethod
    def closed_world_absence(
        cls,
        *,
        sensor_id: str,
        subject: str,
        property_iri: str,
        observed_at: str,
        scope: str,
        evidence_digest: str,
        coverage_complete: bool,
    ) -> "Observation":
        return cls(
            sensor_id=sensor_id,
            subject=subject,
            property_iri=property_iri,
            value=None,
            observed_at=observed_at,
            scope=scope,
            evidence_digest=evidence_digest,
            absent=True,
            closed_world=True,
            coverage_complete=coverage_complete,
        )


@dataclass(frozen=True, slots=True)
class AdmittedClaim:
    subject: str
    property_iri: str
    value: Any
    scope: str
    observation_ids: tuple[str, ...]
    admitted_at: str
    absent: bool = False

    @property
    def claim_id(self) -> str:
        raw = json.dumps(
            {
                "subject": self.subject,
                "property_iri": self.property_iri,
                "value": self.value,
                "scope": self.scope,
                "observation_ids": self.observation_ids,
                "absent": self.absent,
            },
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode()
        return hashlib.sha256(raw).hexdigest()


class ObservationLedger:
    """Durable O ledger plus computed O* admission view.

    Raw observations are append-only by content identity. Admission never overwrites O;
    it records which exact observations justified a claim in O*.
    """

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
                CREATE TABLE IF NOT EXISTS observations (
                    observation_id TEXT PRIMARY KEY,
                    sensor_id TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    property_iri TEXT NOT NULL,
                    value_json TEXT,
                    observed_at TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    evidence_digest TEXT NOT NULL,
                    method TEXT NOT NULL,
                    absent INTEGER NOT NULL,
                    closed_world INTEGER NOT NULL,
                    coverage_complete INTEGER NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS observation_lookup
                    ON observations(subject, property_iri, scope, observed_at);
                CREATE TABLE IF NOT EXISTS admissions (
                    claim_id TEXT PRIMARY KEY,
                    subject TEXT NOT NULL,
                    property_iri TEXT NOT NULL,
                    value_json TEXT,
                    scope TEXT NOT NULL,
                    absent INTEGER NOT NULL,
                    observation_ids_json TEXT NOT NULL,
                    admitted_at TEXT NOT NULL
                );
                """
            )

    @staticmethod
    def _json(value: Any) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)

    @staticmethod
    def _parse_time(value: str) -> datetime:
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ObservationRefusal(
                ObservationRefusalCode.INVALID_OBSERVATION, f"INVALID_TIME:{value}"
            ) from exc
        if dt.tzinfo is None:
            raise ObservationRefusal(
                ObservationRefusalCode.INVALID_OBSERVATION,
                "OBSERVED_AT_MUST_BE_TIMEZONED",
            )
        return dt.astimezone(timezone.utc)

    @staticmethod
    def _validate_digest(value: str) -> None:
        if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise ObservationRefusal(
                ObservationRefusalCode.INVALID_OBSERVATION,
                "EVIDENCE_DIGEST_MUST_BE_LOWERCASE_SHA256",
            )

    def append(self, observation: Observation) -> str:
        for value, label in (
            (observation.sensor_id, "SENSOR_ID"),
            (observation.subject, "SUBJECT"),
            (observation.property_iri, "PROPERTY_IRI"),
            (observation.scope, "SCOPE"),
            (observation.method, "METHOD"),
        ):
            if not value.strip():
                raise ObservationRefusal(
                    ObservationRefusalCode.INVALID_OBSERVATION, f"{label}_MISSING"
                )
        self._parse_time(observation.observed_at)
        self._validate_digest(observation.evidence_digest)
        if observation.absent and not (
            observation.closed_world and observation.coverage_complete
        ):
            raise ObservationRefusal(
                ObservationRefusalCode.ABSENCE_NOT_CLOSED_WORLD,
                "absence requires closed_world=true and coverage_complete=true",
            )
        if not observation.absent and observation.value is None:
            raise ObservationRefusal(
                ObservationRefusalCode.INVALID_OBSERVATION,
                "positive observation requires a value",
            )
        payload = observation.canonical_payload()
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO observations
                    (observation_id, sensor_id, subject, property_iri, value_json,
                     observed_at, scope, evidence_digest, method, absent,
                     closed_world, coverage_complete, payload_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    observation.observation_id,
                    observation.sensor_id,
                    observation.subject,
                    observation.property_iri,
                    None if observation.value is None else self._json(observation.value),
                    observation.observed_at,
                    observation.scope,
                    observation.evidence_digest,
                    observation.method,
                    int(observation.absent),
                    int(observation.closed_world),
                    int(observation.coverage_complete),
                    self._json(payload),
                ),
            )
        return observation.observation_id

    def raw_count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0])

    def observation_payloads(
        self, *, subject: str, property_iri: str, scope: str
    ) -> tuple[Mapping[str, Any], ...]:
        rows = self._conn.execute(
            """
            SELECT payload_json FROM observations
            WHERE subject = ? AND property_iri = ? AND scope = ?
            ORDER BY observed_at, observation_id
            """,
            (subject, property_iri, scope),
        ).fetchall()
        return tuple(json.loads(row[0]) for row in rows)

    def admit_current(
        self,
        *,
        subject: str,
        property_iri: str,
        scope: str,
        now: str,
        max_age_seconds: float,
        required_sensors: Iterable[str] = (),
    ) -> AdmittedClaim:
        now_dt = self._parse_time(now)
        rows = self._conn.execute(
            """
            SELECT * FROM observations
            WHERE subject = ? AND property_iri = ? AND scope = ?
            ORDER BY observed_at DESC, observation_id
            """,
            (subject, property_iri, scope),
        ).fetchall()
        if not rows:
            raise ObservationRefusal(
                ObservationRefusalCode.INSUFFICIENT_COVERAGE, "NO_OBSERVATIONS"
            )

        fresh: list[sqlite3.Row] = []
        for row in rows:
            age = (now_dt - self._parse_time(str(row["observed_at"]))).total_seconds()
            if 0 <= age <= max_age_seconds:
                fresh.append(row)
        if not fresh:
            raise ObservationRefusal(
                ObservationRefusalCode.STALE_OBSERVATION,
                f"NO_OBSERVATION_WITHIN_{max_age_seconds:g}_SECONDS",
            )

        required = {sensor for sensor in required_sensors if sensor}
        observed_sensors = {str(row["sensor_id"]) for row in fresh}
        missing = sorted(required - observed_sensors)
        if missing:
            raise ObservationRefusal(
                ObservationRefusalCode.INSUFFICIENT_COVERAGE,
                "MISSING_SENSORS:" + ",".join(missing),
            )

        by_value: dict[str, list[sqlite3.Row]] = {}
        for row in fresh:
            key = "__ABSENT__" if row["absent"] else str(row["value_json"])
            by_value.setdefault(key, []).append(row)
        if len(by_value) != 1:
            raise ObservationRefusal(
                ObservationRefusalCode.OBSERVATION_CONFLICT,
                "FRESH_SENSORS_DISAGREE",
            )

        only_rows = next(iter(by_value.values()))
        absent = bool(only_rows[0]["absent"])
        if absent and any(
            not (bool(row["closed_world"]) and bool(row["coverage_complete"]))
            for row in only_rows
        ):
            raise ObservationRefusal(
                ObservationRefusalCode.ABSENCE_NOT_CLOSED_WORLD,
                "admitted absence lost closed-world coverage",
            )
        value = None if absent else json.loads(str(only_rows[0]["value_json"]))
        observation_ids = tuple(sorted(str(row["observation_id"]) for row in only_rows))
        claim = AdmittedClaim(
            subject=subject,
            property_iri=property_iri,
            value=value,
            scope=scope,
            observation_ids=observation_ids,
            admitted_at=now_dt.isoformat(),
            absent=absent,
        )
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO admissions
                    (claim_id, subject, property_iri, value_json, scope, absent,
                     observation_ids_json, admitted_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    claim.claim_id,
                    claim.subject,
                    claim.property_iri,
                    None if claim.value is None else self._json(claim.value),
                    claim.scope,
                    int(claim.absent),
                    self._json(claim.observation_ids),
                    claim.admitted_at,
                ),
            )
        return claim

    def admitted_count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM admissions").fetchone()[0])

    @staticmethod
    def rdfdelta(claim: AdmittedClaim) -> Mapping[str, Any]:
        """Deterministic Knowledge Hook intake envelope over an admitted semantic change."""
        object_value = {"absent": True} if claim.absent else {"json": claim.value}
        statement = {
            "subject": claim.subject,
            "predicate": claim.property_iri,
            "object": object_value,
        }
        return {
            "schema": "autofde.rdfdelta/1",
            "claim_id": claim.claim_id,
            "scope": claim.scope,
            "observation_ids": list(claim.observation_ids),
            "adds": [statement],
            "removes": [],
        }

    @staticmethod
    def replay_rdfdelta(delta: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
        if delta.get("schema") != "autofde.rdfdelta/1":
            raise ObservationRefusal(
                ObservationRefusalCode.INVALID_OBSERVATION, "RDFDELTA_SCHEMA"
            )
        adds = delta.get("adds")
        removes = delta.get("removes")
        if not isinstance(adds, list) or not isinstance(removes, list):
            raise ObservationRefusal(
                ObservationRefusalCode.INVALID_OBSERVATION, "RDFDELTA_SHAPE"
            )
        if removes:
            raise ObservationRefusal(
                ObservationRefusalCode.INVALID_OBSERVATION,
                "CURRENT_ADMISSION_DELTA_MUST_NOT_WITHDRAW_RAW_O",
            )
        return tuple(item for item in adds if isinstance(item, Mapping))


def _nested(value: Mapping[str, Any], *keys: str) -> Any:
    current: Any = value
    for key in keys:
        if not isinstance(current, Mapping) or key not in current:
            return None
        current = current[key]
    return current
