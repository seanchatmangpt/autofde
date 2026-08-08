from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

from .runtime import AuthorityEnvelope, BRCEBroker, CapabilityBundle, RuntimeStore, Standing, WorkItem

REQ_SCHEMA = "autofde.engineering-requirement/1"
ADM_SCHEMA = "autofde.lab-admission/1"
PAYLOAD_SCHEMA = "autofde.compiled-capability/1"
MFG_SCHEMA = "autofde.manufacture-receipt/1"
PROMOTION_SCHEMA = "autofde.promotion-receipt/1"


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str).encode()


def sha256_json(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def raw_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _read(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text())
    if not isinstance(value, dict):
        raise ValueError("REFUSED:JSON_OBJECT_REQUIRED")
    return value


def _safe_relative(raw: str) -> Path:
    path = Path(raw)
    if path.is_absolute() or not raw or ".." in path.parts:
        raise ValueError("REFUSED:PROGRAM_PATH_INVALID")
    return path


@dataclass(frozen=True, slots=True)
class CapabilityRequirement:
    schema: str
    standing: str
    authority_class: str
    requirement_id: str
    observation_digest: str
    capability: str
    subject: str
    consequence: str
    idempotency_key: str
    payload: Mapping[str, Any]
    manufacture_spec: Mapping[str, Any]


class EngineeringStore:
    def __init__(self, runtime: RuntimeStore) -> None:
        self.runtime = runtime
        self.conn = sqlite3.connect(runtime.path)
        self.conn.row_factory = sqlite3.Row
        with self.conn:
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS engineering_requirements (
                    requirement_id TEXT PRIMARY KEY,
                    body_json TEXT NOT NULL,
                    state TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS promotion_receipts (
                    requirement_id TEXT PRIMARY KEY,
                    bundle_digest TEXT NOT NULL,
                    body_json TEXT NOT NULL
                );
                """
            )

    def put_requirement(self, requirement: Mapping[str, Any]) -> None:
        body = canonical_bytes(requirement).decode()
        with self.conn:
            existing = self.conn.execute(
                "SELECT body_json FROM engineering_requirements WHERE requirement_id = ?",
                (requirement["requirement_id"],),
            ).fetchone()
            if existing is not None and existing[0] != body:
                raise ValueError("REFUSED:REQUIREMENT_IDEMPOTENCY_CONFLICT")
            self.conn.execute(
                "INSERT OR IGNORE INTO engineering_requirements(requirement_id, body_json, state) VALUES (?, ?, 'CAPABILITY_ABSENT')",
                (requirement["requirement_id"], body),
            )

    def get_requirement(self, requirement_id: str) -> dict[str, Any]:
        row = self.conn.execute(
            "SELECT body_json FROM engineering_requirements WHERE requirement_id = ?", (requirement_id,)
        ).fetchone()
        if row is None:
            raise KeyError(requirement_id)
        return json.loads(row[0])

    def mark_promoted(self, requirement_id: str, bundle_digest: str, receipt: Mapping[str, Any]) -> None:
        body = canonical_bytes(receipt).decode()
        with self.conn:
            existing = self.conn.execute(
                "SELECT bundle_digest, body_json FROM promotion_receipts WHERE requirement_id = ?",
                (requirement_id,),
            ).fetchone()
            if existing is not None and (existing[0] != bundle_digest or existing[1] != body):
                raise ValueError("REFUSED:PROMOTION_IDEMPOTENCY_CONFLICT")
            self.conn.execute(
                "INSERT OR IGNORE INTO promotion_receipts(requirement_id, bundle_digest, body_json) VALUES (?, ?, ?)",
                (requirement_id, bundle_digest, body),
            )
            self.conn.execute(
                "UPDATE engineering_requirements SET state = 'PROMOTED' WHERE requirement_id = ?",
                (requirement_id,),
            )


class FilesystemActuator:
    def __init__(self, world_root: str | Path, program: Mapping[str, Any]) -> None:
        self.world_root = Path(world_root)
        self.program = dict(program)
        self.calls = 0

    def actuate(self, payload: Mapping[str, Any]) -> Any:
        del payload
        self.calls += 1
        if self.program.get("kind") == "noop":
            return {"kind": "noop"}
        if self.program.get("kind") != "filesystem_write":
            raise RuntimeError("unsupported compiled program")
        rel = _safe_relative(str(self.program["path"]))
        target = self.world_root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(str(self.program["content"]))
        return {"path": rel.as_posix(), "written": True}


class IndependentVerifier:
    def __init__(self, world_root: str | Path, contract: Mapping[str, Any]) -> None:
        self.world_root = Path(world_root)
        self.contract = dict(contract)
        self.calls = 0

    def verify(self, payload: Mapping[str, Any], result: Any) -> bool:
        del payload, result
        self.calls += 1
        if self.contract.get("kind") == "noop":
            return True
        if self.contract.get("kind") != "file_sha256":
            return False
        try:
            rel = _safe_relative(str(self.contract["path"]))
            observed = hashlib.sha256((self.world_root / rel).read_bytes()).hexdigest()
        except (OSError, ValueError, KeyError):
            return False
        return observed == self.contract.get("digest")


class SelfManufacturingRuntime:
    def __init__(self, runtime: RuntimeStore, world_root: str | Path, evidence_root: str | Path) -> None:
        self.runtime = runtime
        self.engineering = EngineeringStore(runtime)
        self.world_root = Path(world_root)
        self.evidence_root = Path(evidence_root)
        self.evidence_root.mkdir(parents=True, exist_ok=True)

    def _pinned_by_name(self, capability: str) -> str | None:
        conn = sqlite3.connect(self.runtime.path)
        try:
            row = conn.execute(
                "SELECT digest FROM capability_bundles WHERE name = ? ORDER BY pinned_at DESC LIMIT 1", (capability,)
            ).fetchone()
            return None if row is None else str(row[0])
        finally:
            conn.close()

    def require_capability(
        self,
        *,
        observation: Mapping[str, Any],
        capability: str,
        subject: str,
        consequence: str,
        idempotency_key: str,
        payload: Mapping[str, Any],
        manufacture_spec: Mapping[str, Any],
    ) -> dict[str, Any]:
        pinned = self._pinned_by_name(capability)
        if pinned is not None:
            return {"standing": "ALIVE", "capability_digest": pinned, "capability": capability}
        observation_digest = sha256_json(observation)
        core = {
            "observation_digest": observation_digest,
            "capability": capability,
            "subject": subject,
            "consequence": consequence,
            "idempotency_key": idempotency_key,
            "payload": dict(payload),
            "manufacture_spec": dict(manufacture_spec),
        }
        requirement_id = hashlib.sha256(canonical_bytes(core)).hexdigest()
        requirement = asdict(
            CapabilityRequirement(
                schema=REQ_SCHEMA,
                standing="BLOCKED:CAPABILITY_ABSENT",
                authority_class="CONSTRUCT",
                requirement_id=requirement_id,
                **core,
            )
        )
        self.engineering.put_requirement(requirement)
        path = self.evidence_root / f"{requirement_id}.requirement.json"
        path.write_text(json.dumps(requirement, indent=2, sort_keys=True) + "\n")
        return {"standing": "BLOCKED:CAPABILITY_ABSENT", "requirement_id": requirement_id, "requirement_path": str(path)}

    def _validate_chain(self, requirement, admission, powl_bytes, payload, manufacture) -> CapabilityBundle:
        if requirement.get("schema") != REQ_SCHEMA or requirement.get("standing") != "BLOCKED:CAPABILITY_ABSENT":
            raise ValueError("REFUSED:REQUIREMENT_INVALID")
        if admission.get("schema") != ADM_SCHEMA or admission.get("standing") != "ALIVE":
            raise ValueError("REFUSED:LAB_ADMISSION_INVALID")
        if admission.get("authority_class") != "CONSTRUCT" or admission.get("do_authority") is not False:
            raise ValueError("REFUSED:LAB_AUTHORITY_ESCALATION")
        if admission.get("requirement_digest") != sha256_json(requirement) or admission.get("requirement_id") != requirement.get("requirement_id"):
            raise ValueError("REFUSED:LAB_REQUIREMENT_DRIFT")
        if admission.get("powl_digest") != "sha256:" + hashlib.sha256(powl_bytes).hexdigest():
            raise ValueError("REFUSED:POWL_DIGEST_DRIFT")
        admission_copy = dict(admission)
        admission_digest = admission_copy.pop("admission_digest", None)
        if admission_digest != sha256_json(admission_copy):
            raise ValueError("REFUSED:LAB_ADMISSION_DIGEST_DRIFT")
        if manufacture.get("schema") != MFG_SCHEMA or manufacture.get("standing") != "ALIVE":
            raise ValueError("REFUSED:MANUFACTURE_RECEIPT_INVALID")
        if manufacture.get("authority_class") != "CONSTRUCT" or manufacture.get("do_authority") is not False:
            raise ValueError("REFUSED:MANUFACTURE_AUTHORITY_ESCALATION")
        manufacture_copy = dict(manufacture)
        receipt_digest = manufacture_copy.pop("receipt_digest", None)
        if receipt_digest != sha256_json(manufacture_copy):
            raise ValueError("REFUSED:MANUFACTURE_RECEIPT_DIGEST_DRIFT")
        for key in ("requirement_id", "admission_digest", "powl_digest"):
            expected = requirement["requirement_id"] if key == "requirement_id" else admission[key]
            if manufacture.get(key) != expected:
                raise ValueError(f"REFUSED:MANUFACTURE_{key.upper()}_DRIFT")
        if payload.get("schema") != PAYLOAD_SCHEMA or payload.get("capability") != requirement.get("capability") or payload.get("consequence") != requirement.get("consequence"):
            raise ValueError("REFUSED:COMPILED_CAPABILITY_DRIFT")
        bundle_bytes = canonical_bytes(payload)
        if hashlib.sha256(bundle_bytes).hexdigest() != manufacture.get("bundle_digest"):
            raise ValueError("REFUSED:BUNDLE_DIGEST_DRIFT")
        return CapabilityBundle.from_bytes(
            name=str(requirement["capability"]),
            payload=bundle_bytes,
            source_repo="seanchatmangpt/autofde-lab",
            source_sha=str(manufacture["lab_revision"]),
            generated_by="seanchatmangpt/ggen",
            generator_sha=str(manufacture["ggen_revision"]),
        )

    def promote_and_resume(
        self,
        *,
        requirement_path: str | Path,
        admission_path: str | Path,
        powl_path: str | Path,
        bundle_payload_path: str | Path,
        manufacture_receipt_path: str | Path,
        authority: AuthorityEnvelope,
    ) -> dict[str, Any]:
        requirement = _read(requirement_path)
        if self.engineering.get_requirement(str(requirement["requirement_id"])) != requirement:
            raise ValueError("REFUSED:REQUIREMENT_STORE_DRIFT")
        admission = _read(admission_path)
        payload = _read(bundle_payload_path)
        manufacture = _read(manufacture_receipt_path)
        bundle = self._validate_chain(requirement, admission, Path(powl_path).read_bytes(), payload, manufacture)
        if bundle.digest != manufacture["bundle_digest"]:
            raise ValueError("REFUSED:PRODUCTION_DIGEST_DRIFT")
        self.runtime.pin_bundle(bundle)
        if authority.capability_digest != bundle.digest:
            raise ValueError("REFUSED:AUTHORITY_WRONG_PROMOTED_BUNDLE")
        item = WorkItem(
            idempotency_key=str(requirement["idempotency_key"]),
            subject=str(requirement["subject"]),
            consequence=str(requirement["consequence"]),
            capability_digest=bundle.digest,
            payload=dict(requirement["payload"]),
        )
        actuator = FilesystemActuator(self.world_root, payload["program"])
        verifier = IndependentVerifier(self.world_root, payload["verifier"])
        broker = BRCEBroker(self.runtime)
        result = broker.do(item, authority=authority, actuator=actuator, verifier=verifier)
        if result.standing != Standing.ALIVE:
            return {"standing": str(result.standing), "occurrence_id": result.occurrence_id, "refusal": result.refusal}
        calls_after_first = actuator.calls
        replay = broker.do(item, authority=authority, actuator=actuator, verifier=verifier)
        if replay != result or actuator.calls != calls_after_first:
            raise RuntimeError("BUILD_BROKEN:REPLAY_REACTUATED")
        promotion = {
            "schema": PROMOTION_SCHEMA,
            "standing": "ALIVE",
            "requirement_id": requirement["requirement_id"],
            "admission_digest": admission["admission_digest"],
            "manufacture_receipt_digest": manufacture["receipt_digest"],
            "bundle_digest": bundle.digest,
            "lab_revision": bundle.source_sha,
            "ggen_revision": bundle.generator_sha,
            "occurrence_id": result.occurrence_id,
            "postcondition_verified": True,
            "replay_verified": True,
            "completed_activity_reexecuted": False,
        }
        promotion["promotion_digest"] = sha256_json(promotion)
        self.engineering.mark_promoted(str(requirement["requirement_id"]), bundle.digest, promotion)
        ocel = self._write_ocel(requirement, admission, manufacture, promotion)
        return {**promotion, "ocel_path": str(ocel), "actuation_calls": actuator.calls, "verification_calls": verifier.calls}

    def _write_ocel(self, requirement, admission, manufacture, promotion) -> Path:
        rid = str(requirement["requirement_id"])
        occurrence = str(promotion["occurrence_id"])
        bundle = str(promotion["bundle_digest"])
        event_rows = [
            ("e1", "operational", "capability_absent", [rid]),
            ("e2", "engineering", "lab_admitted", [rid]),
            ("e3", "engineering", "bundle_manufactured", [rid, bundle]),
            ("e4", "operational", "bundle_pinned", [bundle, occurrence]),
            ("e5", "operational", "activity_resumed", [occurrence]),
            ("e6", "operational", "postcondition_verified", [occurrence]),
            ("e7", "operational", "replay_verified", [occurrence]),
        ]
        ocel = {
            "ocel:version": "2.0",
            "objectTypes": [
                {"name": "engineering_requirement", "attributes": []},
                {"name": "capability_bundle", "attributes": []},
                {"name": "operational_occurrence", "attributes": []},
            ],
            "eventTypes": [{"name": name, "attributes": []} for name in sorted({row[2] for row in event_rows})],
            "objects": [
                {"id": rid, "type": "engineering_requirement", "attributes": [{"name": "lab_revision", "value": admission["lab_revision"]}, {"name": "ggen_revision", "value": manufacture["ggen_revision"]}]},
                {"id": bundle, "type": "capability_bundle", "attributes": []},
                {"id": occurrence, "type": "operational_occurrence", "attributes": []},
            ],
            "events": [
                {
                    "id": event_id,
                    "type": name,
                    "time": f"0001-01-01T00:00:0{index}Z",
                    "attributes": [{"name": "history", "value": history}],
                    "relationships": [{"objectId": object_id, "qualifier": "involves"} for object_id in objects],
                }
                for index, (event_id, history, name, objects) in enumerate(event_rows)
            ],
        }
        path = self.evidence_root / f"{rid}.ocel.json"
        path.write_text(json.dumps(ocel, indent=2, sort_keys=True) + "\n")
        return path
