from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Protocol

from .runtime import AuthorityEnvelope, BRCEBroker, CapabilityBundle, ExecutionResult, RuntimeStore, Standing, WorkItem


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


@dataclass(frozen=True, slots=True)
class ProcessNode:
    id: str
    activity: str
    predecessors: frozenset[str]
    required_object_types: frozenset[str]


@dataclass(frozen=True, slots=True)
class PowlModel:
    nodes: tuple[ProcessNode, ...]
    schema: str = "powl.partial-order.v1"

    @classmethod
    def from_bundle(cls, bundle: Mapping[str, Any]) -> "PowlModel":
        nodes = tuple(
            ProcessNode(
                str(row["id"]), str(row["activity"]),
                frozenset(map(str, row.get("predecessors", []))),
                frozenset(map(str, row.get("required_object_types", []))),
            )
            for row in bundle["process"]
        )
        ids = {n.id for n in nodes}
        if len(ids) != len(nodes) or len({n.activity for n in nodes}) != len(nodes):
            raise ValueError("process ids and activities must be unique")
        if any(n.predecessors - ids for n in nodes):
            raise ValueError("process contains unknown predecessor")
        return cls(nodes, str(bundle.get("process_schema", "powl.partial-order.v1")))

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical({
            "schema": self.schema,
            "nodes": [{
                "id": n.id, "activity": n.activity,
                "predecessors": sorted(n.predecessors),
                "required_object_types": sorted(n.required_object_types),
            } for n in self.nodes],
        })).hexdigest()


Clock = Callable[[], str]

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class Ocel2Log:
    clock: Clock = utc_now
    objects: dict[str, dict[str, Any]] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)

    def add_object(self, object_id: str, object_type: str, **attributes: Any) -> None:
        current = self.objects.get(object_id)
        if current and current["type"] != object_type:
            raise ValueError(f"object {object_id} already typed {current['type']}")
        self.objects.setdefault(object_id, {
            "id": object_id, "type": object_type,
            "attributes": [{"name": k, "time": "1970-01-01T00:00:00+00:00", "value": v}
                           for k, v in sorted(attributes.items())],
            "relationships": [],
        })

    def emit(self, activity: str, object_ids: Iterable[str], **attributes: Any) -> None:
        ids = tuple(object_ids)
        missing = [i for i in ids if i not in self.objects]
        if missing:
            raise KeyError(f"unregistered OCEL objects: {missing}")
        self.events.append({
            "id": f"e{len(self.events)+1:04d}", "type": activity, "time": self.clock(),
            "attributes": [{"name": k, "value": v} for k, v in sorted(attributes.items())],
            "relationships": [{"objectId": i, "qualifier": "involved"} for i in ids],
        })

    def as_json(self) -> dict[str, Any]:
        return {
            "objectTypes": [{"name": t, "attributes": []} for t in sorted({o["type"] for o in self.objects.values()})],
            "eventTypes": [{"name": t, "attributes": []} for t in sorted({e["type"] for e in self.events})],
            "objects": [self.objects[k] for k in sorted(self.objects)],
            "events": self.events,
        }

    def bytes(self) -> bytes:
        return canonical(self.as_json())

    def write(self, path: str | Path) -> str:
        Path(path).write_bytes(self.bytes() + b"\n")
        return hashlib.sha256(self.bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class Conformance:
    conforms: bool
    completed: frozenset[str]
    violations: tuple[str, ...]


class ConformanceChecker:
    def __init__(self, model: PowlModel) -> None:
        self.model = model
        self.by_activity = {n.activity: n for n in model.nodes}

    def check(self, log: Ocel2Log, *, allow_prefix: bool = False) -> Conformance:
        completed: set[str] = set()
        seen: set[str] = set()
        violations: list[str] = []
        object_types = {oid: obj["type"] for oid, obj in log.objects.items()}
        for event in log.events:
            node = self.by_activity.get(event["type"])
            if node is None:
                violations.append(f"UNKNOWN_ACTIVITY:{event['type']}"); continue
            if node.id in seen:
                violations.append(f"DUPLICATE_ACTIVITY:{event['type']}"); continue
            missing = node.predecessors - completed
            if missing:
                violations.append(f"PREDECESSOR_VIOLATION:{event['type']}:{','.join(sorted(missing))}")
            related = {object_types.get(r["objectId"], "") for r in event["relationships"]}
            missing_types = node.required_object_types - related
            if missing_types:
                violations.append(f"OBJECT_TYPE_VIOLATION:{event['type']}:{','.join(sorted(missing_types))}")
            completed.add(node.id); seen.add(node.id)
        if not allow_prefix:
            missing = {n.id for n in self.model.nodes} - completed
            if missing:
                violations.append(f"INCOMPLETE_PROCESS:{','.join(sorted(missing))}")
        return Conformance(not violations, frozenset(completed), tuple(violations))


@dataclass(frozen=True, slots=True)
class ProcessReceipt:
    bundle_digest: str
    model_digest: str
    ocel_sha256: str
    digest: str

    @classmethod
    def issue(cls, bundle_digest: str, model: PowlModel, log: Ocel2Log) -> "ProcessReceipt":
        ocel = hashlib.sha256(log.bytes()).hexdigest()
        body = {"schema": "autofde.process-receipt.v1", "bundle_digest": bundle_digest,
                "model_digest": model.digest, "ocel_sha256": ocel}
        return cls(bundle_digest, model.digest, ocel, hashlib.sha256(canonical(body)).hexdigest())

    def replay(self, model: PowlModel, log: Ocel2Log) -> Conformance:
        if ProcessReceipt.issue(self.bundle_digest, model, log).digest != self.digest:
            return Conformance(False, frozenset(), ("RECEIPT_DIGEST_MISMATCH",))
        return ConformanceChecker(model).check(log)


class OrphanVerifier(Protocol):
    def verify_absent(self, resource_id: str) -> bool: ...


@dataclass(frozen=True, slots=True)
class ClosedVerticalResult:
    standing: Standing
    apply: ExecutionResult | None
    destroy: ExecutionResult | None
    conformance: Conformance | None
    receipt: ProcessReceipt | None
    ocel: Ocel2Log
    refusal: str | None = None


class AzureClosedVertical:
    """One bounded reconciliation episode. All consequential calls cross BRCE."""

    def __init__(self, *, store: RuntimeStore, bundle_bytes: bytes, source_repo: str, source_sha: str,
                 generator_repo: str, generator_sha: str, authority: AuthorityEnvelope,
                 clock: Clock = utc_now) -> None:
        doc = json.loads(bundle_bytes)
        self.model = PowlModel.from_bundle(doc)
        self.bundle = CapabilityBundle.from_bytes(
            name=str(doc["name"]), payload=bundle_bytes, source_repo=source_repo, source_sha=source_sha,
            generated_by=generator_repo, generator_sha=generator_sha,
        )
        if authority.capability_digest != self.bundle.digest:
            raise ValueError("authority envelope must pin the exact capability bundle digest")
        self.store, self.authority = store, authority
        self.store.pin_bundle(self.bundle)
        self.broker = BRCEBroker(store)
        self.log = Ocel2Log(clock)

    def run(self, *, signal_id: str, subscription_id: str, resource_id: str,
            apply_actuator: Any, apply_verifier: Any, destroy_actuator: Any,
            destroy_verifier: Any, orphan_verifier: OrphanVerifier) -> ClosedVerticalResult:
        ids = {
            "incident": f"incident:{signal_id}", "bundle": f"bundle:{self.bundle.digest}",
            "session": f"session:{signal_id}", "authority": self.authority.envelope_id,
            "subscription": subscription_id, "resource": resource_id,
        }
        for key, typ in [("incident","Incident"),("bundle","CapabilityBundle"),("session","AgentSession"),
                         ("authority","AuthorityEnvelope"),("subscription","AzureSubscription"),("resource","TerraformResource")]:
            self.log.add_object(ids[key], typ, **({"digest": self.bundle.digest} if key == "bundle" else {}))
        self.log.emit("incident.observed", [ids["incident"], ids["subscription"]])
        self.log.emit("rdfdelta.admitted", [ids["incident"], ids["bundle"]])
        self.log.emit("hook.intent_manufactured", [ids["incident"], ids["session"], ids["bundle"]])
        self.log.emit("agent.session_started", [ids["session"], ids["subscription"]])
        self.log.emit("powl.plan_admitted", [ids["session"], ids["bundle"], ids["resource"]])
        self.log.emit("authority.admitted", [ids["authority"], ids["subscription"], ids["bundle"]])

        def do(key: str, consequence: str, operation: str, actuator: Any, verifier: Any) -> ExecutionResult:
            return self.broker.do(WorkItem(
                f"{signal_id}:{key}", subscription_id, consequence, self.bundle.digest,
                {"resource_id": resource_id, "subscription_id": subscription_id, "operation": operation},
            ), authority=self.authority, actuator=actuator, verifier=verifier)

        apply = do("apply", "azure:terraform-apply", "apply", apply_actuator, apply_verifier)
        if apply.standing != Standing.ALIVE:
            return ClosedVerticalResult(apply.standing, apply, None,
                ConformanceChecker(self.model).check(self.log, allow_prefix=True), None, self.log, apply.refusal)
        common = list(ids.values())
        self.log.emit("brce.apply_verified", common, occurrence_id=apply.occurrence_id)
        self.log.emit("postcondition.apply_verified", [ids["subscription"], ids["resource"]])

        destroy = do("destroy", "azure:terraform-destroy", "destroy", destroy_actuator, destroy_verifier)
        if destroy.standing != Standing.ALIVE:
            return ClosedVerticalResult(destroy.standing, apply, destroy,
                ConformanceChecker(self.model).check(self.log, allow_prefix=True), None, self.log, destroy.refusal)
        self.log.emit("brce.destroy_verified", common, occurrence_id=destroy.occurrence_id)
        self.log.emit("postcondition.destroy_verified", [ids["subscription"], ids["resource"]])
        if not orphan_verifier.verify_absent(resource_id):
            return ClosedVerticalResult(Standing.REFUSED, apply, destroy,
                ConformanceChecker(self.model).check(self.log, allow_prefix=True), None, self.log, "REFUSED:ORPHAN_SWEEP")
        self.log.emit("orphan_sweep.verified", [ids["subscription"], ids["resource"]])
        prefix = ConformanceChecker(self.model).check(self.log, allow_prefix=True)
        if not prefix.conforms:
            return ClosedVerticalResult(Standing.REFUSED, apply, destroy, prefix, None, self.log, "REFUSED:PROCESS_CONFORMANCE")
        self.log.emit("evidence.replay_verified", common)
        conformance = ConformanceChecker(self.model).check(self.log)
        receipt = ProcessReceipt.issue(self.bundle.digest, self.model, self.log) if conformance.conforms else None
        if receipt is None or not receipt.replay(self.model, self.log).conforms:
            return ClosedVerticalResult(Standing.REFUSED, apply, destroy, conformance, receipt, self.log, "REFUSED:REPLAY")
        return ClosedVerticalResult(Standing.ALIVE, apply, destroy, conformance, receipt, self.log)
