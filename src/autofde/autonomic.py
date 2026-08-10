from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

from .runtime import (
    AuthorityEnvelope,
    BRCEBroker,
    CapabilityBundle,
    ExecutionResult,
    RuntimeStore,
    WorkItem,
)

PROMOTION_SCHEMA = "urn:autofde-lab:knowledge-hook-promotion:v1"
CAPABILITY_SCHEMA = "autofde.compiled-capability/1"
MANUFACTURE_RECEIPT_SCHEMA = "autofde.manufacture-receipt/1"


class AutonomicRefusal(ValueError):
    """Fail-closed refusal at the promoted-hook production admission boundary."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}:{detail}")
        self.code = code
        self.detail = detail


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _require_string(mapping: Mapping[str, Any], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise AutonomicRefusal("REFUSED:SCHEMA", key)
    return value


@dataclass(frozen=True, slots=True)
class PromotedHook:
    hook_id: str
    promotion_digest: str
    implementation_digest: str
    subjects: frozenset[str]
    scopes: frozenset[str]
    action: str
    policy: str
    verifier: str
    max_age_ticks: int
    capability_digest: str
    match_all: tuple[tuple[str, str], ...]
    lab_revision: str
    ggen_revision: str

    def matches(self, observation: Mapping[str, Any]) -> bool:
        if observation.get("subject") not in self.subjects:
            return False
        if observation.get("scope") not in self.scopes:
            return False
        if observation.get("policy") != self.policy:
            return False
        age_ticks = observation.get("age_ticks")
        if not isinstance(age_ticks, int) or age_ticks < 0 or age_ticks > self.max_age_ticks:
            return False
        facts = observation.get("facts")
        if not isinstance(facts, Mapping):
            return False
        return all(facts.get(key) == value for key, value in self.match_all)

    def work_item(self, observation: Mapping[str, Any]) -> WorkItem:
        if not self.matches(observation):
            raise AutonomicRefusal("REFUSED:OUTSIDE_PROMOTED_ENVELOPE", self.hook_id)
        observation_id = _require_string(observation, "observation_id")
        payload = {
            "hook_id": self.hook_id,
            "promotion_digest": self.promotion_digest,
            "implementation_digest": self.implementation_digest,
            "observation_id": observation_id,
            "subject": observation["subject"],
            "scope": observation["scope"],
            "policy": observation["policy"],
            "facts": dict(sorted(observation["facts"].items())),
        }
        idempotency_key = "hook:" + _sha256_json(
            {
                "promotion_digest": self.promotion_digest,
                "observation_id": observation_id,
                "subject": observation["subject"],
                "scope": observation["scope"],
            }
        )
        return WorkItem(
            idempotency_key=idempotency_key,
            subject=str(observation["subject"]),
            consequence=self.action,
            capability_digest=self.capability_digest,
            payload=payload,
        )


class PromotedHookAdmission:
    """Admit an exact Lab promotion + exact ggen manufacture receipt into production.

    Admission pins provenance and capability identity into RuntimeStore. It does not grant
    authority and it does not actuate. Only BRCEBroker.do can cross the DO boundary.
    """

    def __init__(
        self,
        store: RuntimeStore,
        *,
        admitted_lab_revision: str,
        admitted_ggen_revision: str,
    ) -> None:
        if not admitted_lab_revision or not admitted_ggen_revision:
            raise ValueError("exact Lab and ggen revisions are required")
        self.store = store
        self.admitted_lab_revision = admitted_lab_revision
        self.admitted_ggen_revision = admitted_ggen_revision

    def admit(
        self,
        promotion: Mapping[str, Any],
        capability: Mapping[str, Any],
        manufacture_receipt: Mapping[str, Any],
    ) -> PromotedHook:
        self._validate_promotion(promotion)
        self._validate_manufacture(capability, manufacture_receipt)

        envelope = promotion.get("envelope")
        if not isinstance(envelope, Mapping):
            raise AutonomicRefusal("REFUSED:PROMOTION_ENVELOPE", "missing")
        subjects = self._string_set(envelope.get("subjects"), "subjects")
        scopes = self._string_set(envelope.get("scopes"), "scopes")
        action = _require_string(envelope, "action")
        policy = _require_string(envelope, "policy")
        verifier = _require_string(envelope, "verifier")
        max_age_ticks = envelope.get("max_age_ticks")
        if not isinstance(max_age_ticks, int) or max_age_ticks <= 0:
            raise AutonomicRefusal("REFUSED:PROMOTION_ENVELOPE", "max_age_ticks")

        if capability.get("consequence") != action:
            raise AutonomicRefusal("REFUSED:CONSEQUENCE_DRIFT", action)
        match_all = capability.get("match_all")
        if not isinstance(match_all, Mapping) or not match_all:
            raise AutonomicRefusal("REFUSED:MATCH_SPEC", "empty")
        if not all(isinstance(k, str) and isinstance(v, str) for k, v in match_all.items()):
            raise AutonomicRefusal("REFUSED:MATCH_SPEC", "non-string predicate")

        bundle_digest = _require_string(manufacture_receipt, "bundle_digest")
        self.store.pin_bundle(
            CapabilityBundle(
                name=_require_string(promotion, "hook_id"),
                digest=bundle_digest,
                source_repo="seanchatmangpt/autofde-lab",
                source_sha=self.admitted_lab_revision,
                generated_by="seanchatmangpt/ggen",
                generator_sha=self.admitted_ggen_revision,
            )
        )

        return PromotedHook(
            hook_id=_require_string(promotion, "hook_id"),
            promotion_digest=_require_string(promotion, "promotion_digest"),
            implementation_digest=_require_string(promotion, "implementation_digest"),
            subjects=subjects,
            scopes=scopes,
            action=action,
            policy=policy,
            verifier=verifier,
            max_age_ticks=max_age_ticks,
            capability_digest=bundle_digest,
            match_all=tuple(sorted((str(k), str(v)) for k, v in match_all.items())),
            lab_revision=self.admitted_lab_revision,
            ggen_revision=self.admitted_ggen_revision,
        )

    def _validate_promotion(self, promotion: Mapping[str, Any]) -> None:
        if promotion.get("schema") != PROMOTION_SCHEMA:
            raise AutonomicRefusal("REFUSED:PROMOTION_SCHEMA", str(promotion.get("schema")))
        if promotion.get("standing") != "CANDIDATE":
            raise AutonomicRefusal("REFUSED:PROMOTION_STANDING", str(promotion.get("standing")))
        if promotion.get("hook_class") not in {"ACTUATION", "REFLEX"}:
            raise AutonomicRefusal("REFUSED:HOOK_CLASS", str(promotion.get("hook_class")))
        if promotion.get("requires_brce") is not True:
            raise AutonomicRefusal("REFUSED:BRCE_BYPASS", "requires_brce")
        if promotion.get("direct_do_authority") is not False:
            raise AutonomicRefusal("REFUSED:DIRECT_DO_AUTHORITY", "promotion")
        digest = _require_string(promotion, "promotion_digest")
        implementation = _require_string(promotion, "implementation_digest")
        if not digest.startswith("sha256:") or not implementation.startswith("sha256:"):
            raise AutonomicRefusal("REFUSED:PROMOTION_DIGEST", "sha256 binding required")

    def _validate_manufacture(
        self,
        capability: Mapping[str, Any],
        receipt: Mapping[str, Any],
    ) -> None:
        if capability.get("schema") != CAPABILITY_SCHEMA:
            raise AutonomicRefusal("REFUSED:CAPABILITY_SCHEMA", str(capability.get("schema")))
        if receipt.get("schema") != MANUFACTURE_RECEIPT_SCHEMA:
            raise AutonomicRefusal("REFUSED:MANUFACTURE_SCHEMA", str(receipt.get("schema")))
        if receipt.get("standing") != "ALIVE":
            raise AutonomicRefusal("REFUSED:MANUFACTURE_STANDING", str(receipt.get("standing")))
        if receipt.get("authority_class") != "CONSTRUCT" or receipt.get("do_authority") is not False:
            raise AutonomicRefusal("REFUSED:MANUFACTURE_AUTHORITY", "must remain CONSTRUCT")
        if receipt.get("lab_revision") != self.admitted_lab_revision:
            raise AutonomicRefusal("REFUSED:LAB_REVISION_DRIFT", str(receipt.get("lab_revision")))
        if receipt.get("ggen_revision") != self.admitted_ggen_revision:
            raise AutonomicRefusal("REFUSED:GGEN_REVISION_DRIFT", str(receipt.get("ggen_revision")))
        observed = _sha256_json(capability)
        if receipt.get("bundle_digest") != observed:
            raise AutonomicRefusal("REFUSED:BUNDLE_DIGEST_MISMATCH", observed)

    @staticmethod
    def _string_set(value: Any, field: str) -> frozenset[str]:
        if not isinstance(value, (list, tuple, set, frozenset)):
            raise AutonomicRefusal("REFUSED:PROMOTION_ENVELOPE", field)
        result = frozenset(item for item in value if isinstance(item, str) and item)
        if len(result) != len(value) or not result:
            raise AutonomicRefusal("REFUSED:PROMOTION_ENVELOPE", field)
        return result


class AutonomicFastPath:
    """Known-pattern router: deterministic match -> powerless WorkItem -> BRCE.

    The router contains no actuator and no authority. Calling execute still requires a
    production AuthorityEnvelope plus actuator and independent verifier, and delegates DO
    exclusively to BRCEBroker.
    """

    def __init__(self, broker: BRCEBroker) -> None:
        self.broker = broker

    def construct(self, hook: PromotedHook, observation: Mapping[str, Any]) -> WorkItem:
        return hook.work_item(observation)

    def execute(
        self,
        hook: PromotedHook,
        observation: Mapping[str, Any],
        *,
        authority: AuthorityEnvelope,
        actuator: Any,
        verifier: Any,
    ) -> ExecutionResult:
        item = self.construct(hook, observation)
        return self.broker.do(
            item,
            authority=authority,
            actuator=actuator,
            verifier=verifier,
        )
