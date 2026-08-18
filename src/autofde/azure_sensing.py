from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .azure import AzureARMClient, AzureObservationError
from .observations import Observation, ObservationLedger, ObservationRefusal, ObservationRefusalCode


@dataclass(frozen=True, slots=True)
class AzureSenseReceipt:
    sensor_id: str
    scope: str
    evidence_digest: str
    observation_ids: tuple[str, ...]
    complete_enumeration: bool


class AzureARMObservationSensor:
    """Read-only Azure control-plane sensor feeding the durable O ledger.

    It never actuates and never treats a 404 point lookup as sufficient absence proof.
    Strong absence is admitted only from a complete resource-group enumeration.
    """

    def __init__(
        self,
        client: AzureARMClient,
        ledger: ObservationLedger,
        *,
        sensor_id: str = "azure-arm",
    ) -> None:
        self.client = client
        self.ledger = ledger
        self.sensor_id = sensor_id

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _digest(value: Any) -> str:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
        return hashlib.sha256(raw).hexdigest()

    def sense_resource(
        self,
        resource_id: str,
        *,
        scope: str,
        observed_at: str | None = None,
    ) -> AzureSenseReceipt:
        status, body = self.client.resource(resource_id)
        at = observed_at or self._now()
        evidence = {"status": status, "body": body, "resource_id": resource_id}
        evidence_digest = self._digest(evidence)
        if status == 404:
            raise ObservationRefusal(
                ObservationRefusalCode.ABSENCE_NOT_CLOSED_WORLD,
                "ARM_POINT_404_REQUIRES_COMPLETE_ENUMERATION",
            )
        if status != 200 or body is None:
            raise AzureObservationError(f"ARM_RESOURCE_OBSERVATION_FAILED:{status}")
        observations = Observation.from_arm_resource(
            sensor_id=self.sensor_id,
            resource=body,
            observed_at=at,
            scope=scope,
            evidence_digest=evidence_digest,
        )
        exists = Observation(
            sensor_id=self.sensor_id,
            subject=resource_id,
            property_iri="urn:autofde:cloud:exists",
            value=True,
            observed_at=at,
            scope=scope,
            evidence_digest=evidence_digest,
        )
        ids = [self.ledger.append(exists)]
        ids.extend(self.ledger.append(observation) for observation in observations)
        return AzureSenseReceipt(
            sensor_id=self.sensor_id,
            scope=scope,
            evidence_digest=evidence_digest,
            observation_ids=tuple(ids),
            complete_enumeration=False,
        )

    def sense_resource_group(
        self,
        resource_group: str,
        *,
        observed_at: str | None = None,
    ) -> AzureSenseReceipt:
        at = observed_at or self._now()
        scope = (
            f"/subscriptions/{self.client.authority.subscription_id}"
            f"/resourceGroups/{resource_group}"
        )
        resources = self.client.resource_group_resources(resource_group)
        normalized = tuple(
            sorted((dict(resource) for resource in resources), key=lambda r: str(r.get("id", "")))
        )
        evidence = {
            "subscription_id": self.client.authority.subscription_id,
            "resource_group": resource_group,
            "resources": normalized,
            "complete_enumeration": True,
        }
        evidence_digest = self._digest(evidence)
        ids: list[str] = []
        for resource in normalized:
            resource_id = str(resource.get("id", "")).strip()
            if not resource_id:
                raise ObservationRefusal(
                    ObservationRefusalCode.INVALID_OBSERVATION,
                    "RESOURCE_GROUP_MEMBER_MISSING_ID",
                )
            ids.append(
                self.ledger.append(
                    Observation(
                        sensor_id=self.sensor_id + ":resource-group-enumeration",
                        subject=resource_id,
                        property_iri="urn:autofde:cloud:exists",
                        value=True,
                        observed_at=at,
                        scope=scope,
                        evidence_digest=evidence_digest,
                    )
                )
            )
            ids.extend(
                self.ledger.append(observation)
                for observation in Observation.from_arm_resource(
                    sensor_id=self.sensor_id + ":resource-group-enumeration",
                    resource=resource,
                    observed_at=at,
                    scope=scope,
                    evidence_digest=evidence_digest,
                )
            )
        return AzureSenseReceipt(
            sensor_id=self.sensor_id + ":resource-group-enumeration",
            scope=scope,
            evidence_digest=evidence_digest,
            observation_ids=tuple(ids),
            complete_enumeration=True,
        )

    def sense_absence(
        self,
        resource_id: str,
        *,
        resource_group: str,
        observed_at: str | None = None,
    ) -> AzureSenseReceipt:
        at = observed_at or self._now()
        scope = (
            f"/subscriptions/{self.client.authority.subscription_id}"
            f"/resourceGroups/{resource_group}"
        )
        expected_fragment = f"/resourceGroups/{resource_group}/".lower()
        if expected_fragment not in resource_id.lower():
            raise ObservationRefusal(
                ObservationRefusalCode.INVALID_OBSERVATION,
                "RESOURCE_OUTSIDE_ENUMERATION_SCOPE",
            )
        resources = self.client.resource_group_resources(resource_group)
        ids_by_lower = {str(resource.get("id", "")).lower() for resource in resources}
        if resource_id.lower() in ids_by_lower:
            raise ObservationRefusal(
                ObservationRefusalCode.OBSERVATION_CONFLICT,
                "RESOURCE_PRESENT_IN_COMPLETE_ENUMERATION",
            )
        evidence = {
            "subscription_id": self.client.authority.subscription_id,
            "resource_group": resource_group,
            "resource_ids": sorted(ids_by_lower),
            "complete_enumeration": True,
            "target": resource_id.lower(),
        }
        evidence_digest = self._digest(evidence)
        observation = Observation.closed_world_absence(
            sensor_id=self.sensor_id + ":resource-group-enumeration",
            subject=resource_id,
            property_iri="urn:autofde:cloud:exists",
            observed_at=at,
            scope=scope,
            evidence_digest=evidence_digest,
            coverage_complete=True,
        )
        observation_id = self.ledger.append(observation)
        return AzureSenseReceipt(
            sensor_id=observation.sensor_id,
            scope=scope,
            evidence_digest=evidence_digest,
            observation_ids=(observation_id,),
            complete_enumeration=True,
        )
