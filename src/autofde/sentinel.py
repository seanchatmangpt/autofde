from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping

from .azure import AzureARMClient

SENTINEL_API_VERSION = "2025-09-01"
_ALLOWED_CLASSIFICATIONS = frozenset({"BenignPositive", "FalsePositive", "TruePositive", "Undetermined"})
_ALLOWED_CLASSIFICATION_REASONS = frozenset(
    {"SuspiciousActivity", "SuspiciousButExpected", "IncorrectAlertLogic", "InaccurateData"}
)


class SentinelRefusal(RuntimeError):
    """Typed fail-closed refusal before a Sentinel consequence is dispatched."""


class SentinelActuationError(RuntimeError):
    """Transport or remote-side failure after the BRCE DO boundary is entered."""


@dataclass(frozen=True, slots=True)
class SentinelIncidentRef:
    subscription_id: str
    resource_group: str
    workspace_name: str
    incident_id: str

    def __post_init__(self) -> None:
        values = {
            "subscription_id": self.subscription_id,
            "resource_group": self.resource_group,
            "workspace_name": self.workspace_name,
            "incident_id": self.incident_id,
        }
        for name, value in values.items():
            if not isinstance(value, str) or not value.strip():
                raise SentinelRefusal(f"REFUSED:SENTINEL_{name.upper()}_MISSING")
        if any("/" in value for value in (self.resource_group, self.workspace_name, self.incident_id)):
            raise SentinelRefusal("REFUSED:SENTINEL_PATH_SEGMENT_INVALID")

    @property
    def resource_id(self) -> str:
        return (
            f"/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{self.workspace_name}"
            f"/providers/Microsoft.SecurityInsights/incidents/{self.incident_id}"
        )


def _incident_ref(payload: Mapping[str, Any]) -> SentinelIncidentRef:
    return SentinelIncidentRef(
        subscription_id=str(payload.get("subscription_id", "")),
        resource_group=str(payload.get("resource_group", "")),
        workspace_name=str(payload.get("workspace_name", "")),
        incident_id=str(payload.get("incident_id", "")),
    )


def _require_text(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise SentinelRefusal(f"REFUSED:SENTINEL_{key.upper()}_MISSING")
    return value.strip()


def _properties(body: Mapping[str, Any]) -> Mapping[str, Any]:
    properties = body.get("properties")
    if not isinstance(properties, Mapping):
        raise SentinelRefusal("REFUSED:SENTINEL_INCIDENT_PROPERTIES_INVALID")
    return properties


class SentinelIncidentClient:
    """Narrow Microsoft Sentinel incident transport over the admitted ARM client authority."""

    def __init__(self, arm: AzureARMClient) -> None:
        self.arm = arm

    def _assert_ref(self, ref: SentinelIncidentRef) -> None:
        if ref.subscription_id != self.arm.authority.subscription_id:
            raise SentinelRefusal("REFUSED:SENTINEL_SUBSCRIPTION_NOT_ADMITTED")

    def get(self, ref: SentinelIncidentRef) -> Mapping[str, Any]:
        self._assert_ref(ref)
        status, body = self.arm.get(ref.resource_id, api_version=SENTINEL_API_VERSION)
        if status != 200 or not isinstance(body, Mapping):
            raise SentinelRefusal(f"REFUSED:SENTINEL_INCIDENT_NOT_OBSERVED:{status}")
        observed_id = str(body.get("id", ""))
        if observed_id.lower() != ref.resource_id.lower():
            raise SentinelRefusal("REFUSED:SENTINEL_INCIDENT_ID_MISMATCH")
        return body

    def put(self, ref: SentinelIncidentRef, *, body: Mapping[str, Any], expected_etag: str) -> Mapping[str, Any]:
        self._assert_ref(ref)
        if not expected_etag.strip():
            raise SentinelRefusal("REFUSED:SENTINEL_ETAG_MISSING")
        endpoint = self.arm.authority.arm_endpoint.rstrip("/")
        url = f"{endpoint}{ref.resource_id}?api-version={urllib.parse.quote(SENTINEL_API_VERSION)}"
        request = urllib.request.Request(
            url,
            data=json.dumps(body, sort_keys=True, separators=(",", ":")).encode(),
            headers={
                "Authorization": f"Bearer {self.arm.token()}",
                "Accept": "application/json",
                "Content-Type": "application/json",
                "If-Match": expected_etag,
            },
            method="PUT",
        )
        try:
            response = self.arm.opener(request, self.arm.timeout)
            raw = response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[-1000:]
            raise SentinelActuationError(f"SENTINEL_HTTP_{exc.code}:{detail}") from exc
        if response.status != 200:
            # This path is an update-only production capability. A 201 would mean an incident
            # was created/re-created and is therefore outside the admitted consequence.
            raise SentinelActuationError(f"SENTINEL_UPDATE_STATUS_UNEXPECTED:{response.status}")
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise SentinelActuationError("SENTINEL_UPDATE_RESPONSE_INVALID_JSON") from exc
        if not isinstance(payload, Mapping):
            raise SentinelActuationError("SENTINEL_UPDATE_RESPONSE_INVALID")
        return payload


class SentinelIncidentCloseActuator:
    """Close an already-observed Sentinel incident; caller must be BRCEBroker.do()."""

    consequence = "azure:sentinel:close-incident"

    def __init__(self, client: SentinelIncidentClient) -> None:
        self.client = client

    def actuate(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        ref = _incident_ref(payload)
        expected_etag = _require_text(payload, "expected_etag")
        classification = _require_text(payload, "classification")
        classification_reason = _require_text(payload, "classification_reason")
        classification_comment = _require_text(payload, "classification_comment")
        if payload.get("target_status") != "Closed":
            raise SentinelRefusal("REFUSED:SENTINEL_TARGET_STATUS_NOT_CLOSED")
        if classification not in _ALLOWED_CLASSIFICATIONS:
            raise SentinelRefusal("REFUSED:SENTINEL_CLASSIFICATION_INVALID")
        if classification_reason not in _ALLOWED_CLASSIFICATION_REASONS:
            raise SentinelRefusal("REFUSED:SENTINEL_CLASSIFICATION_REASON_INVALID")

        current = self.client.get(ref)
        current_etag = str(current.get("etag", ""))
        if current_etag != expected_etag:
            raise SentinelRefusal("REFUSED:SENTINEL_ETAG_DRIFT")
        properties = _properties(current)
        title = properties.get("title")
        severity = properties.get("severity")
        if not isinstance(title, str) or not title.strip():
            raise SentinelRefusal("REFUSED:SENTINEL_CURRENT_TITLE_INVALID")
        if severity not in {"High", "Medium", "Low", "Informational"}:
            raise SentinelRefusal("REFUSED:SENTINEL_CURRENT_SEVERITY_INVALID")
        if properties.get("status") == "Closed":
            raise SentinelRefusal("REFUSED:SENTINEL_ALREADY_CLOSED")

        update_properties: dict[str, Any] = {
            "title": title,
            "severity": severity,
            "status": "Closed",
            "classification": classification,
            "classificationReason": classification_reason,
            "classificationComment": classification_comment,
        }
        for key in ("description", "owner", "labels", "firstActivityTimeUtc", "lastActivityTimeUtc"):
            if key in properties:
                update_properties[key] = properties[key]
        updated = self.client.put(
            ref,
            body={"etag": expected_etag, "properties": update_properties},
            expected_etag=expected_etag,
        )
        updated_properties = _properties(updated)
        if str(updated.get("id", "")).lower() != ref.resource_id.lower():
            raise SentinelActuationError("SENTINEL_UPDATE_ID_MISMATCH")
        if updated_properties.get("status") != "Closed":
            raise SentinelActuationError("SENTINEL_UPDATE_ACK_NOT_CLOSED")
        return {
            "resource_id": ref.resource_id,
            "status": "Closed",
            "classification": updated_properties.get("classification"),
            "classification_reason": updated_properties.get("classificationReason"),
            "etag": str(updated.get("etag", "")),
        }


class SentinelIncidentClosedVerifier:
    """Independent GET-based postcondition verifier; it does not trust the actuator response."""

    def __init__(self, client: SentinelIncidentClient) -> None:
        self.client = client

    def verify(self, payload: Mapping[str, Any], result: Any) -> bool:
        if not isinstance(result, Mapping):
            return False
        try:
            ref = _incident_ref(payload)
            observed = self.client.get(ref)
            properties = _properties(observed)
        except (SentinelRefusal, SentinelActuationError):
            return False
        expected_etag = str(payload.get("expected_etag", ""))
        observed_etag = str(observed.get("etag", ""))
        return (
            observed_etag != ""
            and observed_etag != expected_etag
            and observed_etag == str(result.get("etag", ""))
            and properties.get("status") == "Closed"
            and properties.get("classification") == payload.get("classification")
            and properties.get("classificationReason") == payload.get("classification_reason")
            and str(observed.get("id", "")).lower() == ref.resource_id.lower()
        )
