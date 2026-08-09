use crate::knowledge_hook::{HookReceipt, HookRefusal, KnowledgeHookLedger, RdfDelta, Triple};
use serde_json::Value;
use std::fmt;

pub const SENTINEL_INCIDENT_SCHEMA: &str = "microsoft.sentinel.incident/1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentinelIngressPolicy {
    pub subscription_id: String,
    pub workspace_resource_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentinelIncident {
    pub arm_id: String,
    pub name: String,
    pub status: String,
    pub title: String,
    pub severity: Option<String>,
    pub last_modified_time_utc: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SentinelIngressRefusal {
    InvalidJson(String),
    InvalidShape(String),
    SubscriptionMismatch,
    WorkspaceMismatch,
    Hook(HookRefusal),
}

impl SentinelIngressRefusal {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidJson(_) => "REFUSED_SENTINEL_JSON",
            Self::InvalidShape(_) => "REFUSED_SENTINEL_SHAPE",
            Self::SubscriptionMismatch => "REFUSED_SENTINEL_SUBSCRIPTION",
            Self::WorkspaceMismatch => "REFUSED_SENTINEL_WORKSPACE",
            Self::Hook(error) => error.code(),
        }
    }
}

impl fmt::Display for SentinelIngressRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson(reason) | Self::InvalidShape(reason) => {
                write!(f, "{}: {reason}", self.code())
            }
            Self::SubscriptionMismatch => write!(f, "{}", self.code()),
            Self::WorkspaceMismatch => write!(f, "{}", self.code()),
            Self::Hook(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for SentinelIngressRefusal {}

impl From<HookRefusal> for SentinelIngressRefusal {
    fn from(value: HookRefusal) -> Self {
        Self::Hook(value)
    }
}

pub fn admit_sentinel_incident(
    ledger: &mut KnowledgeHookLedger,
    policy: &SentinelIngressPolicy,
    raw_body: &[u8],
) -> Result<HookReceipt, SentinelIngressRefusal> {
    let incident = parse_sentinel_incident(policy, raw_body)?;
    ledger.admit(to_rdf_delta(&incident)).map_err(Into::into)
}

pub fn parse_sentinel_incident(
    policy: &SentinelIngressPolicy,
    raw_body: &[u8],
) -> Result<SentinelIncident, SentinelIngressRefusal> {
    validate_policy(policy)?;
    let root: Value = serde_json::from_slice(raw_body)
        .map_err(|error| SentinelIngressRefusal::InvalidJson(error.to_string()))?;
    let incident = locate_incident(&root)
        .ok_or_else(|| SentinelIngressRefusal::InvalidShape("incident object not found".into()))?;

    let arm_id = required_string(incident, "id")?;
    let name = required_string(incident, "name")?;
    let properties = incident
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(|| SentinelIngressRefusal::InvalidShape("properties missing".into()))?;
    let status = required_object_string(properties, "status")?;
    let title = required_object_string(properties, "title")?;
    let last_modified_time_utc = required_object_string(properties, "lastModifiedTimeUtc")?;
    let severity = properties
        .get("severity")
        .and_then(Value::as_str)
        .map(str::to_owned);

    let expected_subscription = format!(
        "/subscriptions/{}/",
        policy.subscription_id.to_ascii_lowercase()
    );
    let normalized_arm = arm_id.to_ascii_lowercase();
    if !normalized_arm.starts_with(&expected_subscription) {
        return Err(SentinelIngressRefusal::SubscriptionMismatch);
    }

    let workspace = policy
        .workspace_resource_id
        .trim_end_matches('/')
        .to_ascii_lowercase();
    let expected_prefix = format!("{workspace}/providers/microsoft.securityinsights/incidents/");
    if !normalized_arm.starts_with(&expected_prefix) {
        return Err(SentinelIngressRefusal::WorkspaceMismatch);
    }

    Ok(SentinelIncident {
        arm_id,
        name,
        status,
        title,
        severity,
        last_modified_time_utc,
    })
}

pub fn to_rdf_delta(incident: &SentinelIncident) -> RdfDelta {
    let subject = incident.arm_id.clone();
    let mut additions = vec![
        triple(
            &subject,
            "urn:autofde:sourceSchema",
            SENTINEL_INCIDENT_SCHEMA,
        ),
        triple(&subject, "urn:autofde:incidentName", &incident.name),
        triple(&subject, "urn:autofde:incidentStatus", &incident.status),
        triple(&subject, "urn:autofde:incidentTitle", &incident.title),
        triple(
            &subject,
            "urn:autofde:lastModifiedTimeUtc",
            &incident.last_modified_time_utc,
        ),
    ];
    if let Some(severity) = &incident.severity {
        additions.push(triple(&subject, "urn:autofde:incidentSeverity", severity));
    }

    let event_identity = blake3::hash(
        format!("{}\n{}", incident.arm_id, incident.last_modified_time_utc).as_bytes(),
    )
    .to_hex()
    .to_string();

    RdfDelta {
        stream_id: format!("azure-sentinel/incident-event/{event_identity}"),
        sequence: 1,
        prior_digest: None,
        additions,
        removals: Vec::new(),
    }
}

fn locate_incident(root: &Value) -> Option<&serde_json::Map<String, Value>> {
    for candidate in [
        root.get("incident"),
        root.get("body").and_then(|v| v.get("incident")),
        Some(root),
    ] {
        if let Some(object) = candidate.and_then(Value::as_object) {
            if object.contains_key("id") && object.contains_key("properties") {
                return Some(object);
            }
        }
    }
    None
}

fn validate_policy(policy: &SentinelIngressPolicy) -> Result<(), SentinelIngressRefusal> {
    if policy.subscription_id.trim().is_empty() || policy.subscription_id.contains('/') {
        return Err(SentinelIngressRefusal::InvalidShape(
            "subscription_id must be one non-empty ARM segment".into(),
        ));
    }
    let workspace = policy.workspace_resource_id.to_ascii_lowercase();
    let expected = format!(
        "/subscriptions/{}/",
        policy.subscription_id.to_ascii_lowercase()
    );
    if !workspace.starts_with(&expected)
        || !workspace.contains("/providers/microsoft.operationalinsights/workspaces/")
    {
        return Err(SentinelIngressRefusal::InvalidShape(
            "workspace_resource_id is not an admitted Log Analytics workspace ARM id".into(),
        ));
    }
    Ok(())
}

fn required_string(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<String, SentinelIngressRefusal> {
    required_object_string(object, key)
}

fn required_object_string(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<String, SentinelIngressRefusal> {
    let value = object
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| SentinelIngressRefusal::InvalidShape(format!("{key} missing")))?;
    Ok(value.to_owned())
}

fn triple(subject: &str, predicate: &str, object: &str) -> Triple {
    Triple {
        subject: subject.to_owned(),
        predicate: predicate.to_owned(),
        object: object.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const SUBSCRIPTION: &str = "00000000-1111-2222-3333-444444444444";
    const WORKSPACE: &str = "/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/sec-rg/providers/Microsoft.OperationalInsights/workspaces/sec-law";

    fn policy() -> SentinelIngressPolicy {
        SentinelIngressPolicy {
            subscription_id: SUBSCRIPTION.into(),
            workspace_resource_id: WORKSPACE.into(),
        }
    }

    fn incident(status: &str, modified: &str) -> Vec<u8> {
        format!(
            r#"{{"incident":{{"id":"{WORKSPACE}/providers/Microsoft.SecurityInsights/incidents/8d1c8125-5f92-4dd5-98bf-1a3ed09b1234","name":"8d1c8125-5f92-4dd5-98bf-1a3ed09b1234","properties":{{"status":"{status}","title":"Suspicious sign-in","severity":"High","lastModifiedTimeUtc":"{modified}"}}}}}}"#
        )
        .into_bytes()
    }

    #[test]
    fn real_connector_shape_enters_construct_only_rdfdelta_and_replays_idempotently() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sentinel.db");
        let mut ledger = KnowledgeHookLedger::open(&path).unwrap();

        let first = admit_sentinel_incident(
            &mut ledger,
            &policy(),
            &incident("Active", "2026-08-09T15:00:00Z"),
        )
        .unwrap();
        assert!(!first.replayed);
        assert_eq!(first.intent.authority_class, "CONSTRUCT");
        assert!(!first.intent.do_authority);
        assert_eq!(first.intent.operation, "knowledge_hook.rdfdelta_intake");

        let replay = admit_sentinel_incident(
            &mut ledger,
            &policy(),
            &incident("Active", "2026-08-09T15:00:00Z"),
        )
        .unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.digest, first.digest);

        drop(ledger);
        let reopened = KnowledgeHookLedger::open(&path).unwrap();
        assert_eq!(reopened.verify_stream(&first.intent.stream_id).unwrap(), 1);
    }

    #[test]
    fn incident_update_gets_distinct_event_identity_without_mutating_prior_event() {
        let first = parse_sentinel_incident(&policy(), &incident("Active", "2026-08-09T15:00:00Z"))
            .unwrap();
        let second =
            parse_sentinel_incident(&policy(), &incident("Closed", "2026-08-09T15:05:00Z"))
                .unwrap();
        let first_delta = to_rdf_delta(&first);
        let second_delta = to_rdf_delta(&second);
        assert_ne!(first_delta.stream_id, second_delta.stream_id);
        assert_eq!(first_delta.sequence, 1);
        assert_eq!(second_delta.sequence, 1);
    }

    #[test]
    fn refuses_cross_subscription_and_cross_workspace_incidents() {
        let body = incident("Active", "2026-08-09T15:00:00Z");
        let wrong_subscription = SentinelIngressPolicy {
            subscription_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
            workspace_resource_id: "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/sec-rg/providers/Microsoft.OperationalInsights/workspaces/sec-law".into(),
        };
        assert_eq!(
            parse_sentinel_incident(&wrong_subscription, &body)
                .unwrap_err()
                .code(),
            "REFUSED_SENTINEL_SUBSCRIPTION"
        );

        let wrong_workspace = SentinelIngressPolicy {
            subscription_id: SUBSCRIPTION.into(),
            workspace_resource_id: "/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/sec-rg/providers/Microsoft.OperationalInsights/workspaces/other-law".into(),
        };
        assert_eq!(
            parse_sentinel_incident(&wrong_workspace, &body)
                .unwrap_err()
                .code(),
            "REFUSED_SENTINEL_WORKSPACE"
        );
    }

    #[test]
    fn malformed_or_vacuous_incidents_are_refused_before_ledger_mutation() {
        let dir = tempdir().unwrap();
        let mut ledger = KnowledgeHookLedger::open(dir.path().join("sentinel.db")).unwrap();
        let bad = br#"{"incident":{"id":"x","name":"n","properties":{}}}"#;
        assert_eq!(
            admit_sentinel_incident(&mut ledger, &policy(), bad)
                .unwrap_err()
                .code(),
            "REFUSED_SENTINEL_SHAPE"
        );
    }
}
