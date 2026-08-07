//! AutoFDE process-constitution conformance kernel.
//!
//! The lab may prove candidates, but only a trace conforming to the admitted
//! production lifecycle can receive production standing.

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::{Display, Formatter};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct ActivitySpec {
    pub name: String,
    #[serde(default)]
    pub requires: Vec<String>,
    #[serde(default)]
    pub authority: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Constitution {
    pub schema: String,
    pub sequence: Vec<ActivitySpec>,
    #[serde(default)]
    pub required_object_types: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OcelObject {
    #[serde(rename = "ocel:oid")]
    pub id: String,
    #[serde(rename = "ocel:type")]
    pub object_type: String,
    #[serde(default, rename = "autofde:attributes")]
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OcelEvent {
    #[serde(rename = "ocel:eid")]
    pub id: String,
    #[serde(rename = "ocel:activity")]
    pub activity: String,
    #[serde(rename = "ocel:timestamp")]
    pub timestamp: String,
    #[serde(default, rename = "ocel:omap")]
    pub object_ids: Vec<String>,
    #[serde(default, rename = "autofde:attributes")]
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OcelLog {
    #[serde(rename = "ocel:objects")]
    pub objects: Vec<OcelObject>,
    #[serde(rename = "ocel:events")]
    pub events: Vec<OcelEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub code: &'static str,
    pub detail: String,
}

impl Display for Violation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.code, self.detail)
    }
}

#[derive(Debug, Clone)]
pub struct Report {
    pub constitution_schema: String,
    pub conforms: bool,
    pub violations: Vec<Violation>,
}

pub fn load_constitution(path: impl AsRef<Path>) -> Result<Constitution, String> {
    let bytes = fs::read(path.as_ref()).map_err(|error| format!("model_read:{error}"))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("model_parse:{error}"))
}

pub fn load_ocel(path: impl AsRef<Path>) -> Result<OcelLog, String> {
    let bytes = fs::read(path.as_ref()).map_err(|error| format!("ocel_read:{error}"))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("ocel_parse:{error}"))
}

#[must_use]
pub fn check(constitution: &Constitution, log: &OcelLog) -> Report {
    let mut violations = Vec::new();
    let objects: HashMap<&str, &OcelObject> =
        log.objects.iter().map(|object| (object.id.as_str(), object)).collect();

    let mut seen_ids = BTreeSet::new();
    for object in &log.objects {
        if !seen_ids.insert(object.id.as_str()) {
            violations.push(Violation {
                code: "DUPLICATE_OBJECT_ID",
                detail: object.id.clone(),
            });
        }
    }

    let present_types: BTreeSet<&str> =
        log.objects.iter().map(|object| object.object_type.as_str()).collect();
    for required in &constitution.required_object_types {
        if !present_types.contains(required.as_str()) {
            violations.push(Violation {
                code: "MISSING_REQUIRED_OBJECT_TYPE",
                detail: required.clone(),
            });
        }
    }

    let mut event_ids = BTreeSet::new();
    for event in &log.events {
        if !event_ids.insert(event.id.as_str()) {
            violations.push(Violation {
                code: "DUPLICATE_EVENT_ID",
                detail: event.id.clone(),
            });
        }
        for object_id in &event.object_ids {
            if !objects.contains_key(object_id.as_str()) {
                violations.push(Violation {
                    code: "DANGLING_OBJECT_REFERENCE",
                    detail: format!("{}->{object_id}", event.id),
                });
            }
        }
    }

    let observed: Vec<&str> = log.events.iter().map(|event| event.activity.as_str()).collect();
    let expected: Vec<&str> = constitution
        .sequence
        .iter()
        .map(|activity| activity.name.as_str())
        .collect();
    if observed != expected {
        violations.push(Violation {
            code: "LIFECYCLE_SEQUENCE_DEVIATION",
            detail: format!("expected={expected:?};observed={observed:?}"),
        });
    }

    for (spec, event) in constitution.sequence.iter().zip(log.events.iter()) {
        if event.activity != spec.name {
            continue;
        }
        let bound_types: BTreeSet<&str> = event
            .object_ids
            .iter()
            .filter_map(|id| objects.get(id.as_str()).map(|object| object.object_type.as_str()))
            .collect();
        for required in &spec.requires {
            if !bound_types.contains(required.as_str()) {
                violations.push(Violation {
                    code: "EVENT_OBJECT_CONTRACT_VIOLATION",
                    detail: format!("{} missing {required}", event.activity),
                });
            }
        }
        if let Some(required_authority) = &spec.authority {
            let observed_authority = event.attributes.get("authority").map(String::as_str);
            if observed_authority != Some(required_authority.as_str()) {
                violations.push(Violation {
                    code: "AUTHORITY_CONTRACT_VIOLATION",
                    detail: format!(
                        "{} expected={} observed={observed_authority:?}",
                        event.activity, required_authority
                    ),
                });
            }
        }
    }

    enforce_product_laws(log, &objects, &mut violations);
    violations.sort_by(|left, right| (left.code, &left.detail).cmp(&(right.code, &right.detail)));

    Report {
        constitution_schema: constitution.schema.clone(),
        conforms: violations.is_empty(),
        violations,
    }
}

fn enforce_product_laws(
    log: &OcelLog,
    objects: &HashMap<&str, &OcelObject>,
    violations: &mut Vec<Violation>,
) {
    for event in &log.events {
        match event.activity.as_str() {
            "LabProved" | "PromotionAdmitted" | "BundleManufactured" | "BundlePinned"
            | "SessionStarted" | "POWLCommitted" => {
                if event.attributes.get("authority").map(String::as_str) == Some("bearer") {
                    violations.push(Violation {
                        code: "ADVISORY_AUTHORITY_USED_AS_BEARER",
                        detail: event.id.clone(),
                    });
                }
            }
            "ActuationOpened" => {
                if event.attributes.get("path").map(String::as_str) != Some("BRCE") {
                    violations.push(Violation {
                        code: "ACTUATION_BYPASSED_BRCE",
                        detail: event.id.clone(),
                    });
                }
            }
            "PostconditionVerified" => {
                let observer = event.attributes.get("observer").map(String::as_str);
                let actuator = event.attributes.get("actuator").map(String::as_str);
                if observer.is_none() || observer == actuator {
                    violations.push(Violation {
                        code: "SELF_CERTIFIED_POSTCONDITION",
                        detail: event.id.clone(),
                    });
                }
            }
            "HookActuated" => violations.push(Violation {
                code: "HOOK_DIRECT_ACTUATION",
                detail: event.id.clone(),
            }),
            _ => {}
        }
    }

    if let Some(session) = log.events.iter().find(|event| event.activity == "SessionStarted") {
        let declared_digest = session.attributes.get("bundle_digest");
        let bound_bundle = session
            .object_ids
            .iter()
            .filter_map(|id| objects.get(id.as_str()))
            .find(|object| object.object_type == "CapabilityBundle");
        let pinned_digest = bound_bundle.and_then(|bundle| bundle.attributes.get("digest"));
        if declared_digest.is_none() || declared_digest != pinned_digest {
            violations.push(Violation {
                code: "CAPABILITY_BUNDLE_NOT_PINNED",
                detail: session.id.clone(),
            });
        }
    }

    if let Some(receipt_event) = log.events.iter().find(|event| event.activity == "ReceiptEmitted") {
        let types: BTreeSet<&str> = receipt_event
            .object_ids
            .iter()
            .filter_map(|id| objects.get(id.as_str()).map(|object| object.object_type.as_str()))
            .collect();
        if !(types.contains("Actuation") && types.contains("PostconditionObservation")) {
            violations.push(Violation {
                code: "RECEIPT_WITHOUT_OBSERVED_CONSEQUENCE",
                detail: receipt_event.id.clone(),
            });
        }
    }

    if let Some(replay) = log.events.iter().find(|event| event.activity == "ReplayCompleted") {
        let binds_receipt = replay
            .object_ids
            .iter()
            .filter_map(|id| objects.get(id.as_str()))
            .any(|object| object.object_type == "Receipt");
        if !binds_receipt {
            violations.push(Violation {
                code: "REPLAY_WITHOUT_SOURCE_RECEIPT",
                detail: replay.id.clone(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model() -> Constitution {
        serde_json::from_str(include_str!("../process/autofde-lifecycle.powl.json")).unwrap()
    }

    fn valid_log() -> OcelLog {
        serde_json::from_str(include_str!(
            "../fixtures/autofde-lifecycle/valid.ocel.json"
        ))
        .unwrap()
    }

    fn codes(report: &Report) -> BTreeSet<&'static str> {
        report.violations.iter().map(|violation| violation.code).collect()
    }

    #[test]
    fn valid_trace_conforms() {
        let report = check(&model(), &valid_log());
        assert!(report.conforms, "{:?}", report.violations);
    }

    #[test]
    fn missing_authority_is_a_lifecycle_deviation() {
        let mut log = valid_log();
        log.events
            .retain(|event| event.activity != "AuthorityAdmitted");
        let report = check(&model(), &log);
        assert!(!report.conforms);
        assert!(codes(&report).contains("LIFECYCLE_SEQUENCE_DEVIATION"));
    }

    #[test]
    fn planner_or_lab_evidence_cannot_become_bearer_authority() {
        let mut log = valid_log();
        let event = log
            .events
            .iter_mut()
            .find(|event| event.activity == "POWLCommitted")
            .unwrap();
        event.attributes.insert("authority".into(), "bearer".into());
        let report = check(&model(), &log);
        assert!(codes(&report).contains("ADVISORY_AUTHORITY_USED_AS_BEARER"));
    }

    #[test]
    fn self_certified_postcondition_is_refused() {
        let mut log = valid_log();
        let event = log
            .events
            .iter_mut()
            .find(|event| event.activity == "PostconditionVerified")
            .unwrap();
        event
            .attributes
            .insert("observer".into(), "brce-actuator".into());
        let report = check(&model(), &log);
        assert!(codes(&report).contains("SELF_CERTIFIED_POSTCONDITION"));
    }

    #[test]
    fn unpinned_bundle_is_refused() {
        let mut log = valid_log();
        let event = log
            .events
            .iter_mut()
            .find(|event| event.activity == "SessionStarted")
            .unwrap();
        event
            .attributes
            .insert("bundle_digest".into(), "sha256:tampered".into());
        let report = check(&model(), &log);
        assert!(codes(&report).contains("CAPABILITY_BUNDLE_NOT_PINNED"));
    }

    #[test]
    fn direct_non_brce_actuation_is_refused() {
        let mut log = valid_log();
        let event = log
            .events
            .iter_mut()
            .find(|event| event.activity == "ActuationOpened")
            .unwrap();
        event.attributes.insert("path".into(), "planner".into());
        let report = check(&model(), &log);
        assert!(codes(&report).contains("ACTUATION_BYPASSED_BRCE"));
    }
}
