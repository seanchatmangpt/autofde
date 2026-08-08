use clap_noun_verb::Result;
use serde_json::{json, Value};

use crate::runtime;

pub fn bundle_verify_handler(path: String) -> Result<Value> {
    Ok(runtime::bundle_verify(&path))
}

pub fn bundle_install_handler(path: String) -> Result<Value> {
    Ok(runtime::bundle_install(&path))
}

pub fn bundle_list_handler() -> Result<Value> {
    Ok(runtime::bundle_list())
}

pub fn observation_match_handler(path: String) -> Result<Value> {
    Ok(runtime::observation_match(&path))
}

pub fn run_execute_handler(observation: String, authority: String) -> Result<Value> {
    Ok(runtime::run_execute(&observation, &authority))
}

pub fn occurrence_show_handler(id: String) -> Result<Value> {
    Ok(runtime::occurrence_show(&id))
}

pub fn occurrence_reconcile_handler(id: String) -> Result<Value> {
    Ok(runtime::occurrence_reconcile(&id))
}

pub fn replay_run_handler(id: String) -> Result<Value> {
    Ok(runtime::replay_run(&id))
}

pub fn evidence_ocel_handler(id: String) -> Result<Value> {
    Ok(runtime::evidence_ocel(&id))
}

pub fn novelty_show_handler(id: String) -> Result<Value> {
    Ok(runtime::novelty_show(&id))
}

// The single requested ggen pack is compatibility-oriented and contributes
// three legacy specimen handlers. They are deliberately inert here: they
// satisfy the pack's compile-time route proof without gaining AutoFDE product
// semantics or authority.
pub fn session_login_handler(_token: String) -> Result<Value> {
    Ok(json!({
        "standing": "UNSUPPORTED",
        "reason": "CLAP_NOUN_VERB_PACK_SPECIMEN",
        "direct_actuation": false
    }))
}

pub fn session_verify_handler() -> Result<Value> {
    Ok(json!({
        "standing": "UNSUPPORTED",
        "reason": "CLAP_NOUN_VERB_PACK_SPECIMEN",
        "direct_actuation": false
    }))
}

pub fn user_create_handler(_name: String, _email: Option<String>) -> Result<Value> {
    Ok(json!({
        "standing": "UNSUPPORTED",
        "reason": "CLAP_NOUN_VERB_PACK_SPECIMEN",
        "direct_actuation": false
    }))
}
