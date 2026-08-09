use rusqlite::{params, Connection, OptionalExtension};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const BUNDLE_SCHEMA: &str = "autofde.capability-bundle/1";
pub const OBSERVATION_SCHEMA: &str = "autofde.observation/1";
pub const AUTHORITY_SCHEMA: &str = "autofde.authority-envelope/1";
pub const RUNTIME_ABI: &str = "autofde.runtime/26.8.8";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilityBundle {
    pub schema: String,
    pub runtime_abi: String,
    pub bundle_digest: String,
    pub capability: String,
    pub lab_revision: String,
    pub ggen_revision: String,
    #[serde(default)]
    pub match_all: BTreeMap<String, String>,
    pub effect: String,
    pub program: CompiledProgram,
    pub verifier: VerifierContract,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CompiledProgram {
    Noop,
    FilesystemWrite { path: String, content: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VerifierContract {
    Noop,
    FileBlake3 { path: String, digest: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObservationEnvelope {
    pub schema: String,
    #[serde(default)]
    pub facts: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorityEnvelope {
    pub schema: String,
    pub authority_digest: String,
    pub bundle_digest: String,
    #[serde(default)]
    pub allowed_effects: Vec<String>,
    #[serde(default)]
    pub resource_prefixes: Vec<String>,
    #[serde(default)]
    pub valid_until_unix: u64,
}

#[derive(Clone, Debug)]
pub struct RuntimePaths {
    pub state: PathBuf,
    pub world: PathBuf,
}

impl RuntimePaths {
    pub fn from_env() -> Self {
        let state = std::env::var_os("AUTOFDE_STATE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(".autofde"));
        let world = std::env::var_os("AUTOFDE_WORLD_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| state.join("world"));
        Self { state, world }
    }

    fn bundles(&self) -> PathBuf {
        self.state.join("bundles")
    }

    fn novelty(&self) -> PathBuf {
        self.state.join("novelty")
    }

    fn db(&self) -> PathBuf {
        self.state.join("runtime.sqlite")
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .unwrap_or(0)
}

fn digest_bytes(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| digest_bytes(&bytes))
        .map_err(|error| format!("JSON_CANONICALIZATION:{error}"))
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, String> {
    let bytes = fs::read(path).map_err(|error| format!("READ:{}:{error}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("JSON:{}:{error}", path.display()))
}

fn refused(code: &str, detail: impl Into<String>) -> Value {
    json!({"standing": format!("REFUSED:{code}"), "detail": detail.into()})
}

fn blocked(code: &str, detail: impl Into<String>) -> Value {
    json!({"standing": "BLOCKED", "reason": code, "detail": detail.into()})
}

fn build_broken(code: &str, detail: impl Into<String>) -> Value {
    json!({"standing": "BUILD_BROKEN", "reason": code, "detail": detail.into()})
}

impl CapabilityBundle {
    pub fn expected_digest(&self) -> Result<String, String> {
        let mut copy = self.clone();
        copy.bundle_digest.clear();
        digest_json(&copy)
    }

    pub fn verify(&self) -> Result<(), String> {
        if self.schema != BUNDLE_SCHEMA {
            return Err("UNSUPPORTED_BUNDLE_SCHEMA".into());
        }
        if self.runtime_abi != RUNTIME_ABI {
            return Err("UNSUPPORTED_PROGRAM_ABI".into());
        }
        if self.lab_revision.is_empty() || self.ggen_revision.is_empty() {
            return Err("MANUFACTURE_PROVENANCE_INCOMPLETE".into());
        }
        if self.bundle_digest != self.expected_digest()? {
            return Err("BUNDLE_DIGEST_MISMATCH".into());
        }
        match (&self.program, &self.verifier) {
            (CompiledProgram::Noop, VerifierContract::Noop) if self.effect == "none" => Ok(()),
            (
                CompiledProgram::FilesystemWrite { path, content },
                VerifierContract::FileBlake3 {
                    path: verifier_path,
                    digest,
                },
            ) if self.effect == "filesystem.write"
                && path == verifier_path
                && *digest == digest_bytes(content.as_bytes())
                && safe_relative(path).is_ok() =>
            {
                Ok(())
            }
            _ => Err("COMPILED_PROGRAM_VERIFIER_NOT_CLOSED".into()),
        }
    }
}

impl AuthorityEnvelope {
    pub fn expected_digest(&self) -> Result<String, String> {
        let mut copy = self.clone();
        copy.authority_digest.clear();
        digest_json(&copy)
    }

    pub fn verify_for(&self, bundle: &CapabilityBundle) -> Result<(), String> {
        if self.schema != AUTHORITY_SCHEMA {
            return Err("UNSUPPORTED_AUTHORITY_SCHEMA".into());
        }
        if self.authority_digest != self.expected_digest()? {
            return Err("AUTHORITY_DIGEST_MISMATCH".into());
        }
        if self.bundle_digest != bundle.bundle_digest {
            return Err("AUTHORITY_WRONG_BUNDLE".into());
        }
        if !self.allowed_effects.iter().any(|effect| effect == &bundle.effect) {
            return Err("AUTHORITY_EFFECT_DENIED".into());
        }
        if self.valid_until_unix != 0 && unix_now() > self.valid_until_unix {
            return Err("AUTHORITY_EXPIRED".into());
        }
        if let CompiledProgram::FilesystemWrite { path, .. } = &bundle.program {
            let normalized = safe_relative(path)?;
            let normalized = normalized.to_string_lossy();
            if !self.resource_prefixes.iter().any(|prefix| normalized.starts_with(prefix)) {
                return Err("AUTHORITY_RESOURCE_SCOPE".into());
            }
        }
        Ok(())
    }
}

fn safe_relative(raw: &str) -> Result<PathBuf, String> {
    let path = Path::new(raw);
    if path.is_absolute() {
        return Err("PATH_ABSOLUTE".into());
    }
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(segment) => clean.push(segment),
            _ => return Err("PATH_TRAVERSAL".into()),
        }
    }
    if clean.as_os_str().is_empty() {
        return Err("PATH_EMPTY".into());
    }
    Ok(clean)
}

fn observation_digest(observation: &ObservationEnvelope) -> Result<String, String> {
    if observation.schema != OBSERVATION_SCHEMA {
        return Err("UNSUPPORTED_OBSERVATION_SCHEMA".into());
    }
    digest_json(observation)
}

fn bundle_matches(bundle: &CapabilityBundle, observation: &ObservationEnvelope) -> bool {
    bundle
        .match_all
        .iter()
        .all(|(key, value)| observation.facts.get(key) == Some(value))
}

fn installed_bundles(paths: &RuntimePaths) -> Result<Vec<CapabilityBundle>, String> {
    let dir = paths.bundles();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut bundles = Vec::new();
    for entry in fs::read_dir(&dir).map_err(|error| format!("BUNDLE_REGISTRY_READ:{error}"))? {
        let entry = entry.map_err(|error| format!("BUNDLE_REGISTRY_ENTRY:{error}"))?;
        if entry.path().extension().and_then(|v| v.to_str()) != Some("json") {
            continue;
        }
        let bundle: CapabilityBundle = read_json(&entry.path())?;
        bundle.verify()?;
        bundles.push(bundle);
    }
    bundles.sort_by(|a, b| a.bundle_digest.cmp(&b.bundle_digest));
    Ok(bundles)
}

fn matching_bundles(
    paths: &RuntimePaths,
    observation: &ObservationEnvelope,
) -> Result<Vec<CapabilityBundle>, String> {
    observation_digest(observation)?;
    Ok(installed_bundles(paths)?
        .into_iter()
        .filter(|bundle| bundle_matches(bundle, observation))
        .collect())
}

fn persist_novelty(paths: &RuntimePaths, observation: &ObservationEnvelope) -> Result<Value, String> {
    let installed = installed_bundles(paths)?;
    let observation_digest = observation_digest(observation)?;
    let candidates: Vec<String> = installed.into_iter().map(|b| b.bundle_digest).collect();
    let id = digest_json(&(observation_digest.clone(), &candidates))?;
    let packet = json!({
        "schema": "autofde.novelty-packet/1",
        "novelty_id": id,
        "standing": "REFUSED:NOVEL_OBSERVATION",
        "observation_digest": observation_digest,
        "observation": observation,
        "installed_bundle_digests": candidates,
        "authority": "NONE",
        "direct_actuation": false,
        "route": "autofde-lab"
    });
    fs::create_dir_all(paths.novelty()).map_err(|error| format!("NOVELTY_DIR:{error}"))?;
    fs::write(
        paths.novelty().join(format!("{}.json", packet["novelty_id"].as_str().unwrap_or("invalid"))),
        serde_json::to_vec_pretty(&packet).map_err(|error| format!("NOVELTY_JSON:{error}"))?,
    )
    .map_err(|error| format!("NOVELTY_WRITE:{error}"))?;
    Ok(packet)
}

fn open_db(paths: &RuntimePaths) -> Result<Connection, String> {
    fs::create_dir_all(&paths.state).map_err(|error| format!("STATE_DIR:{error}"))?;
    let connection = Connection::open(paths.db()).map_err(|error| format!("SQLITE_OPEN:{error}"))?;
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .map_err(|error| format!("SQLITE_WAL:{error}"))?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(|error| format!("SQLITE_SYNC:{error}"))?;
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS occurrences (
                occurrence_id TEXT PRIMARY KEY,
                bundle_digest TEXT NOT NULL,
                observation_json TEXT NOT NULL,
                authority_json TEXT NOT NULL,
                state TEXT NOT NULL,
                pre_digest TEXT NOT NULL,
                receipt_json TEXT
            );",
        )
        .map_err(|error| format!("SQLITE_SCHEMA:{error}"))?;
    Ok(connection)
}

fn receipt_with_digest(mut receipt: Value) -> Result<Value, String> {
    if let Some(object) = receipt.as_object_mut() {
        object.remove("receipt_digest");
    }
    let digest = digest_json(&receipt)?;
    receipt
        .as_object_mut()
        .ok_or_else(|| "RECEIPT_NOT_OBJECT".to_string())?
        .insert("receipt_digest".into(), Value::String(digest));
    Ok(receipt)
}

fn save_final(
    connection: &Connection,
    occurrence_id: &str,
    state: &str,
    receipt: &Value,
) -> Result<(), String> {
    let receipt_json = serde_json::to_string(receipt).map_err(|error| format!("RECEIPT_JSON:{error}"))?;
    connection
        .execute(
            "UPDATE occurrences SET state = ?2, receipt_json = ?3 WHERE occurrence_id = ?1",
            params![occurrence_id, state, receipt_json],
        )
        .map_err(|error| format!("SQLITE_FINAL:{error}"))?;
    Ok(())
}

fn verify_consequence(paths: &RuntimePaths, verifier: &VerifierContract) -> Result<String, String> {
    match verifier {
        VerifierContract::Noop => Ok("NOOP_VERIFIED".into()),
        VerifierContract::FileBlake3 { path, digest } => {
            let relative = safe_relative(path)?;
            let bytes = fs::read(paths.world.join(relative))
                .map_err(|error| format!("POSTCONDITION_READ:{error}"))?;
            let observed = digest_bytes(&bytes);
            if &observed != digest {
                return Err("POSTCONDITION_DIGEST_MISMATCH".into());
            }
            Ok(observed)
        }
    }
}

fn brce_filesystem_write(paths: &RuntimePaths, path: &str, content: &str) -> Result<(), String> {
    let relative = safe_relative(path)?;
    let target = paths.world.join(relative);
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("BRCE_CREATE_PARENT:{error}"))?;
    }
    fs::write(&target, content.as_bytes()).map_err(|error| format!("BRCE_WRITE:{error}"))
}

fn load_installed(paths: &RuntimePaths, digest: &str) -> Result<CapabilityBundle, String> {
    let path = paths.bundles().join(format!("{digest}.json"));
    let bundle: CapabilityBundle = read_json(&path)?;
    bundle.verify()?;
    if bundle.bundle_digest != digest {
        return Err("INSTALLED_BUNDLE_IDENTITY_DRIFT".into());
    }
    Ok(bundle)
}

pub fn bundle_verify(path: &str) -> Value {
    match read_json::<CapabilityBundle>(Path::new(path)).and_then(|bundle| {
        bundle.verify()?;
        Ok(bundle)
    }) {
        Ok(bundle) => json!({
            "standing": "ALIVE",
            "bundle_digest": bundle.bundle_digest,
            "capability": bundle.capability,
            "runtime_abi": bundle.runtime_abi
        }),
        Err(error) => refused("UNPINNED_BUNDLE", error),
    }
}

pub fn bundle_install(path: &str) -> Value {
    let paths = RuntimePaths::from_env();
    let bundle: CapabilityBundle = match read_json(Path::new(path)) {
        Ok(bundle) => bundle,
        Err(error) => return refused("UNPINNED_BUNDLE", error),
    };
    if let Err(error) = bundle.verify() {
        return refused("UNPINNED_BUNDLE", error);
    }
    if let Err(error) = fs::create_dir_all(paths.bundles()) {
        return build_broken("BUNDLE_REGISTRY_CREATE", error.to_string());
    }
    let target = paths.bundles().join(format!("{}.json", bundle.bundle_digest));
    let bytes = match serde_json::to_vec_pretty(&bundle) {
        Ok(bytes) => bytes,
        Err(error) => return build_broken("BUNDLE_SERIALIZE", error.to_string()),
    };
    if let Err(error) = fs::write(&target, bytes) {
        return build_broken("BUNDLE_INSTALL", error.to_string());
    }
    json!({"standing": "ALIVE", "bundle_digest": bundle.bundle_digest, "installed": target})
}

pub fn bundle_list() -> Value {
    let paths = RuntimePaths::from_env();
    match installed_bundles(&paths) {
        Ok(bundles) => json!({
            "standing": "ALIVE",
            "bundles": bundles.into_iter().map(|bundle| json!({
                "digest": bundle.bundle_digest,
                "capability": bundle.capability,
                "effect": bundle.effect
            })).collect::<Vec<_>>()
        }),
        Err(error) => build_broken("BUNDLE_REGISTRY", error),
    }
}

pub fn observation_match(path: &str) -> Value {
    let paths = RuntimePaths::from_env();
    let observation: ObservationEnvelope = match read_json(Path::new(path)) {
        Ok(value) => value,
        Err(error) => return refused("OBSERVATION_INVALID", error),
    };
    match matching_bundles(&paths, &observation) {
        Ok(matches) if matches.len() == 1 => json!({
            "standing": "ALIVE",
            "bundle_digest": matches[0].bundle_digest,
            "capability": matches[0].capability,
            "authority": "NOT_ADMITTED",
            "direct_actuation": false
        }),
        Ok(matches) if matches.is_empty() => persist_novelty(&paths, &observation)
            .unwrap_or_else(|error| build_broken("NOVELTY_PERSIST", error)),
        Ok(matches) => refused(
            "AMBIGUOUS_CAPABILITY_MATCH",
            matches.into_iter().map(|b| b.bundle_digest).collect::<Vec<_>>().join(","),
        ),
        Err(error) => refused("OBSERVATION_INVALID", error),
    }
}

pub fn run_execute(observation_path: &str, authority_path: &str) -> Value {
    execute_with_paths(
        &RuntimePaths::from_env(),
        observation_path,
        authority_path,
    )
}

pub fn execute_with_paths(
    paths: &RuntimePaths,
    observation_path: &str,
    authority_path: &str,
) -> Value {
    let observation: ObservationEnvelope = match read_json(Path::new(observation_path)) {
        Ok(value) => value,
        Err(error) => return refused("OBSERVATION_INVALID", error),
    };
    let matches = match matching_bundles(paths, &observation) {
        Ok(value) => value,
        Err(error) => return refused("OBSERVATION_INVALID", error),
    };
    if matches.is_empty() {
        return persist_novelty(paths, &observation)
            .unwrap_or_else(|error| build_broken("NOVELTY_PERSIST", error));
    }
    if matches.len() != 1 {
        return refused("AMBIGUOUS_CAPABILITY_MATCH", matches.len().to_string());
    }
    let bundle = &matches[0];
    let authority: AuthorityEnvelope = match read_json(Path::new(authority_path)) {
        Ok(value) => value,
        Err(error) => return refused("AUTHORITY_DENIED", error),
    };
    if let Err(error) = authority.verify_for(bundle) {
        return refused("AUTHORITY_DENIED", error);
    }
    let observation_digest = match observation_digest(&observation) {
        Ok(value) => value,
        Err(error) => return refused("OBSERVATION_INVALID", error),
    };
    let occurrence_id = digest_bytes(
        format!(
            "{}|{}|{}",
            bundle.bundle_digest, observation_digest, authority.authority_digest
        )
        .as_bytes(),
    );
    let pre_digest = digest_bytes(
        format!(
            "PRE_ACTUATION|{}|{}|{}",
            occurrence_id, bundle.bundle_digest, authority.authority_digest
        )
        .as_bytes(),
    );
    let connection = match open_db(paths) {
        Ok(value) => value,
        Err(error) => return build_broken("OCCURRENCE_STORE", error),
    };
    let existing: Option<(String, Option<String>)> = match connection
        .query_row(
            "SELECT state, receipt_json FROM occurrences WHERE occurrence_id = ?1",
            params![occurrence_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
    {
        Ok(value) => value,
        Err(error) => return build_broken("OCCURRENCE_LOOKUP", error.to_string()),
    };
    if let Some((state, receipt_json)) = existing {
        if state == "ALIVE" {
            if let Some(raw) = receipt_json {
                if let Ok(mut receipt) = serde_json::from_str::<Value>(&raw) {
                    receipt["replayed"] = Value::Bool(true);
                    return receipt;
                }
            }
        }
        if state == "UNKNOWN_RECONCILIATION" {
            return blocked(
                "UNKNOWN_RECONCILIATION",
                "existing occurrence is uncertain; use `autofde occurrence reconcile`",
            );
        }
        return blocked("OCCURRENCE_ALREADY_EXISTS", state);
    }
    let observation_json = match serde_json::to_string(&observation) {
        Ok(value) => value,
        Err(error) => return build_broken("OBSERVATION_SERIALIZE", error.to_string()),
    };
    let authority_json = match serde_json::to_string(&authority) {
        Ok(value) => value,
        Err(error) => return build_broken("AUTHORITY_SERIALIZE", error.to_string()),
    };
    if let Err(error) = connection.execute(
        "INSERT INTO occurrences (occurrence_id, bundle_digest, observation_json, authority_json, state, pre_digest, receipt_json)
         VALUES (?1, ?2, ?3, ?4, 'PRE_ACTUATION', ?5, NULL)",
        params![
            occurrence_id,
            bundle.bundle_digest,
            observation_json,
            authority_json,
            pre_digest
        ],
    ) {
        return build_broken("PRE_ACTUATION_PERSIST", error.to_string());
    }

    match &bundle.program {
        CompiledProgram::Noop => {
            let receipt = match receipt_with_digest(json!({
                "schema": "autofde.process-receipt/1",
                "occurrence_id": occurrence_id,
                "bundle_digest": bundle.bundle_digest,
                "authority_digest": authority.authority_digest,
                "pre_actuation_digest": pre_digest,
                "consequence": "NONE",
                "verification": "NOOP_VERIFIED",
                "standing": "ALIVE"
            })) {
                Ok(value) => value,
                Err(error) => return build_broken("RECEIPT", error),
            };
            if let Err(error) = save_final(&connection, &occurrence_id, "ALIVE", &receipt) {
                return build_broken("RECEIPT_PERSIST", error);
            }
            receipt
        }
        CompiledProgram::FilesystemWrite { path, content } => {
            if let Err(error) = brce_filesystem_write(paths, path, content) {
                let receipt = receipt_with_digest(json!({
                    "schema": "autofde.process-receipt/1",
                    "occurrence_id": occurrence_id,
                    "bundle_digest": bundle.bundle_digest,
                    "authority_digest": authority.authority_digest,
                    "pre_actuation_digest": pre_digest,
                    "standing": "BLOCKED",
                    "reason": "BRCE_FAILURE",
                    "error_digest": digest_bytes(error.as_bytes())
                }))
                .unwrap_or_else(|_| json!({"standing":"BUILD_BROKEN","reason":"RECEIPT"}));
                let _ = save_final(&connection, &occurrence_id, "BLOCKED", &receipt);
                return receipt;
            }
            if std::env::var_os("AUTOFDE_INJECT_UNCERTAIN_AFTER_DO").is_some() {
                if let Err(error) = connection.execute(
                    "UPDATE occurrences SET state = 'UNKNOWN_RECONCILIATION' WHERE occurrence_id = ?1",
                    params![occurrence_id],
                ) {
                    return build_broken("UNCERTAIN_PERSIST", error.to_string());
                }
                return blocked(
                    "UNKNOWN_RECONCILIATION",
                    "consequence may have occurred; automatic retry is forbidden",
                );
            }
            let observed_digest = match verify_consequence(paths, &bundle.verifier) {
                Ok(value) => value,
                Err(error) => {
                    let receipt = receipt_with_digest(json!({
                        "schema": "autofde.process-receipt/1",
                        "occurrence_id": occurrence_id,
                        "bundle_digest": bundle.bundle_digest,
                        "authority_digest": authority.authority_digest,
                        "pre_actuation_digest": pre_digest,
                        "standing": "REFUSED:POSTCONDITION",
                        "verification_error": error
                    }))
                    .unwrap_or_else(|_| json!({"standing":"BUILD_BROKEN","reason":"RECEIPT"}));
                    let _ = save_final(&connection, &occurrence_id, "REFUSED:POSTCONDITION", &receipt);
                    return receipt;
                }
            };
            let receipt = match receipt_with_digest(json!({
                "schema": "autofde.process-receipt/1",
                "occurrence_id": occurrence_id,
                "bundle_digest": bundle.bundle_digest,
                "authority_digest": authority.authority_digest,
                "pre_actuation_digest": pre_digest,
                "brce": "FILESYSTEM_WRITE",
                "independent_observation_digest": observed_digest,
                "verification": "PASS",
                "standing": "ALIVE"
            })) {
                Ok(value) => value,
                Err(error) => return build_broken("RECEIPT", error),
            };
            if let Err(error) = save_final(&connection, &occurrence_id, "ALIVE", &receipt) {
                return build_broken("RECEIPT_PERSIST", error);
            }
            receipt
        }
    }
}

pub fn occurrence_show(id: &str) -> Value {
    occurrence_show_with_paths(&RuntimePaths::from_env(), id)
}

fn occurrence_show_with_paths(paths: &RuntimePaths, id: &str) -> Value {
    let connection = match open_db(paths) {
        Ok(value) => value,
        Err(error) => return build_broken("OCCURRENCE_STORE", error),
    };
    let row: Option<(String, String, String, String, Option<String>)> = match connection
        .query_row(
            "SELECT bundle_digest, observation_json, authority_json, state, receipt_json FROM occurrences WHERE occurrence_id = ?1",
            params![id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .optional()
    {
        Ok(value) => value,
        Err(error) => return build_broken("OCCURRENCE_LOOKUP", error.to_string()),
    };
    match row {
        None => refused("OCCURRENCE_UNKNOWN", id),
        Some((bundle_digest, observation, authority, state, receipt)) => json!({
            "standing": state,
            "occurrence_id": id,
            "bundle_digest": bundle_digest,
            "observation": serde_json::from_str::<Value>(&observation).unwrap_or(Value::Null),
            "authority": serde_json::from_str::<Value>(&authority).unwrap_or(Value::Null),
            "receipt": receipt.and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        }),
    }
}

pub fn occurrence_reconcile(id: &str) -> Value {
    reconcile_with_paths(&RuntimePaths::from_env(), id)
}

fn reconcile_with_paths(paths: &RuntimePaths, id: &str) -> Value {
    let connection = match open_db(paths) {
        Ok(value) => value,
        Err(error) => return build_broken("OCCURRENCE_STORE", error),
    };
    let row: Option<(String, String, String, String)> = match connection
        .query_row(
            "SELECT bundle_digest, authority_json, state, pre_digest FROM occurrences WHERE occurrence_id = ?1",
            params![id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
    {
        Ok(value) => value,
        Err(error) => return build_broken("OCCURRENCE_LOOKUP", error.to_string()),
    };
    let Some((bundle_digest, authority_json, state, pre_digest)) = row else {
        return refused("OCCURRENCE_UNKNOWN", id);
    };
    if state != "UNKNOWN_RECONCILIATION" {
        return occurrence_show_with_paths(paths, id);
    }
    let bundle = match load_installed(paths, &bundle_digest) {
        Ok(value) => value,
        Err(error) => return blocked("RECONCILIATION_BUNDLE", error),
    };
    let authority: AuthorityEnvelope = match serde_json::from_str(&authority_json) {
        Ok(value) => value,
        Err(error) => return build_broken("RECONCILIATION_AUTHORITY", error.to_string()),
    };
    if let Err(error) = authority.verify_for(&bundle) {
        return refused("AUTHORITY_DENIED", error);
    }
    let observed_digest = match verify_consequence(paths, &bundle.verifier) {
        Ok(value) => value,
        Err(error) => return blocked("RECONCILIATION_OBSERVATION", error),
    };
    let receipt = match receipt_with_digest(json!({
        "schema": "autofde.process-receipt/1",
        "occurrence_id": id,
        "bundle_digest": bundle_digest,
        "authority_digest": authority.authority_digest,
        "pre_actuation_digest": pre_digest,
        "reconciled": true,
        "automatic_retry": false,
        "independent_observation_digest": observed_digest,
        "verification": "PASS",
        "standing": "ALIVE"
    })) {
        Ok(value) => value,
        Err(error) => return build_broken("RECEIPT", error),
    };
    if let Err(error) = save_final(&connection, id, "ALIVE", &receipt) {
        return build_broken("RECEIPT_PERSIST", error);
    }
    receipt
}

pub fn replay_run(id: &str) -> Value {
    let shown = occurrence_show(id);
    let Some(receipt) = shown.get("receipt").filter(|v| !v.is_null()).cloned() else {
        return blocked("REPLAY_RECEIPT_MISSING", id);
    };
    let Some(expected) = receipt.get("receipt_digest").and_then(Value::as_str) else {
        return refused("REPLAY_DIVERGENCE", "receipt digest missing");
    };
    let mut subject = receipt.clone();
    if let Some(object) = subject.as_object_mut() {
        object.remove("receipt_digest");
    }
    match digest_json(&subject) {
        Ok(actual) if actual == expected => json!({
            "standing": "ALIVE",
            "replay": "REPLAY_MATCH",
            "occurrence_id": id,
            "receipt_digest": expected
        }),
        Ok(actual) => refused("REPLAY_DIVERGENCE", format!("expected={expected} actual={actual}")),
        Err(error) => build_broken("REPLAY", error),
    }
}

pub fn evidence_ocel(id: &str) -> Value {
    let shown = occurrence_show(id);
    if shown.get("occurrence_id").is_none() {
        return shown;
    }
    let state = shown
        .get("standing")
        .and_then(Value::as_str)
        .unwrap_or("UNKNOWN");
    let bundle = shown
        .get("bundle_digest")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    json!({
        "objectTypes": [
            {"name":"occurrence","attributes":[]},
            {"name":"capability_bundle","attributes":[]}
        ],
        "eventTypes": [
            {"name":"runtime_occurrence","attributes":[{"name":"standing","type":"string"}]}
        ],
        "objects": [
            {"id": id, "type":"occurrence", "attributes":[], "relationships":[{"objectId":bundle,"qualifier":"uses"}]},
            {"id": bundle, "type":"capability_bundle", "attributes":[], "relationships":[]}
        ],
        "events": [
            {"id": format!("event:{id}"), "type":"runtime_occurrence", "time":"1970-01-01T00:00:00Z", "attributes":[{"name":"standing","value":state}], "relationships":[{"objectId":id,"qualifier":"subject"},{"objectId":bundle,"qualifier":"bundle"}]}
        ]
    })
}

pub fn novelty_show(id: &str) -> Value {
    let path = RuntimePaths::from_env().novelty().join(format!("{id}.json"));
    match fs::read(&path)
        .map_err(|error| format!("NOVELTY_READ:{error}"))
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).map_err(|error| format!("NOVELTY_JSON:{error}")))
    {
        Ok(value) => value,
        Err(error) => refused("NOVELTY_UNKNOWN", error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_bundle() -> CapabilityBundle {
        let content = "compiled consequence".to_string();
        let mut bundle = CapabilityBundle {
            schema: BUNDLE_SCHEMA.into(),
            runtime_abi: RUNTIME_ABI.into(),
            bundle_digest: String::new(),
            capability: "fixture.write".into(),
            lab_revision: "1111111111111111111111111111111111111111".into(),
            ggen_revision: "2222222222222222222222222222222222222222".into(),
            match_all: BTreeMap::from([("kind".into(), "fixture".into())]),
            effect: "filesystem.write".into(),
            program: CompiledProgram::FilesystemWrite {
                path: "allowed/result.txt".into(),
                content: content.clone(),
            },
            verifier: VerifierContract::FileBlake3 {
                path: "allowed/result.txt".into(),
                digest: digest_bytes(content.as_bytes()),
            },
        };
        bundle.bundle_digest = bundle.expected_digest().unwrap();
        bundle
    }

    fn make_authority(bundle: &CapabilityBundle) -> AuthorityEnvelope {
        let mut authority = AuthorityEnvelope {
            schema: AUTHORITY_SCHEMA.into(),
            authority_digest: String::new(),
            bundle_digest: bundle.bundle_digest.clone(),
            allowed_effects: vec!["filesystem.write".into()],
            resource_prefixes: vec!["allowed/".into()],
            valid_until_unix: 0,
        };
        authority.authority_digest = authority.expected_digest().unwrap();
        authority
    }

    #[test]
    fn exact_bundle_authority_brce_verification_and_idempotent_replay_close() {
        let temp = TempDir::new().unwrap();
        let paths = RuntimePaths {
            state: temp.path().join("state"),
            world: temp.path().join("world"),
        };
        fs::create_dir_all(paths.bundles()).unwrap();
        let bundle = make_bundle();
        bundle.verify().unwrap();
        fs::write(
            paths.bundles().join(format!("{}.json", bundle.bundle_digest)),
            serde_json::to_vec_pretty(&bundle).unwrap(),
        )
        .unwrap();
        let observation = ObservationEnvelope {
            schema: OBSERVATION_SCHEMA.into(),
            facts: BTreeMap::from([("kind".into(), "fixture".into())]),
        };
        let authority = make_authority(&bundle);
        let observation_path = temp.path().join("observation.json");
        let authority_path = temp.path().join("authority.json");
        fs::write(&observation_path, serde_json::to_vec(&observation).unwrap()).unwrap();
        fs::write(&authority_path, serde_json::to_vec(&authority).unwrap()).unwrap();

        let first = execute_with_paths(
            &paths,
            observation_path.to_str().unwrap(),
            authority_path.to_str().unwrap(),
        );
        assert_eq!(first["standing"], "ALIVE");
        assert_eq!(fs::read_to_string(paths.world.join("allowed/result.txt")).unwrap(), "compiled consequence");

        let second = execute_with_paths(
            &paths,
            observation_path.to_str().unwrap(),
            authority_path.to_str().unwrap(),
        );
        assert_eq!(second["standing"], "ALIVE");
        assert_eq!(second["replayed"], true);
    }

    #[test]
    fn bundle_mutation_and_authority_scope_fail_closed() {
        let mut bundle = make_bundle();
        bundle.capability = "tampered".into();
        assert_eq!(bundle.verify().unwrap_err(), "BUNDLE_DIGEST_MISMATCH");

        let bundle = make_bundle();
        let mut authority = make_authority(&bundle);
        authority.resource_prefixes = vec!["other/".into()];
        authority.authority_digest = authority.expected_digest().unwrap();
        assert_eq!(authority.verify_for(&bundle).unwrap_err(), "AUTHORITY_RESOURCE_SCOPE");
    }
}
