use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Triple {
    pub subject: String,
    pub predicate: String,
    pub object: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RdfDelta {
    pub stream_id: String,
    pub sequence: u64,
    pub prior_digest: Option<String>,
    #[serde(default)]
    pub additions: Vec<Triple>,
    #[serde(default)]
    pub removals: Vec<Triple>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookIntent {
    pub intent_id: String,
    pub stream_id: String,
    pub sequence: u64,
    pub source_digest: String,
    pub authority_class: String,
    pub operation: String,
    pub do_authority: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookReceipt {
    pub digest: String,
    pub intent: HookIntent,
    pub replayed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookRefusal {
    InvalidDelta(String),
    SequenceGap { expected: u64, observed: u64 },
    PriorDigestMismatch,
    ConflictingReplay,
    LedgerCorruption(String),
    Storage(String),
}

impl HookRefusal {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidDelta(_) => "REFUSED_RDFDELTA_INVALID",
            Self::SequenceGap { .. } => "REFUSED_RDFDELTA_SEQUENCE",
            Self::PriorDigestMismatch => "REFUSED_RDFDELTA_CHAIN",
            Self::ConflictingReplay => "REFUSED_RDFDELTA_CONFLICT",
            Self::LedgerCorruption(_) => "REFUSED_RDFDELTA_LEDGER_CORRUPT",
            Self::Storage(_) => "BLOCKED_RDFDELTA_STORAGE",
        }
    }
}

impl fmt::Display for HookRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDelta(reason) => write!(f, "{}: {reason}", self.code()),
            Self::SequenceGap { expected, observed } => write!(
                f,
                "{}: expected sequence {expected}, observed {observed}",
                self.code()
            ),
            Self::PriorDigestMismatch => write!(f, "{}: prior digest mismatch", self.code()),
            Self::ConflictingReplay => write!(f, "{}: sequence replay changed bytes", self.code()),
            Self::LedgerCorruption(reason) => write!(f, "{}: {reason}", self.code()),
            Self::Storage(reason) => write!(f, "{}: {reason}", self.code()),
        }
    }
}

impl std::error::Error for HookRefusal {}

pub struct KnowledgeHookLedger {
    conn: Connection,
}

impl KnowledgeHookLedger {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, HookRefusal> {
        let conn = Connection::open(path).map_err(storage)?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(storage)?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(storage)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS knowledge_hook_delta (
                stream_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                digest TEXT NOT NULL,
                prior_digest TEXT,
                canonical_json TEXT NOT NULL,
                intent_id TEXT NOT NULL,
                authority_class TEXT NOT NULL CHECK(authority_class = 'CONSTRUCT'),
                do_authority INTEGER NOT NULL CHECK(do_authority = 0),
                PRIMARY KEY(stream_id, sequence),
                UNIQUE(digest)
            );",
        )
        .map_err(storage)?;
        Ok(Self { conn })
    }

    pub fn journal_mode(&self) -> Result<String, HookRefusal> {
        self.conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .map_err(storage)
    }

    pub fn admit(&mut self, delta: RdfDelta) -> Result<HookReceipt, HookRefusal> {
        let canonical = canonicalize(&delta)?;
        let digest = blake3::hash(canonical.as_bytes()).to_hex().to_string();
        let intent_id = blake3::hash(format!("autofde:knowledge-hook:{digest}").as_bytes())
            .to_hex()
            .to_string();

        let tx = self.conn.transaction().map_err(storage)?;
        let existing: Option<(String, String)> = tx
            .query_row(
                "SELECT digest, intent_id FROM knowledge_hook_delta WHERE stream_id = ?1 AND sequence = ?2",
                params![delta.stream_id, delta.sequence],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(storage)?;

        if let Some((existing_digest, existing_intent)) = existing {
            if existing_digest != digest || existing_intent != intent_id {
                return Err(HookRefusal::ConflictingReplay);
            }
            return Ok(HookReceipt {
                digest: existing_digest,
                intent: intent(&delta, existing_intent, digest),
                replayed: true,
            });
        }

        let latest: Option<(u64, String)> = tx
            .query_row(
                "SELECT sequence, digest FROM knowledge_hook_delta WHERE stream_id = ?1 ORDER BY sequence DESC LIMIT 1",
                params![delta.stream_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(storage)?;

        match latest {
            None => {
                if delta.sequence != 1 {
                    return Err(HookRefusal::SequenceGap {
                        expected: 1,
                        observed: delta.sequence,
                    });
                }
                if delta.prior_digest.is_some() {
                    return Err(HookRefusal::PriorDigestMismatch);
                }
            }
            Some((latest_sequence, latest_digest)) => {
                let expected = latest_sequence + 1;
                if delta.sequence != expected {
                    return Err(HookRefusal::SequenceGap {
                        expected,
                        observed: delta.sequence,
                    });
                }
                if delta.prior_digest.as_deref() != Some(latest_digest.as_str()) {
                    return Err(HookRefusal::PriorDigestMismatch);
                }
            }
        }

        tx.execute(
            "INSERT INTO knowledge_hook_delta
             (stream_id, sequence, digest, prior_digest, canonical_json, intent_id, authority_class, do_authority)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'CONSTRUCT', 0)",
            params![
                delta.stream_id,
                delta.sequence,
                digest,
                delta.prior_digest,
                canonical,
                intent_id
            ],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)?;

        Ok(HookReceipt {
            digest: digest.clone(),
            intent: intent(&delta, intent_id, digest),
            replayed: false,
        })
    }

    pub fn verify_stream(&self, stream_id: &str) -> Result<usize, HookRefusal> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT sequence, digest, prior_digest, canonical_json, authority_class, do_authority
                 FROM knowledge_hook_delta WHERE stream_id = ?1 ORDER BY sequence ASC",
            )
            .map_err(storage)?;
        let rows = statement
            .query_map(params![stream_id], |row| {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })
            .map_err(storage)?;

        let mut prior: Option<String> = None;
        let mut count = 0_usize;
        for (expected_sequence, row) in (1_u64..).zip(rows) {
            let (sequence, digest, observed_prior, canonical, authority_class, do_authority) =
                row.map_err(storage)?;
            if sequence != expected_sequence {
                return Err(HookRefusal::LedgerCorruption(format!(
                    "expected sequence {expected_sequence}, observed {sequence}"
                )));
            }
            if observed_prior != prior {
                return Err(HookRefusal::LedgerCorruption(
                    "stored prior digest chain diverged".into(),
                ));
            }
            let recomputed = blake3::hash(canonical.as_bytes()).to_hex().to_string();
            if recomputed != digest {
                return Err(HookRefusal::LedgerCorruption(
                    "canonical payload digest diverged".into(),
                ));
            }
            if authority_class != "CONSTRUCT" || do_authority != 0 {
                return Err(HookRefusal::LedgerCorruption(
                    "knowledge hook acquired DO authority".into(),
                ));
            }
            prior = Some(digest);
            count += 1;
        }
        Ok(count)
    }
}

fn canonicalize(delta: &RdfDelta) -> Result<String, HookRefusal> {
    if delta.stream_id.trim().is_empty() {
        return Err(HookRefusal::InvalidDelta("stream_id is empty".into()));
    }
    if delta.sequence == 0 {
        return Err(HookRefusal::InvalidDelta("sequence must start at 1".into()));
    }
    if delta.additions.is_empty() && delta.removals.is_empty() {
        return Err(HookRefusal::InvalidDelta("delta has no changes".into()));
    }

    let additions = normalize(&delta.additions)?;
    let removals = normalize(&delta.removals)?;
    if additions.iter().any(|triple| removals.contains(triple)) {
        return Err(HookRefusal::InvalidDelta(
            "same triple appears in additions and removals".into(),
        ));
    }

    #[derive(Serialize)]
    struct Canonical<'a> {
        stream_id: &'a str,
        sequence: u64,
        prior_digest: &'a Option<String>,
        additions: Vec<&'a Triple>,
        removals: Vec<&'a Triple>,
    }

    serde_json::to_string(&Canonical {
        stream_id: &delta.stream_id,
        sequence: delta.sequence,
        prior_digest: &delta.prior_digest,
        additions: additions.into_iter().collect(),
        removals: removals.into_iter().collect(),
    })
    .map_err(|error| HookRefusal::InvalidDelta(error.to_string()))
}

fn normalize(triples: &[Triple]) -> Result<BTreeSet<&Triple>, HookRefusal> {
    let mut normalized = BTreeSet::new();
    for triple in triples {
        if triple.subject.trim().is_empty()
            || triple.predicate.trim().is_empty()
            || triple.object.trim().is_empty()
        {
            return Err(HookRefusal::InvalidDelta(
                "triple terms must be non-empty".into(),
            ));
        }
        if !normalized.insert(triple) {
            return Err(HookRefusal::InvalidDelta(
                "duplicate triple in one delta side".into(),
            ));
        }
    }
    Ok(normalized)
}

fn intent(delta: &RdfDelta, intent_id: String, source_digest: String) -> HookIntent {
    HookIntent {
        intent_id,
        stream_id: delta.stream_id.clone(),
        sequence: delta.sequence,
        source_digest,
        authority_class: "CONSTRUCT".into(),
        operation: "knowledge_hook.rdfdelta_intake".into(),
        do_authority: false,
    }
}

fn storage(error: rusqlite::Error) -> HookRefusal {
    HookRefusal::Storage(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn triple(object: &str) -> Triple {
        Triple {
            subject: "urn:incident:42".into(),
            predicate: "urn:autofde:status".into(),
            object: object.into(),
        }
    }

    fn first() -> RdfDelta {
        RdfDelta {
            stream_id: "azure-sentinel/incidents".into(),
            sequence: 1,
            prior_digest: None,
            additions: vec![triple("open")],
            removals: vec![],
        }
    }

    #[test]
    fn durable_chain_manufactures_construct_only_intent_and_replays_idempotently() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("hooks.db");
        let mut ledger = KnowledgeHookLedger::open(&path).unwrap();
        assert_eq!(ledger.journal_mode().unwrap().to_ascii_lowercase(), "wal");

        let first_receipt = ledger.admit(first()).unwrap();
        assert!(!first_receipt.replayed);
        assert_eq!(first_receipt.intent.authority_class, "CONSTRUCT");
        assert!(!first_receipt.intent.do_authority);

        let replay = ledger.admit(first()).unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.digest, first_receipt.digest);
        assert_eq!(replay.intent.intent_id, first_receipt.intent.intent_id);

        let second = RdfDelta {
            stream_id: "azure-sentinel/incidents".into(),
            sequence: 2,
            prior_digest: Some(first_receipt.digest),
            additions: vec![triple("triaged")],
            removals: vec![triple("open")],
        };
        ledger.admit(second).unwrap();
        assert_eq!(ledger.verify_stream("azure-sentinel/incidents").unwrap(), 2);

        drop(ledger);
        let reopened = KnowledgeHookLedger::open(&path).unwrap();
        assert_eq!(
            reopened.verify_stream("azure-sentinel/incidents").unwrap(),
            2
        );
    }

    #[test]
    fn refuses_sequence_gap_and_bad_prior_without_mutating_ledger() {
        let dir = tempdir().unwrap();
        let mut ledger = KnowledgeHookLedger::open(dir.path().join("hooks.db")).unwrap();

        let mut gap = first();
        gap.sequence = 2;
        assert!(matches!(
            ledger.admit(gap),
            Err(HookRefusal::SequenceGap {
                expected: 1,
                observed: 2
            })
        ));
        assert_eq!(ledger.verify_stream("azure-sentinel/incidents").unwrap(), 0);

        let receipt = ledger.admit(first()).unwrap();
        let bad = RdfDelta {
            stream_id: "azure-sentinel/incidents".into(),
            sequence: 2,
            prior_digest: Some(format!("{}x", receipt.digest)),
            additions: vec![triple("triaged")],
            removals: vec![triple("open")],
        };
        assert_eq!(
            ledger.admit(bad).unwrap_err().code(),
            "REFUSED_RDFDELTA_CHAIN"
        );
        assert_eq!(ledger.verify_stream("azure-sentinel/incidents").unwrap(), 1);
    }

    #[test]
    fn refuses_conflicting_replay_and_contradictory_delta() {
        let dir = tempdir().unwrap();
        let mut ledger = KnowledgeHookLedger::open(dir.path().join("hooks.db")).unwrap();
        ledger.admit(first()).unwrap();

        let mut conflict = first();
        conflict.additions = vec![triple("closed")];
        assert_eq!(
            ledger.admit(conflict).unwrap_err().code(),
            "REFUSED_RDFDELTA_CONFLICT"
        );

        let contradictory = RdfDelta {
            stream_id: "azure-sentinel/incidents-2".into(),
            sequence: 1,
            prior_digest: None,
            additions: vec![triple("open")],
            removals: vec![triple("open")],
        };
        assert_eq!(
            ledger.admit(contradictory).unwrap_err().code(),
            "REFUSED_RDFDELTA_INVALID"
        );
    }

    #[test]
    fn adversarial_tamper_cannot_retain_verified_standing() {
        let dir = tempdir().unwrap();
        let mut ledger = KnowledgeHookLedger::open(dir.path().join("hooks.db")).unwrap();
        ledger.admit(first()).unwrap();
        ledger
            .conn
            .execute(
                "UPDATE knowledge_hook_delta SET do_authority = 1 WHERE stream_id = ?1",
                params!["azure-sentinel/incidents"],
            )
            .unwrap_err();

        ledger
            .conn
            .execute(
                "UPDATE knowledge_hook_delta SET canonical_json = 'tampered' WHERE stream_id = ?1",
                params!["azure-sentinel/incidents"],
            )
            .unwrap();
        assert_eq!(
            ledger
                .verify_stream("azure-sentinel/incidents")
                .unwrap_err()
                .code(),
            "REFUSED_RDFDELTA_LEDGER_CORRUPT"
        );
    }
}
