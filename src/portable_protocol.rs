//! Replaceable implementation of the portable consequence admission relation.
//!
//! This module owns no authority and performs no actuation. A caller must supply
//! an external authority decision bound to the exact consequence plus a receipt
//! capability that exists before DO.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Consequence<'a> { pub digest: &'a str }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorityDecision<'a> {
    pub decision_id: &'a str,
    pub allowed: bool,
    pub consequence_digest: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptCapability<'a> {
    pub available: bool,
    pub digest_algorithm: &'a str,
    pub replay_scheme: &'a str,
}

pub fn admit_portable_consequence(consequence: Consequence<'_>, authority: Option<AuthorityDecision<'_>>, receipt: ReceiptCapability<'_>) -> Result<(), &'static str> {
    if consequence.digest.is_empty() { return Err("REFUSED:CONSEQUENCE_IDENTITY_REQUIRED"); }
    let authority = authority.ok_or("REFUSED:AUTHORITY_REQUIRED")?;
    if !authority.allowed || authority.decision_id.is_empty() { return Err("REFUSED:AUTHORITY_DENIED"); }
    if authority.consequence_digest != consequence.digest { return Err("REFUSED:AUTHORITY_SCOPE_MISMATCH"); }
    if !receipt.available { return Err("REFUSED:RECEIPT_CAPABILITY_REQUIRED"); }
    if receipt.digest_algorithm.is_empty() || receipt.replay_scheme.is_empty() { return Err("REFUSED:RECEIPT_CAPABILITY_INCOMPLETE"); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn receipt(available: bool) -> ReceiptCapability<'static> { ReceiptCapability { available, digest_algorithm: "sha-256", replay_scheme: "hash-chain" } }
    #[test] fn external_exact_authority_admits() {
        assert_eq!(admit_portable_consequence(Consequence { digest: "d" },Some(AuthorityDecision { decision_id: "a", allowed: true, consequence_digest: "d" }),receipt(true)),Ok(()));
    }
    #[test] fn runtime_has_no_ambient_authority() {
        assert_eq!(admit_portable_consequence(Consequence { digest: "d" },None,receipt(true)),Err("REFUSED:AUTHORITY_REQUIRED"));
    }
    #[test] fn authority_for_another_consequence_is_refused() {
        assert_eq!(admit_portable_consequence(Consequence { digest: "d" },Some(AuthorityDecision { decision_id: "a", allowed: true, consequence_digest: "other" }),receipt(true)),Err("REFUSED:AUTHORITY_SCOPE_MISMATCH"));
    }
    #[test] fn unreceiptable_do_is_refused_before_actuation() {
        assert_eq!(admit_portable_consequence(Consequence { digest: "d" },Some(AuthorityDecision { decision_id: "a", allowed: true, consequence_digest: "d" }),receipt(false)),Err("REFUSED:RECEIPT_CAPABILITY_REQUIRED"));
    }
}
