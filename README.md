# AutoFDE

AutoFDE is the Rust production/runtime side of the AutoFDE system. `autofde-lab` proves concepts in Python; production capabilities cross into this repository only through an admitted promotion contract and are then independently implemented and verified here.

## Process Constitution v1

The first v26.8.7 Gall checkpoint makes the lab-to-production lifecycle executable:

`LabProved -> PromotionAdmitted -> BundleManufactured -> BundlePinned -> SessionStarted -> POWLCommitted -> AuthorityAdmitted -> ActuationOpened -> ActuationClosed -> PostconditionVerified -> ReceiptEmitted -> ReplayCompleted`

The Rust conformance kernel checks an observed OCEL episode against the admitted lifecycle and enforces additional product laws: planning/lab evidence cannot become bearer authority, DO must cross BRCE, postconditions cannot self-certify, capability bundles must be digest pinned, receipts must bind observed consequences, and replay must bind a source receipt.

Run the crown:

```bash
just crown
```

or directly:

```bash
cargo test
cargo run --bin autofde-conformance -- process/autofde-lifecycle.powl.json fixtures/autofde-lifecycle/valid.ocel.json
```

This checkpoint proves process-language conformance only. It does not claim Azure integration, Terraform execution, Sentinel ingress, Logic App wiring, or cloud actuation standing.
