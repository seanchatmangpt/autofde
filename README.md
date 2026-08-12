# AutoFDE

AutoFDE is the EXPLOIT-only production/runtime surface for admitted forward-deployment capabilities.

The repository deliberately separates observation, construction, authority, consequence, verification, and replay. Planner/model output and Knowledge Hooks do not receive ambient execution authority; consequential work must cross the receipt-bearing BRCE boundary.

## Canonical source and projections

- `ontology/autofde.ttl` plus `ontology/source-bundle.txt` are the canonical product ontology capsule.
- `ontology/bootstrap-to-breach.ttl` is the canonical executable case instance.
- `ontology/shapes.ttl` carries admission constraints.
- `ggen.toml` is the generation manifest.
- `generated/` contains projections and must not be hand-edited.

## Production runtime boundaries

The Python runtime under `src/autofde/` owns the persistent occurrence/WAL boundary, capability pins, authority envelopes, BRCE consequence execution, independent verification, OCEL/process evidence, replay, Azure sensing, and provider adapters that have been admitted into this repository.

`autofde-lab` is not an ambient production dependency. It is an exploration, planning, falsification, and capability-admission source. `ggen` deterministically manufactures admitted projections; manufacturing provenance does not itself confer production authority.

## Validation

The canonical local crown is:

```bash
make crown-ontology
```

It now includes the executable vacuity refusal court in addition to deterministic reference generation, ontology verification, and the complete Python test suite. The direct static gate is:

```bash
make vacuity
```

That court rejects concrete pass/ellipsis/NotImplemented bodies, constant verifier implementations, self-asserted ALIVE/PARTIAL_ALIVE returns, tautological tests, Rust `todo!`/`unimplemented!`, explicit not-implemented panics/exceptions across supported source languages, and Lean `sorry`/`admit`. Protocol/ABC declarations and empty exception types are intentionally not treated as implementations.

The exact-head GitHub court also fetches every branch and inventories every tracked executable source file. Historical branch findings are evidence about those historical subjects; they are not silently rewritten or promoted into current standing.

## Azure authority

Repository code may validate, sense, simulate local HTTP protocol behavior, and construct non-consequential artifacts without live Azure authority. Creating, changing, closing, or destroying real Azure resources requires explicit live authority and a named allowlisted test subscription. Presence of credentials or Terraform/OpenTofu alone is readiness, not `ALIVE` standing.
