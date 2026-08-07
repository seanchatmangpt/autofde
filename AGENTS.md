# AutoFDE repository law

This repository is the EXPLOIT-only product surface for AutoFDE.

## Canonical source

- `ontology/autofde.ttl` plus the ordered modules in `ontology/source-bundle.txt` are the canonical product ontology capsule.
- `ontology/bootstrap-to-breach.ttl` is the canonical executable case instance.
- `ontology/shapes.ttl` is the admission contract.
- Files under `generated/` are projections. Never hand-edit them.
- `ggen.toml` is the only generation manifest.

## Authority

SELECT, CONSTRUCT, and DO are distinct. BRCE is the exclusive DO path. Knowledge Hooks manufacture intents and never actuate. Every actuation requires an admitted authority intersection and a pre-actuation receipt.

## Mode

AutoFDE consumes admitted inputs and manufactures bounded consequences. This repository has one execution mode: `autofde:ExploitOnly`.

## Validation

Run `make crown-ontology`. A change is not ALIVE until parsing, law gates, deterministic projection, generated-drift, and falsifier tests pass.
