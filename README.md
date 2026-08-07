# AutoFDE

**AutoFDE is the Forward Deployment Operating System.**

This repository contains the canonical ontology and ggen generation contract for the product system that compiles admitted enterprise intent into a governed delivery system, executable capability, bounded operation, evidence, and replay.

## EXPLOIT-only boundary

AutoFDE does not search an unbounded design space in this repository. It consumes exact, admitted semantic sources, requirements, policies, capability bundles, and authority; deterministically selects from those bounded inputs; constructs projections; and actuates only through BRCE.

```text
O → O* → C → I → Ia → A → R
```

- Raw observations have no execution authority.
- Knowledge Hooks may observe, enrich, and route; they never actuate.
- SELECT, CONSTRUCT, and DO are separate authority classes.
- `A = μ(O*)`; `R = receipt(A)`.
- GitHub, POWL, Terraform, SDKs, and reports are projections of the admitted AutoFDE graph.

## Canonical source surfaces

| Surface | Role |
|---|---|
| `ontology/autofde.ttl` + `ontology/*.ttl` source bundle | Product ontology, capability calculus, authority, evidence, lifecycle, and generator vocabulary |
| `ontology/shapes.ttl` | SHACL admission law |
| `ontology/bootstrap-to-breach.ttl` | Canonical product instance from semantic foundation through governed breach response |
| `ggen.toml` | Deterministic generation rules |
| `queries/gates/*.rq` | Law falsifiers; every query must return `false` for an admitted graph |
| `templates/*.tera` | Generator-owned projections |
| `generated/` | Reproducible outputs; edit the graph or template instead |

## Product modules

- **AutoFDE Core** — admission, orchestration, authority, BRCE, receipts, replay, standing.
- **AutoFDE Forge** — ontology-to-artifact manufacture through ggen.
- **AutoFDE Workflow** — proof-carrying workflow and execution-model evidence.
- **AutoFDE Process** — process mining, OCEL, conformance, and portable runtime bindings.
- **AutoFDE Process Language** — POWL work semantics.
- **AutoFDE Code Intelligence** — protocol-aware code observation and verification.
- **AutoFDE Models** — visual and semantic model projections.
- **AutoFDE Foundation Graph** — admitted graph substrate.
- **AutoFDE Manufacture** — the lawful manufacturing operator μ.

Existing repository and package coordinates remain compatibility identities until dependency-closed migration receipts authorize replacement.

## Generate and validate

```bash
make generate-reference
make verify
make crown-ontology
```

With ggen v26.8.6 or a compatible release installed:

```bash
ggen sync run --config ggen.toml
git diff --exit-code -- generated
```

The local reference renderer is a validation transport for the same RDF/SPARQL/Tera surfaces; ggen remains the production generator.
