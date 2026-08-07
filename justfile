set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

default:
    @just --list

fmt:
    cargo fmt --all -- --check

check:
    cargo check

test:
    cargo test

clippy:
    cargo clippy --all-targets -- -D warnings

conformance:
    cargo run --quiet --bin autofde-conformance -- process/autofde-lifecycle.powl.json fixtures/autofde-lifecycle/valid.ocel.json

crown: fmt check test clippy conformance
    @echo "ALIVE: AutoFDE Process Constitution v1 crown passed"
