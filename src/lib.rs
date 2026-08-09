use clap_noun_verb::Result;

mod clap_noun_verb_routes;
pub mod knowledge_hook;
pub mod runtime;
pub mod sentinel_ingress;
pub mod verbs;

pub fn run() -> Result<()> {
    clap_noun_verb::run()
}
