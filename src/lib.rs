use clap_noun_verb::Result;

mod clap_noun_verb_routes;
pub mod runtime;
pub mod verbs;

pub fn run() -> Result<()> {
    clap_noun_verb::run()
}
