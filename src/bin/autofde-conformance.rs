use autofde::{check, load_constitution, load_ocel};
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(model_path) = args.next() else {
        eprintln!("usage: autofde-conformance <process-model.json> <episode.ocel.json>");
        return ExitCode::from(64);
    };
    let Some(log_path) = args.next() else {
        eprintln!("usage: autofde-conformance <process-model.json> <episode.ocel.json>");
        return ExitCode::from(64);
    };
    if args.next().is_some() {
        eprintln!("usage: autofde-conformance <process-model.json> <episode.ocel.json>");
        return ExitCode::from(64);
    }

    let model = match load_constitution(&model_path) {
        Ok(model) => model,
        Err(error) => {
            eprintln!("REFUSED:MODEL_INVALID:{error}");
            return ExitCode::from(2);
        }
    };
    let log = match load_ocel(&log_path) {
        Ok(log) => log,
        Err(error) => {
            eprintln!("REFUSED:OCEL_INVALID:{error}");
            return ExitCode::from(2);
        }
    };
    let report = check(&model, &log);
    if report.conforms {
        println!("ALIVE:CONFORMANT:{}", report.constitution_schema);
        ExitCode::SUCCESS
    } else {
        println!("REFUSED:NON_CONFORMANT:{}", report.constitution_schema);
        for violation in report.violations {
            println!("{violation}");
        }
        ExitCode::from(3)
    }
}
