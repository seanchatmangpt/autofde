use std::process;

fn main() {
    match autofde::run() {
        Ok(()) => process::exit(0),
        Err(error) => {
            eprintln!("ERROR: {error}");
            process::exit(1);
        }
    }
}
