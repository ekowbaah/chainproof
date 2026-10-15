use chainproof::{digest, verify_file};
fn main() {
    let a: Vec<_> = std::env::args().collect();
    match a.as_slice() {
        [_, path] => match std::fs::read(path) {
            Ok(b) => println!("{}  {}", digest(&b), path),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(2)
            }
        },
        [_, path, expected] => match verify_file(path, expected) {
            Ok(true) => println!("verified"),
            Ok(false) => {
                eprintln!("digest mismatch");
                std::process::exit(1)
            }
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(2)
            }
        },
        _ => {
            eprintln!("usage: chainproof <artifact> [expected-digest]");
            std::process::exit(2)
        }
    }
}
