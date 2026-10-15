use chainproof::{digest, inspect_sbom, verify_file};
fn main() {
    let a: Vec<_> = std::env::args().collect();
    match a.as_slice() {
        [_, command, path] if command == "sbom" => match std::fs::read(path)
            .map_err(|error| error.to_string())
            .and_then(|bytes| inspect_sbom(&bytes).map_err(|error| format!("{error:?}")))
        {
            Ok(summary) => println!(
                "format={:?} components={} name={}",
                summary.format,
                summary.component_count,
                summary.document_name.as_deref().unwrap_or("unknown")
            ),
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1)
            }
        },
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
            eprintln!("usage: chainproof <artifact> [expected-sha256] | chainproof sbom <file>");
            std::process::exit(2)
        }
    }
}
