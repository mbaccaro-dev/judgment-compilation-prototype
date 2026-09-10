use std::io::{self, Read};

const MAX_REQUEST_BYTES: u64 = 16 * 1024 * 1024;

fn read_request() -> Result<String, String> {
    let mut raw = Vec::new();
    io::stdin()
        .lock()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    if raw.len() as u64 > MAX_REQUEST_BYTES {
        return Err("native request size".into());
    }
    String::from_utf8(raw).map_err(|e| e.to_string())
}

fn main() {
    let result = read_request().and_then(|raw| judgment_kernel::run_json(&raw));
    match result {
        Ok(value) => println!("{}", value),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    }
}
