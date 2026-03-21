fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: kernrift <file.krbo>");
        std::process::exit(2);
    }
    let file = &args[1];

    // Ensure the path is unambiguous — exec() / CreateProcess() won't search
    // the current directory for bare names without a path separator.
    let path = if file.contains('/') || file.contains('\\') {
        file.clone()
    } else {
        format!(".{}{}", std::path::MAIN_SEPARATOR, file)
    };

    run(&path, file, &args[2..]);
}

#[cfg(unix)]
fn run(path: &str, file: &str, extra: &[String]) -> ! {
    use std::os::unix::process::CommandExt;
    let err = std::process::Command::new(path).args(extra).exec();
    eprintln!("kernrift: failed to execute '{}': {}", file, err);
    std::process::exit(1);
}

#[cfg(not(unix))]
fn run(path: &str, file: &str, extra: &[String]) -> ! {
    // Check for ELF magic — .krbo files are Linux ELF executables and cannot
    // run on Windows directly.
    if let Ok(mut f) = std::fs::File::open(path) {
        use std::io::Read;
        let mut magic = [0u8; 4];
        if f.read_exact(&mut magic).is_ok() && &magic == b"\x7fELF" {
            eprintln!(
                "kernrift: '{}' is a Linux ELF executable and cannot run on Windows.\n\
                 Use WSL (wsl --install) to run .krbo files: wsl kernrift {}",
                file, file
            );
            std::process::exit(1);
        }
    }

    match std::process::Command::new(path).args(extra).status() {
        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
        Err(err) => {
            eprintln!("kernrift: failed to execute '{}': {}", file, err);
            std::process::exit(1);
        }
    }
}
