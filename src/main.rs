mod crypto;
mod error;
mod gamekit;

use camino::{Utf8Path, Utf8PathBuf};
use crossterm::event::{self, Event, KeyEventKind};
use crossterm::style::Stylize;
use error::Result;
use gamekit::{
    FileState, FormatType, Operation, classify_file, detect_file_state, version_hint_from_filename,
};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use obfstr::obfstr;
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::sync::mpsc::{Receiver, channel};
use walkdir::WalkDir;

struct ProcessResult {
    format: FormatType,
    operation: Operation,
}

fn strip_tool_prefix(name: &str) -> &str {
    let name = name.strip_prefix(obfstr!("enc.")).unwrap_or(name);
    name.strip_prefix(obfstr!("dec.")).unwrap_or(name)
}

fn decrypt_payload(format: FormatType, payload: &[u8], filename: &str) -> Result<Vec<u8>> {
    match format {
        FormatType::Ver111 => Ok(crypto::decrypt_111(payload, None)),
        FormatType::Ver120 => Ok(crypto::decrypt_120(payload, None)),
        FormatType::Ver121 => Ok(crypto::decrypt_121(payload, filename, None)),
        FormatType::Ver211 => Ok(crypto::decrypt_211(payload, None)),
        FormatType::Ver212 => Ok(crypto::decrypt_212(payload, None)),
        FormatType::Ver413 => crypto::decrypt_413(payload, None),
        FormatType::OggSL2SDBM => Ok(payload.to_vec()),
    }
}

fn encrypt_payload(format: FormatType, data: &[u8], filename: &str) -> Result<Vec<u8>> {
    match format {
        FormatType::Ver111 => Ok(crypto::encrypt_111(data, None)),
        FormatType::Ver120 => Ok(crypto::encrypt_120(data, None)),
        FormatType::Ver121 => Ok(crypto::encrypt_121(data, filename, None)),
        FormatType::Ver211 => Ok(crypto::encrypt_211(data, None)),
        FormatType::Ver212 => Ok(crypto::encrypt_212(data, None)),
        FormatType::Ver413 => crypto::encrypt_413(data, None),
        FormatType::OggSL2SDBM => Err(error::AppError::InvalidHeader),
    }
}

fn process_file(file_path: &Utf8Path) -> Result<ProcessResult> {
    let data = fs::read(file_path)?;
    if data.is_empty() {
        return Err(error::AppError::InvalidHeader);
    }
    let state = detect_file_state(&data);
    let raw_name = file_path.file_name().unwrap_or("");
    let filename = strip_tool_prefix(raw_name);

    match state {
        FileState::Encrypted(format) => {
            let decrypted = decrypt_payload(format, &data[28..], filename)?;
            fs::write(file_path, decrypted)?;
            Ok(ProcessResult {
                format,
                operation: Operation::Decrypted,
            })
        }
        FileState::Plaintext => {
            let category = classify_file(filename);
            let format =
                version_hint_from_filename(filename).unwrap_or_else(|| category.default_format());
            let encrypted = encrypt_payload(format, &data, filename)?;
            fs::write(file_path, encrypted)?;
            Ok(ProcessResult {
                format,
                operation: Operation::Encrypted,
            })
        }
    }
}

fn collect_files(input_path: &str, files: &mut Vec<Utf8PathBuf>) {
    for entry in WalkDir::new(input_path).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file()
            && let Ok(path) = Utf8PathBuf::from_path_buf(entry.into_path())
        {
            files.push(path);
        }
    }
}

fn wait_any_key() {
    print!(
        "\n  {} ",
        obfstr!("Press any key to exit . . .").dark_grey()
    );
    let _ = io::stdout().flush();
    let _ = crossterm::terminal::enable_raw_mode();
    loop {
        if let Ok(Event::Key(key_event)) = event::read()
            && key_event.kind == KeyEventKind::Press
        {
            break;
        }
    }
    let _ = crossterm::terminal::disable_raw_mode();
    println!();
}

fn print_banner() {
    println!("\n  {}\n", obfstr!("Scryde Gamekit encrypter & decrypter"));
}

fn print_usage() {
    println!("  {}", obfstr!("Usage:").yellow());
    println!(
        "    {}\n",
        obfstr!("Drag & Drop files or folders onto scryde_encdec.exe")
    );
    println!("  {}", obfstr!("Supported file extensions:").yellow());
    println!("    {}", obfstr!("dat, xdat, u, uax, ugx, uix, ukx,"));
    println!("    {}\n", obfstr!("unr, usk, usx, utx, ini, int, ogg"));
    println!("  {}", obfstr!("Supported headers:").yellow());
    println!("    {}\n", obfstr!("111, 120, 121, 211, 212, 413"));
}

type FileOutcome = (usize, Utf8PathBuf, Result<ProcessResult>);

fn print_outcome(
    multi_progress: &MultiProgress,
    position: usize,
    total_files: usize,
    counter_width: usize,
    path: &Utf8PathBuf,
    outcome: Result<ProcessResult>,
) -> bool {
    let filename = path.file_name().unwrap_or("");
    let counter = format!("[{:>counter_width$}/{}]", position, total_files)
        .blue()
        .bold();
    match outcome {
        Ok(processed) => {
            let _ = multi_progress.println(format!(
                " {} {} {} {} - {}",
                counter,
                obfstr!("[SUCCESS]").green().bold(),
                format!("[{}]", processed.format).yellow().bold(),
                processed.operation,
                filename
            ));
            true
        }
        Err(err) => {
            let _ = multi_progress.println(format!(
                " {} {} {} - {}",
                counter,
                obfstr!("[ERROR]").red().bold(),
                filename,
                err
            ));
            false
        }
    }
}

fn report_in_input_order(
    rx: Receiver<FileOutcome>,
    total_files: usize,
    counter_width: usize,
    multi_progress: &MultiProgress,
) -> usize {
    let mut pending: BTreeMap<usize, (Utf8PathBuf, Result<ProcessResult>)> = BTreeMap::new();
    let mut next = 0usize;
    let mut success_count = 0usize;
    while next < total_files {
        let Ok((idx, path, outcome)) = rx.recv() else {
            break;
        };
        pending.insert(idx, (path, outcome));
        while let Some((path, outcome)) = pending.remove(&next) {
            if print_outcome(
                multi_progress,
                next + 1,
                total_files,
                counter_width,
                &path,
                outcome,
            ) {
                success_count += 1;
            }
            next += 1;
        }
    }
    success_count
}

fn main() {
    print_banner();
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        wait_any_key();
        return;
    }

    let mut files = Vec::new();
    for input_path in &args[1..] {
        collect_files(input_path, &mut files);
    }

    if files.is_empty() {
        println!(
            "  {}\n",
            obfstr!("No valid files found to process.").yellow()
        );
        wait_any_key();
        return;
    }

    files.sort();
    let total_files = files.len();
    let counter_width = total_files.to_string().len();

    let multi_progress = MultiProgress::new();
    let progress = multi_progress.add(ProgressBar::new(total_files as u64));
    progress.set_style(
        ProgressStyle::default_bar()
            .template(obfstr!("  Progress: \x1b[34m[{bar:30.cyan/blue}]\x1b[0m \x1b[1;33m{pos}/{len}\x1b[0m files ({percent}%)"))
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars(obfstr!("█▓▒░ ")),
    );

    let (tx, rx) = channel::<FileOutcome>();
    let success_count = std::thread::scope(|s| {
        s.spawn(|| {
            files.par_iter().enumerate().for_each(|(idx, path)| {
                let outcome = process_file(path);
                progress.inc(1);
                let _ = tx.send((idx, path.clone(), outcome));
            });
        });
        report_in_input_order(rx, total_files, counter_width, &multi_progress)
    });

    progress.finish_and_clear();

    println!(
        "\n  {}: {} / {}",
        obfstr!("Processed files"),
        success_count.to_string().green().bold(),
        total_files.to_string().white().bold()
    );
    wait_any_key();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_tool_prefix() {
        assert_eq!(strip_tool_prefix("enc.codec.utx"), "codec.utx");
        assert_eq!(strip_tool_prefix("dec.declaration.utx"), "declaration.utx");
        assert_eq!(strip_tool_prefix("codec.utx"), "codec.utx");
        assert_eq!(strip_tool_prefix("declaration.utx"), "declaration.utx");
        assert_eq!(strip_tool_prefix("fence_dec.utx"), "fence_dec.utx");
    }

    fn temp_workdir(case: &str) -> Utf8PathBuf {
        let dir = std::env::temp_dir().join(format!("scryde_encdec_{}_{case}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Utf8PathBuf::from_path_buf(dir).unwrap()
    }

    #[test]
    fn process_file_roundtrip_ver413() {
        let dir = temp_workdir("process_ver413");
        let path = dir.join("table.dat");
        let plain = b"roundtrip payload ver413 - ".repeat(8);
        std::fs::write(&path, &plain).unwrap();

        let step1 = process_file(&path).unwrap();
        assert_eq!(step1.operation, Operation::Encrypted);
        assert_eq!(step1.format, FormatType::Ver413);

        let step2 = process_file(&path).unwrap();
        assert_eq!(step2.operation, Operation::Decrypted);
        assert_eq!(step2.format, FormatType::Ver413);
        assert_eq!(std::fs::read(&path).unwrap(), plain);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn process_file_roundtrip_ver121() {
        let dir = temp_workdir("process_ver121");
        let path = dir.join("texture.utx");
        let plain = b"plain utx bytes, no magic inside 0123456789".to_vec();
        std::fs::write(&path, &plain).unwrap();

        let step1 = process_file(&path).unwrap();
        assert_eq!(step1.operation, Operation::Encrypted);
        assert_eq!(step1.format, FormatType::Ver121);

        let step2 = process_file(&path).unwrap();
        assert_eq!(step2.operation, Operation::Decrypted);
        assert_eq!(step2.format, FormatType::Ver121);
        assert_eq!(std::fs::read(&path).unwrap(), plain);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
