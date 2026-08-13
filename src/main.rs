mod crypto;
mod error;
mod gamekit;

use camino::{Utf8Path, Utf8PathBuf};
use crossterm::event::{self, Event, KeyEventKind};
use crossterm::style::Stylize;
use error::Result;
use gamekit::{
    FileState, FormatType, classify_file, detect_file_state, version_hint_from_filename,
};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use obfstr::obfstr;
use rayon::prelude::*;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use walkdir::WalkDir;

struct ProcessResult {
    format: FormatType,
    operation: String,
}

fn strip_tool_segments(name: &str) -> &str {
    let name = name.strip_prefix(obfstr!("enc.")).unwrap_or(name);
    name.strip_prefix(obfstr!("dec.")).unwrap_or(name)
}

fn process_file(file_path: &Utf8Path) -> Result<ProcessResult> {
    let data = fs::read(file_path)?;
    if data.is_empty() {
        return Err(error::AppError::InvalidHeader);
    }
    let state = detect_file_state(&data)?;
    let raw_name = file_path.file_name().unwrap_or("");
    let filename = strip_tool_segments(raw_name);

    match state {
        FileState::Encrypted(format) => {
            let payload = &data[28..];
            let decrypted = match format {
                FormatType::Ver111 => crypto::decrypt_111(payload, None),
                FormatType::Ver120 => crypto::decrypt_120(payload, None),
                FormatType::Ver121 => crypto::decrypt_121(payload, filename, None),
                FormatType::Ver211 => crypto::decrypt_211(payload, None),
                FormatType::Ver212 => crypto::decrypt_212(payload, None),
                FormatType::Ver413 => crypto::decrypt_413(payload, None)?,
                FormatType::OggSL2SDBM => payload.to_vec(),
            };
            fs::write(file_path, decrypted)?;
            Ok(ProcessResult {
                format,
                operation: obfstr!("Decrypted").to_string(),
            })
        }
        FileState::DecryptedPlaintext => {
            let category = classify_file(filename);
            let version =
                version_hint_from_filename(filename).unwrap_or_else(|| category.default_format());
            let encrypted = match version {
                FormatType::Ver111 => crypto::encrypt_111(&data, None),
                FormatType::Ver120 => crypto::encrypt_120(&data, None),
                FormatType::Ver121 => crypto::encrypt_121(&data, filename, None),
                FormatType::Ver211 => crypto::encrypt_211(&data, None),
                FormatType::Ver212 => crypto::encrypt_212(&data, None),
                FormatType::Ver413 => crypto::encrypt_413(&data, None)?,
                FormatType::OggSL2SDBM => return Err(error::AppError::InvalidHeader),
            };
            fs::write(file_path, encrypted)?;
            Ok(ProcessResult {
                format: version,
                operation: obfstr!("Encrypted").to_string(),
            })
        }
    }
}

fn collect_files(arg: &str, files: &mut Vec<Utf8PathBuf>) {
    for entry in WalkDir::new(arg).into_iter().filter_map(|e| e.ok()) {
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

fn main() {
    print_banner();
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
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
        wait_any_key();
        return;
    }

    let mut files = Vec::new();
    for arg in &args[1..] {
        collect_files(arg, &mut files);
    }

    if files.is_empty() {
        println!(
            "  {}\n",
            obfstr!("No valid files found to process.").yellow()
        );
        wait_any_key();
        return;
    }

    let total_files = files.len();
    let success_count = AtomicUsize::new(0);
    let processed_count = AtomicUsize::new(0);

    let mp = MultiProgress::new();
    let overall_pb = mp.add(ProgressBar::new(total_files as u64));
    overall_pb.set_style(
        ProgressStyle::default_bar()
            .template("  Progress: \x1b[34m[{bar:30.cyan/blue}]\x1b[0m \x1b[1;33m{pos}/{len}\x1b[0m files ({percent}%)")
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("█▓▒░ "),
    );

    files.par_iter().for_each(|path| {
        let filename = path.file_name().unwrap_or("");
        let res = process_file(path);
        let idx = processed_count.fetch_add(1, Ordering::SeqCst) + 1;
        overall_pb.inc(1);

        match res {
            Ok(res) => {
                success_count.fetch_add(1, Ordering::SeqCst);
                let _ = mp.println(format!(
                    " {} {} {} {} - {}",
                    format!("[{}/{}]", idx, total_files).blue().bold(),
                    obfstr!("[SUCCESS]").green().bold(),
                    format!("[{}]", res.format).yellow().bold(),
                    res.operation,
                    filename
                ));
            }
            Err(err) => {
                let _ = mp.println(format!(
                    " {} {} {} - {}",
                    format!("[{}/{}]", idx, total_files).blue().bold(),
                    obfstr!("[ERROR]").red().bold(),
                    filename,
                    err
                ));
            }
        }
    });

    overall_pb.finish_and_clear();

    println!(
        "\n  {}: {} / {}",
        obfstr!("Processed files"),
        success_count
            .load(Ordering::SeqCst)
            .to_string()
            .green()
            .bold(),
        total_files.to_string().white().bold()
    );
    wait_any_key();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_tool_segments() {
        assert_eq!(strip_tool_segments("enc.codec.utx"), "codec.utx");
        assert_eq!(
            strip_tool_segments("dec.declaration.utx"),
            "declaration.utx"
        );
        assert_eq!(strip_tool_segments("codec.utx"), "codec.utx");
        assert_eq!(strip_tool_segments("declaration.utx"), "declaration.utx");
        assert_eq!(strip_tool_segments("fence_dec.utx"), "fence_dec.utx");
    }
}
