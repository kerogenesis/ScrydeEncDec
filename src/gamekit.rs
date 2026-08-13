use crate::error::Result;
use camino::Utf8Path;
use obfstr::obfstr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatType {
    Ver111 = 1,
    Ver120 = 2,
    Ver121 = 3,
    Ver211 = 4,
    Ver212 = 5,
    Ver413 = 6,
    OggSL2SDBM = 9,
}

impl std::fmt::Display for FormatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FormatType::Ver111 => write!(f, "Ver111"),
            FormatType::Ver120 => write!(f, "Ver120"),
            FormatType::Ver121 => write!(f, "Ver121"),
            FormatType::Ver211 => write!(f, "Ver211"),
            FormatType::Ver212 => write!(f, "Ver212"),
            FormatType::Ver413 => write!(f, "Ver413"),
            FormatType::OggSL2SDBM => write!(f, "OggSL2SDBM"),
        }
    }
}

pub const GAMEKIT_HEADER: &[u8; 22] = b"G\x00a\x00m\x00e\x00k\x00i\x00t\x00D\x00a\x00t\x00a\x00";
pub const HEADER_VER_111: &[u8; 6] = b"1\x001\x001\x00";
pub const HEADER_VER_120: &[u8; 6] = b"1\x002\x000\x00";
pub const HEADER_VER_121: &[u8; 6] = b"1\x002\x001\x00";
pub const HEADER_VER_211: &[u8; 6] = b"2\x001\x001\x00";
pub const HEADER_VER_212: &[u8; 6] = b"2\x001\x002\x00";
pub const HEADER_VER_413: &[u8; 6] = b"4\x001\x003\x00";

#[derive(Debug, PartialEq, Eq)]
pub enum FileState {
    Encrypted(FormatType),
    DecryptedPlaintext,
}

pub fn detect_file_state(data: &[u8]) -> Result<FileState> {
    if data.len() < 28 {
        return Ok(FileState::DecryptedPlaintext);
    }
    if data.starts_with(b"OggSL2SDBM") {
        return Ok(FileState::Encrypted(FormatType::OggSL2SDBM));
    }
    if &data[0..22] == GAMEKIT_HEADER {
        let sub_ver = &data[22..28];
        if sub_ver == HEADER_VER_111 {
            Ok(FileState::Encrypted(FormatType::Ver111))
        } else if sub_ver == HEADER_VER_120 {
            Ok(FileState::Encrypted(FormatType::Ver120))
        } else if sub_ver == HEADER_VER_121 {
            Ok(FileState::Encrypted(FormatType::Ver121))
        } else if sub_ver == HEADER_VER_211 {
            Ok(FileState::Encrypted(FormatType::Ver211))
        } else if sub_ver == HEADER_VER_212 {
            Ok(FileState::Encrypted(FormatType::Ver212))
        } else if sub_ver == HEADER_VER_413 {
            Ok(FileState::Encrypted(FormatType::Ver413))
        } else {
            Ok(FileState::DecryptedPlaintext)
        }
    } else {
        Ok(FileState::DecryptedPlaintext)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileCategory {
    Category1, // utx, ugx, bmp  (encrypted as Ver121)
    Category2, // uax, unr, uix, ukx, usx, usk, u  (encrypted as Ver120)
    Category3, // dat, l2.ini, user.ini  (encrypted as Ver413)
    Category4, // htm, int, interface.xdat, ttfontinfo.ini, localization.ini  (encrypted as Ver111)
    Other,
}

impl FileCategory {
    pub fn default_format(&self) -> FormatType {
        match self {
            FileCategory::Category1 => FormatType::Ver121,
            FileCategory::Category2 => FormatType::Ver120,
            FileCategory::Category3 => FormatType::Ver413,
            FileCategory::Category4 => FormatType::Ver111,
            FileCategory::Other => FormatType::Ver413,
        }
    }
}

pub fn classify_file(filename: &str) -> FileCategory {
    let filename_lower = filename.to_lowercase();
    let ext = Utf8Path::new(&filename_lower).extension().unwrap_or("");
    match ext {
        s if s == obfstr!("utx") || s == obfstr!("ugx") || s == obfstr!("bmp") => {
            FileCategory::Category1
        }
        s if s == obfstr!("uax")
            || s == obfstr!("unr")
            || s == obfstr!("uix")
            || s == obfstr!("ukx")
            || s == obfstr!("usx")
            || s == obfstr!("usk")
            || s == obfstr!("u") =>
        {
            FileCategory::Category2
        }
        s if s == obfstr!("dat") => FileCategory::Category3,
        s if s == obfstr!("ini")
            && (filename_lower.starts_with(obfstr!("l2"))
                || filename_lower.starts_with(obfstr!("user"))) =>
        {
            FileCategory::Category3
        }
        s if s == obfstr!("htm") || s == obfstr!("int") => FileCategory::Category4,
        s if s == obfstr!("xdat") && filename_lower.starts_with(obfstr!("interface")) => {
            FileCategory::Category4
        }
        s if s == obfstr!("ini")
            && (filename_lower.starts_with(obfstr!("ttfontinfo"))
                || filename_lower.starts_with(obfstr!("localization"))) =>
        {
            FileCategory::Category4
        }
        _ => FileCategory::Other,
    }
}

pub fn version_hint_from_filename(filename: &str) -> Option<FormatType> {
    let lower = filename.to_lowercase();
    if lower.contains(obfstr!(".v111")) {
        Some(FormatType::Ver111)
    } else if lower.contains(obfstr!(".v120")) {
        Some(FormatType::Ver120)
    } else if lower.contains(obfstr!(".v121")) {
        Some(FormatType::Ver121)
    } else if lower.contains(obfstr!(".v211")) {
        Some(FormatType::Ver211)
    } else if lower.contains(obfstr!(".v212")) {
        Some(FormatType::Ver212)
    } else if lower.contains(obfstr!(".v413")) {
        Some(FormatType::Ver413)
    } else {
        None
    }
}
