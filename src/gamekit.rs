use camino::Utf8Path;
use obfstr::obfstr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFormat {
    Ver111,
    Ver120,
    Ver121,
    Ver211,
    Ver212,
    Ver413,
    OggSL2SDBM,
}

impl std::fmt::Display for FileFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileFormat::Ver111 => write!(f, "Ver111"),
            FileFormat::Ver120 => write!(f, "Ver120"),
            FileFormat::Ver121 => write!(f, "Ver121"),
            FileFormat::Ver211 => write!(f, "Ver211"),
            FileFormat::Ver212 => write!(f, "Ver212"),
            FileFormat::Ver413 => write!(f, "Ver413"),
            FileFormat::OggSL2SDBM => write!(f, "OggSL2SDBM"),
        }
    }
}

pub const HEADER_PREFIX_LEN: usize = 22;
pub const HEADER_VERSION_LEN: usize = 6;
pub const HEADER_LEN: usize = HEADER_PREFIX_LEN + HEADER_VERSION_LEN;
pub const HEADER_OGG_MAGIC: &[u8; 10] = b"OggSL2SDBM";
/// First 22 bytes of every encrypted file: `GamekitData` in UTF-16LE.
pub const HEADER_PREFIX: &[u8; HEADER_PREFIX_LEN] =
    b"G\x00a\x00m\x00e\x00k\x00i\x00t\x00D\x00a\x00t\x00a\x00";
/// Last 6 bytes of the 28-byte header: version digits (`111`, `120`, …) in UTF-16LE.
pub const VERSION_SUFFIX_111: &[u8; HEADER_VERSION_LEN] = b"1\x001\x001\x00";
pub const VERSION_SUFFIX_120: &[u8; HEADER_VERSION_LEN] = b"1\x002\x000\x00";
pub const VERSION_SUFFIX_121: &[u8; HEADER_VERSION_LEN] = b"1\x002\x001\x00";
pub const VERSION_SUFFIX_211: &[u8; HEADER_VERSION_LEN] = b"2\x001\x001\x00";
pub const VERSION_SUFFIX_212: &[u8; HEADER_VERSION_LEN] = b"2\x001\x002\x00";
pub const VERSION_SUFFIX_413: &[u8; HEADER_VERSION_LEN] = b"4\x001\x003\x00";

const fn full_header(version: &[u8; HEADER_VERSION_LEN]) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    let mut i = 0;
    while i < HEADER_PREFIX.len() {
        out[i] = HEADER_PREFIX[i];
        i += 1;
    }
    let mut j = 0;
    while j < version.len() {
        out[HEADER_PREFIX_LEN + j] = version[j];
        j += 1;
    }
    out
}

pub const HEADER_111: &[u8; HEADER_LEN] = &full_header(VERSION_SUFFIX_111);
pub const HEADER_120: &[u8; HEADER_LEN] = &full_header(VERSION_SUFFIX_120);
pub const HEADER_121: &[u8; HEADER_LEN] = &full_header(VERSION_SUFFIX_121);
pub const HEADER_211: &[u8; HEADER_LEN] = &full_header(VERSION_SUFFIX_211);
pub const HEADER_212: &[u8; HEADER_LEN] = &full_header(VERSION_SUFFIX_212);
pub const HEADER_413: &[u8; HEADER_LEN] = &full_header(VERSION_SUFFIX_413);

#[derive(Debug, PartialEq, Eq)]
pub enum FileState {
    Encrypted(FileFormat),
    Plaintext,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Encrypt,
    Decrypt,
}

impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Operation::Encrypt => write!(f, "{}", obfstr!("Encrypted")),
            Operation::Decrypt => write!(f, "{}", obfstr!("Decrypted")),
        }
    }
}

const VERSION_TABLE: [(&[u8; HEADER_VERSION_LEN], FileFormat); 6] = [
    (VERSION_SUFFIX_111, FileFormat::Ver111),
    (VERSION_SUFFIX_120, FileFormat::Ver120),
    (VERSION_SUFFIX_121, FileFormat::Ver121),
    (VERSION_SUFFIX_211, FileFormat::Ver211),
    (VERSION_SUFFIX_212, FileFormat::Ver212),
    (VERSION_SUFFIX_413, FileFormat::Ver413),
];

pub fn detect_file_state(data: &[u8]) -> FileState {
    if data.len() < HEADER_LEN {
        return FileState::Plaintext;
    }
    if data.starts_with(HEADER_OGG_MAGIC) {
        return FileState::Encrypted(FileFormat::OggSL2SDBM);
    }
    if &data[..HEADER_PREFIX_LEN] != HEADER_PREFIX {
        return FileState::Plaintext;
    }
    let version = &data[HEADER_PREFIX_LEN..HEADER_LEN];
    VERSION_TABLE
        .iter()
        .find(|(suffix, _)| suffix.as_slice() == version)
        .map(|(_, file_format)| FileState::Encrypted(*file_format))
        .unwrap_or(FileState::Plaintext)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileCategory {
    Texture, // utx, ugx, bmp  (encrypted as Ver121)
    Package, // uax, unr, uix, ukx, usx, usk, u  (encrypted as Ver120)
    Data,    // dat, l2.ini, user.ini  (encrypted as Ver413)
    Text,    // htm, int, interface.xdat, ttfontinfo.ini, localization.ini  (encrypted as Ver111)
    Unknown,
}

impl FileCategory {
    pub fn default_format(&self) -> FileFormat {
        match self {
            FileCategory::Texture => FileFormat::Ver121,
            FileCategory::Package => FileFormat::Ver120,
            FileCategory::Data => FileFormat::Ver413,
            FileCategory::Text => FileFormat::Ver111,
            FileCategory::Unknown => FileFormat::Ver413,
        }
    }
}

pub fn classify_file(filename: &str) -> FileCategory {
    let filename_lower = filename.to_ascii_lowercase();
    let ext = Utf8Path::new(&filename_lower).extension().unwrap_or("");
    match ext {
        "utx" | "ugx" | "bmp" => FileCategory::Texture,
        "uax" | "unr" | "uix" | "ukx" | "usx" | "usk" | "u" => FileCategory::Package,
        "dat" => FileCategory::Data,
        "ini"
            if filename_lower.starts_with(obfstr!("l2"))
                || filename_lower.starts_with(obfstr!("user")) =>
        {
            FileCategory::Data
        }
        "htm" | "int" => FileCategory::Text,
        "xdat" if filename_lower.starts_with(obfstr!("interface")) => FileCategory::Text,
        "ini"
            if filename_lower.starts_with(obfstr!("ttfontinfo"))
                || filename_lower.starts_with(obfstr!("localization")) =>
        {
            FileCategory::Text
        }
        _ => FileCategory::Unknown,
    }
}

pub fn format_override_from_filename(filename: &str) -> Option<FileFormat> {
    let lower = filename.to_ascii_lowercase();
    if lower.contains(obfstr!(".v111")) {
        Some(FileFormat::Ver111)
    } else if lower.contains(obfstr!(".v120")) {
        Some(FileFormat::Ver120)
    } else if lower.contains(obfstr!(".v121")) {
        Some(FileFormat::Ver121)
    } else if lower.contains(obfstr!(".v211")) {
        Some(FileFormat::Ver211)
    } else if lower.contains(obfstr!(".v212")) {
        Some(FileFormat::Ver212)
    } else if lower.contains(obfstr!(".v413")) {
        Some(FileFormat::Ver413)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_data(version: &[u8; HEADER_VERSION_LEN]) -> Vec<u8> {
        let mut data = HEADER_PREFIX.to_vec();
        data.extend_from_slice(version);
        data.extend_from_slice(&[0u8; 100]);
        data
    }

    #[test]
    fn detects_all_encrypted_versions() {
        let cases = [
            (VERSION_SUFFIX_111, FileFormat::Ver111),
            (VERSION_SUFFIX_120, FileFormat::Ver120),
            (VERSION_SUFFIX_121, FileFormat::Ver121),
            (VERSION_SUFFIX_211, FileFormat::Ver211),
            (VERSION_SUFFIX_212, FileFormat::Ver212),
            (VERSION_SUFFIX_413, FileFormat::Ver413),
        ];
        for (version, expected) in cases {
            assert_eq!(
                detect_file_state(&header_data(version)),
                FileState::Encrypted(expected)
            );
        }
    }

    #[test]
    fn short_or_foreign_input_is_plaintext() {
        assert_eq!(detect_file_state(&[]), FileState::Plaintext);
        assert_eq!(detect_file_state(&[0u8; 27]), FileState::Plaintext);
        assert_eq!(detect_file_state(&[0xFFu8; 64]), FileState::Plaintext);
        assert_eq!(
            detect_file_state(&header_data(b"9\x009\x009\x00")),
            FileState::Plaintext
        );
    }

    #[test]
    fn detects_ogg_header() {
        let mut data = HEADER_OGG_MAGIC.to_vec();
        data.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            detect_file_state(&data),
            FileState::Encrypted(FileFormat::OggSL2SDBM)
        );
    }

    #[test]
    fn full_headers_match_gamekit_prefix_and_version() {
        let cases = [
            (HEADER_111, VERSION_SUFFIX_111),
            (HEADER_120, VERSION_SUFFIX_120),
            (HEADER_121, VERSION_SUFFIX_121),
            (HEADER_211, VERSION_SUFFIX_211),
            (HEADER_212, VERSION_SUFFIX_212),
            (HEADER_413, VERSION_SUFFIX_413),
        ];
        for (full, version) in cases {
            assert_eq!(full.len(), HEADER_LEN);
            assert_eq!(&full[..HEADER_PREFIX_LEN], HEADER_PREFIX);
            assert_eq!(&full[HEADER_PREFIX_LEN..], version);
        }
    }

    #[test]
    fn full_header_111_matches_known_bytes() {
        assert_eq!(
            HEADER_111,
            b"G\x00a\x00m\x00e\x00k\x00i\x00t\x00D\x00a\x00t\x00a\x001\x001\x001\x00"
        );
    }

    #[test]
    fn classifies_known_extensions() {
        let cases = [
            ("texture.utx", FileCategory::Texture),
            ("TEXTURE.UTX", FileCategory::Texture),
            ("mesh.ugx", FileCategory::Texture),
            ("image.bmp", FileCategory::Texture),
            ("anim.uax", FileCategory::Package),
            ("map.unr", FileCategory::Package),
            ("item.uix", FileCategory::Package),
            ("item.ukx", FileCategory::Package),
            ("mesh.usx", FileCategory::Package),
            ("mesh.usk", FileCategory::Package),
            ("package.u", FileCategory::Package),
            ("table.dat", FileCategory::Data),
            ("l2.ini", FileCategory::Data),
            ("user.ini", FileCategory::Data),
            ("page.htm", FileCategory::Text),
            ("strings.int", FileCategory::Text),
            ("interface.xdat", FileCategory::Text),
            ("ttfontinfo.ini", FileCategory::Text),
            ("localization.ini", FileCategory::Text),
        ];
        for (name, expected) in cases {
            assert_eq!(classify_file(name), expected, "{name}");
        }
    }

    #[test]
    fn classifies_unknown_extensions() {
        for name in ["readme.md", "tool.exe", "archive.zip", "noext"] {
            assert_eq!(classify_file(name), FileCategory::Unknown, "{name}");
        }
    }

    #[test]
    fn format_override_from_filename_markers() {
        assert_eq!(
            format_override_from_filename("table.v111.dat"),
            Some(FileFormat::Ver111)
        );
        assert_eq!(
            format_override_from_filename("table.v120.dat"),
            Some(FileFormat::Ver120)
        );
        assert_eq!(
            format_override_from_filename("table.v121.dat"),
            Some(FileFormat::Ver121)
        );
        assert_eq!(
            format_override_from_filename("table.v211.dat"),
            Some(FileFormat::Ver211)
        );
        assert_eq!(
            format_override_from_filename("table.v212.dat"),
            Some(FileFormat::Ver212)
        );
        assert_eq!(
            format_override_from_filename("table.v413.dat"),
            Some(FileFormat::Ver413)
        );
        assert_eq!(format_override_from_filename("plain.dat"), None);
    }

    #[test]
    fn default_format_mapping() {
        assert_eq!(FileCategory::Texture.default_format(), FileFormat::Ver121);
        assert_eq!(FileCategory::Package.default_format(), FileFormat::Ver120);
        assert_eq!(FileCategory::Data.default_format(), FileFormat::Ver413);
        assert_eq!(FileCategory::Text.default_format(), FileFormat::Ver111);
        assert_eq!(FileCategory::Unknown.default_format(), FileFormat::Ver413);
    }

    #[test]
    fn operation_display_names() {
        assert_eq!(Operation::Encrypt.to_string(), "Encrypted");
        assert_eq!(Operation::Decrypt.to_string(), "Decrypted");
    }
}
