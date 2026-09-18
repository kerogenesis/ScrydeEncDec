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

const fn full_header(ver: &[u8; 6]) -> [u8; 28] {
    let mut out = [0u8; 28];
    let mut i = 0;
    while i < GAMEKIT_HEADER.len() {
        out[i] = GAMEKIT_HEADER[i];
        i += 1;
    }
    let mut j = 0;
    while j < ver.len() {
        out[22 + j] = ver[j];
        j += 1;
    }
    out
}

pub const HEADER_111_FULL: &[u8; 28] = &full_header(HEADER_VER_111);
pub const HEADER_120_FULL: &[u8; 28] = &full_header(HEADER_VER_120);
pub const HEADER_121_FULL: &[u8; 28] = &full_header(HEADER_VER_121);
pub const HEADER_211_FULL: &[u8; 28] = &full_header(HEADER_VER_211);
pub const HEADER_212_FULL: &[u8; 28] = &full_header(HEADER_VER_212);
pub const HEADER_413_FULL: &[u8; 28] = &full_header(HEADER_VER_413);

#[derive(Debug, PartialEq, Eq)]
pub enum FileState {
    Encrypted(FormatType),
    Plaintext,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Encrypted,
    Decrypted,
}

impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Operation::Encrypted => write!(f, "{}", obfstr!("Encrypted")),
            Operation::Decrypted => write!(f, "{}", obfstr!("Decrypted")),
        }
    }
}

pub fn detect_file_state(data: &[u8]) -> FileState {
    if data.len() < 28 {
        return FileState::Plaintext;
    }
    if data.starts_with(b"OggSL2SDBM") {
        return FileState::Encrypted(FormatType::OggSL2SDBM);
    }
    if &data[0..22] == GAMEKIT_HEADER {
        let sub_ver = &data[22..28];
        if sub_ver == HEADER_VER_111 {
            FileState::Encrypted(FormatType::Ver111)
        } else if sub_ver == HEADER_VER_120 {
            FileState::Encrypted(FormatType::Ver120)
        } else if sub_ver == HEADER_VER_121 {
            FileState::Encrypted(FormatType::Ver121)
        } else if sub_ver == HEADER_VER_211 {
            FileState::Encrypted(FormatType::Ver211)
        } else if sub_ver == HEADER_VER_212 {
            FileState::Encrypted(FormatType::Ver212)
        } else if sub_ver == HEADER_VER_413 {
            FileState::Encrypted(FormatType::Ver413)
        } else {
            FileState::Plaintext
        }
    } else {
        FileState::Plaintext
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileCategory {
    Texture, // utx, ugx, bmp  (encrypted as Ver121)
    Package, // uax, unr, uix, ukx, usx, usk, u  (encrypted as Ver120)
    Data,    // dat, l2.ini, user.ini  (encrypted as Ver413)
    Text,    // htm, int, interface.xdat, ttfontinfo.ini, localization.ini  (encrypted as Ver111)
    Other,
}

impl FileCategory {
    pub fn default_format(&self) -> FormatType {
        match self {
            FileCategory::Texture => FormatType::Ver121,
            FileCategory::Package => FormatType::Ver120,
            FileCategory::Data => FormatType::Ver413,
            FileCategory::Text => FormatType::Ver111,
            FileCategory::Other => FormatType::Ver413,
        }
    }
}

pub fn classify_file(filename: &str) -> FileCategory {
    let filename_lower = filename.to_lowercase();
    let ext = Utf8Path::new(&filename_lower).extension().unwrap_or("");
    match ext {
        s if s == obfstr!("utx") || s == obfstr!("ugx") || s == obfstr!("bmp") => {
            FileCategory::Texture
        }
        s if s == obfstr!("uax")
            || s == obfstr!("unr")
            || s == obfstr!("uix")
            || s == obfstr!("ukx")
            || s == obfstr!("usx")
            || s == obfstr!("usk")
            || s == obfstr!("u") =>
        {
            FileCategory::Package
        }
        s if s == obfstr!("dat") => FileCategory::Data,
        s if s == obfstr!("ini")
            && (filename_lower.starts_with(obfstr!("l2"))
                || filename_lower.starts_with(obfstr!("user"))) =>
        {
            FileCategory::Data
        }
        s if s == obfstr!("htm") || s == obfstr!("int") => FileCategory::Text,
        s if s == obfstr!("xdat") && filename_lower.starts_with(obfstr!("interface")) => {
            FileCategory::Text
        }
        s if s == obfstr!("ini")
            && (filename_lower.starts_with(obfstr!("ttfontinfo"))
                || filename_lower.starts_with(obfstr!("localization"))) =>
        {
            FileCategory::Text
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

#[cfg(test)]
mod tests {
    use super::*;

    fn header_data(ver: &[u8; 6]) -> Vec<u8> {
        let mut data = GAMEKIT_HEADER.to_vec();
        data.extend_from_slice(ver);
        data.extend_from_slice(&[0u8; 100]);
        data
    }

    #[test]
    fn detects_all_encrypted_versions() {
        let cases = [
            (HEADER_VER_111, FormatType::Ver111),
            (HEADER_VER_120, FormatType::Ver120),
            (HEADER_VER_121, FormatType::Ver121),
            (HEADER_VER_211, FormatType::Ver211),
            (HEADER_VER_212, FormatType::Ver212),
            (HEADER_VER_413, FormatType::Ver413),
        ];
        for (ver, expected) in cases {
            assert_eq!(
                detect_file_state(&header_data(ver)),
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
        let mut data = b"OggSL2SDBM".to_vec();
        data.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            detect_file_state(&data),
            FileState::Encrypted(FormatType::OggSL2SDBM)
        );
    }

    #[test]
    fn full_headers_match_gamekit_prefix_and_version() {
        let cases = [
            (HEADER_111_FULL, HEADER_VER_111),
            (HEADER_120_FULL, HEADER_VER_120),
            (HEADER_121_FULL, HEADER_VER_121),
            (HEADER_211_FULL, HEADER_VER_211),
            (HEADER_212_FULL, HEADER_VER_212),
            (HEADER_413_FULL, HEADER_VER_413),
        ];
        for (full, ver) in cases {
            assert_eq!(full.len(), 28);
            assert_eq!(&full[..22], GAMEKIT_HEADER);
            assert_eq!(&full[22..], ver);
        }
    }

    #[test]
    fn full_header_111_matches_known_bytes() {
        assert_eq!(
            HEADER_111_FULL,
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
    fn classifies_unknown_as_other() {
        for name in ["readme.md", "tool.exe", "archive.zip", "noext"] {
            assert_eq!(classify_file(name), FileCategory::Other, "{name}");
        }
    }

    #[test]
    fn version_hint_from_filename_markers() {
        assert_eq!(
            version_hint_from_filename("table.v111.dat"),
            Some(FormatType::Ver111)
        );
        assert_eq!(
            version_hint_from_filename("table.v120.dat"),
            Some(FormatType::Ver120)
        );
        assert_eq!(
            version_hint_from_filename("table.v121.dat"),
            Some(FormatType::Ver121)
        );
        assert_eq!(
            version_hint_from_filename("table.v211.dat"),
            Some(FormatType::Ver211)
        );
        assert_eq!(
            version_hint_from_filename("table.v212.dat"),
            Some(FormatType::Ver212)
        );
        assert_eq!(
            version_hint_from_filename("table.v413.dat"),
            Some(FormatType::Ver413)
        );
        assert_eq!(version_hint_from_filename("plain.dat"), None);
    }

    #[test]
    fn default_format_mapping() {
        assert_eq!(FileCategory::Texture.default_format(), FormatType::Ver121);
        assert_eq!(FileCategory::Package.default_format(), FormatType::Ver120);
        assert_eq!(FileCategory::Data.default_format(), FormatType::Ver413);
        assert_eq!(FileCategory::Text.default_format(), FormatType::Ver111);
        assert_eq!(FileCategory::Other.default_format(), FormatType::Ver413);
    }

    #[test]
    fn operation_display_names() {
        assert_eq!(Operation::Encrypted.to_string(), "Encrypted");
        assert_eq!(Operation::Decrypted.to_string(), "Decrypted");
    }
}
