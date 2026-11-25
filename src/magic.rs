use serde::{Deserialize, Serialize};

/// Known binary/document container formats detected purely from leading magic bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MagicKind {
    Sqlite,
    Parquet,
    ZipOrXlsx,
    Pdf,
    Gzip,
    Zstd,
    Png,
    Jpeg,
    Gif,
    Webp,
    Elf,
    MachO,
}

/// Zero-allocation magic-byte header classifier for content sniffing.
pub fn sniff(bytes: &[u8]) -> Option<MagicKind> {
    if bytes.starts_with(b"SQLite format 3\0") {
        return Some(MagicKind::Sqlite);
    }
    if bytes.starts_with(b"PAR1") {
        return Some(MagicKind::Parquet);
    }
    if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
        return Some(MagicKind::ZipOrXlsx);
    }
    if bytes.starts_with(b"%PDF-") {
        return Some(MagicKind::Pdf);
    }
    if bytes.starts_with(&[0x1f, 0x8b]) {
        return Some(MagicKind::Gzip);
    }
    if bytes.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        return Some(MagicKind::Zstd);
    }
    if bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]) {
        return Some(MagicKind::Png);
    }
    if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        return Some(MagicKind::Jpeg);
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return Some(MagicKind::Gif);
    }
    if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        return Some(MagicKind::Webp);
    }
    if bytes.starts_with(b"\x7fELF") {
        return Some(MagicKind::Elf);
    }
    if bytes.len() >= 4 {
        let head = [bytes[0], bytes[1], bytes[2], bytes[3]];
        if matches!(
            head,
            [0xfe, 0xed, 0xfa, 0xce]
                | [0xfe, 0xed, 0xfa, 0xcf]
                | [0xce, 0xfa, 0xed, 0xfe]
                | [0xcf, 0xfa, 0xed, 0xfe]
                | [0xca, 0xfe, 0xba, 0xbe]
        ) {
            return Some(MagicKind::MachO);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffs_core_data_and_document_formats() {
        assert_eq!(sniff(b"SQLite format 3\0rest"), Some(MagicKind::Sqlite));
        assert_eq!(sniff(b"PAR1xxxx"), Some(MagicKind::Parquet));
        assert_eq!(sniff(b"PK\x03\x04xlsx"), Some(MagicKind::ZipOrXlsx));
        assert_eq!(sniff(b"%PDF-1.7"), Some(MagicKind::Pdf));
        assert_eq!(sniff(b"plain csv,text,here"), None);
    }
}
