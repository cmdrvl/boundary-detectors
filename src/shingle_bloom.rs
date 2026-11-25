use std::fmt;

use crate::{Finding, Pack, Severity, hash_match};

const MAGIC: [u8; 4] = *b"BDBL";
const FORMAT_VERSION: u8 = 1;
const HEADER_LEN: usize = 40;
const MAX_BITS: u64 = 64 * 1024 * 1024 * 8; // 64 MiB max bitset

/// Configuration for building a one-way protected-corpus shingle Bloom filter.
#[derive(Debug, Clone, PartialEq)]
pub struct BloomConfig {
    pub expected_shingles: usize,
    pub false_positive_rate: f64,
    pub shingle_words: u8,
    pub window_bytes: u8,
    pub salt: [u8; 16],
}

impl Default for BloomConfig {
    fn default() -> Self {
        Self {
            expected_shingles: 50_000,
            false_positive_rate: 0.001,
            shingle_words: 8,
            window_bytes: 64,
            salt: *b"cmdrvl-bdbl-v001",
        }
    }
}

/// Errors encountered when decoding a serialized [`ShingleBloom`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BloomError {
    TruncatedHeader,
    InvalidMagic,
    UnsupportedVersion(u8),
    InvalidParameters,
    BitsetLengthMismatch { expected: usize, actual: usize },
}

impl fmt::Display for BloomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader => write!(f, "bloom filter header truncated"),
            Self::InvalidMagic => write!(f, "invalid bloom filter magic (expected BDBL)"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported bloom filter version {v}"),
            Self::InvalidParameters => write!(f, "invalid bloom filter parameters"),
            Self::BitsetLengthMismatch { expected, actual } => {
                write!(
                    f,
                    "bloom bitset length mismatch: expected {expected} bytes, got {actual}"
                )
            }
        }
    }
}

impl std::error::Error for BloomError {}

/// Strictly one-way rolling-shingle Bloom filter over protected corpora.
///
/// Stores only a salted `blake3` bitset and compact header parameters — never
/// raw source text — so a host-side launcher (`veil sandbox`) can pass it to an
/// egress proxy (`airlock gate --protected-bloom`) with zero raw-data exposure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShingleBloom {
    k_hashes: u8,
    shingle_words: u8,
    window_bytes: u8,
    m_bits: u64,
    inserted_shingles: u64,
    salt: [u8; 16],
    bits: Vec<u8>,
}

impl ShingleBloom {
    /// Allocate a new empty filter sized for `config.expected_shingles` and
    /// `config.false_positive_rate`.
    pub fn new(config: BloomConfig) -> Self {
        let n = config.expected_shingles.max(64) as f64;
        let fpr = config.false_positive_rate.clamp(1e-6, 0.25);
        let ln2 = std::f64::consts::LN_2;
        let m_raw = (-(n * fpr.ln()) / (ln2 * ln2)).ceil() as u64;
        let m_bits = m_raw.clamp(1024, MAX_BITS).div_ceil(8) * 8;
        let k = (((m_bits as f64) / n) * ln2).round().clamp(2.0, 16.0) as u8;
        let byte_len = usize::try_from(m_bits / 8).expect("m_bits fits in usize");

        Self {
            k_hashes: k,
            shingle_words: config.shingle_words.max(3),
            window_bytes: config.window_bytes.max(24),
            m_bits,
            inserted_shingles: 0,
            salt: config.salt,
            bits: vec![0u8; byte_len],
        }
    }

    pub fn inserted_shingles(&self) -> u64 {
        self.inserted_shingles
    }

    pub fn bit_len(&self) -> u64 {
        self.m_bits
    }

    /// Insert all normalized word-shingles and sliding byte-windows from `text`.
    pub fn insert_text(&mut self, text: &str) {
        let normalized = normalize_text(text);
        let shingle_words = self.shingle_words;
        let window_bytes = self.window_bytes;
        for_each_shingle(&normalized, shingle_words, window_bytes, |shingle| {
            self.insert_shingle(shingle);
        });
    }

    /// Insert text extracted from `bytes`, capping at `max_bytes`.
    pub fn insert_bytes_bounded(&mut self, bytes: &[u8], max_bytes: usize) {
        let slice = if bytes.len() > max_bytes {
            &bytes[..max_bytes]
        } else {
            bytes
        };
        let text = String::from_utf8_lossy(slice);
        self.insert_text(&text);
    }

    /// Count how many distinct shingles in `text` hit this Bloom filter.
    pub fn count_hits(&self, text: &str) -> usize {
        if self.inserted_shingles == 0 {
            return 0;
        }
        let normalized = normalize_text(text);
        let mut hits = 0;
        for_each_shingle(
            &normalized,
            self.shingle_words,
            self.window_bytes,
            |shingle| {
                if self.contains_shingle(shingle) {
                    hits += 1;
                }
            },
        );
        hits
    }

    /// Return `true` if `text` produces at least `min_hits` shingle hits.
    pub fn matches(&self, text: &str, min_hits: usize) -> bool {
        self.count_hits(text) >= min_hits.max(1)
    }

    /// Emit a `PROTECTED_CORPUS_MATCH` finding if `text` hits at least
    /// `min_hits` shingles in this filter.
    pub fn scan_text(&self, text: &str, min_hits: usize, depth: u8) -> Vec<Finding> {
        if self.matches(text, min_hits) {
            vec![Finding {
                pack: Pack::ProtectedCorpus,
                rule_id: "PROTECTED_CORPUS_MATCH".to_string(),
                severity: Severity::Critical,
                byte_span: (0, text.len()),
                match_len: text.len(),
                match_hash: hash_match(text.as_bytes()),
                depth,
            }]
        } else {
            Vec::new()
        }
    }

    /// Serialize into the compact binary `BDBL` v1 format (strictly one-way).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_LEN + self.bits.len());
        buf.extend_from_slice(&MAGIC);
        buf.push(FORMAT_VERSION);
        buf.push(self.k_hashes);
        buf.push(self.shingle_words);
        buf.push(self.window_bytes);
        buf.extend_from_slice(&self.m_bits.to_le_bytes());
        buf.extend_from_slice(&self.inserted_shingles.to_le_bytes());
        buf.extend_from_slice(&self.salt);
        buf.extend_from_slice(&self.bits);
        buf
    }

    /// Deserialize from the binary `BDBL` v1 format with strict validation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BloomError> {
        if bytes.len() < HEADER_LEN {
            return Err(BloomError::TruncatedHeader);
        }
        if bytes[0..4] != MAGIC {
            return Err(BloomError::InvalidMagic);
        }
        let version = bytes[4];
        if version != FORMAT_VERSION {
            return Err(BloomError::UnsupportedVersion(version));
        }
        let k_hashes = bytes[5];
        let shingle_words = bytes[6];
        let window_bytes = bytes[7];
        let m_bits = u64::from_le_bytes(bytes[8..16].try_into().expect("8 bytes"));
        let inserted_shingles = u64::from_le_bytes(bytes[16..24].try_into().expect("8 bytes"));
        let salt: [u8; 16] = bytes[24..40].try_into().expect("16 bytes");

        if k_hashes == 0
            || k_hashes > 32
            || shingle_words < 3
            || window_bytes < 24
            || m_bits == 0
            || m_bits > MAX_BITS
            || !m_bits.is_multiple_of(8)
        {
            return Err(BloomError::InvalidParameters);
        }

        let expected = usize::try_from(m_bits / 8).map_err(|_| BloomError::InvalidParameters)?;
        let actual = bytes.len() - HEADER_LEN;
        if actual != expected {
            return Err(BloomError::BitsetLengthMismatch { expected, actual });
        }

        Ok(Self {
            k_hashes,
            shingle_words,
            window_bytes,
            m_bits,
            inserted_shingles,
            salt,
            bits: bytes[HEADER_LEN..].to_vec(),
        })
    }

    fn insert_shingle(&mut self, shingle: &[u8]) {
        let (h1, h2) = self.double_hash(shingle);
        for i in 0..u64::from(self.k_hashes) {
            let bit_idx = h1.wrapping_add(i.wrapping_mul(h2)) % self.m_bits;
            let byte_idx = (bit_idx / 8) as usize;
            let mask = 1u8 << (bit_idx % 8);
            self.bits[byte_idx] |= mask;
        }
        self.inserted_shingles = self.inserted_shingles.saturating_add(1);
    }

    fn contains_shingle(&self, shingle: &[u8]) -> bool {
        let (h1, h2) = self.double_hash(shingle);
        for i in 0..u64::from(self.k_hashes) {
            let bit_idx = h1.wrapping_add(i.wrapping_mul(h2)) % self.m_bits;
            let byte_idx = (bit_idx / 8) as usize;
            let mask = 1u8 << (bit_idx % 8);
            if self.bits[byte_idx] & mask == 0 {
                return false;
            }
        }
        true
    }

    fn double_hash(&self, shingle: &[u8]) -> (u64, u64) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.salt);
        hasher.update(shingle);
        let digest = hasher.finalize();
        let bytes = digest.as_bytes();
        let h1 = u64::from_le_bytes(bytes[0..8].try_into().expect("8 bytes"));
        let h2 = u64::from_le_bytes(bytes[8..16].try_into().expect("8 bytes")) | 1;
        (h1, h2)
    }
}

fn for_each_shingle<F: FnMut(&[u8])>(
    normalized: &str,
    shingle_words: u8,
    window_bytes: u8,
    mut f: F,
) {
    let words: Vec<&str> = normalized.split(' ').filter(|w| !w.is_empty()).collect();
    let w = usize::from(shingle_words);
    if words.len() >= w {
        let mut joined = String::new();
        for win in words.windows(w) {
            joined.clear();
            for (idx, word) in win.iter().enumerate() {
                if idx > 0 {
                    joined.push(' ');
                }
                joined.push_str(word);
            }
            if joined.len() >= 24 {
                f(joined.as_bytes());
            }
        }
    }

    // Also emit sliding byte windows for compact non-whitespace rows (CSV/JSONL).
    let raw = normalized.as_bytes();
    let win_len = usize::from(window_bytes);
    if raw.len() >= win_len {
        let stride = (win_len / 4).max(8);
        let mut offset = 0;
        while offset + win_len <= raw.len() {
            f(&raw[offset..offset + win_len]);
            offset += stride;
        }
    }
}

fn normalize_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut prev_space = true;
    for ch in input.chars() {
        if ch.is_whitespace() {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.push(ch.to_ascii_lowercase());
            prev_space = false;
        }
    }
    if out.ends_with(' ') {
        out.pop();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_zero_raw_text_in_serialized_bytes() {
        let secret_memo = "Project Orion confidential acquisition target valuation forty-two million dollars in mezzanine tranche B";
        let mut bloom = ShingleBloom::new(BloomConfig::default());
        bloom.insert_text(secret_memo);
        let serialized = bloom.to_bytes();

        // Serialized filter must never contain raw substrings of the source text.
        assert!(!serialized.windows(12).any(|w| w == b"Project Orio"));
        assert!(!serialized.windows(11).any(|w| w == b"acquisition"));

        let loaded = ShingleBloom::from_bytes(&serialized).expect("valid bloom");
        assert!(loaded.matches(
            "FYI summary: project orion confidential acquisition target valuation forty-two million dollars in mezzanine tranche B",
            2
        ));
        assert!(!loaded.matches(
            "fn main() { println!(\"hello world from normal rust source code\"); }",
            2
        ));
    }
}
