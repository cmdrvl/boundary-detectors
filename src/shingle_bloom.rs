use std::fmt;

use crate::{Finding, Pack, Severity, hash_match};

const MAGIC: [u8; 4] = *b"BDBL";
const FORMAT_VERSION: u8 = 1;
const HEADER_LEN: usize = 40;
const MAX_BITS: u64 = 64 * 1024 * 1024 * 8; // 64 MiB max bitset
const PARALLEL_SCAN_MIN_BYTES: usize = 128 * 1024;
const MAX_SCAN_WORKERS: usize = 8;

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
        // A power-of-two bit count lets membership checks use a mask instead
        // of an integer remainder for every shingle hash.
        let m_bits = m_raw.clamp(1024, MAX_BITS).next_power_of_two();
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
        if normalized.len() >= PARALLEL_SCAN_MIN_BYTES {
            let workers = std::thread::available_parallelism()
                .map(|parallelism| parallelism.get().min(MAX_SCAN_WORKERS))
                .unwrap_or(1);
            return self.count_hits_parallel(&normalized, workers);
        }
        self.count_hits_serial(&normalized)
    }

    fn count_hits_serial(&self, normalized: &str) -> usize {
        let mut hits = 0;
        for_each_shingle(
            normalized,
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

    fn count_shingles(&self, shingles: &[&[u8]]) -> usize {
        shingles
            .iter()
            .filter(|shingle| self.contains_shingle(shingle))
            .count()
    }

    fn count_hits_parallel(&self, normalized: &str, workers: usize) -> usize {
        let mut shingles = Vec::with_capacity(normalized.len() / 4);
        for_each_shingle(
            normalized,
            self.shingle_words,
            self.window_bytes,
            |shingle| shingles.push(shingle),
        );
        if shingles.is_empty() {
            return 0;
        }
        if workers <= 1 {
            return self.count_shingles(&shingles);
        }

        let chunk_count = workers.min(shingles.len());
        let chunk_size = shingles.len().div_ceil(chunk_count);
        std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(chunk_count);
            let mut hits = 0;
            for chunk in shingles.chunks(chunk_size) {
                match std::thread::Builder::new()
                    .spawn_scoped(scope, move || self.count_shingles(chunk))
                {
                    Ok(handle) => handles.push((chunk, handle)),
                    Err(_) => hits += self.count_shingles(chunk),
                }
            }
            for (chunk, handle) in handles {
                hits += handle.join().unwrap_or_else(|_| self.count_shingles(chunk));
            }
            hits
        })
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
        let bit_mask = self.m_bits - 1;
        if self.m_bits.is_power_of_two() {
            let mut bit_idx = h1 & bit_mask;
            let step = h2 & bit_mask;
            for _ in 0..self.k_hashes {
                let byte_idx = (bit_idx / 8) as usize;
                let bit = 1u8 << (bit_idx % 8);
                self.bits[byte_idx] |= bit;
                bit_idx = bit_idx.wrapping_add(step) & bit_mask;
            }
        } else {
            for i in 0..u64::from(self.k_hashes) {
                let bit_idx = h1.wrapping_add(i.wrapping_mul(h2)) % self.m_bits;
                let byte_idx = (bit_idx / 8) as usize;
                let bit = 1u8 << (bit_idx % 8);
                self.bits[byte_idx] |= bit;
            }
        }
        self.inserted_shingles = self.inserted_shingles.saturating_add(1);
    }

    fn contains_shingle(&self, shingle: &[u8]) -> bool {
        let (h1, h2) = self.double_hash(shingle);
        let bit_mask = self.m_bits - 1;
        if self.m_bits.is_power_of_two() {
            let mut bit_idx = h1 & bit_mask;
            let step = h2 & bit_mask;
            for _ in 0..self.k_hashes {
                let byte_idx = (bit_idx / 8) as usize;
                let bit = 1u8 << (bit_idx % 8);
                if self.bits[byte_idx] & bit == 0 {
                    return false;
                }
                bit_idx = bit_idx.wrapping_add(step) & bit_mask;
            }
        } else {
            for i in 0..u64::from(self.k_hashes) {
                let bit_idx = h1.wrapping_add(i.wrapping_mul(h2)) % self.m_bits;
                let byte_idx = (bit_idx / 8) as usize;
                let bit = 1u8 << (bit_idx % 8);
                if self.bits[byte_idx] & bit == 0 {
                    return false;
                }
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

fn for_each_shingle<'a, F: FnMut(&'a [u8])>(
    normalized: &'a str,
    shingle_words: u8,
    window_bytes: u8,
    mut f: F,
) {
    let w = usize::from(shingle_words);
    let raw = normalized.as_bytes();
    let mut word_starts = [0usize; 255];
    let mut next = 0;
    let mut words_seen = 0;
    let mut add_word = |start, end| {
        word_starts[next] = start;
        next += 1;
        if next == w {
            next = 0;
        }
        words_seen = (words_seen + 1).min(w);
        if words_seen == w {
            let shingle_start = word_starts[next];
            if end - shingle_start >= 24 {
                f(&raw[shingle_start..end]);
            }
        }
    };
    let mut word_start = None;
    for (idx, byte) in raw.iter().enumerate() {
        if *byte == b' ' {
            if let Some(start) = word_start.take() {
                add_word(start, idx);
            }
        } else if word_start.is_none() {
            word_start = Some(idx);
        }
    }
    if let Some(start) = word_start {
        add_word(start, raw.len());
    }

    // Also emit sliding byte windows for compact non-whitespace rows (CSV/JSONL).
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
        let protected_source = "Project Orion confidential acquisition target valuation forty-two million dollars in mezzanine tranche B";
        let mut bloom = ShingleBloom::new(BloomConfig::default());
        assert!(bloom.bit_len().is_power_of_two());
        bloom.insert_text(protected_source);
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

    #[test]
    fn non_power_of_two_serialized_filters_keep_the_legacy_index_path() {
        let mut bloom = ShingleBloom::new(BloomConfig {
            expected_shingles: 1_000,
            false_positive_rate: 0.01,
            ..BloomConfig::default()
        });
        // This is the v1 size and hash count for the configuration above.
        bloom.m_bits = 9_592;
        bloom.k_hashes = 7;
        bloom
            .bits
            .truncate(usize::try_from(bloom.m_bits / 8).expect("test size fits"));
        let phrase =
            "legacy serialized filter payload preserves the original salted bloom index mapping";
        let probe = &phrase.as_bytes()[..64];
        let (h1, h2) = bloom.double_hash(probe);
        for i in 0..u64::from(bloom.k_hashes) {
            let bit_idx = h1.wrapping_add(i.wrapping_mul(h2)) % bloom.m_bits;
            let byte_idx = usize::try_from(bit_idx / 8).expect("test size fits");
            let bit = 1u8 << (bit_idx % 8);
            bloom.bits[byte_idx] |= bit;
        }
        bloom.inserted_shingles = 1;

        let legacy = ShingleBloom::from_bytes(&bloom.to_bytes()).expect("valid legacy filter");
        assert_eq!(legacy.bit_len(), 9_592);
        assert!(legacy.matches(phrase, 1));
    }

    #[test]
    fn parallel_scan_preserves_serial_hit_counts() {
        let protected_text =
            "project orion confidential acquisition target valuation forty two million dollars";
        let mut bloom = ShingleBloom::new(BloomConfig::default());
        bloom.insert_text(protected_text);

        let mut text = "alpha beta gamma delta epsilon zeta eta theta ".repeat(4_000);
        text.push_str(protected_text);
        let normalized = normalize_text(&text);
        assert!(normalized.len() >= PARALLEL_SCAN_MIN_BYTES);

        let serial_hits = bloom.count_hits_serial(&normalized);
        let parallel_hits = bloom.count_hits_parallel(&normalized, 4);
        assert!(parallel_hits > 0);
        assert_eq!(parallel_hits, serial_hits);
    }
}
