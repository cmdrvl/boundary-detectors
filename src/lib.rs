#![forbid(unsafe_code)]

//! Deterministic pure-Rust content boundary detectors shared by CMD+RVL ingress
//! (`veil`) and egress (`airlock`) boundaries.
//!
//! Findings never echo matched raw values; every finding reports only byte
//! spans, lengths, rule identifiers, recursion depth, and a `blake3:` digest.

pub mod blobs;
pub mod magic;
pub mod paths;
pub mod pii;
pub mod secrets;
pub mod shingle_bloom;
pub mod tabular;

use serde::{Deserialize, Serialize};
use shingle_bloom::ShingleBloom;

const PARALLEL_COMBINED_SCAN_MIN_BYTES: usize = 128 * 1024;

/// Detector pack categories that can be enabled independently in policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Pack {
    Secrets,
    Pii,
    Tabular,
    Blobs,
    Paths,
    ProtectedCorpus,
}

/// Finding severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// A single deterministic boundary finding. Never contains matched raw text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub pack: Pack,
    pub rule_id: String,
    pub severity: Severity,
    pub byte_span: (usize, usize),
    pub match_len: usize,
    pub match_hash: String,
    pub depth: u8,
}

/// Configuration controlling active packs and decoding/scanning budgets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanConfig {
    pub packs: Vec<Pack>,
    pub tabular_min_rows: usize,
    pub tabular_min_columns: usize,
    pub blob_min_len: usize,
    pub max_decode_depth: u8,
    pub max_decoded_bytes: usize,
    pub max_input_bytes: usize,
    pub exempt_email_domains: Vec<String>,
    pub shingle_min_hits: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            packs: vec![
                Pack::Secrets,
                Pack::Pii,
                Pack::Tabular,
                Pack::Blobs,
                Pack::Paths,
            ],
            tabular_min_rows: 5,
            tabular_min_columns: 3,
            blob_min_len: 512,
            max_decode_depth: 2,
            max_decoded_bytes: 256 * 1024,
            max_input_bytes: 4 * 1024 * 1024,
            exempt_email_domains: Vec::new(),
            shingle_min_hits: 2,
        }
    }
}

impl ScanConfig {
    /// Construct a config with explicit enabled packs and default budgets.
    pub fn with_packs(packs: Vec<Pack>) -> Self {
        Self {
            packs,
            ..Self::default()
        }
    }

    pub fn has_pack(&self, pack: Pack) -> bool {
        self.packs.contains(&pack)
    }
}

/// Compute a canonical `blake3:<hex>` digest for a matched byte slice.
pub fn hash_match(bytes: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(bytes).to_hex())
}

/// Configured boundary scanner supporting all detector packs, bounded recursive
/// decode-and-rescan, and optional protected-corpus shingle Bloom screening.
#[derive(Debug, Clone)]
pub struct Scanner {
    config: ScanConfig,
    bloom: Option<ShingleBloom>,
}

impl Scanner {
    pub fn new(config: ScanConfig) -> Self {
        Self {
            config,
            bloom: None,
        }
    }

    pub fn with_bloom(config: ScanConfig, bloom: ShingleBloom) -> Self {
        Self {
            config,
            bloom: Some(bloom),
        }
    }

    pub fn config(&self) -> &ScanConfig {
        &self.config
    }

    /// Scan arbitrary bytes (lossy UTF-8 for text packs) within `max_input_bytes`.
    pub fn scan_bytes(&self, input: &[u8]) -> Vec<Finding> {
        let capped = if input.len() > self.config.max_input_bytes {
            &input[..self.config.max_input_bytes]
        } else {
            input
        };
        let text = String::from_utf8_lossy(capped);
        self.scan_str(&text)
    }

    /// Scan a UTF-8 string across all enabled packs with bounded recursive
    /// base64/hex decode-and-rescan.
    pub fn scan_str(&self, input: &str) -> Vec<Finding> {
        let capped = truncate_utf8(input, self.config.max_input_bytes);
        let mut findings = Vec::new();
        let mut remaining_decoded = self.config.max_decoded_bytes;
        self.scan_level(capped, 0, None, &mut remaining_decoded, &mut findings);

        findings.sort_by(|a, b| {
            a.byte_span
                .cmp(&b.byte_span)
                .then_with(|| a.depth.cmp(&b.depth))
                .then_with(|| a.pack.cmp(&b.pack))
                .then_with(|| a.rule_id.cmp(&b.rule_id))
                .then_with(|| a.match_hash.cmp(&b.match_hash))
        });
        findings.dedup_by(|a, b| {
            a.byte_span == b.byte_span
                && a.depth == b.depth
                && a.pack == b.pack
                && a.rule_id == b.rule_id
                && a.match_hash == b.match_hash
        });
        findings
    }

    fn scan_level(
        &self,
        text: &str,
        depth: u8,
        outer_span: Option<(usize, usize)>,
        remaining_decoded: &mut usize,
        out: &mut Vec<Finding>,
    ) {
        let bloom_enabled = self.bloom.is_some()
            && (self.config.has_pack(Pack::ProtectedCorpus) || !self.config.packs.is_empty());
        let other_packs_enabled = self
            .config
            .packs
            .iter()
            .any(|pack| *pack != Pack::ProtectedCorpus);

        let mut level_findings = if bloom_enabled
            && other_packs_enabled
            && text.len() >= PARALLEL_COMBINED_SCAN_MIN_BYTES
        {
            let bloom = self
                .bloom
                .as_ref()
                .expect("enabled Bloom filter is present");
            let min_hits = self.config.shingle_min_hits;
            std::thread::scope(|scope| {
                let bloom_worker = std::thread::Builder::new()
                    .spawn_scoped(scope, || bloom.scan_text(text, min_hits, depth));
                let mut findings = self.scan_packs(text, depth);
                match bloom_worker {
                    Ok(worker) => match worker.join() {
                        Ok(bloom_findings) => findings.extend(bloom_findings),
                        Err(_) => findings.extend(bloom.scan_text(text, min_hits, depth)),
                    },
                    Err(_) => findings.extend(bloom.scan_text(text, min_hits, depth)),
                }
                findings
            })
        } else {
            let mut findings = self.scan_packs(text, depth);
            if bloom_enabled && let Some(bloom) = &self.bloom {
                findings.extend(bloom.scan_text(text, self.config.shingle_min_hits, depth));
            }
            findings
        };

        if let Some(span) = outer_span {
            for finding in &mut level_findings {
                finding.byte_span = span;
            }
        }
        out.extend(level_findings);

        if depth < self.config.max_decode_depth && *remaining_decoded > 0 {
            let candidates = blobs::extract_decodable_candidates(text, *remaining_decoded);
            for candidate in candidates {
                if candidate.decoded.is_empty() || candidate.decoded.len() > *remaining_decoded {
                    continue;
                }
                *remaining_decoded -= candidate.decoded.len();
                let decoded_text = String::from_utf8_lossy(&candidate.decoded);
                let span = outer_span.unwrap_or(candidate.outer_span);
                self.scan_level(&decoded_text, depth + 1, Some(span), remaining_decoded, out);
                if *remaining_decoded == 0 {
                    break;
                }
            }
        }
    }

    fn scan_packs(&self, text: &str, depth: u8) -> Vec<Finding> {
        let mut findings = Vec::new();

        if self.config.has_pack(Pack::Secrets) {
            findings.extend(secrets::scan(text, depth));
        }
        if self.config.has_pack(Pack::Pii) {
            findings.extend(pii::scan(text, &self.config.exempt_email_domains, depth));
        }
        if self.config.has_pack(Pack::Tabular) {
            findings.extend(tabular::scan(
                text,
                self.config.tabular_min_rows,
                self.config.tabular_min_columns,
                depth,
            ));
        }
        if self.config.has_pack(Pack::Blobs) {
            findings.extend(blobs::scan(text, self.config.blob_min_len, depth));
        }
        if self.config.has_pack(Pack::Paths) {
            findings.extend(paths::scan(text, depth));
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shingle_bloom::BloomConfig;

    #[test]
    fn large_combined_scan_keeps_bloom_and_detector_findings_deterministic() {
        let protected_text = "protected corpus document words should match copied passages safely across the detector boundary";
        let mut bloom = ShingleBloom::new(BloomConfig {
            expected_shingles: 1_000,
            false_positive_rate: 0.001,
            ..BloomConfig::default()
        });
        bloom.insert_text(protected_text);

        let filler = "steady quiet review window signal record answer change branch sample memory writer reader ".repeat(3_000);
        let input = format!("aws=AKIAIOSFODNN7EXAMPLE ssn=123-45-6789 {filler} {protected_text}");
        assert!(input.len() >= PARALLEL_COMBINED_SCAN_MIN_BYTES);

        let mut config = ScanConfig::default();
        config.packs.push(Pack::ProtectedCorpus);
        let scanner = Scanner::with_bloom(config, bloom);

        let findings = scanner.scan_str(&input);
        assert!(findings.iter().any(|finding| {
            finding.pack == Pack::ProtectedCorpus && finding.rule_id == "PROTECTED_CORPUS_MATCH"
        }));
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "SECRET_AWS_ACCESS_KEY")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "PII_US_SSN")
        );
        assert_eq!(findings, scanner.scan_str(&input));
    }
}

fn truncate_utf8(input: &str, max_bytes: usize) -> &str {
    if input.len() <= max_bytes {
        return input;
    }
    let mut end = max_bytes;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    &input[..end]
}
