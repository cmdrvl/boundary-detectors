use std::sync::OnceLock;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use regex::{Regex, RegexSet};

use crate::{Finding, Pack, Severity, hash_match};

const DATA_URI_PATTERN: &str =
    r"data:[a-zA-Z0-9.+/-]+(?:;[a-zA-Z0-9=._-]+)*;base64,([A-Za-z0-9+/=_-]{24,})";
const BASE64_TOKEN_PATTERN: &str = r"[A-Za-z0-9+/_-]{24,}={0,2}";
const HEX_TOKEN_PATTERN: &str = r"\b(?:[0-9a-fA-F]{2}){16,}\b";

/// A decoded base64 or hex candidate extracted for bounded recursive rescanning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedCandidate {
    pub outer_span: (usize, usize),
    pub decoded: Vec<u8>,
}

struct BlobPatterns {
    candidates: RegexSet,
    data_uri: Regex,
    base64_token: Regex,
    hex_token: Regex,
}

fn patterns() -> &'static BlobPatterns {
    static PATTERNS: OnceLock<BlobPatterns> = OnceLock::new();
    PATTERNS.get_or_init(|| BlobPatterns {
        candidates: RegexSet::new([DATA_URI_PATTERN, BASE64_TOKEN_PATTERN, HEX_TOKEN_PATTERN])
            .expect("valid blob candidate regex set"),
        data_uri: Regex::new(DATA_URI_PATTERN).expect("valid data_uri regex"),
        base64_token: Regex::new(BASE64_TOKEN_PATTERN).expect("valid base64_token regex"),
        hex_token: Regex::new(HEX_TOKEN_PATTERN).expect("valid hex_token regex"),
    })
}

/// Scan `text` for `data:` URIs and long base64/hex blob runs.
pub fn scan(text: &str, min_len: usize, depth: u8) -> Vec<Finding> {
    let p = patterns();
    let mut out = Vec::new();
    if !p.candidates.is_match(text) {
        return out;
    }
    let effective_min = min_len.max(32);

    for m in p.data_uri.find_iter(text) {
        out.push(Finding {
            pack: Pack::Blobs,
            rule_id: "BLOB_DATA_URI".to_string(),
            severity: Severity::High,
            byte_span: (m.start(), m.end()),
            match_len: m.len(),
            match_hash: hash_match(m.as_str().as_bytes()),
            depth,
        });
    }

    for m in p.hex_token.find_iter(text) {
        if m.len() >= effective_min {
            out.push(Finding {
                pack: Pack::Blobs,
                rule_id: "BLOB_HEX_RUN".to_string(),
                severity: Severity::High,
                byte_span: (m.start(), m.end()),
                match_len: m.len(),
                match_hash: hash_match(m.as_str().as_bytes()),
                depth,
            });
        }
    }

    for m in p.base64_token.find_iter(text) {
        let s = m.as_str();
        if s.len() >= effective_min && !is_pure_hex(s) && looks_like_base64(s) {
            out.push(Finding {
                pack: Pack::Blobs,
                rule_id: "BLOB_BASE64_RUN".to_string(),
                severity: Severity::High,
                byte_span: (m.start(), m.end()),
                match_len: s.len(),
                match_hash: hash_match(s.as_bytes()),
                depth,
            });
        }
    }

    out
}

/// Extract bounded decoded payloads from base64 tokens, `data:` URIs, and hex
/// runs so the top-level scanner can recursively rescan wrapped leaks.
pub fn extract_decodable_candidates(text: &str, max_decoded_bytes: usize) -> Vec<DecodedCandidate> {
    if max_decoded_bytes == 0 {
        return Vec::new();
    }
    let p = patterns();
    let mut out = Vec::new();
    if !p.candidates.is_match(text) {
        return out;
    }
    let mut budget = max_decoded_bytes;

    for caps in p.data_uri.captures_iter(text) {
        if budget == 0 {
            break;
        }
        let full = caps.get(0).expect("match 0");
        let payload = &caps[1];
        if let Some(decoded) = decode_base64_bounded(payload, budget) {
            budget -= decoded.len();
            out.push(DecodedCandidate {
                outer_span: (full.start(), full.end()),
                decoded,
            });
        }
    }

    for m in p.hex_token.find_iter(text) {
        if budget == 0 {
            break;
        }
        if let Some(decoded) = decode_hex_bounded(m.as_str(), budget)
            && is_mostly_printable_text(&decoded)
        {
            budget -= decoded.len();
            out.push(DecodedCandidate {
                outer_span: (m.start(), m.end()),
                decoded,
            });
        }
    }

    for m in p.base64_token.find_iter(text) {
        if budget == 0 {
            break;
        }
        let s = m.as_str();
        if is_pure_hex(s) || !looks_like_base64(s) {
            continue;
        }
        if let Some(decoded) = decode_base64_bounded(s, budget)
            && is_mostly_printable_text(&decoded)
        {
            budget -= decoded.len();
            out.push(DecodedCandidate {
                outer_span: (m.start(), m.end()),
                decoded,
            });
        }
    }

    out
}

fn is_pure_hex(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn looks_like_base64(s: &str) -> bool {
    if s.len() < 24 {
        return false;
    }
    let has_upper = s.bytes().any(|b| b.is_ascii_uppercase());
    let has_lower = s.bytes().any(|b| b.is_ascii_lowercase());
    let has_digit = s.bytes().any(|b| b.is_ascii_digit());
    let has_sym = s
        .bytes()
        .any(|b| matches!(b, b'+' | b'/' | b'=' | b'-' | b'_'));
    let classes = usize::from(has_upper)
        + usize::from(has_lower)
        + usize::from(has_digit)
        + usize::from(has_sym);
    classes >= 2
}

fn decode_base64_bounded(input: &str, max_bytes: usize) -> Option<Vec<u8>> {
    let trimmed = input.trim();
    if trimmed.len() / 4 * 3 > max_bytes.saturating_add(3) {
        return None;
    }
    let decoded = STANDARD
        .decode(trimmed)
        .or_else(|_| URL_SAFE.decode(trimmed))
        .or_else(|_| STANDARD_NO_PAD.decode(trimmed))
        .or_else(|_| URL_SAFE_NO_PAD.decode(trimmed))
        .ok()?;
    if decoded.is_empty() || decoded.len() > max_bytes {
        return None;
    }
    Some(decoded)
}

fn decode_hex_bounded(input: &str, max_bytes: usize) -> Option<Vec<u8>> {
    if !input.len().is_multiple_of(2) || input.len() / 2 > max_bytes {
        return None;
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    for pair in bytes.as_chunks::<2>().0 {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn is_mostly_printable_text(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let printable = bytes
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        .count();
    printable * 10 >= bytes.len() * 8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_candidate_filter_preserves_base64_and_hex_scans() {
        let secret = b"api_key=q8Z9kL2mN5pR7tV9xY1bC4dF6hJ8";
        let base64 = STANDARD.encode(secret);
        let hex = "41".repeat(32);
        let input = format!("{base64} {hex}");

        let findings = scan(&input, 32, 0);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "BLOB_BASE64_RUN")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "BLOB_HEX_RUN")
        );

        let candidates = extract_decodable_candidates(&input, 1024);
        assert_eq!(candidates.len(), 2);
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.decoded.as_slice() == secret.as_slice())
        );
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.decoded == vec![b'A'; 32])
        );

        let ordinary = "ordinary prose with no long encoded runs";
        assert!(scan(ordinary, 32, 0).is_empty());
        assert!(extract_decodable_candidates(ordinary, 1024).is_empty());
    }
}
