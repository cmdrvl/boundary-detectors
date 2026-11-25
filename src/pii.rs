use std::sync::OnceLock;

use regex::Regex;

use crate::{Finding, Pack, Severity, hash_match};

struct PiiPatterns {
    ssn: Regex,
    card: Regex,
    email: Regex,
    e164_phone: Regex,
    us_phone: Regex,
    iban: Regex,
}

fn patterns() -> &'static PiiPatterns {
    static PATTERNS: OnceLock<PiiPatterns> = OnceLock::new();
    PATTERNS.get_or_init(|| PiiPatterns {
        ssn: Regex::new(r"\b(\d{3})-(\d{2})-(\d{4})\b").expect("valid ssn regex"),
        card: Regex::new(r"\b(?:\d[ -]?){13,19}\b").expect("valid card regex"),
        email: Regex::new(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
            .expect("valid email regex"),
        e164_phone: Regex::new(r"(?:^|[^0-9A-Za-z])(\+[1-9]\d{6,14})\b")
            .expect("valid e164_phone regex"),
        us_phone: Regex::new(r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b")
            .expect("valid us_phone regex"),
        iban: Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b").expect("valid iban regex"),
    })
}

/// Validate a sequence of ASCII digit bytes using the Luhn checksum.
pub fn luhn_valid(digits: &[u8]) -> bool {
    if !(13..=19).contains(&digits.len()) || !digits.iter().all(u8::is_ascii_digit) {
        return false;
    }
    let mut sum: u32 = 0;
    let mut double = false;
    for &b in digits.iter().rev() {
        let mut d = u32::from(b - b'0');
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }
    sum.is_multiple_of(10)
}

/// Validate an IBAN using the ISO 13616 mod-97 algorithm.
pub fn iban_valid(iban: &str) -> bool {
    let bytes = iban.as_bytes();
    if !(15..=34).contains(&bytes.len()) {
        return false;
    }
    if !bytes[0].is_ascii_uppercase()
        || !bytes[1].is_ascii_uppercase()
        || !bytes[2].is_ascii_digit()
        || !bytes[3].is_ascii_digit()
    {
        return false;
    }
    let mut remainder: u32 = 0;
    for &b in bytes[4..].iter().chain(&bytes[..4]) {
        if b.is_ascii_digit() {
            remainder = (remainder * 10 + u32::from(b - b'0')) % 97;
        } else if b.is_ascii_uppercase() {
            let val = u32::from(b - b'A' + 10);
            remainder = (remainder * 100 + val) % 97;
        } else {
            return false;
        }
    }
    remainder == 1
}

fn is_exempt_domain(domain: &str, exempt_domains: &[String]) -> bool {
    let lower = domain.to_ascii_lowercase();
    exempt_domains.iter().any(|exempt| {
        let e = exempt.to_ascii_lowercase();
        lower == e || lower.ends_with(&format!(".{e}"))
    })
}

/// Scan `text` for US SSNs, Luhn-valid payment cards, emails, phone numbers,
/// and mod-97-valid IBANs.
pub fn scan(text: &str, exempt_email_domains: &[String], depth: u8) -> Vec<Finding> {
    let p = patterns();
    let mut out = Vec::new();

    for caps in p.ssn.captures_iter(text) {
        let full = caps.get(0).expect("match 0");
        let area: u16 = caps[1].parse().unwrap_or(0);
        let group: u16 = caps[2].parse().unwrap_or(0);
        let serial: u16 = caps[3].parse().unwrap_or(0);
        if area != 0 && area != 666 && area < 900 && group != 0 && serial != 0 {
            out.push(Finding {
                pack: Pack::Pii,
                rule_id: "PII_US_SSN".to_string(),
                severity: Severity::Critical,
                byte_span: (full.start(), full.end()),
                match_len: full.len(),
                match_hash: hash_match(full.as_str().as_bytes()),
                depth,
            });
        }
    }

    for m in p.card.find_iter(text) {
        let raw = m.as_str();
        let digits: Vec<u8> = raw.bytes().filter(u8::is_ascii_digit).collect();
        if luhn_valid(&digits) {
            out.push(Finding {
                pack: Pack::Pii,
                rule_id: "PII_PAYMENT_CARD".to_string(),
                severity: Severity::Critical,
                byte_span: (m.start(), m.end()),
                match_len: m.len(),
                match_hash: hash_match(raw.as_bytes()),
                depth,
            });
        }
    }

    for caps in p.email.captures_iter(text) {
        let full = caps.get(0).expect("match 0");
        let domain = &caps[1];
        if !is_exempt_domain(domain, exempt_email_domains) {
            out.push(Finding {
                pack: Pack::Pii,
                rule_id: "PII_EMAIL".to_string(),
                severity: Severity::Medium,
                byte_span: (full.start(), full.end()),
                match_len: full.len(),
                match_hash: hash_match(full.as_str().as_bytes()),
                depth,
            });
        }
    }

    for caps in p.e164_phone.captures_iter(text) {
        let m = caps.get(1).expect("group 1");
        out.push(Finding {
            pack: Pack::Pii,
            rule_id: "PII_PHONE_E164".to_string(),
            severity: Severity::Medium,
            byte_span: (m.start(), m.end()),
            match_len: m.len(),
            match_hash: hash_match(m.as_str().as_bytes()),
            depth,
        });
    }

    for m in p.us_phone.find_iter(text) {
        out.push(Finding {
            pack: Pack::Pii,
            rule_id: "PII_PHONE_US".to_string(),
            severity: Severity::Medium,
            byte_span: (m.start(), m.end()),
            match_len: m.len(),
            match_hash: hash_match(m.as_str().as_bytes()),
            depth,
        });
    }

    for m in p.iban.find_iter(text) {
        if iban_valid(m.as_str()) {
            out.push(Finding {
                pack: Pack::Pii,
                rule_id: "PII_IBAN".to_string(),
                severity: Severity::High,
                byte_span: (m.start(), m.end()),
                match_len: m.len(),
                match_hash: hash_match(m.as_str().as_bytes()),
                depth,
            });
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_luhn_and_iban() {
        assert!(luhn_valid(b"4532015112830366"));
        assert!(!luhn_valid(b"4532015112830367"));
        assert!(iban_valid("DE89370400440532013000"));
        assert!(!iban_valid("DE89370400440532013001"));
    }

    #[test]
    fn detects_ssn_and_respects_email_exemptions() {
        let text = "ssn 123-45-6789 mail alice@example.com dev bob@users.noreply.github.com";
        let exempt = vec!["users.noreply.github.com".to_string()];
        let findings = scan(text, &exempt, 0);
        let emails: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.rule_id == "PII_EMAIL")
            .collect();
        assert_eq!(emails.len(), 1);
        assert!(findings.iter().any(|f| f.rule_id == "PII_US_SSN"));
    }
}
