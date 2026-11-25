use std::sync::OnceLock;

use regex::Regex;

use crate::{Finding, Pack, Severity, hash_match};

const HIGH_ENTROPY_THRESHOLD: f64 = 3.5;

struct SecretPatterns {
    aws_key: Regex,
    pem_key: Regex,
    jwt: Regex,
    github: Regex,
    slack: Regex,
    anthropic: Regex,
    openai: Regex,
    generic_assignment: Regex,
}

fn patterns() -> &'static SecretPatterns {
    static PATTERNS: OnceLock<SecretPatterns> = OnceLock::new();
    PATTERNS.get_or_init(|| SecretPatterns {
        aws_key: Regex::new(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b").expect("valid aws_key regex"),
        pem_key: Regex::new(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")
            .expect("valid pem_key regex"),
        jwt: Regex::new(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
            .expect("valid jwt regex"),
        github: Regex::new(
            r"\b(?:ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,82})\b",
        )
        .expect("valid github regex"),
        slack: Regex::new(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b").expect("valid slack regex"),
        anthropic: Regex::new(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b").expect("valid anthropic regex"),
        openai: Regex::new(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b")
            .expect("valid openai regex"),
        generic_assignment: Regex::new(
            r#"(?i)\b(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|private[_-]?key|password|passwd|client[_-]?secret)\b\s*[:=]\s*["']?([A-Za-z0-9+/=._-]{20,})["']?"#,
        )
        .expect("valid generic_assignment regex"),
    })
}

/// Compute Shannon entropy in bits per byte.
pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[usize::from(b)] += 1;
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0;
    for count in counts {
        if count > 0 {
            let p = f64::from(count) / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Scan `text` for hardcoded credentials, private keys, tokens, and
/// high-entropy secret assignments.
pub fn scan(text: &str, depth: u8) -> Vec<Finding> {
    let p = patterns();
    let mut out = Vec::new();

    let fixed_rules: &[(&Regex, &str, Severity)] = &[
        (&p.aws_key, "SECRET_AWS_ACCESS_KEY", Severity::Critical),
        (&p.pem_key, "SECRET_PEM_PRIVATE_KEY", Severity::Critical),
        (&p.jwt, "SECRET_JWT", Severity::High),
        (&p.github, "SECRET_GITHUB_TOKEN", Severity::Critical),
        (&p.slack, "SECRET_SLACK_TOKEN", Severity::High),
        (&p.anthropic, "SECRET_ANTHROPIC_KEY", Severity::Critical),
        (&p.openai, "SECRET_OPENAI_KEY", Severity::Critical),
    ];

    for (regex, rule_id, severity) in fixed_rules {
        for m in regex.find_iter(text) {
            out.push(Finding {
                pack: Pack::Secrets,
                rule_id: (*rule_id).to_string(),
                severity: *severity,
                byte_span: (m.start(), m.end()),
                match_len: m.len(),
                match_hash: hash_match(m.as_str().as_bytes()),
                depth,
            });
        }
    }

    for caps in p.generic_assignment.captures_iter(text) {
        if let Some(val) = caps.get(1)
            && shannon_entropy(val.as_str().as_bytes()) >= HIGH_ENTROPY_THRESHOLD
        {
            out.push(Finding {
                pack: Pack::Secrets,
                rule_id: "SECRET_HIGH_ENTROPY_ASSIGNMENT".to_string(),
                severity: Severity::High,
                byte_span: (val.start(), val.end()),
                match_len: val.len(),
                match_hash: hash_match(val.as_str().as_bytes()),
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
    fn detects_aws_and_pem_and_high_entropy() {
        let sample = "aws=AKIAIOSFODNN7EXAMPLE\n-----BEGIN RSA PRIVATE KEY-----\napi_key = \"q8Z9kL2mN5pR7tV9xY1bC4dF6hJ8\"\n";
        let findings = scan(sample, 0);
        let rules: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(rules.contains(&"SECRET_AWS_ACCESS_KEY"));
        assert!(rules.contains(&"SECRET_PEM_PRIVATE_KEY"));
        assert!(rules.contains(&"SECRET_HIGH_ENTROPY_ASSIGNMENT"));
    }

    #[test]
    fn ignores_low_entropy_placeholder_assignment() {
        let sample = "api_key = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaa\"";
        let findings = scan(sample, 0);
        assert!(findings.is_empty());
    }
}
