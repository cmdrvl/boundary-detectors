use std::sync::OnceLock;

use regex::Regex;

use crate::{Finding, Pack, Severity, hash_match};

struct PathPatterns {
    file_uri: Regex,
    posix_abs: Regex,
    home_tilde: Regex,
    windows_abs: Regex,
}

fn patterns() -> &'static PathPatterns {
    static PATTERNS: OnceLock<PathPatterns> = OnceLock::new();
    PATTERNS.get_or_init(|| PathPatterns {
        file_uri: Regex::new(r#"file://[^\s"'<>]+"#).expect("valid file_uri regex"),
        posix_abs: Regex::new(
            r#"(?:^|[\s"'=(:,])(/(?:Users|home|etc|var|tmp|private|opt|srv|mnt|Volumes|root)/[A-Za-z0-9._/@%+-]+)"#,
        )
        .expect("valid posix_abs regex"),
        home_tilde: Regex::new(r#"(?:^|[\s"'=(:,])(~/[A-Za-z0-9._/@%+-]+)"#)
            .expect("valid home_tilde regex"),
        windows_abs: Regex::new(
            r#"\b[A-Za-z]:\\(?:Users|Windows|ProgramData|Temp|Data)\\[^\s"'<>]+"#,
        )
        .expect("valid windows_abs regex"),
    })
}

/// Scan `text` for absolute filesystem paths, `~/` home paths, `file://` URIs,
/// and Windows drive paths.
pub fn scan(text: &str, depth: u8) -> Vec<Finding> {
    let p = patterns();
    let mut out = Vec::new();

    for m in p.file_uri.find_iter(text) {
        out.push(Finding {
            pack: Pack::Paths,
            rule_id: "PATH_FILE_URI".to_string(),
            severity: Severity::Medium,
            byte_span: (m.start(), m.end()),
            match_len: m.len(),
            match_hash: hash_match(m.as_str().as_bytes()),
            depth,
        });
    }

    for caps in p.posix_abs.captures_iter(text) {
        let m = caps.get(1).expect("group 1");
        out.push(Finding {
            pack: Pack::Paths,
            rule_id: "PATH_POSIX_ABSOLUTE".to_string(),
            severity: Severity::Low,
            byte_span: (m.start(), m.end()),
            match_len: m.len(),
            match_hash: hash_match(m.as_str().as_bytes()),
            depth,
        });
    }

    for caps in p.home_tilde.captures_iter(text) {
        let m = caps.get(1).expect("group 1");
        out.push(Finding {
            pack: Pack::Paths,
            rule_id: "PATH_HOME_TILDE".to_string(),
            severity: Severity::Low,
            byte_span: (m.start(), m.end()),
            match_len: m.len(),
            match_hash: hash_match(m.as_str().as_bytes()),
            depth,
        });
    }

    for m in p.windows_abs.find_iter(text) {
        out.push(Finding {
            pack: Pack::Paths,
            rule_id: "PATH_WINDOWS_ABSOLUTE".to_string(),
            severity: Severity::Low,
            byte_span: (m.start(), m.end()),
            match_len: m.len(),
            match_hash: hash_match(m.as_str().as_bytes()),
            depth,
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_posix_tilde_and_file_uri() {
        let s = "open /Users/alice/secret.csv or ~/.ssh/id_ed25519 or file:///etc/passwd";
        let findings = scan(s, 0);
        let rules: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(rules.contains(&"PATH_POSIX_ABSOLUTE"));
        assert!(rules.contains(&"PATH_HOME_TILDE"));
        assert!(rules.contains(&"PATH_FILE_URI"));
    }
}
