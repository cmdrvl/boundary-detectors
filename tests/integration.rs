use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use boundary_detectors::magic::{MagicKind, sniff};
use boundary_detectors::shingle_bloom::{BloomConfig, ShingleBloom};
use boundary_detectors::{Pack, ScanConfig, Scanner};

#[test]
fn recursive_base64_decode_catches_wrapped_secret_and_csv() {
    let raw_csv = "loan_id,borrower_ssn,upb\nL-1001,123-45-6789,5000000\nL-1002,234-56-7890,6200000\nL-1003,345-67-8901,7100000\nL-1004,456-78-9012,8300000\n";
    let encoded = STANDARD.encode(raw_csv);
    let payload = format!("wrapped payload: {encoded}");

    let scanner = Scanner::new(ScanConfig::default());
    let findings = scanner.scan_str(&payload);

    assert!(
        findings
            .iter()
            .any(|f| f.pack == Pack::Pii && f.rule_id == "PII_US_SSN" && f.depth == 1)
    );
    assert!(
        findings
            .iter()
            .any(|f| f.pack == Pack::Tabular && f.rule_id == "TABULAR_CSV_BLOCK" && f.depth == 1)
    );

    // Ensure zero raw sensitive values appear in serialized JSON findings.
    let json = serde_json::to_string(&findings).expect("serialize findings");
    assert!(!json.contains("123-45-6789"));
    assert!(!json.contains("L-1001"));
}

#[test]
fn protected_corpus_bloom_catches_base64_encoded_memo() {
    let protected_doc = "Confidential credit committee memorandum regarding Meridian Plaza senior bridge loan extension and covenant waiver schedule";
    let mut bloom = ShingleBloom::new(BloomConfig::default());
    bloom.insert_text(protected_doc);
    let reloaded = ShingleBloom::from_bytes(&bloom.to_bytes()).expect("roundtrip bloom");

    let encoded = STANDARD.encode(protected_doc);
    let scanner = Scanner::with_bloom(
        ScanConfig::with_packs(vec![Pack::ProtectedCorpus, Pack::Blobs]),
        reloaded,
    );

    let findings = scanner.scan_str(&format!("blob={encoded}"));
    assert!(
        findings
            .iter()
            .any(|f| f.pack == Pack::ProtectedCorpus && f.rule_id == "PROTECTED_CORPUS_MATCH")
    );
}

#[test]
fn clean_code_produces_zero_findings() {
    let code = r#"
pub fn add(a: i64, b: i64) -> i64 {
    a.saturating_add(b)
}
"#;
    let scanner = Scanner::new(ScanConfig::default());
    assert!(scanner.scan_str(code).is_empty());
}

#[test]
fn magic_sniffer_identifies_containers() {
    assert_eq!(sniff(b"PAR1\x00\x00"), Some(MagicKind::Parquet));
    assert_eq!(sniff(b"SQLite format 3\0"), Some(MagicKind::Sqlite));
    assert_eq!(sniff(b"PK\x03\x04"), Some(MagicKind::ZipOrXlsx));
    assert_eq!(sniff(b"%PDF-1.7\n"), Some(MagicKind::Pdf));
}
