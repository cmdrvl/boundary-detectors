//! Attribute large-payload scan time to the default detectors and the optional
//! protected-corpus Bloom matcher. Run with
//! `cargo bench --bench shingle_bloom_latency`.

use std::time::{Duration, Instant};

use boundary_detectors::shingle_bloom::{BloomConfig, ShingleBloom};
use boundary_detectors::{Finding, Pack, ScanConfig, Scanner};

const ITERATIONS: usize = 31;

fn clean_payload(bytes: usize) -> Vec<u8> {
    const WORDS: &[&str] = &[
        "steady", "quiet", "review", "window", "signal", "record", "answer", "change", "branch",
        "sample", "memory", "reader", "writer", "result", "method", "normal", "useful", "direct",
        "simple", "clear", "source", "future", "current", "report",
    ];

    let mut output = Vec::with_capacity(bytes);
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let word_count = u64::try_from(WORDS.len()).unwrap_or(u64::MAX);
    while output.len() < bytes {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let index = usize::try_from(state % word_count).unwrap_or_default();
        output.extend_from_slice(
            WORDS
                .iter()
                .nth(index)
                .copied()
                .unwrap_or("steady")
                .as_bytes(),
        );
        output.push(b' ');
    }
    output.truncate(bytes);
    output
}

fn bloom() -> ShingleBloom {
    let mut filter = ShingleBloom::new(BloomConfig {
        expected_shingles: 20_000,
        false_positive_rate: 0.000001,
        ..BloomConfig::default()
    });
    filter.insert_text(
        "confidential memorandum account portfolio exposure settlement allocation "
            .repeat(1_000)
            .as_str(),
    );
    filter
}

fn measure(label: &str, input: &[u8], scan: impl Fn() -> Vec<Finding>) -> Duration {
    for _ in 0..5 {
        assert!(scan().is_empty(), "{label} workload must remain clean");
    }

    let mut samples = Vec::with_capacity(ITERATIONS);
    for _ in 0..ITERATIONS {
        let started = Instant::now();
        let findings = scan();
        let elapsed = started.elapsed();
        assert!(findings.is_empty(), "{label} workload must remain clean");
        samples.push(elapsed);
    }
    samples.sort_unstable();

    let min = samples.first().copied().unwrap_or_default();
    let median = samples.get(samples.len() / 2).copied().unwrap_or_default();
    let p95 = samples
        .get(samples.len() * 95 / 100)
        .copied()
        .unwrap_or_default();
    let max = samples.last().copied().unwrap_or_default();
    println!(
        "{label}: {} bytes, min {min:?}, median {median:?}, p95 {p95:?}, max {max:?}",
        input.len()
    );
    median
}

fn main() {
    let filter = bloom();
    let mut all_with_bloom_config = ScanConfig::default();
    all_with_bloom_config.packs.push(Pack::ProtectedCorpus);

    let base = Scanner::new(ScanConfig::default());
    let bloom_only = Scanner::with_bloom(
        ScanConfig::with_packs(vec![Pack::ProtectedCorpus]),
        filter.clone(),
    );
    let all_with_bloom = Scanner::with_bloom(all_with_bloom_config, filter);

    for (label, size) in [("4 KiB", 4 * 1024), ("256 KiB", 256 * 1024)] {
        let payload = clean_payload(size);
        println!("{label} payload:");
        measure("  default packs, no Bloom", &payload, || {
            base.scan_bytes(&payload)
        });
        measure("  protected-corpus Bloom only", &payload, || {
            bloom_only.scan_bytes(&payload)
        });
        measure("  default packs plus Bloom", &payload, || {
            all_with_bloom.scan_bytes(&payload)
        });
    }
}
