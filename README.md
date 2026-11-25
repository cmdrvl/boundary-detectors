# boundary-detectors

Shared deterministic pure-Rust (`#![forbid(unsafe_code)]`, zero ML) content
boundary detectors used by [CMD+RVL](https://cmdrvl.com) ingress (`veil`) and
egress (`airlock`) boundaries so local content sniffing, broker stdout scanning,
and wire egress screening never drift.

**Status: pre-1.0 (v0.1.0). Not published on crates.io (`publish = false`); depend
on it by git rev.**

## Design Guarantees

- **Zero raw value leakage:** `Finding` never echoes matched secret, PII, or
  protected-corpus text — only byte offsets, match lengths, and `blake3:`
  digests (`Finding.match_hash`).
- **Deterministic & linear-time:** Pure Rust regexes (no backtracking engines),
  check-digit validation (Luhn for cards, ISO 13616 mod-97 for IBAN), and
  deterministic finding ordering.
- **Bounded recursive decode-and-rescan:** Detects secrets, PII, tabular dumps,
  and protected-corpus matches even when wrapped in base64 or hex encodings,
  within configurable depth and decoded-byte budgets.
- **One-way protected-corpus Bloom filter (`shingle_bloom`):** Builds a
  serializable, strictly one-way `blake3` shingle Bloom filter over protected
  files (outside a sandbox) and screens outbound text without ever storing or
  exporting raw protected text.

## Modules

| Module | What it detects |
|---|---|
| `secrets` | AWS `AKIA`/`ASIA`, PEM private keys, JWTs, GitHub tokens, Slack tokens, Anthropic/OpenAI keys, and high-entropy secret assignments (`>= 3.5` bits/char) |
| `pii` | US SSN, Luhn-valid payment cards, emails (with domain exemptions), E.164/US phone numbers, and ISO 13616 mod-97 IBANs |
| `tabular` | Delimited tabular blocks (`>= N` consecutive lines with consistent `,`, `\t`, `|`, or `;` column counts) |
| `blobs` | Long base64 runs, long hex runs, `data:` URIs, plus bounded base64/hex candidate decoding for recursive rescan |
| `paths` | Absolute POSIX paths, `~/` paths, `file://` URIs, and Windows drive paths |
| `shingle_bloom` | One-way normalized 8-word / 64-byte rolling-shingle Bloom filter builder, binary serializer (`BDBL` v1), and `PROTECTED_CORPUS_MATCH` scanner |
| `magic` | Zero-allocation magic-byte sniffer (SQLite, Parquet, ZIP/XLSX, PDF, GZIP, ZSTD, PNG, JPEG, GIF, WebP, ELF, Mach-O) |

## Usage

```rust
use boundary_detectors::{Pack, ScanConfig, Scanner};

let config = ScanConfig::with_packs(vec![
    Pack::Secrets,
    Pack::Pii,
    Pack::Tabular,
    Pack::Blobs,
    Pack::Paths,
]);
let scanner = Scanner::new(config);
let findings = scanner.scan_str("AKIAIOSFODNN7EXAMPLE");
assert!(!findings.is_empty());
assert!(findings[0].match_hash.starts_with("blake3:"));
```
