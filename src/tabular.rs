use crate::{Finding, Pack, Severity, hash_match};

const DELIMITERS: [u8; 4] = *b",\t|;";

/// Scan `text` for delimited tabular blocks (`>= min_rows` consecutive
/// non-empty lines sharing the same delimiter count `>= min_columns - 1`).
pub fn scan(text: &str, min_rows: usize, min_columns: usize, depth: u8) -> Vec<Finding> {
    if min_rows < 2 || min_columns < 2 {
        return Vec::new();
    }
    let min_delims = min_columns - 1;
    let lines = line_spans(text);
    let mut out = Vec::new();

    for delim in DELIMITERS {
        let mut run_start: Option<usize> = None;
        let mut run_end: usize = 0;
        let mut run_count: usize = 0;
        let mut expected_delims: usize = 0;

        for &(start, end) in &lines {
            let line = text[start..end].trim();
            if line.is_empty() {
                flush_run(
                    text, delim, min_rows, run_start, run_end, run_count, depth, &mut out,
                );
                run_start = None;
                run_count = 0;
                continue;
            }

            let count = count_unquoted(line.as_bytes(), delim);
            if count >= min_delims {
                if run_start.is_some() && count == expected_delims {
                    run_end = end;
                    run_count += 1;
                } else {
                    flush_run(
                        text, delim, min_rows, run_start, run_end, run_count, depth, &mut out,
                    );
                    run_start = Some(start);
                    run_end = end;
                    run_count = 1;
                    expected_delims = count;
                }
            } else {
                flush_run(
                    text, delim, min_rows, run_start, run_end, run_count, depth, &mut out,
                );
                run_start = None;
                run_count = 0;
            }
        }

        flush_run(
            text, delim, min_rows, run_start, run_end, run_count, depth, &mut out,
        );
    }

    out
}

#[allow(clippy::too_many_arguments)]
fn flush_run(
    text: &str,
    delim: u8,
    min_rows: usize,
    run_start: Option<usize>,
    run_end: usize,
    run_count: usize,
    depth: u8,
    out: &mut Vec<Finding>,
) {
    if let Some(start) = run_start
        && run_count >= min_rows
        && run_end > start
    {
        let rule_id = match delim {
            b',' => "TABULAR_CSV_BLOCK",
            b'\t' => "TABULAR_TSV_BLOCK",
            b'|' => "TABULAR_PIPE_BLOCK",
            _ => "TABULAR_SEMICOLON_BLOCK",
        };
        let slice = &text.as_bytes()[start..run_end];
        out.push(Finding {
            pack: Pack::Tabular,
            rule_id: rule_id.to_string(),
            severity: Severity::High,
            byte_span: (start, run_end),
            match_len: slice.len(),
            match_hash: hash_match(slice),
            depth,
        });
    }
}

fn count_unquoted(bytes: &[u8], delim: u8) -> usize {
    let mut in_quotes = false;
    let mut count = 0;
    for &b in bytes {
        if b == b'"' {
            in_quotes = !in_quotes;
        } else if b == delim && !in_quotes {
            count += 1;
        }
    }
    count
}

fn line_spans(text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start = 0;
    for (idx, b) in text.bytes().enumerate() {
        if b == b'\n' {
            let end = if idx > start && text.as_bytes()[idx - 1] == b'\r' {
                idx - 1
            } else {
                idx
            };
            spans.push((start, end));
            start = idx + 1;
        }
    }
    if start < text.len() {
        spans.push((start, text.len()));
    }
    spans
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_csv_block_of_five_rows() {
        let csv = "id,name,balance\n1,Alpha,100\n2,Beta,200\n3,Gamma,300\n4,Delta,400\n";
        let findings = scan(csv, 5, 3, 0);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "TABULAR_CSV_BLOCK");
    }

    #[test]
    fn ignores_short_csv_snippet() {
        let csv = "id,name,balance\n1,Alpha,100\n2,Beta,200\n";
        let findings = scan(csv, 5, 3, 0);
        assert!(findings.is_empty());
    }
}
