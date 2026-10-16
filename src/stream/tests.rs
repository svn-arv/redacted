//! Unit tests for the stream loop, on an in-memory reader and writer.

use std::io::{self, Write};

use super::*;
use crate::config::{Config, EngineConfig};
use crate::fake_secrets;

/// Records what was written between flushes, so a test can see what reached the reader and when.
#[derive(Default)]
struct FlushLog {
    pending: Vec<u8>,
    flushed: Vec<String>,
}

impl Write for FlushLog {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let chunk = String::from_utf8_lossy(&self.pending).into_owned();
        self.flushed.push(chunk);
        self.pending.clear();
        Ok(())
    }
}

/// Runs the loop over `input` with the built-in patterns and returns each flushed chunk.
fn stream_chunks(input: &str) -> Vec<String> {
    let scrubber = Scrubber::new(&Config::default(), &EngineConfig::default()).unwrap();
    let mut log = FlushLog::default();
    scrub_lines(input.as_bytes(), &mut log, &|text| scrubber.scrub(text)).unwrap();
    log.flushed
}

#[test]
fn each_line_is_scrubbed_and_flushed_alone_so_a_live_log_reaches_the_reader_as_it_grows() {
    let key = fake_secrets::aws_access_key();
    let chunks = stream_chunks(&format!("key {key}\nplain\n"));
    let marker = format!(
        "[REDACTED:aws_access_key ...{}]",
        fake_secrets::last_four_chars(&key)
    );
    assert_eq!(chunks, [format!("key {marker}\n"), "plain\n".to_string()]);
}

#[test]
fn a_pem_key_split_over_lines_is_redacted_as_one_key_because_no_single_line_matches() {
    let key = fake_secrets::private_key("RSA ");
    let chunks = stream_chunks(&format!("{key}\nafter\n"));
    assert_eq!(
        chunks.len(),
        2,
        "the block is one chunk, then the next line"
    );
    assert!(chunks[0].starts_with("[REDACTED:private_key"), "{chunks:?}");
    assert!(chunks[0].ends_with('\n'));
    assert!(!chunks[0].contains("PRIVATE KEY-----"));
    assert_eq!(chunks[1], "after\n");
}

#[test]
fn a_begin_without_end_is_released_after_64_lines_so_the_stream_never_stalls() {
    let filler = "filler line\n".repeat(70);
    let chunks = stream_chunks(&format!("-----BEGIN CERTIFICATE-----\n{filler}"));
    assert_eq!(chunks[0].lines().count(), MAX_PEM_BLOCK_LINES);
    assert_eq!(
        chunks.len(),
        1 + 71 - MAX_PEM_BLOCK_LINES,
        "the rest go line by line"
    );
    assert!(chunks[1..].iter().all(|chunk| chunk == "filler line\n"));
}

#[test]
fn a_crlf_line_keeps_its_ending_so_windows_logs_are_not_rewritten() {
    let chunks = stream_chunks("plain\r\nnext");
    assert_eq!(chunks, ["plain\r\n", "next"]);
}

#[test]
fn a_json_object_line_is_scrubbed_as_text_because_stream_mode_never_reads_hook_payloads() {
    let key = fake_secrets::aws_access_key();
    let chunks = stream_chunks(&format!("{{\"token\":\"{key}\"}}\n"));
    assert_eq!(chunks.len(), 1);
    assert!(
        chunks[0].starts_with("{\"token\":\"[REDACTED:aws_access_key"),
        "{chunks:?}"
    );
    assert!(chunks[0].ends_with("\"}\n"));
}

#[test]
fn a_scrubber_panic_withholds_that_line_and_keeps_streaming_so_nothing_raw_leaks() {
    let scrubber = Scrubber::new(&Config::default(), &EngineConfig::default()).unwrap();
    let scrub = |text: &str| -> ScrubResult {
        assert!(!text.contains("boom"), "simulated scrubber bug");
        scrubber.scrub(text)
    };
    let mut log = FlushLog::default();
    scrub_lines("boom secret\r\nfine\n".as_bytes(), &mut log, &scrub).unwrap();
    assert_eq!(log.flushed, ["[redacted] line withheld\r\n", "fine\n"]);
}
