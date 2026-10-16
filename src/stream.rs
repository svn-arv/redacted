//! `redacted scrub --stream`: scrubs stdin line by line, for output that never
//! ends, such as `tail -f` under Claude Code's Monitor tool (issue #58).

use std::io::{self, BufRead, ErrorKind, Write};
use std::panic::{self, AssertUnwindSafe};
use std::path::Path;

use crate::config;
use crate::scrub::{ScrubResult, Scrubber};

/// Printed in place of a line, or a PEM block, the scrubber panicked on.
const WITHHELD: &str = "[redacted] line withheld";

/// A block with no END line is released at this size, so the stream never stalls.
const MAX_PEM_BLOCK_LINES: usize = 64;

/// Builds the scrubber once, then streams stdin to stdout. No stats and no
/// stderr count: a stream has no end at which to report them.
pub fn run(cwd: Option<&Path>) -> Result<(), String> {
    // Silent: a panic message can carry part of the raw line, and stderr is readable under Monitor.
    panic::set_hook(Box::new(|_| {}));
    let home_dir = config::home_dir();
    let home_dir = home_dir.as_deref();
    let scrubber = config::load(home_dir, cwd)
        .and_then(|config| Scrubber::new(&config, &config::load_engine(home_dir, cwd)?))
        .map_err(|e| format!("scrub: {e}"))?;
    let result = scrub_lines(io::stdin().lock(), &mut io::stdout().lock(), &|text| {
        scrubber.scrub(text)
    });
    match result {
        // A closed stdout means the reader stopped (Monitor ended, `head` had enough).
        Err(error) if error.kind() != ErrorKind::BrokenPipe => {
            Err(format!("scrub --stream: {error}"))
        }
        _ => Ok(()),
    }
}

/// Writes each scrubbed line as soon as it is complete. A line holding
/// `-----BEGIN` opens a block scrubbed whole at its `-----END` line, because a
/// PEM key only matches as a whole.
fn scrub_lines(
    mut input: impl BufRead,
    output: &mut impl Write,
    scrub: &dyn Fn(&str) -> ScrubResult,
) -> io::Result<()> {
    let mut line_bytes = Vec::new();
    let mut pem_block = String::new();
    let mut pem_block_lines = 0;
    // read_until keeps the line ending and, unlike read_line, survives a non-UTF-8 byte.
    while input.read_until(b'\n', &mut line_bytes)? > 0 {
        let line = String::from_utf8_lossy(&line_bytes);
        let is_inside_pem_block = pem_block_lines > 0;
        if !is_inside_pem_block && !line.contains("-----BEGIN") {
            write_scrubbed(output, &line, scrub)?;
        } else {
            pem_block.push_str(&line);
            pem_block_lines += 1;
            if line.contains("-----END") || pem_block_lines == MAX_PEM_BLOCK_LINES {
                write_scrubbed(output, &pem_block, scrub)?;
                pem_block.clear();
                pem_block_lines = 0;
            }
        }
        line_bytes.clear();
    }
    // Input ended inside a block: release what was held.
    if pem_block_lines > 0 {
        write_scrubbed(output, &pem_block, scrub)?;
    }
    Ok(())
}

/// Scrubs `text`, writes it with its line ending and flushes, so the reader sees
/// it now. Fail closed: a scrubber panic writes WITHHELD, never the raw text.
fn write_scrubbed(
    output: &mut impl Write,
    text: &str,
    scrub: &dyn Fn(&str) -> ScrubResult,
) -> io::Result<()> {
    // Scrubbed without its ending, so no pattern can swallow the newline and merge two lines.
    let body = text.trim_end_matches(['\r', '\n']);
    let ending = &text[body.len()..];
    // AssertUnwindSafe vouches that nothing a panic may leave half-written is used afterwards.
    let scrubbed = panic::catch_unwind(AssertUnwindSafe(|| scrub(body).text))
        .unwrap_or_else(|_| WITHHELD.to_string());
    output.write_all(scrubbed.as_bytes())?;
    output.write_all(ending.as_bytes())?;
    output.flush()
}

#[cfg(test)]
mod tests;
