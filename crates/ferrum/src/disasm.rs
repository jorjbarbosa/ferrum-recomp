// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The `ferrum disasm` subcommand: a listing of the instructions at a guest address.
//!
//! Each line has the layout of `objdump -D -z` on a file with no symbols, so that the two can be
//! compared directly. A word that does not decode prints as `.long` and the listing goes on.

use std::fs;
use std::io::{self, BufWriter, ErrorKind, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use ferrum_decoder::{decode, format_at, format_undecoded};
use ferrum_xex::{Image, Section, Xex};

const WORD_SIZE: u32 = 4;

/// Lists the instructions at `address` of the XEX file at `path` on standard output.
///
/// With `count`, the listing has that many words. Otherwise it runs as [`default_end`] says.
/// Warnings about the file go to standard error.
pub fn run(path: &Path, address: u32, count: Option<u32>) -> Result<()> {
    let file = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    let xex = Xex::parse(&file).with_context(|| format!("cannot parse {}", path.display()))?;
    for warning in &xex.warnings {
        eprintln!("warning: {warning}");
    }
    let (start, words) = listing_range(&xex.image, address, count)?;
    let mut out = BufWriter::new(io::stdout().lock());
    match write_listing(&mut out, &xex.image, start, words).and_then(|()| out.flush()) {
        // The reader went away, as with `ferrum disasm game.xex --addr 0x... | head`.
        Err(error) if error.kind() == ErrorKind::BrokenPipe => Ok(()),
        result => result.context("cannot write the listing"),
    }
}

/// Checks an address and works out how many words to list from it.
fn listing_range(image: &Image, address: u32, count: Option<u32>) -> Result<(u32, u32)> {
    if !address.is_multiple_of(WORD_SIZE) {
        bail!("address {address:#010x} is not aligned to a 4-byte instruction");
    }
    let Some(section) = image.sections.iter().find(|s| s.contains(address)) else {
        bail!("address {address:#010x} is not in any section of the image");
    };
    let limit = section_end(image, section);
    if u64::from(address) + u64::from(WORD_SIZE) > limit {
        bail!(
            "address {address:#010x} is in section {} but past the part the image holds",
            section.name
        );
    }
    let available = limit - u64::from(address);
    let words = match count {
        // Asking for more words than the section has is not an error: a listing ends with it.
        Some(count) => u64::from(count).min(available / u64::from(WORD_SIZE)),
        None => (default_end(image, address, limit) - u64::from(address)) / u64::from(WORD_SIZE),
    };
    // The image is smaller than 4 GiB, so the number of words in it fits.
    Ok((address, words as u32))
}

/// Returns the address just past the part of a section the image really holds.
fn section_end(image: &Image, section: &Section) -> u64 {
    u64::from(section.address) + image.section_data(section).len() as u64
}

/// Returns where a listing with no `--count` stops: the end of the `.pdata` function at
/// `address`, or else the start of the next one, and never past `limit`, the end of the section.
fn default_end(image: &Image, address: u32, limit: u64) -> u64 {
    let containing = image
        .pdata
        .iter()
        .find(|function| function.begin <= address && u64::from(address) < function.end());
    let end = match containing {
        Some(function) => function.end(),
        None => image
            .pdata
            .iter()
            .filter(|function| function.size() != 0 && function.begin > address)
            .map(|function| u64::from(function.begin))
            .min()
            .unwrap_or(limit),
    };
    end.min(limit)
}

/// Writes one line per word.
fn write_listing(out: &mut impl Write, image: &Image, start: u32, words: u32) -> io::Result<()> {
    for index in 0..words {
        let address = start.wrapping_add(index * WORD_SIZE);
        // The range was checked against the bytes of the image, so these words are there.
        let Some(bytes) = image.bytes_at(address, WORD_SIZE as usize) else {
            break;
        };
        write_line(out, address, bytes)?;
    }
    Ok(())
}

/// Writes one word as objdump does: address, bytes and instruction.
fn write_line(out: &mut impl Write, address: u32, bytes: &[u8]) -> io::Result<()> {
    let word = bytes
        .iter()
        .fold(0, |word, &byte| (word << 8) | u32::from(byte));
    let text =
        decode(word).map_or_else(|| format_undecoded(word), |insn| format_at(&insn, address));
    write!(out, "{address:8x}:\t")?;
    for byte in bytes {
        write!(out, "{byte:02x} ")?;
    }
    writeln!(out, "\t{text}")
}
