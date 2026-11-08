// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! A small LZX encoder for fixtures.
//!
//! It favors being easy to check over compressing well: Huffman codes are fixed and matches are
//! only tried at a few offsets. Output goes one chunk per 32 KiB frame, the shape XEX files use.

/// Uncompressed bytes per LZX frame.
const FRAME_SIZE: usize = 0x8000;
/// Longest match the main and length trees can express.
const MAX_MATCH: usize = 257;
/// Block type of a verbatim block.
const BLOCK_VERBATIM: u32 = 1;
/// Block type of an uncompressed block.
const BLOCK_UNCOMPRESSED: u32 = 3;
/// Offsets the encoder tries when looking for a match.
const MATCH_OFFSETS: [usize; 12] = [1, 2, 3, 4, 8, 16, 32, 64, 128, 256, 1024, 4096];

/// Writes LZX bits: most significant first, in little-endian 16-bit words.
#[derive(Default)]
struct BitWriter {
    out: Vec<u8>,
    word: u16,
    used: u32,
}

impl BitWriter {
    fn bits(&mut self, value: u32, count: u32) {
        for bit in (0..count).rev() {
            self.word = (self.word << 1) | ((value >> bit) & 1) as u16;
            self.used += 1;
            if self.used == 16 {
                self.out.extend_from_slice(&self.word.to_le_bytes());
                self.word = 0;
                self.used = 0;
            }
        }
    }

    /// Pads to a word boundary, writing a whole word when already on one, as LZX requires before
    /// the raw part of an uncompressed block.
    fn align_for_raw_data(&mut self) {
        self.bits(0, 16 - self.used);
    }

    /// Pads to a word boundary and returns the bytes.
    fn finish(mut self) -> Vec<u8> {
        if self.used != 0 {
            self.bits(0, 16 - self.used);
        }
        self.out
    }
}

/// A complete canonical Huffman code with lengths as equal as they can be.
struct FixedCode {
    lengths: Vec<u32>,
    codes: Vec<u32>,
}

impl FixedCode {
    /// Builds a code for `symbols` symbols.
    fn new(symbols: usize) -> Self {
        let long = symbols.next_power_of_two().trailing_zeros();
        // `short` symbols of length `long - 1` and the rest of length `long` fill the tree exactly.
        let short = (1usize << long) - symbols;
        let lengths: Vec<u32> = (0..symbols)
            .map(|symbol| if symbol < short { long - 1 } else { long })
            .collect();
        let mut codes = vec![0; symbols];
        let mut code = 0;
        for length in 1..=long {
            for symbol in 0..symbols {
                if lengths[symbol] == length {
                    codes[symbol] = code;
                    code += 1;
                }
            }
            code <<= 1;
        }
        Self { lengths, codes }
    }

    fn put(&self, writer: &mut BitWriter, symbol: usize) {
        writer.bits(self.codes[symbol], self.lengths[symbol]);
    }
}

/// Number of position slots of a window, per the LZX specification.
fn position_slots(window_size: u32) -> usize {
    match window_size {
        0x8000 => 30,
        0x1_0000 => 32,
        0x2_0000 => 34,
        0x4_0000 => 36,
        0x8_0000 => 38,
        0x10_0000 => 42,
        0x20_0000 => 50,
        other => panic!("fixture does not support an LZX window of {other:#x}"),
    }
}

/// Number of footer bits of a position slot.
fn footer_bits(slot: usize) -> u32 {
    match slot {
        0..=3 => 0,
        4..=35 => (slot as u32 - 2) / 2,
        _ => 17,
    }
}

/// Finds the slot of a formatted offset, returning the slot and the footer value.
fn slot_of(formatted: u32) -> (usize, u32) {
    let mut base = 0;
    for slot in 0.. {
        let span = 1u32 << footer_bits(slot);
        if formatted < base + span {
            return (slot, formatted - base);
        }
        base += span;
    }
    unreachable!("the loop only ends by returning");
}

/// The Huffman state and repeated offsets shared by the frames of a verbatim stream.
struct Verbatim {
    pre: FixedCode,
    main: FixedCode,
    length: FixedCode,
    previous_main: Vec<u32>,
    previous_length: Vec<u32>,
    last_offset: usize,
}

impl Verbatim {
    fn new(window_size: u32) -> Self {
        let main = FixedCode::new(256 + 8 * position_slots(window_size));
        let length = FixedCode::new(249);
        Self {
            pre: FixedCode::new(20),
            previous_main: vec![0; main.lengths.len()],
            previous_length: vec![0; length.lengths.len()],
            main,
            length,
            // The format starts with every repeated offset set to 1.
            last_offset: 1,
        }
    }

    /// Writes a part of a tree: the pretree, then each length as a delta from the previous tree.
    fn put_tree(&self, writer: &mut BitWriter, lengths: &[u32], previous: &[u32]) {
        for length in &self.pre.lengths {
            writer.bits(*length, 4);
        }
        for (length, previous) in lengths.iter().zip(previous) {
            let delta = (previous + 17 - length) % 17;
            self.pre.put(writer, delta as usize);
        }
    }

    /// Writes one block holding the whole frame at `start` of `data`.
    fn put_frame(&mut self, writer: &mut BitWriter, data: &[u8], start: usize, end: usize) {
        writer.bits(BLOCK_VERBATIM, 3);
        writer.bits((end - start) as u32, 24);
        self.put_tree(
            writer,
            &self.main.lengths[..256],
            &self.previous_main[..256],
        );
        self.put_tree(
            writer,
            &self.main.lengths[256..],
            &self.previous_main[256..],
        );
        self.put_tree(writer, &self.length.lengths, &self.previous_length);
        self.previous_main.clone_from(&self.main.lengths);
        self.previous_length.clone_from(&self.length.lengths);

        let mut position = start;
        while position < end {
            match best_match(data, position, end) {
                Some((offset, length)) => {
                    self.put_match(writer, offset, length);
                    position += length;
                }
                None => {
                    self.main.put(writer, data[position].into());
                    position += 1;
                }
            }
        }
    }

    fn put_match(&mut self, writer: &mut BitWriter, offset: usize, length: usize) {
        let (slot, footer) = if offset == self.last_offset {
            (0, 0)
        } else {
            slot_of(offset as u32 + 2)
        };
        self.last_offset = offset;
        let header = (length - 2).min(7);
        self.main.put(writer, 256 + (slot << 3 | header));
        if header == 7 {
            self.length.put(writer, length - 9);
        }
        writer.bits(footer, footer_bits(slot));
    }
}

/// Returns the longest match at `position` among the offsets the encoder tries.
fn best_match(data: &[u8], position: usize, end: usize) -> Option<(usize, usize)> {
    MATCH_OFFSETS
        .iter()
        .filter(|&&offset| offset <= position)
        .map(|&offset| {
            let limit = (end - position).min(MAX_MATCH);
            let length = (0..limit)
                .take_while(|&i| data[position + i] == data[position + i - offset])
                .count();
            (offset, length)
        })
        .filter(|&(_, length)| length >= 3)
        .max_by_key(|&(_, length)| length)
}

/// Encodes `data` as chunks with Huffman-coded verbatim blocks, one per frame.
pub fn encode_verbatim(data: &[u8], window_size: u32) -> Vec<Vec<u8>> {
    let mut state = Verbatim::new(window_size);
    let mut chunks = Vec::new();
    for start in (0..data.len()).step_by(FRAME_SIZE) {
        let end = (start + FRAME_SIZE).min(data.len());
        let mut writer = BitWriter::default();
        if start == 0 {
            // No E8 translation.
            writer.bits(0, 1);
        }
        state.put_frame(&mut writer, data, start, end);
        chunks.push(writer.finish());
    }
    chunks
}

/// Encodes `data` as chunks with uncompressed blocks, one per frame.
pub fn encode_uncompressed(data: &[u8]) -> Vec<Vec<u8>> {
    data.chunks(FRAME_SIZE)
        .enumerate()
        .map(|(index, frame)| uncompressed_chunk(index == 0, frame, [1, 1, 1]))
        .collect()
}

/// Builds a chunk holding one uncompressed block with the given repeated offsets.
pub fn uncompressed_chunk(first: bool, frame: &[u8], repeated_offsets: [u32; 3]) -> Vec<u8> {
    let mut writer = BitWriter::default();
    if first {
        // No E8 translation.
        writer.bits(0, 1);
    }
    writer.bits(BLOCK_UNCOMPRESSED, 3);
    writer.bits(frame.len() as u32, 24);
    writer.align_for_raw_data();
    let mut chunk = writer.finish();
    for offset in repeated_offsets {
        chunk.extend_from_slice(&offset.to_le_bytes());
    }
    chunk.extend_from_slice(frame);
    if !frame.len().is_multiple_of(2) {
        chunk.push(0);
    }
    chunk
}

/// Builds a chunk with a verbatim block whose only tokens are matches against repeated offset R0.
///
/// A stream starting with [`uncompressed_chunk`] controls what R0 holds when this runs.
pub fn repeated_offset_chunk(window_size: u32, length: usize) -> Vec<u8> {
    let mut state = Verbatim::new(window_size);
    let mut writer = BitWriter::default();
    writer.bits(BLOCK_VERBATIM, 3);
    writer.bits(length as u32, 24);
    state.put_tree(
        &mut writer,
        &state.main.lengths[..256],
        &state.previous_main[..256],
    );
    state.put_tree(
        &mut writer,
        &state.main.lengths[256..],
        &state.previous_main[256..],
    );
    state.put_tree(&mut writer, &state.length.lengths, &state.previous_length);
    let mut remaining = length;
    while remaining > 0 {
        let run = remaining.min(MAX_MATCH);
        state.put_match(&mut writer, state.last_offset, run);
        remaining -= run;
    }
    writer.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_codes_fill_the_tree_exactly() {
        for symbols in [20usize, 249, 496, 512] {
            let code = FixedCode::new(symbols);
            let long = *code.lengths.iter().max().unwrap();
            let kraft: u64 = code
                .lengths
                .iter()
                .map(|length| 1u64 << (long - length))
                .sum();
            assert_eq!(kraft, 1 << long, "{symbols} symbols");
        }
    }

    #[test]
    fn slots_follow_the_format_table() {
        assert_eq!(slot_of(3), (3, 0));
        assert_eq!(slot_of(4), (4, 0));
        assert_eq!(slot_of(5), (4, 1));
        assert_eq!(slot_of(6), (5, 0));
        assert_eq!(slot_of(4098), (24, 2));
    }
}
