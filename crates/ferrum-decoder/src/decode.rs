// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Turns a word into an instruction by finding the row of the opcode table it matches.

use crate::table::{Insn, OPCODES, ROW_VALUES};

const ROW_COUNT: usize = ROW_VALUES.len();
const PRIMARY_COUNT: usize = 64;

/// The rows of the opcode table grouped by primary opcode.
struct Index {
    /// Row numbers, ordered by primary opcode.
    rows: [u16; ROW_COUNT],
    /// Where the rows of each primary opcode start in `rows`. The last entry is the end.
    starts: [u16; PRIMARY_COUNT + 1],
}

/// Groups the rows at compile time, so that decoding only looks at rows that can match.
const fn build_index() -> Index {
    let mut index = Index {
        rows: [0; ROW_COUNT],
        starts: [0; PRIMARY_COUNT + 1],
    };
    let mut next = 0;
    let mut primary = 0;
    while primary < PRIMARY_COUNT {
        index.starts[primary] = next as u16;
        let mut row = 0;
        while row < ROW_COUNT {
            if (ROW_VALUES[row] >> 26) as usize == primary {
                // The table has far fewer than 65536 rows.
                index.rows[next] = row as u16;
                next += 1;
            }
            row += 1;
        }
        primary += 1;
    }
    index.starts[PRIMARY_COUNT] = next as u16;
    index
}

static INDEX: Index = build_index();

/// Decodes one instruction word, given in host order.
///
/// Returns `None` for a word that is not a known Xenon instruction. Every word gets an answer, and
/// none makes this panic.
pub fn decode(word: u32) -> Option<Insn> {
    let primary = (word >> 26) as usize;
    let start = usize::from(INDEX.starts[primary]);
    let end = usize::from(INDEX.starts[primary + 1]);
    INDEX.rows[start..end].iter().find_map(|&row| {
        let row = &OPCODES[usize::from(row)];
        let matches = word & row.mask == row.value && row.check.is_none_or(|check| check(word));
        matches.then(|| (row.decode)(word))
    })
}
