// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

use super::*;

#[test]
#[should_panic(expected = "sub_82000000: no block at 0x82000010")]
fn no_block_names_the_function_and_the_target() {
    no_block("sub_82000000", 0x8200_0010);
}

#[test]
#[should_panic(expected = "sub_82000000: no block at 0x00000004")]
fn no_block_prints_the_whole_word() {
    no_block("sub_82000000", 4);
}
