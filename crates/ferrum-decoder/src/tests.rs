// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Unit tests of the table, the decoder and the formatter.
//!
//! The comparison with objdump's own output is in `tests/xenia_dis.rs`. The tests here cover what
//! the Xenia suite does not reach: every combination of the opcode fields, over sampled operands.

use std::collections::HashSet;

use crate::fields::{
    BD, DS, LI, MB6, Print, SH6, SI, SPR, UI, VA128, VB128, VD128, VPERM128, VSIM,
};
use crate::table::{Form, Insn, OPCODES};
use crate::{CrBit, CrField, Fpr, Gpr, Vr, decode, format, format_at, format_undecoded};

/// A small deterministic generator, so that a failure can be repeated.
struct XorShift(u32);

impl XorShift {
    fn next(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 17;
        self.0 ^= self.0 << 5;
        self.0
    }
}

/// Every primary opcode with every value of bits 0 to 10, over these operand bits.
fn opcode_field_words(operands: u32) -> impl Iterator<Item = u32> {
    (0..64u32).flat_map(move |primary| {
        (0..2048u32).map(move |low| (primary << 26) | (operands & 0x03FF_F800) | low)
    })
}

/// Formats a word the way a listing does.
fn text_of(word: u32, address: u32) -> String {
    decode(word).map_or_else(|| format_undecoded(word), |insn| format_at(&insn, address))
}

#[test]
fn opcodes_index_their_own_rows() {
    for (index, row) in OPCODES.iter().enumerate() {
        assert_eq!(row.opcode as usize, index, "{}", row.mnemonic);
        assert_eq!(row.opcode.info().mnemonic, row.mnemonic);
    }
}

#[test]
fn every_row_value_only_sets_fixed_bits() {
    for row in OPCODES {
        assert_eq!(row.value & !row.mask, 0, "{}", row.mnemonic);
    }
}

#[test]
fn no_word_can_match_two_rows() {
    for (index, a) in OPCODES.iter().enumerate() {
        for b in &OPCODES[index + 1..] {
            assert_ne!(
                (a.value ^ b.value) & a.mask & b.mask,
                0,
                "{} and {} overlap",
                a.mnemonic,
                b.mnemonic
            );
        }
    }
}

#[test]
fn fields_of_a_row_do_not_overlap() {
    for row in OPCODES {
        let mut used = 0;
        for field in row.fields {
            assert_eq!(used & field.mask(), 0, "{}", row.mnemonic);
            used |= field.mask();
        }
        assert_eq!(used, !row.mask, "{}", row.mnemonic);
    }
}

#[test]
fn rows_convert_a_word_and_back() {
    let mut random = XorShift(0x2468_ACE1);
    for row in OPCODES {
        for _ in 0..64 {
            let word = row.value | (random.next() & !row.mask);
            assert_eq!((row.decode)(word).encode(), word, "{}", row.mnemonic);
        }
    }
}

#[test]
fn fields_read_the_right_bits() {
    // The two halves of a special register number are swapped in the word.
    assert_eq!(SPR.get(1 << 16), 1);
    assert_eq!(SPR.get(1 << 11), 32);
    // The sixth bit of a 64-bit rotate sits apart from the other five.
    assert_eq!(SH6.get(1 << 1), 32);
    assert_eq!(MB6.get(1 << 5), 32);
    // Displacements are signed, and some count words.
    assert_eq!(SI.get(0xFFFF), -1);
    assert_eq!(DS.get(0xFFFC), -4);
    assert_eq!(BD.get(0xFFFC), -4);
    assert_eq!(LI.get(0x03FF_FFFC), -4);
    assert_eq!(VSIM.get(31 << 16), -1);
    assert_eq!(UI.get(0xFFFF), 0xFFFF);
}

#[test]
fn fields_write_back_what_they_read() {
    for (field, value) in [
        (SPR, 287),
        (SH6, 37),
        (MB6, 37),
        (SI, -1),
        (DS, -4),
        (BD, -4),
        (LI, -4),
    ] {
        assert_eq!(field.get(field.put(value)), value);
    }
}

#[test]
fn vmx128_registers_are_split_over_the_word() {
    assert_eq!(VD128.get(1 << 21), 1);
    assert_eq!(VD128.get(1 << 2), 32);
    assert_eq!(VD128.get(2 << 2), 64);
    assert_eq!(VA128.get(1 << 16), 1);
    assert_eq!(VA128.get(1 << 5), 32);
    assert_eq!(VA128.get(1 << 10), 64);
    assert_eq!(VB128.get(1 << 11), 1);
    assert_eq!(VB128.get(1), 32);
    assert_eq!(VB128.get(2), 64);
    assert_eq!(VPERM128.get(1 << 6), 32);
    for field in [VD128, VA128, VB128] {
        assert_eq!(field.get(field.put(127)), 127);
    }
}

#[test]
fn mnemonics_are_unique() {
    let mut seen = HashSet::new();
    for row in OPCODES {
        assert!(seen.insert(row.mnemonic), "{}", row.mnemonic);
    }
}

#[test]
fn every_form_has_rows() {
    for form in [
        Form::I,
        Form::B,
        Form::SC,
        Form::D,
        Form::DS,
        Form::X,
        Form::XL,
        Form::XFX,
        Form::XFL,
        Form::XS,
        Form::XO,
        Form::A,
        Form::M,
        Form::MD,
        Form::MDS,
        Form::VA,
        Form::VX,
        Form::VXR,
        Form::VX128,
        Form::VX128_1,
        Form::VX128_2,
        Form::VX128_3,
        Form::VX128_4,
        Form::VX128_5,
        Form::VX128_R,
        Form::VX128_P,
    ] {
        assert!(OPCODES.iter().any(|row| row.form == form), "{form:?}");
    }
}

#[test]
fn every_row_is_reachable() {
    let mut random = XorShift(0x1234_5678);
    for row in OPCODES {
        // Some rows only take a few values of an operand, so this can take many tries.
        let reached = (0..100_000).any(|_| {
            let word = row.value | (random.next() & !row.mask);
            decode(word).is_some_and(|insn| insn.opcode() == row.opcode)
        });
        assert!(reached, "{} never decodes", row.mnemonic);
    }
}

/// The exhaustive test: all 131072 values of the opcode fields, with operands set in several ways.
#[test]
fn opcode_fields_decode_to_the_row_they_match() {
    let mut random = XorShift(0x9ABC_DEF1);
    let mut operands = vec![0, 0x03FF_F800, 0x0108_4000, 0x0294_A800];
    operands.extend((0..4).map(|_| random.next()));
    for operands in operands {
        for word in opcode_field_words(operands) {
            match decode(word) {
                Some(insn) => {
                    assert_eq!(insn.encode(), word, "{word:#010x}");
                    let row = insn.opcode().info();
                    assert_eq!(word & row.mask, row.value, "{word:#010x}");
                    assert!(row.check.is_none_or(|check| check(word)));
                    assert!(!format(&insn).is_empty());
                    assert!(!format_at(&insn, 0xFFFF_FFFC).is_empty());
                }
                None => assert!(format_undecoded(word).starts_with(".long 0x")),
            }
        }
    }
}

/// The index only looks at the rows of one primary opcode, so check it against a plain search.
#[test]
fn decoding_agrees_with_searching_the_whole_table() {
    let matching = |word: u32| {
        OPCODES
            .iter()
            .find(|row| word & row.mask == row.value && row.check.is_none_or(|check| check(word)))
    };
    let mut random = XorShift(0x0BAD_F00D);
    for word in opcode_field_words(random.next()) {
        let found = matching(word).map(|row| row.opcode);
        assert_eq!(
            decode(word).map(|insn| insn.opcode()),
            found,
            "{word:#010x}"
        );
    }
}

#[test]
fn random_words_never_panic_and_stay_lossless() {
    let mut random = XorShift(0xDEAD_BEEF);
    for _ in 0..200_000 {
        let word = random.next();
        if let Some(insn) = decode(word) {
            assert_eq!(insn.encode(), word, "{word:#010x}");
            assert!(!format(&insn).is_empty());
        }
    }
}

#[test]
fn bits_objdump_ignores_do_not_change_the_text() {
    let mut random = XorShift(0x5555_AAAB);
    for row in OPCODES {
        let ignored = row
            .fields
            .iter()
            .filter(|field| field.print == Print::Ignored)
            .fold(0, |bits, field| bits | field.mask());
        for _ in 0..200 {
            let word = row.value | (random.next() & !row.mask & !ignored);
            let (Some(quiet), Some(noisy)) = (decode(word), decode(word | ignored)) else {
                continue;
            };
            assert_eq!(format(&quiet), format(&noisy), "{}", row.mnemonic);
        }
    }
}

#[test]
fn vmx128_registers_reach_127() {
    for n in 0..128u8 {
        let insn = Insn::Vaddfp128 {
            vd: Vr(n),
            va: Vr(127 - n),
            vb: Vr(n),
        };
        let word = insn.encode();
        assert_eq!(decode(word), Some(insn));
        let expected = format!("vaddfp128 v{n},v{},v{n}", 127 - n);
        assert_eq!(format(&insn), expected);
        let load = Insn::Lvx128 {
            vd: Vr(n),
            ra: Gpr(3),
            rb: Gpr(4),
        };
        assert_eq!(decode(load.encode()), Some(load));
    }
}

#[test]
fn typed_fields_hold_the_operands() {
    assert_eq!(
        decode(0x7D65_CA14),
        Some(Insn::Add {
            rt: Gpr(11),
            ra: Gpr(5),
            rb: Gpr(25),
            oe: false,
            rc: false,
        })
    );
    assert_eq!(
        decode(0x8064_FFF0),
        Some(Insn::Lwz {
            rt: Gpr(3),
            d: -16,
            ra: Gpr(4),
        })
    );
    assert_eq!(
        decode(0xE864_0012),
        Some(Insn::Lwa {
            rt: Gpr(3),
            ds: 16,
            ra: Gpr(4),
        })
    );
    assert_eq!(
        decode(0x4BFF_FFFC),
        Some(Insn::B {
            li: -4,
            aa: false,
            lk: false,
        })
    );
    assert_eq!(
        decode(0x4186_0008),
        Some(Insn::Bc {
            bo: 12,
            bi: CrBit(6),
            bd: 8,
            aa: false,
            lk: false,
        })
    );
    assert_eq!(
        decode(0xFC22_1828),
        Some(Insn::Fsub {
            frt: Fpr(1),
            fra: Fpr(2),
            frb: Fpr(3),
            rc: false,
        })
    );
    assert_eq!(
        decode(0x7C83_2000),
        Some(Insn::Cmp {
            bf: CrField(1),
            l: false,
            ra: Gpr(3),
            rb: Gpr(4),
        })
    );
    assert_eq!(
        decode(0x7C68_02A6),
        Some(Insn::Mfspr { rt: Gpr(3), spr: 8 })
    );
}

/// A word and what objdump prints for it at address 0x100000. These go over each family of
/// simplified mnemonics and the odd cases of each form, trailing spaces included.
const TEXTS: &[(u32, &str)] = &[
    // Branches.
    (0x4800_0008, "b       0x100008"),
    (0x4BFF_FFF8, "b       0xffff8"),
    (0x4800_0009, "bl      0x100008"),
    (0x4800_000A, "ba      0x8"),
    (0x4800_000B, "bla     0x8"),
    (0x4082_0008, "bne     0x100008"),
    (0x4182_0008, "beq     0x100008"),
    (0x4085_0008, "ble     cr1,0x100008"),
    (0x40C5_0008, "ble-    cr1,0x100008"),
    (0x40E5_0008, "ble+    cr1,0x100008"),
    (0x4185_0009, "bgtl    cr1,0x100008"),
    (0x4185_000A, "bgta    cr1,0x8"),
    (0x41C5_000B, "bgtla-  cr1,0x8"),
    (0x4005_0008, "bdnzf   4*cr1+gt,0x100008"),
    (0x4045_0008, "bdzf    4*cr1+gt,0x100008"),
    (0x4105_0008, "bdnzt   4*cr1+gt,0x100008"),
    (0x4145_0008, "bdzt    4*cr1+gt,0x100008"),
    (0x4200_0008, "bdnz    0x100008"),
    (0x4240_0008, "bdz     0x100008"),
    (0x4300_0008, "bdnz-   0x100008"),
    (0x4320_0008, "bdnz+   0x100008"),
    (0x4340_0008, "bdz-    0x100008"),
    (0x4360_0008, "bdz+    0x100008"),
    (0x4285_0008, "bc      20,4*cr1+gt,0x100008"),
    (0x4305_0008, "bc-     24,4*cr1+gt,0x100008"),
    (0x4325_0008, "bc+     24,4*cr1+gt,0x100008"),
    (0x42A5_0008, ".long 0x42a50008"),
    (0x4E80_0020, "blr"),
    (0x4E80_0021, "blrl"),
    (0x4E80_0420, "bctr"),
    (0x4E80_0421, "bctrl"),
    (0x4D82_0020, "beqlr   "),
    (0x4C82_0021, "bnelrl  "),
    (0x4D85_0020, "bgtlr   cr1"),
    (0x4DC5_0020, "bgtlr-  cr1"),
    (0x4C80_0420, "bgectr  "),
    (0x4C22_0020, ".long 0x4c220020"),
    (0x4C05_0020, "bdnzflr 4*cr1+gt"),
    (0x4E00_0020, "bdnzlr"),
    (0x4E40_0020, "bdzlr"),
    (0x4F00_0020, "bdnzlr-"),
    (0x4E85_0020, "bclr-   20,4*cr1+gt"),
    (0x4E20_0020, "bclr+   16,lt"),
    (0x4C05_0420, "bcctr-  0,4*cr1+gt"),
    (0x4E85_0420, "bcctr-  20,4*cr1+gt"),
    (0x4D82_0820, "bclr    12,eq,1"),
    (0x4D82_0C20, "bcctr   12,eq,1"),
    (0x4400_0002, "sc      "),
    (0x4400_0022, "sc      1"),
    // Integer arithmetic and logic.
    (0x3860_0005, "li      r3,5"),
    (0x3863_FFFB, "addi    r3,r3,-5"),
    (0x3C60_FFFF, "lis     r3,-1"),
    (0x3C63_0005, "addis   r3,r3,5"),
    (0x6000_0000, "nop"),
    (0x6063_0000, "ori     r3,r3,0"),
    (0x6800_0000, "xnop"),
    (0x7C64_2378, "or      r4,r3,r4"),
    (0x7C64_1B78, "mr      r4,r3"),
    (0x7C64_1B79, "mr.     r4,r3"),
    (0x7F7B_DB78, "yield"),
    (0x7FBD_EB78, "mdoio"),
    (0x7FDE_F378, "mdoom"),
    (0x7FFF_FB78, "mr      r31,r31"),
    (0x7C64_18F8, "not     r4,r3"),
    (0x7C64_20F8, "nor     r4,r3,r4"),
    (0x7D65_CA14, "add     r11,r5,r25"),
    (0x7D65_CE15, "addo.   r11,r5,r25"),
    (0x7C64_0194, "addze   r3,r4"),
    (0x7C64_00D0, "neg     r3,r4"),
    (0x7C64_2896, "mulhw   r3,r4,r5"),
    (0x7C64_2C96, ".long 0x7c642c96"),
    (0x3463_0001, "addic.  r3,r3,1"),
    (0x7064_FFFF, "andi.   r4,r3,65535"),
    (0x7C64_2B3A, ".long 0x7c642b3a"),
    (0x7C64_2E74, "sradi   r4,r3,5"),
    (0x7C64_2E76, "sradi   r4,r3,37"),
    (0x7C64_2E70, "srawi   r4,r3,5"),
    (0x7C64_00F4, "popcntb r4,r3"),
    // Comparisons.
    (0x7C03_2000, "cmpw    r3,r4"),
    (0x7C23_2000, "cmpd    r3,r4"),
    (0x7C83_2000, "cmpw    cr1,r3,r4"),
    (0x7CA3_2040, "cmpld   cr1,r3,r4"),
    (0x7C43_2000, ".long 0x7c432000"),
    (0x2C03_FFFF, "cmpwi   r3,-1"),
    (0x2C43_FFFF, "cmpwi   r3,-1"),
    (0x2823_FFFF, "cmpldi  r3,65535"),
    (0x2C83_0001, "cmpwi   cr1,r3,1"),
    // Traps.
    (0x7C83_2008, "tweq    r3,r4"),
    (0x7FE3_2008, "twu     r3,r4"),
    (0x7C63_2008, "tw      3,r3,r4"),
    (0x7C83_2088, "tdeq    r3,r4"),
    (0x0C83_FFF0, "tweqi   r3,-16"),
    (0x0C63_FFF0, "twi     3,r3,-16"),
    (0x0A03_0010, "tdlti   r3,16"),
    // Rotates.
    (0x5464_283E, "rotlwi  r4,r3,5"),
    (0x5464_003E, "rotlwi  r4,r3,0"),
    (0x5464_017E, "clrlwi  r4,r3,5"),
    (0x5464_017F, "clrlwi. r4,r3,5"),
    (0x5464_2834, "rlwinm  r4,r3,5,0,26"),
    (0x5C64_283E, "rotlw   r4,r3,r5"),
    (0x5C64_28FF, "rlwnm.  r4,r3,r5,3,31"),
    (0x5064_28CE, "rlwimi  r4,r3,5,3,7"),
    (0x7864_2800, "rotldi  r4,r3,5"),
    (0x7864_0140, "clrldi  r4,r3,5"),
    (0x7864_0420, "clrldi  r4,r3,48"),
    (0x7864_28C0, "rldicl  r4,r3,5,3"),
    (0x7864_2BA4, "rldicr  r4,r3,5,46"),
    (0x7864_28C8, "rldic   r4,r3,5,3"),
    (0x7864_28CC, "rldimi  r4,r3,5,3"),
    (0x7864_2810, "rotld   r4,r3,r5"),
    (0x7864_28D0, "rldcl   r4,r3,r5,3"),
    (0x7864_28D2, "rldcr   r4,r3,r5,3"),
    // Loads and stores.
    (0x8064_0010, "lwz     r3,16(r4)"),
    (0x8060_0010, "lwz     r3,16(0)"),
    (0x8064_FFF0, "lwz     r3,-16(r4)"),
    (0xE864_0010, "ld      r3,16(r4)"),
    (0xE864_0011, "ldu     r3,16(r4)"),
    (0xE864_0012, "lwa     r3,16(r4)"),
    (0xE864_0013, ".long 0xe8640013"),
    (0xF864_0011, "stdu    r3,16(r4)"),
    (0x7C64_282E, "lwzx    r3,r4,r5"),
    (0x7C60_282E, "lwzx    r3,0,r5"),
    (0x7C64_2828, "lwarx   r3,r4,r5"),
    (0x7C64_2829, "lwarx   r3,r4,r5,1"),
    (0x7C64_29AD, "stdcx.  r3,r4,r5"),
    (0x7C64_29AC, ".long 0x7c6429ac"),
    (0x7C64_2CAA, "lswi    r3,r4,5"),
    (0x7C64_04AA, "lswi    r3,r4,32"),
    (0xC024_0010, "lfs     f1,16(r4)"),
    (0x7C24_2C2E, "lfsx    f1,r4,r5"),
    // Moves between registers.
    (0x7C68_02A6, "mflr    r3"),
    (0x7C69_02A6, "mfctr   r3"),
    (0x7C61_02A6, "mfxer   r3"),
    (0x7C68_03A6, "mtlr    r3"),
    (0x7C69_03A6, "mtctr   r3"),
    (0x7C70_42A6, "mfsprg  r3,0"),
    (0x7C71_42A6, "mfsprg  r3,1"),
    (0x7C70_43A6, "mtsprg  0,r3"),
    (0x7C74_42A6, "mfspr   r3,276"),
    (0x7C70_82A6, "mfibatu r3,0"),
    (0x7C71_82A6, "mfibatl r3,0"),
    (0x7C72_82A6, "mfibatu r3,1"),
    (0x7C7F_FAA6, "mfspr   r3,1023"),
    (0x7C7F_FBA6, "mtspr   1023,r3"),
    (0x7C6C_42E6, "mftbl   r3"),
    (0x7C6D_42E6, "mftbu   r3"),
    (0x7C61_02E6, ".long 0x7c6102e6"),
    (0x7C60_0026, "mfcr    r3"),
    (0x7C78_0026, "mfocrf  r3,128"),
    (0x7C78_1026, ".long 0x7c781026"),
    (0x7C6F_F120, "mtcr    r3"),
    (0x7C68_0120, "mtcrf   128,r3"),
    (0x7C78_0120, "mtocrf  128,r3"),
    // Condition register logic.
    (0x4C21_0A42, "crset   gt"),
    (0x4C21_0982, "crclr   gt"),
    (0x4CA6_3382, "crmove  4*cr1+gt,4*cr1+eq"),
    (0x4CA6_3042, "crnot   4*cr1+gt,4*cr1+eq"),
    (0x4CA6_3A02, "crand   4*cr1+gt,4*cr1+eq,4*cr1+so"),
    (0x4C8C_0000, "mcrf    cr1,cr3"),
    // Synchronization and cache control.
    (0x7C00_04AC, "sync    "),
    (0x7C20_04AC, "lwsync"),
    (0x7C40_04AC, "ptesync"),
    (0x7C60_04AC, "sync    3"),
    (0x7C00_06AC, "eieio"),
    (0x4C00_012C, "isync"),
    (0x7C03_20AC, "dcbf    r3,r4"),
    (0x7C23_20AC, "dcbfl   r3,r4"),
    (0x7C43_20AC, "dcbf    r3,r4"),
    (0x7C63_20AC, "dcbf    r3,r4,1"),
    (0x7C83_20AC, ".long 0x7c8320ac"),
    (0x7C03_222C, "dcbt    r3,r4"),
    (0x7C23_222C, "dcbt    r3,r4,1"),
    (0x7E03_222C, "dcbtt   r3,r4"),
    (0x7E23_222C, "dcbt    r3,r4,17"),
    (0x7C00_222C, "dcbt    0,r4"),
    (0x7C03_21EC, "dcbtst  r3,r4"),
    (0x7E03_21EC, "dcbtstt r3,r4"),
    (0x7C03_27EC, "dcbz    r3,r4"),
    (0x7C03_27AC, "icbi    r3,r4"),
    // Floating point.
    (0xFC22_182A, "fadd    f1,f2,f3"),
    (0xFC22_182B, "fadd.   f1,f2,f3"),
    (0xEC22_182A, "fadds   f1,f2,f3"),
    (0xFC22_00F2, "fmul    f1,f2,f3"),
    (0xFC22_20FA, "fmadd   f1,f2,f3,f4"),
    (0xFC22_20EE, "fsel    f1,f2,f3,f4"),
    (0xFC20_102C, "fsqrt   f1,f2"),
    (0xFC22_102C, ".long 0xfc22102c"),
    (0xFC20_1090, "fmr     f1,f2"),
    (0xFC80_1000, "fcmpu   cr1,f0,f2"),
    (0xFC01_1000, "fcmpu   cr0,f1,f2"),
    (0xFC21_1000, ".long 0xfc211000"),
    (0xFC20_048E, "mffs    f1"),
    (0xFDFE_158E, "mtfsf   255,f2"),
    (0xFC02_158E, "mtfsf   1,f2"),
    (0xFE02_158E, "mtfsf   1,f2,1,0"),
    (0xFC03_158E, "mtfsf   1,f2,0,1"),
    (0xFF80_510C, "mtfsfi  7,5"),
    (0xFF81_510C, "mtfsfi  7,5,1"),
    (0xFC60_008C, "mtfsb0  so"),
    (0xFC90_0080, "mcrfs   cr1,cr4"),
    (0xFC88_0080, "mcrfs   cr1,cr2"),
    // VMX.
    (0x1064_2800, "vaddubm v3,v4,v5"),
    (0x1064_2C84, "vor     v3,v4,v5"),
    (0x1065_2C84, "vmr     v3,v5"),
    (0x1064_2806, "vcmpequb v3,v4,v5"),
    (0x1064_2C06, "vcmpequb. v3,v4,v5"),
    (0x1064_298C, "vmrglw  v3,v4,v5"),
    (0x1060_298A, "vexptefp v3,v5"),
    (0x1061_2A0C, "vspltb  v3,v5,1"),
    (0x1070_2A0C, ".long 0x10702a0c"),
    (0x107F_030C, "vspltisb v3,-1"),
    (0x1064_298E, "vpkshss v3,v4,v5"),
    (0x1064_29AE, "vmaddfp v3,v4,v6,v5"),
    (0x1064_29AA, "vsel    v3,v4,v5,v6"),
    (0x1064_288C, "vmrghw  v3,v4,v5"),
    (0x1064_28AC, "vsldoi  v3,v4,v5,2"),
    (0x7C64_28CE, "lvx     v3,r4,r5"),
    (0x7C60_28CE, "lvx     v3,0,r5"),
    (0x7C64_29CE, "stvx    v3,r4,r5"),
    // Instructions objdump has no output for, because of a defect in the tool. The text comes from
    // the assembler, which takes it back to the same word.
    (0x1064_2F40, "vsubshs v3,v4,v5"),
    (0x1064_2E06, "vcmpgtub. v3,v4,v5"),
    (0x1064_2CC6, "vcmpeqfp. v3,v4,v5"),
    (0x1064_2FC6, "vcmpbfp. v3,v4,v5"),
    (0x1064_2D04, "vnor    v3,v4,v5"),
    (0x1060_0604, "mfvscr  v3"),
    (0x1000_2E44, "mtvscr  v5"),
    (0x1064_2D02, "vavgsb  v3,v4,v5"),
    (0x1064_2D42, "vavgsh  v3,v4,v5"),
    (0x1064_2D82, "vavgsw  v3,v4,v5"),
    (0x1064_2DC6, "vcmpgefp. v3,v4,v5"),
    (0x1064_2EC6, "vcmpgtfp. v3,v4,v5"),
    (0x1064_2F06, "vcmpgtsb. v3,v4,v5"),
    (0x1064_2F46, "vcmpgtsh. v3,v4,v5"),
    (0x1064_2F86, "vcmpgtsw. v3,v4,v5"),
    (0x1064_2E46, "vcmpgtuh. v3,v4,v5"),
    (0x1064_2E86, "vcmpgtuw. v3,v4,v5"),
    (0x1064_2D80, "vsubcuw v3,v4,v5"),
    (0x1064_2F00, "vsubsbs v3,v4,v5"),
    (0x1064_2F80, "vsubsws v3,v4,v5"),
    (0x1064_2E00, "vsububs v3,v4,v5"),
    (0x1064_2E40, "vsubuhs v3,v4,v5"),
    (0x1064_2E80, "vsubuws v3,v4,v5"),
    (0x1064_2E88, "vsum2sws v3,v4,v5"),
    (0x1064_2F08, "vsum4sbs v3,v4,v5"),
    (0x1064_2E48, "vsum4shs v3,v4,v5"),
    (0x1064_2E08, "vsum4ubs v3,v4,v5"),
    (0x1064_2F88, "vsumsws v3,v4,v5"),
    // Xenon extensions. objdump has no name for dcbz128 and mtmsree.
    (0x0000_0200, "attn"),
    (0x7C23_27EC, "dcbzl   r3,r4"),
    (0x7C20_27EC, "dcbzl   0,r4"),
    (0x7C61_0164, "mtmsrd  r3,1"),
    (0x7C60_0164, "mtmsrd  r3"),
    (0x7C60_0124, "mtmsr   r3"),
    (0x7C61_0124, "mtmsr   r3,1"),
    (0x7C64_2C0E, "lvlx    v3,r4,r5"),
    (0x7C64_2C4E, "lvrx    v3,r4,r5"),
    (0x7C64_2E0E, "lvlxl   v3,r4,r5"),
    (0x7C64_2E4E, "lvrxl   v3,r4,r5"),
    (0x7C64_2D0E, "stvlx   v3,r4,r5"),
    (0x7C64_2D4E, "stvrx   v3,r4,r5"),
    (0x7C64_2F0E, "stvlxl  v3,r4,r5"),
    (0x7C64_2F4E, "stvrxl  v3,r4,r5"),
    // VMX128.
    (0x10A6_38C3, "lvx128  v5,r6,r7"),
    (0x10A6_38CF, "lvx128  v101,r6,r7"),
    (0x10A0_38C3, "lvx128  v5,r0,r7"),
    (0x10A6_39C3, "stvx128 v5,r6,r7"),
    (0x10A6_3C03, "lvlx128 v5,r6,r7"),
    (0x10A6_3F43, "stvrxl128 v5,r6,r7"),
    (0x14A6_3810, "vaddfp128 v5,v6,v7"),
    (0x14A6_381C, "vaddfp128 v101,v6,v7"),
    (0x14A6_3813, "vaddfp128 v5,v6,v103"),
    (0x14A6_3830, "vaddfp128 v5,v38,v7"),
    (0x14A6_3C10, "vaddfp128 v5,v70,v7"),
    (0x14A6_38D0, "vmaddfp128 v5,v6,v7,v5"),
    (0x14A6_3910, "vmaddcfp128 v5,v6,v5,v7"),
    (0x14A6_3950, "vnmsubfp128 v5,v6,v7,v5"),
    (0x14A6_3B50, "vsel128 v5,v6,v7,v5"),
    (0x14A6_3840, "vperm128 v5,v6,v7,v1"),
    (0x10A6_3850, "vsldoi128 v5,v6,v7,1"),
    (0x18A6_3800, "vcmpeqfp128 v5,v6,v7"),
    (0x18A6_3840, "vcmpeqfp128. v5,v6,v7"),
    (0x18A6_3A40, "vcmpequw128. v5,v6,v7"),
    (0x18A6_3B80, "vupkhsb128 v5,v7"),
    (0x18A6_3A30, "vcfpsxws128 v5,v7,6"),
    (0x18BF_3A30, "vcfpsxws128 v5,v7,-1"),
    (0x18BF_3A70, "vcfpuxws128 v5,v7,31"),
    (0x18A6_3730, "vspltw128 v5,v6,6"),
    (0x18BF_3770, "vspltisw128 v5,v6,-1"),
    (0x18A6_3630, "vrefp128 v5,v6"),
    (0x18A6_3B30, "vrfim128 v5,v7"),
    (0x18A6_3A10, "vpermwi128 v5,v7,6"),
    (0x18A6_3BD0, "vpermwi128 v5,v7,230"),
    (0x18A6_3710, "vrlimi128 v5,v6,6,0"),
    (0x18A6_37D0, "vrlimi128 v5,v6,6,2"),
    (0x18BF_36D0, "vpkd3d128 v5,v6,3,2,2"),
    (0x18A6_37F0, "vupkd3d128 v5,v6,6"),
    // Not an instruction.
    (0x0000_0000, ".long 0x0"),
    (0xFFFF_FFFF, "fnmadd. f31,f31,f31,f31"),
];

/// Words objdump decodes under `-Mpower7` that are not Xenon instructions, so they do not decode.
const NOT_XENON: &[u32] = &[
    0x7C64_2E5E, // isel
    0xE064_0010, // lq
    0xF864_0012, // stq
    0x4C00_0064, // rfi
    0xF000_0000, // VSX
    0xEC00_0004, // decimal floating point
    0x7C03_02F4, // popcntw
    0xFC00_0010, // fcpsgn
    0x7C00_003C, // wait
];

#[test]
fn text_matches_objdump() {
    for &(word, expected) in TEXTS {
        assert_eq!(text_of(word, 0x10_0000), expected, "{word:#010x}");
    }
}

#[test]
fn later_additions_to_the_isa_do_not_decode() {
    for &word in NOT_XENON {
        assert_eq!(decode(word), None, "{word:#010x}");
    }
}

#[test]
fn format_prints_relative_targets_as_offsets() {
    let forward = decode(0x4800_0008).unwrap();
    assert_eq!(format(&forward), "b       .+0x8");
    let backward = decode(0x4BFF_FFF8).unwrap();
    assert_eq!(format(&backward), "b       .-0x8");
    let conditional = decode(0x4085_FFF0).unwrap();
    assert_eq!(format(&conditional), "ble     cr1,.-0x10");
    let absolute = decode(0x4800_000A).unwrap();
    assert_eq!(format(&absolute), "ba      0x8");
}

#[test]
fn targets_wrap_around_the_address_space() {
    let backward = decode(0x4BFF_FFF8).unwrap();
    assert_eq!(format_at(&backward, 0), "b       0xfffffff8");
    let forward = decode(0x4800_0008).unwrap();
    assert_eq!(format_at(&forward, 0xFFFF_FFFC), "b       0x4");
    let absolute = decode(0x4BFF_FFFA).unwrap();
    assert_eq!(format_at(&absolute, 0), "ba      0xfffffff8");
}

#[test]
fn undecoded_words_print_like_objdump() {
    assert_eq!(format_undecoded(0), ".long 0x0");
    assert_eq!(format_undecoded(0xABC), ".long 0xabc");
}
