// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The opcode table, the one place that says what an instruction looks like.
//!
//! Each row names an instruction, its form, the bits that identify it, and its operands in
//! assembly order. Everything else comes from the rows: [`Insn`], [`Opcode`], [`OPCODES`] and the
//! conversions between a word and an [`Insn`].
//!
//! A row does not state a mask. The bits no field takes up are the fixed ones, so a word only
//! matches when they equal the row's value, and every other bit ends up in a typed field. That
//! makes decoding lossless: `decode(word).unwrap().encode() == word` for every word.
//!
//! Encodings come from the PowerPC ISA 2.02 books and, for VMX128, from Xenia's
//! `ppc_opcode_table_gen.cc` and `ppc_decode_data.h` (BSD 3-Clause). Which fields a word may vary
//! in follows what `objdump -Mpower7 -Mvmx128` accepts, checked by running it over the words.

use crate::fields::*;

/// The layout of an instruction word, as the PowerPC manuals and Xenia name them.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Form {
    /// Long branch: 24-bit displacement.
    I,
    /// Conditional branch: 14-bit displacement.
    B,
    /// System call.
    SC,
    /// Two registers and a 16-bit immediate or displacement.
    D,
    /// Like D, with a displacement in words and a two-bit extended opcode.
    DS,
    /// Up to three registers and a 10-bit extended opcode.
    X,
    /// Branches to a register and condition register logic.
    XL,
    /// Moves to and from special registers.
    XFX,
    /// Move to the floating point status register.
    XFL,
    /// Shift with a 6-bit amount.
    XS,
    /// Integer arithmetic with an overflow bit.
    XO,
    /// Floating point with up to four registers.
    A,
    /// 32-bit rotates.
    M,
    /// 64-bit rotates by an immediate.
    MD,
    /// 64-bit rotates by a register.
    MDS,
    /// VMX with four operands.
    VA,
    /// VMX with up to three operands.
    VX,
    /// VMX comparisons, with a record bit.
    VXR,
    /// VMX128 with three vector registers.
    VX128,
    /// VMX128 loads and stores.
    VX128_1,
    /// VMX128 `vperm128`.
    VX128_2,
    /// VMX128 with an immediate between the registers.
    VX128_3,
    /// VMX128 `vrlimi128` and `vpkd3d128`.
    VX128_4,
    /// VMX128 `vsldoi128`.
    VX128_5,
    /// VMX128 comparisons, with a record bit.
    VX128_R,
    /// VMX128 `vpermwi128`.
    VX128_P,
}

/// One row of the opcode table.
#[derive(Debug, Clone, Copy)]
pub struct OpcodeInfo {
    /// The instruction this row describes.
    pub opcode: Opcode,
    /// The name of the instruction, without the suffixes its fields can add.
    pub mnemonic: &'static str,
    /// The layout of the word.
    pub form: Form,
    /// The bits that identify the instruction, with every field at zero.
    pub value: u32,
    /// Which bits of a word have to equal `value` for the word to match this row.
    pub mask: u32,
    /// The operands, in assembly order.
    pub(crate) fields: &'static [Field],
    /// A further condition on the word, for operands with reserved values.
    pub(crate) check: Option<fn(u32) -> bool>,
    /// Builds the instruction from a word that matches.
    pub(crate) decode: fn(u32) -> Insn,
}

macro_rules! check {
    () => {
        None
    };
    ($check:ident) => {
        Some($check)
    };
}

macro_rules! opcodes {
    ($($variant:ident $mnemonic:literal $form:ident $value:literal
        { $($field:ident: $ty:ty = $desc:ident),* $(,)? } $(if $check:ident)?;)*) => {
        /// A decoded instruction, one variant per opcode.
        ///
        /// Suffixes are fields, so `add`, `addo`, `add.` and `addo.` are all [`Insn::Add`].
        /// Simplified mnemonics are not variants: `li` is [`Insn::Addi`], and `blr` is
        /// [`Insn::Bclr`].
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Insn {
            $(
                #[doc = concat!("`", $mnemonic, "`, ", stringify!($form), " form, opcode bits `",
                                stringify!($value), "`.")]
                $variant {
                    $(
                        #[doc = concat!("The `", stringify!($desc), "` operand.")]
                        $field: $ty,
                    )*
                },
            )*
        }

        /// The opcode of an instruction, without its operands.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Opcode {
            $(
                #[doc = concat!("`", $mnemonic, "`.")]
                $variant,
            )*
        }

        /// Every instruction the decoder knows, one row per opcode.
        pub static OPCODES: &[OpcodeInfo] = &[
            $(OpcodeInfo {
                opcode: Opcode::$variant,
                mnemonic: $mnemonic,
                form: Form::$form,
                value: $value,
                mask: fixed_bits(&[$($desc),*]),
                fields: &[$($desc),*],
                check: check!($($check)?),
                decode: |_word| Insn::$variant {
                    $($field: FieldValue::from_field($desc.get(_word))),*
                },
            },)*
        ];

        /// The fixed bits of every row, in table order, for the index built at compile time.
        pub(crate) const ROW_VALUES: &[u32] = &[$($value),*];

        impl Insn {
            /// Returns the opcode of this instruction.
            pub fn opcode(&self) -> Opcode {
                match self {
                    $(Insn::$variant { .. } => Opcode::$variant,)*
                }
            }

            /// Returns the word this instruction decodes from.
            ///
            /// Operands too large for their field, which [`decode`](crate::decode) never produces,
            /// lose their high bits.
            pub fn encode(&self) -> u32 {
                match *self {
                    $(Insn::$variant { $($field),* } => {
                        $value $(| $desc.put(FieldValue::to_field($field)))*
                    })*
                }
            }
        }
    };
}

impl Opcode {
    /// Returns the table row of this opcode.
    pub fn info(self) -> &'static OpcodeInfo {
        // The rows and the variants come from the same list in the same order, so the discriminant
        // is always a valid index.
        &OPCODES[self as usize]
    }
}

/// Branch conditions that objdump accepts for `bc`: the reserved encodings are out, but it lets
/// the `z` bit of the "decrement and test" forms vary.
fn bc_bo_is_valid(word: u32) -> bool {
    !matches!(BO.get(word), 21..=23 | 28..=31)
}

/// Branch conditions that objdump accepts for branches to a register.
fn bclr_bo_is_valid(word: u32) -> bool {
    !matches!(BO.get(word), 1 | 3 | 9 | 11 | 21..=23 | 28..=31)
}

/// `mfocrf` and `mtocrf` name exactly one field of the condition register.
fn fxm_is_one_hot(word: u32) -> bool {
    FXM.get(word).count_ones() == 1
}

/// `mftb` only reads the two halves of the time base.
fn tbr_is_time_base(word: u32) -> bool {
    matches!(SPR.get(word), 268 | 269)
}

opcodes! {
    // I form.
    B "b" I 0x48000000 { li: i32 = LI, aa: bool = AA, lk: bool = LK };

    // B form.
    Bc "bc" B 0x40000000 { bo: u8 = BO, bi: CrBit = BI, bd: i16 = BD, aa: bool = AA, lk: bool = LK }
        if bc_bo_is_valid;

    // SC form.
    Sc "sc" SC 0x44000002 { lev: u8 = LEV, ignored: u8 = SC_IGNORED };

    // D form: traps and integer arithmetic.
    Tdi "tdi" D 0x08000000 { to: u8 = TO, ra: Gpr = RA, si: i16 = SI };
    Twi "twi" D 0x0C000000 { to: u8 = TO, ra: Gpr = RA, si: i16 = SI };
    Mulli "mulli" D 0x1C000000 { rt: Gpr = RT, ra: Gpr = RA, si: i16 = SI };
    Subfic "subfic" D 0x20000000 { rt: Gpr = RT, ra: Gpr = RA, si: i16 = SI };
    Cmpli "cmpli" D 0x28000000 {
        bf: CrField = BF, ignored: bool = CMP_IGNORED, l: bool = CMP_L, ra: Gpr = RA, ui: u16 = UI
    };
    Cmpi "cmpi" D 0x2C000000 {
        bf: CrField = BF, ignored: bool = CMP_IGNORED, l: bool = CMP_L, ra: Gpr = RA, si: i16 = SI
    };
    Addic "addic" D 0x30000000 { rt: Gpr = RT, ra: Gpr = RA, si: i16 = SI };
    AddicDot "addic." D 0x34000000 { rt: Gpr = RT, ra: Gpr = RA, si: i16 = SI };
    Addi "addi" D 0x38000000 { rt: Gpr = RT, ra: Gpr = RA, si: i16 = SI };
    Addis "addis" D 0x3C000000 { rt: Gpr = RT, ra: Gpr = RA, si: i16 = SI };
    Ori "ori" D 0x60000000 { ra: Gpr = RA, rs: Gpr = RS, ui: u16 = UI };
    Oris "oris" D 0x64000000 { ra: Gpr = RA, rs: Gpr = RS, ui: u16 = UI };
    Xori "xori" D 0x68000000 { ra: Gpr = RA, rs: Gpr = RS, ui: u16 = UI };
    Xoris "xoris" D 0x6C000000 { ra: Gpr = RA, rs: Gpr = RS, ui: u16 = UI };
    AndiDot "andi." D 0x70000000 { ra: Gpr = RA, rs: Gpr = RS, ui: u16 = UI };
    AndisDot "andis." D 0x74000000 { ra: Gpr = RA, rs: Gpr = RS, ui: u16 = UI };

    // D form: loads and stores.
    Lwz "lwz" D 0x80000000 { rt: Gpr = RT, d: i16 = D, ra: Gpr = RA0 };
    Lwzu "lwzu" D 0x84000000 { rt: Gpr = RT, d: i16 = D, ra: Gpr = RA0 };
    Lbz "lbz" D 0x88000000 { rt: Gpr = RT, d: i16 = D, ra: Gpr = RA0 };
    Lbzu "lbzu" D 0x8C000000 { rt: Gpr = RT, d: i16 = D, ra: Gpr = RA0 };
    Stw "stw" D 0x90000000 { rs: Gpr = RS, d: i16 = D, ra: Gpr = RA0 };
    Stwu "stwu" D 0x94000000 { rs: Gpr = RS, d: i16 = D, ra: Gpr = RA0 };
    Stb "stb" D 0x98000000 { rs: Gpr = RS, d: i16 = D, ra: Gpr = RA0 };
    Stbu "stbu" D 0x9C000000 { rs: Gpr = RS, d: i16 = D, ra: Gpr = RA0 };
    Lhz "lhz" D 0xA0000000 { rt: Gpr = RT, d: i16 = D, ra: Gpr = RA0 };
    Lhzu "lhzu" D 0xA4000000 { rt: Gpr = RT, d: i16 = D, ra: Gpr = RA0 };
    Lha "lha" D 0xA8000000 { rt: Gpr = RT, d: i16 = D, ra: Gpr = RA0 };
    Lhau "lhau" D 0xAC000000 { rt: Gpr = RT, d: i16 = D, ra: Gpr = RA0 };
    Sth "sth" D 0xB0000000 { rs: Gpr = RS, d: i16 = D, ra: Gpr = RA0 };
    Sthu "sthu" D 0xB4000000 { rs: Gpr = RS, d: i16 = D, ra: Gpr = RA0 };
    Lmw "lmw" D 0xB8000000 { rt: Gpr = RT, d: i16 = D, ra: Gpr = RA0 };
    Stmw "stmw" D 0xBC000000 { rs: Gpr = RS, d: i16 = D, ra: Gpr = RA0 };
    Lfs "lfs" D 0xC0000000 { frt: Fpr = FRT, d: i16 = D, ra: Gpr = RA0 };
    Lfsu "lfsu" D 0xC4000000 { frt: Fpr = FRT, d: i16 = D, ra: Gpr = RA0 };
    Lfd "lfd" D 0xC8000000 { frt: Fpr = FRT, d: i16 = D, ra: Gpr = RA0 };
    Lfdu "lfdu" D 0xCC000000 { frt: Fpr = FRT, d: i16 = D, ra: Gpr = RA0 };
    Stfs "stfs" D 0xD0000000 { frs: Fpr = FRS, d: i16 = D, ra: Gpr = RA0 };
    Stfsu "stfsu" D 0xD4000000 { frs: Fpr = FRS, d: i16 = D, ra: Gpr = RA0 };
    Stfd "stfd" D 0xD8000000 { frs: Fpr = FRS, d: i16 = D, ra: Gpr = RA0 };
    Stfdu "stfdu" D 0xDC000000 { frs: Fpr = FRS, d: i16 = D, ra: Gpr = RA0 };

    // DS form.
    Ld "ld" DS 0xE8000000 { rt: Gpr = RT, ds: i16 = DS, ra: Gpr = RA0 };
    Ldu "ldu" DS 0xE8000001 { rt: Gpr = RT, ds: i16 = DS, ra: Gpr = RA0 };
    Lwa "lwa" DS 0xE8000002 { rt: Gpr = RT, ds: i16 = DS, ra: Gpr = RA0 };
    Std "std" DS 0xF8000000 { rs: Gpr = RS, ds: i16 = DS, ra: Gpr = RA0 };
    Stdu "stdu" DS 0xF8000001 { rs: Gpr = RS, ds: i16 = DS, ra: Gpr = RA0 };

    // XL form.
    Mcrf "mcrf" XL 0x4C000000 { bf: CrField = BF, bfa: CrField = BFA };
    Bclr "bclr" XL 0x4C000020 { bo: u8 = BO, bi: CrBit = BI, bh: u8 = BH, lk: bool = LK }
        if bclr_bo_is_valid;
    Rfid "rfid" XL 0x4C000024 {};
    Crnor "crnor" XL 0x4C000042 { bt: CrBit = BT, ba: CrBit = BA, bb: CrBit = BB };
    Crandc "crandc" XL 0x4C000102 { bt: CrBit = BT, ba: CrBit = BA, bb: CrBit = BB };
    Isync "isync" XL 0x4C00012C {};
    Crxor "crxor" XL 0x4C000182 { bt: CrBit = BT, ba: CrBit = BA, bb: CrBit = BB };
    Crnand "crnand" XL 0x4C0001C2 { bt: CrBit = BT, ba: CrBit = BA, bb: CrBit = BB };
    Crand "crand" XL 0x4C000202 { bt: CrBit = BT, ba: CrBit = BA, bb: CrBit = BB };
    Hrfid "hrfid" XL 0x4C000224 {};
    Creqv "creqv" XL 0x4C000242 { bt: CrBit = BT, ba: CrBit = BA, bb: CrBit = BB };
    Crorc "crorc" XL 0x4C000342 { bt: CrBit = BT, ba: CrBit = BA, bb: CrBit = BB };
    Cror "cror" XL 0x4C000382 { bt: CrBit = BT, ba: CrBit = BA, bb: CrBit = BB };
    Bcctr "bcctr" XL 0x4C000420 { bo: u8 = BO, bi: CrBit = BI, bh: u8 = BH, lk: bool = LK }
        if bclr_bo_is_valid;

    // M form.
    Rlwimi "rlwimi" M 0x50000000 {
        ra: Gpr = RA, rs: Gpr = RS, sh: u8 = SH, mb: u8 = MB, me: u8 = ME, rc: bool = RC
    };
    Rlwinm "rlwinm" M 0x54000000 {
        ra: Gpr = RA, rs: Gpr = RS, sh: u8 = SH, mb: u8 = MB, me: u8 = ME, rc: bool = RC
    };
    Rlwnm "rlwnm" M 0x5C000000 {
        ra: Gpr = RA, rs: Gpr = RS, rb: Gpr = RB, mb: u8 = MB, me: u8 = ME, rc: bool = RC
    };

    // MD form.
    Rldicl "rldicl" MD 0x78000000 {
        ra: Gpr = RA, rs: Gpr = RS, sh: u8 = SH6, mb: u8 = MB6, rc: bool = RC
    };
    Rldicr "rldicr" MD 0x78000004 {
        ra: Gpr = RA, rs: Gpr = RS, sh: u8 = SH6, me: u8 = MB6, rc: bool = RC
    };
    Rldic "rldic" MD 0x78000008 {
        ra: Gpr = RA, rs: Gpr = RS, sh: u8 = SH6, mb: u8 = MB6, rc: bool = RC
    };
    Rldimi "rldimi" MD 0x7800000C {
        ra: Gpr = RA, rs: Gpr = RS, sh: u8 = SH6, mb: u8 = MB6, rc: bool = RC
    };

    // MDS form.
    Rldcl "rldcl" MDS 0x78000010 {
        ra: Gpr = RA, rs: Gpr = RS, rb: Gpr = RB, mb: u8 = MB6, rc: bool = RC
    };
    Rldcr "rldcr" MDS 0x78000012 {
        ra: Gpr = RA, rs: Gpr = RS, rb: Gpr = RB, me: u8 = MB6, rc: bool = RC
    };

    // XO form.
    Subfc "subfc" XO 0x7C000010 {
        rt: Gpr = RT, ra: Gpr = RA, rb: Gpr = RB, oe: bool = OE, rc: bool = RC
    };
    Addc "addc" XO 0x7C000014 {
        rt: Gpr = RT, ra: Gpr = RA, rb: Gpr = RB, oe: bool = OE, rc: bool = RC
    };
    Subf "subf" XO 0x7C000050 {
        rt: Gpr = RT, ra: Gpr = RA, rb: Gpr = RB, oe: bool = OE, rc: bool = RC
    };
    Neg "neg" XO 0x7C0000D0 { rt: Gpr = RT, ra: Gpr = RA, oe: bool = OE, rc: bool = RC };
    Subfe "subfe" XO 0x7C000110 {
        rt: Gpr = RT, ra: Gpr = RA, rb: Gpr = RB, oe: bool = OE, rc: bool = RC
    };
    Adde "adde" XO 0x7C000114 {
        rt: Gpr = RT, ra: Gpr = RA, rb: Gpr = RB, oe: bool = OE, rc: bool = RC
    };
    Subfze "subfze" XO 0x7C000190 { rt: Gpr = RT, ra: Gpr = RA, oe: bool = OE, rc: bool = RC };
    Addze "addze" XO 0x7C000194 { rt: Gpr = RT, ra: Gpr = RA, oe: bool = OE, rc: bool = RC };
    Subfme "subfme" XO 0x7C0001D0 { rt: Gpr = RT, ra: Gpr = RA, oe: bool = OE, rc: bool = RC };
    Addme "addme" XO 0x7C0001D4 { rt: Gpr = RT, ra: Gpr = RA, oe: bool = OE, rc: bool = RC };
    Mulld "mulld" XO 0x7C0001D2 {
        rt: Gpr = RT, ra: Gpr = RA, rb: Gpr = RB, oe: bool = OE, rc: bool = RC
    };
    Mullw "mullw" XO 0x7C0001D6 {
        rt: Gpr = RT, ra: Gpr = RA, rb: Gpr = RB, oe: bool = OE, rc: bool = RC
    };
    Add "add" XO 0x7C000214 {
        rt: Gpr = RT, ra: Gpr = RA, rb: Gpr = RB, oe: bool = OE, rc: bool = RC
    };
    Divdu "divdu" XO 0x7C000392 {
        rt: Gpr = RT, ra: Gpr = RA, rb: Gpr = RB, oe: bool = OE, rc: bool = RC
    };
    Divwu "divwu" XO 0x7C000396 {
        rt: Gpr = RT, ra: Gpr = RA, rb: Gpr = RB, oe: bool = OE, rc: bool = RC
    };
    Divd "divd" XO 0x7C0003D2 {
        rt: Gpr = RT, ra: Gpr = RA, rb: Gpr = RB, oe: bool = OE, rc: bool = RC
    };
    Divw "divw" XO 0x7C0003D6 {
        rt: Gpr = RT, ra: Gpr = RA, rb: Gpr = RB, oe: bool = OE, rc: bool = RC
    };
    Mulhdu "mulhdu" XO 0x7C000012 { rt: Gpr = RT, ra: Gpr = RA, rb: Gpr = RB, rc: bool = RC };
    Mulhwu "mulhwu" XO 0x7C000016 { rt: Gpr = RT, ra: Gpr = RA, rb: Gpr = RB, rc: bool = RC };
    Mulhd "mulhd" XO 0x7C000092 { rt: Gpr = RT, ra: Gpr = RA, rb: Gpr = RB, rc: bool = RC };
    Mulhw "mulhw" XO 0x7C000096 { rt: Gpr = RT, ra: Gpr = RA, rb: Gpr = RB, rc: bool = RC };

    // X form: comparisons and traps.
    Cmp "cmp" X 0x7C000000 { bf: CrField = BF, l: bool = CMP_L, ra: Gpr = RA, rb: Gpr = RB };
    Cmpl "cmpl" X 0x7C000040 { bf: CrField = BF, l: bool = CMP_L, ra: Gpr = RA, rb: Gpr = RB };
    Tw "tw" X 0x7C000008 { to: u8 = TO, ra: Gpr = RA, rb: Gpr = RB };
    Td "td" X 0x7C000088 { to: u8 = TO, ra: Gpr = RA, rb: Gpr = RB };

    // X form: logic and shifts.
    Slw "slw" X 0x7C000030 { ra: Gpr = RA, rs: Gpr = RS, rb: Gpr = RB, rc: bool = RC };
    Cntlzw "cntlzw" X 0x7C000034 { ra: Gpr = RA, rs: Gpr = RS, rc: bool = RC };
    Sld "sld" X 0x7C000036 { ra: Gpr = RA, rs: Gpr = RS, rb: Gpr = RB, rc: bool = RC };
    And "and" X 0x7C000038 { ra: Gpr = RA, rs: Gpr = RS, rb: Gpr = RB, rc: bool = RC };
    Cntlzd "cntlzd" X 0x7C000074 { ra: Gpr = RA, rs: Gpr = RS, rc: bool = RC };
    Andc "andc" X 0x7C000078 { ra: Gpr = RA, rs: Gpr = RS, rb: Gpr = RB, rc: bool = RC };
    Popcntb "popcntb" X 0x7C0000F4 { ra: Gpr = RA, rs: Gpr = RS };
    Nor "nor" X 0x7C0000F8 { ra: Gpr = RA, rs: Gpr = RS, rb: Gpr = RB, rc: bool = RC };
    Eqv "eqv" X 0x7C000238 { ra: Gpr = RA, rs: Gpr = RS, rb: Gpr = RB, rc: bool = RC };
    Xor "xor" X 0x7C000278 { ra: Gpr = RA, rs: Gpr = RS, rb: Gpr = RB, rc: bool = RC };
    Orc "orc" X 0x7C000338 { ra: Gpr = RA, rs: Gpr = RS, rb: Gpr = RB, rc: bool = RC };
    Or "or" X 0x7C000378 { ra: Gpr = RA, rs: Gpr = RS, rb: Gpr = RB, rc: bool = RC };
    Nand "nand" X 0x7C0003B8 { ra: Gpr = RA, rs: Gpr = RS, rb: Gpr = RB, rc: bool = RC };
    Srw "srw" X 0x7C000430 { ra: Gpr = RA, rs: Gpr = RS, rb: Gpr = RB, rc: bool = RC };
    Srd "srd" X 0x7C000436 { ra: Gpr = RA, rs: Gpr = RS, rb: Gpr = RB, rc: bool = RC };
    Sraw "sraw" X 0x7C000630 { ra: Gpr = RA, rs: Gpr = RS, rb: Gpr = RB, rc: bool = RC };
    Srad "srad" X 0x7C000634 { ra: Gpr = RA, rs: Gpr = RS, rb: Gpr = RB, rc: bool = RC };
    Srawi "srawi" X 0x7C000670 { ra: Gpr = RA, rs: Gpr = RS, sh: u8 = SH, rc: bool = RC };
    Extsh "extsh" X 0x7C000734 { ra: Gpr = RA, rs: Gpr = RS, rc: bool = RC };
    Extsb "extsb" X 0x7C000774 { ra: Gpr = RA, rs: Gpr = RS, rc: bool = RC };
    Extsw "extsw" X 0x7C0007B4 { ra: Gpr = RA, rs: Gpr = RS, rc: bool = RC };

    // XS form.
    Sradi "sradi" XS 0x7C000674 { ra: Gpr = RA, rs: Gpr = RS, sh: u8 = SH6, rc: bool = RC };

    // X form: indexed integer loads and stores.
    Lwarx "lwarx" X 0x7C000028 { rt: Gpr = RT, ra: Gpr = RA0, rb: Gpr = RB, eh: u8 = EH };
    Ldx "ldx" X 0x7C00002A { rt: Gpr = RT, ra: Gpr = RA0, rb: Gpr = RB };
    Lwzx "lwzx" X 0x7C00002E { rt: Gpr = RT, ra: Gpr = RA0, rb: Gpr = RB };
    Ldux "ldux" X 0x7C00006A { rt: Gpr = RT, ra: Gpr = RA0, rb: Gpr = RB };
    Lwzux "lwzux" X 0x7C00006E { rt: Gpr = RT, ra: Gpr = RA0, rb: Gpr = RB };
    Ldarx "ldarx" X 0x7C0000A8 { rt: Gpr = RT, ra: Gpr = RA0, rb: Gpr = RB, eh: u8 = EH };
    Lbzx "lbzx" X 0x7C0000AE { rt: Gpr = RT, ra: Gpr = RA0, rb: Gpr = RB };
    Lbzux "lbzux" X 0x7C0000EE { rt: Gpr = RT, ra: Gpr = RA0, rb: Gpr = RB };
    Stdx "stdx" X 0x7C00012A { rs: Gpr = RS, ra: Gpr = RA0, rb: Gpr = RB };
    StwcxDot "stwcx." X 0x7C00012D { rs: Gpr = RS, ra: Gpr = RA0, rb: Gpr = RB };
    Stwx "stwx" X 0x7C00012E { rs: Gpr = RS, ra: Gpr = RA0, rb: Gpr = RB };
    Stdux "stdux" X 0x7C00016A { rs: Gpr = RS, ra: Gpr = RA0, rb: Gpr = RB };
    Stwux "stwux" X 0x7C00016E { rs: Gpr = RS, ra: Gpr = RA0, rb: Gpr = RB };
    StdcxDot "stdcx." X 0x7C0001AD { rs: Gpr = RS, ra: Gpr = RA0, rb: Gpr = RB };
    Stbx "stbx" X 0x7C0001AE { rs: Gpr = RS, ra: Gpr = RA0, rb: Gpr = RB };
    Stbux "stbux" X 0x7C0001EE { rs: Gpr = RS, ra: Gpr = RA0, rb: Gpr = RB };
    Lhzx "lhzx" X 0x7C00022E { rt: Gpr = RT, ra: Gpr = RA0, rb: Gpr = RB };
    Lhzux "lhzux" X 0x7C00026E { rt: Gpr = RT, ra: Gpr = RA0, rb: Gpr = RB };
    Lwax "lwax" X 0x7C0002AA { rt: Gpr = RT, ra: Gpr = RA0, rb: Gpr = RB };
    Lhax "lhax" X 0x7C0002AE { rt: Gpr = RT, ra: Gpr = RA0, rb: Gpr = RB };
    Lwaux "lwaux" X 0x7C0002EA { rt: Gpr = RT, ra: Gpr = RA0, rb: Gpr = RB };
    Lhaux "lhaux" X 0x7C0002EE { rt: Gpr = RT, ra: Gpr = RA0, rb: Gpr = RB };
    Sthx "sthx" X 0x7C00032E { rs: Gpr = RS, ra: Gpr = RA0, rb: Gpr = RB };
    Sthux "sthux" X 0x7C00036E { rs: Gpr = RS, ra: Gpr = RA0, rb: Gpr = RB };
    Ldbrx "ldbrx" X 0x7C000428 { rt: Gpr = RT, ra: Gpr = RA0, rb: Gpr = RB };
    Lswx "lswx" X 0x7C00042A { rt: Gpr = RT, ra: Gpr = RA0, rb: Gpr = RB };
    Lwbrx "lwbrx" X 0x7C00042C { rt: Gpr = RT, ra: Gpr = RA0, rb: Gpr = RB };
    Lswi "lswi" X 0x7C0004AA { rt: Gpr = RT, ra: Gpr = RA0, nb: u8 = NB };
    Stdbrx "stdbrx" X 0x7C000528 { rs: Gpr = RS, ra: Gpr = RA0, rb: Gpr = RB };
    Stswx "stswx" X 0x7C00052A { rs: Gpr = RS, ra: Gpr = RA0, rb: Gpr = RB };
    Stwbrx "stwbrx" X 0x7C00052C { rs: Gpr = RS, ra: Gpr = RA0, rb: Gpr = RB };
    Stswi "stswi" X 0x7C0005AA { rs: Gpr = RS, ra: Gpr = RA0, nb: u8 = NB };
    Lhbrx "lhbrx" X 0x7C00062C { rt: Gpr = RT, ra: Gpr = RA0, rb: Gpr = RB };
    Sthbrx "sthbrx" X 0x7C00072C { rs: Gpr = RS, ra: Gpr = RA0, rb: Gpr = RB };

    // X form: indexed floating point loads and stores.
    Lfsx "lfsx" X 0x7C00042E { frt: Fpr = FRT, ra: Gpr = RA0, rb: Gpr = RB };
    Lfsux "lfsux" X 0x7C00046E { frt: Fpr = FRT, ra: Gpr = RA0, rb: Gpr = RB };
    Lfdx "lfdx" X 0x7C0004AE { frt: Fpr = FRT, ra: Gpr = RA0, rb: Gpr = RB };
    Lfdux "lfdux" X 0x7C0004EE { frt: Fpr = FRT, ra: Gpr = RA0, rb: Gpr = RB };
    Stfsx "stfsx" X 0x7C00052E { frs: Fpr = FRS, ra: Gpr = RA0, rb: Gpr = RB };
    Stfsux "stfsux" X 0x7C00056E { frs: Fpr = FRS, ra: Gpr = RA0, rb: Gpr = RB };
    Stfdx "stfdx" X 0x7C0005AE { frs: Fpr = FRS, ra: Gpr = RA0, rb: Gpr = RB };
    Stfdux "stfdux" X 0x7C0005EE { frs: Fpr = FRS, ra: Gpr = RA0, rb: Gpr = RB };
    Stfiwx "stfiwx" X 0x7C0007AE { frs: Fpr = FRS, ra: Gpr = RA0, rb: Gpr = RB };

    // X form: moves between registers and system instructions.
    Mfcr "mfcr" X 0x7C000026 { rt: Gpr = RT };
    Mfmsr "mfmsr" X 0x7C0000A6 { rt: Gpr = RT };
    Mtmsr "mtmsr" X 0x7C000124 { rs: Gpr = RS, l: u8 = MSR_L };
    Mtmsrd "mtmsrd" X 0x7C000164 { rs: Gpr = RS };
    Tlbiel "tlbiel" X 0x7C000224 { rb: Gpr = RB, l: u8 = TLB_L };
    Tlbie "tlbie" X 0x7C000264 { rb: Gpr = RB, l: u8 = TLB_L };
    Tlbia "tlbia" X 0x7C0002E4 {};
    Slbmte "slbmte" X 0x7C000324 { rs: Gpr = RS, rb: Gpr = RB };
    Slbie "slbie" X 0x7C000364 { rb: Gpr = RB };
    Slbia "slbia" X 0x7C0003E4 {};
    Mcrxr "mcrxr" X 0x7C000400 { bf: CrField = BF };
    Tlbsync "tlbsync" X 0x7C00046C {};
    Sync "sync" X 0x7C0004AC { l: u8 = SYNC_L };
    Slbmfev "slbmfev" X 0x7C0006A6 { rt: Gpr = RT, rb: Gpr = RB };
    Eieio "eieio" X 0x7C0006AC {};
    Slbmfee "slbmfee" X 0x7C000726 { rt: Gpr = RT, rb: Gpr = RB };

    // X form: cache control.
    Dcbst "dcbst" X 0x7C00006C { ra: Gpr = RA0, rb: Gpr = RB };
    Dcbf "dcbf" X 0x7C0000AC { ra: Gpr = RA0, rb: Gpr = RB, l: u8 = CACHE_L };
    Dcbtst "dcbtst" X 0x7C0001EC { ra: Gpr = RA0, rb: Gpr = RB, th: u8 = TH };
    Dcbt "dcbt" X 0x7C00022C { ra: Gpr = RA0, rb: Gpr = RB, th: u8 = TH };
    Eciwx "eciwx" X 0x7C00026C { rt: Gpr = RT, ra: Gpr = RA0, rb: Gpr = RB };
    Ecowx "ecowx" X 0x7C00036C { rs: Gpr = RS, ra: Gpr = RA0, rb: Gpr = RB };
    Dcbi "dcbi" X 0x7C0003AC { ra: Gpr = RA0, rb: Gpr = RB };
    Dcba "dcba" X 0x7C0005EC { ra: Gpr = RA0, rb: Gpr = RB };
    Icbi "icbi" X 0x7C0007AC { ra: Gpr = RA0, rb: Gpr = RB };
    Dcbz "dcbz" X 0x7C0007EC { ra: Gpr = RA0, rb: Gpr = RB };

    // XFX form.
    Mfocrf "mfocrf" XFX 0x7C100026 { rt: Gpr = RT, fxm: u8 = FXM } if fxm_is_one_hot;
    Mtcrf "mtcrf" XFX 0x7C000120 { fxm: u8 = FXM, rs: Gpr = RS };
    Mtocrf "mtocrf" XFX 0x7C100120 { fxm: u8 = FXM, rs: Gpr = RS } if fxm_is_one_hot;
    Mfspr "mfspr" XFX 0x7C0002A6 { rt: Gpr = RT, spr: u16 = SPR };
    Mftb "mftb" XFX 0x7C0002E6 { rt: Gpr = RT, tbr: u16 = SPR } if tbr_is_time_base;
    Mtspr "mtspr" XFX 0x7C0003A6 { spr: u16 = SPR, rs: Gpr = RS };

    // X form: floating point.
    Fcmpu "fcmpu" X 0xFC000000 { bf: CrField = BF, fra: Fpr = FRA, frb: Fpr = FRB };
    Frsp "frsp" X 0xFC000018 { frt: Fpr = FRT, frb: Fpr = FRB, rc: bool = RC };
    Fctiw "fctiw" X 0xFC00001C { frt: Fpr = FRT, frb: Fpr = FRB, rc: bool = RC };
    Fctiwz "fctiwz" X 0xFC00001E { frt: Fpr = FRT, frb: Fpr = FRB, rc: bool = RC };
    Fcmpo "fcmpo" X 0xFC000040 { bf: CrField = BF, fra: Fpr = FRA, frb: Fpr = FRB };
    Mtfsb1 "mtfsb1" X 0xFC00004C { bt: CrBit = BT, rc: bool = RC };
    Fneg "fneg" X 0xFC000050 { frt: Fpr = FRT, frb: Fpr = FRB, rc: bool = RC };
    Mcrfs "mcrfs" X 0xFC000080 { bf: CrField = BF, bfa: CrField = BFA };
    Mtfsb0 "mtfsb0" X 0xFC00008C { bt: CrBit = BT, rc: bool = RC };
    Fmr "fmr" X 0xFC000090 { frt: Fpr = FRT, frb: Fpr = FRB, rc: bool = RC };
    Mtfsfi "mtfsfi" X 0xFC00010C {
        bf: u8 = MTFSFI_BF, u: u8 = FPSCR_U, w: u8 = MTFSF_W, rc: bool = RC
    };
    Fnabs "fnabs" X 0xFC000110 { frt: Fpr = FRT, frb: Fpr = FRB, rc: bool = RC };
    Fabs "fabs" X 0xFC000210 { frt: Fpr = FRT, frb: Fpr = FRB, rc: bool = RC };
    Frin "frin" X 0xFC000310 { frt: Fpr = FRT, frb: Fpr = FRB, rc: bool = RC };
    Friz "friz" X 0xFC000350 { frt: Fpr = FRT, frb: Fpr = FRB, rc: bool = RC };
    Frip "frip" X 0xFC000390 { frt: Fpr = FRT, frb: Fpr = FRB, rc: bool = RC };
    Frim "frim" X 0xFC0003D0 { frt: Fpr = FRT, frb: Fpr = FRB, rc: bool = RC };
    Mffs "mffs" X 0xFC00048E { frt: Fpr = FRT, rc: bool = RC };
    Fctid "fctid" X 0xFC00065C { frt: Fpr = FRT, frb: Fpr = FRB, rc: bool = RC };
    Fctidz "fctidz" X 0xFC00065E { frt: Fpr = FRT, frb: Fpr = FRB, rc: bool = RC };
    Fcfid "fcfid" X 0xFC00069C { frt: Fpr = FRT, frb: Fpr = FRB, rc: bool = RC };

    // XFL form.
    Mtfsf "mtfsf" XFL 0xFC00058E {
        flm: u8 = FLM, frb: Fpr = FRB, l: u8 = MTFSF_L, w: u8 = MTFSF_W, rc: bool = RC
    };

    // A form.
    Fdivs "fdivs" A 0xEC000024 { frt: Fpr = FRT, fra: Fpr = FRA, frb: Fpr = FRB, rc: bool = RC };
    Fsubs "fsubs" A 0xEC000028 { frt: Fpr = FRT, fra: Fpr = FRA, frb: Fpr = FRB, rc: bool = RC };
    Fadds "fadds" A 0xEC00002A { frt: Fpr = FRT, fra: Fpr = FRA, frb: Fpr = FRB, rc: bool = RC };
    Fsqrts "fsqrts" A 0xEC00002C { frt: Fpr = FRT, frb: Fpr = FRB, rc: bool = RC };
    Fres "fres" A 0xEC000030 { frt: Fpr = FRT, frb: Fpr = FRB, rc: bool = RC };
    Fmuls "fmuls" A 0xEC000032 { frt: Fpr = FRT, fra: Fpr = FRA, frc: Fpr = FRC, rc: bool = RC };
    Frsqrtes "frsqrtes" A 0xEC000034 { frt: Fpr = FRT, frb: Fpr = FRB, rc: bool = RC };
    Fmsubs "fmsubs" A 0xEC000038 {
        frt: Fpr = FRT, fra: Fpr = FRA, frc: Fpr = FRC, frb: Fpr = FRB, rc: bool = RC
    };
    Fmadds "fmadds" A 0xEC00003A {
        frt: Fpr = FRT, fra: Fpr = FRA, frc: Fpr = FRC, frb: Fpr = FRB, rc: bool = RC
    };
    Fnmsubs "fnmsubs" A 0xEC00003C {
        frt: Fpr = FRT, fra: Fpr = FRA, frc: Fpr = FRC, frb: Fpr = FRB, rc: bool = RC
    };
    Fnmadds "fnmadds" A 0xEC00003E {
        frt: Fpr = FRT, fra: Fpr = FRA, frc: Fpr = FRC, frb: Fpr = FRB, rc: bool = RC
    };
    Fdiv "fdiv" A 0xFC000024 { frt: Fpr = FRT, fra: Fpr = FRA, frb: Fpr = FRB, rc: bool = RC };
    Fsub "fsub" A 0xFC000028 { frt: Fpr = FRT, fra: Fpr = FRA, frb: Fpr = FRB, rc: bool = RC };
    Fadd "fadd" A 0xFC00002A { frt: Fpr = FRT, fra: Fpr = FRA, frb: Fpr = FRB, rc: bool = RC };
    Fsqrt "fsqrt" A 0xFC00002C { frt: Fpr = FRT, frb: Fpr = FRB, rc: bool = RC };
    Fsel "fsel" A 0xFC00002E {
        frt: Fpr = FRT, fra: Fpr = FRA, frc: Fpr = FRC, frb: Fpr = FRB, rc: bool = RC
    };
    Fre "fre" A 0xFC000030 { frt: Fpr = FRT, frb: Fpr = FRB, rc: bool = RC };
    Fmul "fmul" A 0xFC000032 { frt: Fpr = FRT, fra: Fpr = FRA, frc: Fpr = FRC, rc: bool = RC };
    Frsqrte "frsqrte" A 0xFC000034 { frt: Fpr = FRT, frb: Fpr = FRB, rc: bool = RC };
    Fmsub "fmsub" A 0xFC000038 {
        frt: Fpr = FRT, fra: Fpr = FRA, frc: Fpr = FRC, frb: Fpr = FRB, rc: bool = RC
    };
    Fmadd "fmadd" A 0xFC00003A {
        frt: Fpr = FRT, fra: Fpr = FRA, frc: Fpr = FRC, frb: Fpr = FRB, rc: bool = RC
    };
    Fnmsub "fnmsub" A 0xFC00003C {
        frt: Fpr = FRT, fra: Fpr = FRA, frc: Fpr = FRC, frb: Fpr = FRB, rc: bool = RC
    };
    Fnmadd "fnmadd" A 0xFC00003E {
        frt: Fpr = FRT, fra: Fpr = FRA, frc: Fpr = FRC, frb: Fpr = FRB, rc: bool = RC
    };

    // X form: VMX loads, stores and data streams.
    Lvsl "lvsl" X 0x7C00000C { vd: Vr = VD, ra: Gpr = RA0, rb: Gpr = RB };
    Lvebx "lvebx" X 0x7C00000E { vd: Vr = VD, ra: Gpr = RA0, rb: Gpr = RB };
    Lvsr "lvsr" X 0x7C00004C { vd: Vr = VD, ra: Gpr = RA0, rb: Gpr = RB };
    Lvehx "lvehx" X 0x7C00004E { vd: Vr = VD, ra: Gpr = RA0, rb: Gpr = RB };
    Lvewx "lvewx" X 0x7C00008E { vd: Vr = VD, ra: Gpr = RA0, rb: Gpr = RB };
    Lvx "lvx" X 0x7C0000CE { vd: Vr = VD, ra: Gpr = RA0, rb: Gpr = RB };
    Stvebx "stvebx" X 0x7C00010E { vs: Vr = VS, ra: Gpr = RA0, rb: Gpr = RB };
    Stvehx "stvehx" X 0x7C00014E { vs: Vr = VS, ra: Gpr = RA0, rb: Gpr = RB };
    Stvewx "stvewx" X 0x7C00018E { vs: Vr = VS, ra: Gpr = RA0, rb: Gpr = RB };
    Stvx "stvx" X 0x7C0001CE { vs: Vr = VS, ra: Gpr = RA0, rb: Gpr = RB };
    Lvxl "lvxl" X 0x7C0002CE { vd: Vr = VD, ra: Gpr = RA0, rb: Gpr = RB };
    Stvxl "stvxl" X 0x7C0003CE { vs: Vr = VS, ra: Gpr = RA0, rb: Gpr = RB };
    Dst "dst" X 0x7C0002AC {
        t: bool = DST_T, ra: Gpr = RA, rb: Gpr = RB, strm: u8 = STREAM, ignored: u8 = DST_IGNORED
    };
    Dstst "dstst" X 0x7C0002EC {
        t: bool = DST_T, ra: Gpr = RA, rb: Gpr = RB, strm: u8 = STREAM, ignored: u8 = DST_IGNORED
    };
    Dss "dss" X 0x7C00066C { all: bool = DST_T, strm: u8 = STREAM, ignored: u16 = DSS_IGNORED };

    // VX form: moves to and from the status register.
    Mfvscr "mfvscr" VX 0x10000604 { vd: Vr = VD };
    Mtvscr "mtvscr" VX 0x10000644 { vb: Vr = VB };

    // VX form: three registers.
    Vaddubm "vaddubm" VX 0x10000000 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vmaxub "vmaxub" VX 0x10000002 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vrlb "vrlb" VX 0x10000004 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vmuloub "vmuloub" VX 0x10000008 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vaddfp "vaddfp" VX 0x1000000A { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vmrghb "vmrghb" VX 0x1000000C { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vpkuhum "vpkuhum" VX 0x1000000E { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vadduhm "vadduhm" VX 0x10000040 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vmaxuh "vmaxuh" VX 0x10000042 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vrlh "vrlh" VX 0x10000044 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vmulouh "vmulouh" VX 0x10000048 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vsubfp "vsubfp" VX 0x1000004A { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vmrghh "vmrghh" VX 0x1000004C { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vpkuwum "vpkuwum" VX 0x1000004E { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vadduwm "vadduwm" VX 0x10000080 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vmaxuw "vmaxuw" VX 0x10000082 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vrlw "vrlw" VX 0x10000084 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vmrghw "vmrghw" VX 0x1000008C { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vpkuhus "vpkuhus" VX 0x1000008E { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vpkuwus "vpkuwus" VX 0x100000CE { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vmaxsb "vmaxsb" VX 0x10000102 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vslb "vslb" VX 0x10000104 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vmulosb "vmulosb" VX 0x10000108 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vmrglb "vmrglb" VX 0x1000010C { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vpkshus "vpkshus" VX 0x1000010E { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vmaxsh "vmaxsh" VX 0x10000142 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vslh "vslh" VX 0x10000144 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vmulosh "vmulosh" VX 0x10000148 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vmrglh "vmrglh" VX 0x1000014C { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vpkswus "vpkswus" VX 0x1000014E { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vaddcuw "vaddcuw" VX 0x10000180 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vmaxsw "vmaxsw" VX 0x10000182 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vslw "vslw" VX 0x10000184 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vmrglw "vmrglw" VX 0x1000018C { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vpkshss "vpkshss" VX 0x1000018E { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vsl "vsl" VX 0x100001C4 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vpkswss "vpkswss" VX 0x100001CE { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vaddubs "vaddubs" VX 0x10000200 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vminub "vminub" VX 0x10000202 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vsrb "vsrb" VX 0x10000204 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vmuleub "vmuleub" VX 0x10000208 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vadduhs "vadduhs" VX 0x10000240 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vminuh "vminuh" VX 0x10000242 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vsrh "vsrh" VX 0x10000244 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vmuleuh "vmuleuh" VX 0x10000248 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vadduws "vadduws" VX 0x10000280 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vminuw "vminuw" VX 0x10000282 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vsrw "vsrw" VX 0x10000284 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vsr "vsr" VX 0x100002C4 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vaddsbs "vaddsbs" VX 0x10000300 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vminsb "vminsb" VX 0x10000302 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vsrab "vsrab" VX 0x10000304 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vmulesb "vmulesb" VX 0x10000308 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vpkpx "vpkpx" VX 0x1000030E { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vaddshs "vaddshs" VX 0x10000340 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vminsh "vminsh" VX 0x10000342 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vsrah "vsrah" VX 0x10000344 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vmulesh "vmulesh" VX 0x10000348 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vaddsws "vaddsws" VX 0x10000380 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vminsw "vminsw" VX 0x10000382 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vsraw "vsraw" VX 0x10000384 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vsububm "vsububm" VX 0x10000400 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vavgub "vavgub" VX 0x10000402 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vand "vand" VX 0x10000404 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vmaxfp "vmaxfp" VX 0x1000040A { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vslo "vslo" VX 0x1000040C { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vsubuhm "vsubuhm" VX 0x10000440 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vavguh "vavguh" VX 0x10000442 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vandc "vandc" VX 0x10000444 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vminfp "vminfp" VX 0x1000044A { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vsro "vsro" VX 0x1000044C { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vsubuwm "vsubuwm" VX 0x10000480 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vavguw "vavguw" VX 0x10000482 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vor "vor" VX 0x10000484 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vxor "vxor" VX 0x100004C4 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vavgsb "vavgsb" VX 0x10000502 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vnor "vnor" VX 0x10000504 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vavgsh "vavgsh" VX 0x10000542 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vsubcuw "vsubcuw" VX 0x10000580 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vavgsw "vavgsw" VX 0x10000582 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vsububs "vsububs" VX 0x10000600 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vsum4ubs "vsum4ubs" VX 0x10000608 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vsubuhs "vsubuhs" VX 0x10000640 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vsum4shs "vsum4shs" VX 0x10000648 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vsubuws "vsubuws" VX 0x10000680 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vsum2sws "vsum2sws" VX 0x10000688 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vsubsbs "vsubsbs" VX 0x10000700 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vsum4sbs "vsum4sbs" VX 0x10000708 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vsubshs "vsubshs" VX 0x10000740 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vsubsws "vsubsws" VX 0x10000780 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };
    Vsumsws "vsumsws" VX 0x10000788 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB };

    // VX form: two registers.
    Vrefp "vrefp" VX 0x1000010A { vd: Vr = VD, vb: Vr = VB };
    Vrsqrtefp "vrsqrtefp" VX 0x1000014A { vd: Vr = VD, vb: Vr = VB };
    Vexptefp "vexptefp" VX 0x1000018A { vd: Vr = VD, vb: Vr = VB };
    Vlogefp "vlogefp" VX 0x100001CA { vd: Vr = VD, vb: Vr = VB };
    Vrfin "vrfin" VX 0x1000020A { vd: Vr = VD, vb: Vr = VB };
    Vupkhsb "vupkhsb" VX 0x1000020E { vd: Vr = VD, vb: Vr = VB };
    Vrfiz "vrfiz" VX 0x1000024A { vd: Vr = VD, vb: Vr = VB };
    Vupkhsh "vupkhsh" VX 0x1000024E { vd: Vr = VD, vb: Vr = VB };
    Vrfip "vrfip" VX 0x1000028A { vd: Vr = VD, vb: Vr = VB };
    Vupklsb "vupklsb" VX 0x1000028E { vd: Vr = VD, vb: Vr = VB };
    Vrfim "vrfim" VX 0x100002CA { vd: Vr = VD, vb: Vr = VB };
    Vupklsh "vupklsh" VX 0x100002CE { vd: Vr = VD, vb: Vr = VB };
    Vupkhpx "vupkhpx" VX 0x1000034E { vd: Vr = VD, vb: Vr = VB };
    Vupklpx "vupklpx" VX 0x100003CE { vd: Vr = VD, vb: Vr = VB };

    // VX form: immediates.
    Vspltb "vspltb" VX 0x1000020C { vd: Vr = VD, vb: Vr = VB, uim: u8 = VUIM4 };
    Vsplth "vsplth" VX 0x1000024C { vd: Vr = VD, vb: Vr = VB, uim: u8 = VUIM3 };
    Vspltw "vspltw" VX 0x1000028C { vd: Vr = VD, vb: Vr = VB, uim: u8 = VUIM2 };
    Vcfux "vcfux" VX 0x1000030A { vd: Vr = VD, vb: Vr = VB, uim: u8 = VUIM5 };
    Vspltisb "vspltisb" VX 0x1000030C { vd: Vr = VD, sim: i16 = VSIM };
    Vcfsx "vcfsx" VX 0x1000034A { vd: Vr = VD, vb: Vr = VB, uim: u8 = VUIM5 };
    Vspltish "vspltish" VX 0x1000034C { vd: Vr = VD, sim: i16 = VSIM };
    Vctuxs "vctuxs" VX 0x1000038A { vd: Vr = VD, vb: Vr = VB, uim: u8 = VUIM5 };
    Vspltisw "vspltisw" VX 0x1000038C { vd: Vr = VD, sim: i16 = VSIM };
    Vctsxs "vctsxs" VX 0x100003CA { vd: Vr = VD, vb: Vr = VB, uim: u8 = VUIM5 };

    // VXR form.
    Vcmpequb "vcmpequb" VXR 0x10000006 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB, rc: bool = VRC };
    Vcmpequh "vcmpequh" VXR 0x10000046 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB, rc: bool = VRC };
    Vcmpequw "vcmpequw" VXR 0x10000086 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB, rc: bool = VRC };
    Vcmpeqfp "vcmpeqfp" VXR 0x100000C6 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB, rc: bool = VRC };
    Vcmpgefp "vcmpgefp" VXR 0x100001C6 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB, rc: bool = VRC };
    Vcmpgtub "vcmpgtub" VXR 0x10000206 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB, rc: bool = VRC };
    Vcmpgtuh "vcmpgtuh" VXR 0x10000246 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB, rc: bool = VRC };
    Vcmpgtuw "vcmpgtuw" VXR 0x10000286 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB, rc: bool = VRC };
    Vcmpgtfp "vcmpgtfp" VXR 0x100002C6 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB, rc: bool = VRC };
    Vcmpgtsb "vcmpgtsb" VXR 0x10000306 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB, rc: bool = VRC };
    Vcmpgtsh "vcmpgtsh" VXR 0x10000346 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB, rc: bool = VRC };
    Vcmpgtsw "vcmpgtsw" VXR 0x10000386 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB, rc: bool = VRC };
    Vcmpbfp "vcmpbfp" VXR 0x100003C6 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB, rc: bool = VRC };

    // VA form.
    Vmhaddshs "vmhaddshs" VA 0x10000020 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB, vc: Vr = VC };
    Vmhraddshs "vmhraddshs" VA 0x10000021 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB, vc: Vr = VC };
    Vmladduhm "vmladduhm" VA 0x10000022 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB, vc: Vr = VC };
    Vmsumubm "vmsumubm" VA 0x10000024 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB, vc: Vr = VC };
    Vmsummbm "vmsummbm" VA 0x10000025 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB, vc: Vr = VC };
    Vmsumuhm "vmsumuhm" VA 0x10000026 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB, vc: Vr = VC };
    Vmsumuhs "vmsumuhs" VA 0x10000027 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB, vc: Vr = VC };
    Vmsumshm "vmsumshm" VA 0x10000028 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB, vc: Vr = VC };
    Vmsumshs "vmsumshs" VA 0x10000029 { vd: Vr = VD, va: Vr = VA, vb: Vr = VB, vc: Vr = VC };
    Vsel "vsel" VA 0x1000002A { vd: Vr = VD, va: Vr = VA, vb: Vr = VB, vc: Vr = VC };
    Vperm "vperm" VA 0x1000002B { vd: Vr = VD, va: Vr = VA, vb: Vr = VB, vc: Vr = VC };
    Vsldoi "vsldoi" VA 0x1000002C { vd: Vr = VD, va: Vr = VA, vb: Vr = VB, shb: u8 = VSHB };
    Vmaddfp "vmaddfp" VA 0x1000002E { vd: Vr = VD, va: Vr = VA, vc: Vr = VC, vb: Vr = VB };
    Vnmsubfp "vnmsubfp" VA 0x1000002F { vd: Vr = VD, va: Vr = VA, vc: Vr = VC, vb: Vr = VB };

    // Xenon extensions: instructions the PowerPC books do not have, or that Xenon gives a meaning
    // they do not.
    Attn "attn" X 0x00000200 { ignored: u16 = ATTN_IGNORED };
    Dcbz128 "dcbz128" X 0x7C2007EC { ra: Gpr = RA0, rb: Gpr = RB };
    Mtmsree "mtmsree" X 0x7C010164 { rs: Gpr = RS };

    // Xenon extensions: unaligned vector loads and stores.
    Lvlx "lvlx" X 0x7C00040E { vd: Vr = VD, ra: Gpr = RA0, rb: Gpr = RB };
    Lvrx "lvrx" X 0x7C00044E { vd: Vr = VD, ra: Gpr = RA0, rb: Gpr = RB };
    Stvlx "stvlx" X 0x7C00050E { vs: Vr = VS, ra: Gpr = RA0, rb: Gpr = RB };
    Stvrx "stvrx" X 0x7C00054E { vs: Vr = VS, ra: Gpr = RA0, rb: Gpr = RB };
    Lvlxl "lvlxl" X 0x7C00060E { vd: Vr = VD, ra: Gpr = RA0, rb: Gpr = RB };
    Lvrxl "lvrxl" X 0x7C00064E { vd: Vr = VD, ra: Gpr = RA0, rb: Gpr = RB };
    Stvlxl "stvlxl" X 0x7C00070E { vs: Vr = VS, ra: Gpr = RA0, rb: Gpr = RB };
    Stvrxl "stvrxl" X 0x7C00074E { vs: Vr = VS, ra: Gpr = RA0, rb: Gpr = RB };

    // VMX128: VX128_1, loads and stores.
    Lvsl128 "lvsl128" VX128_1 0x10000003 { vd: Vr = VD128, ra: Gpr = RA, rb: Gpr = RB };
    Lvsr128 "lvsr128" VX128_1 0x10000043 { vd: Vr = VD128, ra: Gpr = RA, rb: Gpr = RB };
    Lvewx128 "lvewx128" VX128_1 0x10000083 { vd: Vr = VD128, ra: Gpr = RA, rb: Gpr = RB };
    Lvx128 "lvx128" VX128_1 0x100000C3 { vd: Vr = VD128, ra: Gpr = RA, rb: Gpr = RB };
    Stvewx128 "stvewx128" VX128_1 0x10000183 { vs: Vr = VD128, ra: Gpr = RA, rb: Gpr = RB };
    Stvx128 "stvx128" VX128_1 0x100001C3 { vs: Vr = VD128, ra: Gpr = RA, rb: Gpr = RB };
    Lvxl128 "lvxl128" VX128_1 0x100002C3 { vd: Vr = VD128, ra: Gpr = RA, rb: Gpr = RB };
    Stvxl128 "stvxl128" VX128_1 0x100003C3 { vs: Vr = VD128, ra: Gpr = RA, rb: Gpr = RB };
    Lvlx128 "lvlx128" VX128_1 0x10000403 { vd: Vr = VD128, ra: Gpr = RA, rb: Gpr = RB };
    Lvrx128 "lvrx128" VX128_1 0x10000443 { vd: Vr = VD128, ra: Gpr = RA, rb: Gpr = RB };
    Stvlx128 "stvlx128" VX128_1 0x10000503 { vs: Vr = VD128, ra: Gpr = RA, rb: Gpr = RB };
    Stvrx128 "stvrx128" VX128_1 0x10000543 { vs: Vr = VD128, ra: Gpr = RA, rb: Gpr = RB };
    Lvlxl128 "lvlxl128" VX128_1 0x10000603 { vd: Vr = VD128, ra: Gpr = RA, rb: Gpr = RB };
    Lvrxl128 "lvrxl128" VX128_1 0x10000643 { vd: Vr = VD128, ra: Gpr = RA, rb: Gpr = RB };
    Stvlxl128 "stvlxl128" VX128_1 0x10000703 { vs: Vr = VD128, ra: Gpr = RA, rb: Gpr = RB };
    Stvrxl128 "stvrxl128" VX128_1 0x10000743 { vs: Vr = VD128, ra: Gpr = RA, rb: Gpr = RB };

    // VMX128: VX128_5.
    Vsldoi128 "vsldoi128" VX128_5 0x10000010 {
        vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128, sh: u8 = VSH128
    };

    // VMX128: VX128_2.
    Vperm128 "vperm128" VX128_2 0x14000000 {
        vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128, vc: Vr = VC128
    };

    // VMX128: VX128, primary opcode 5.
    Vaddfp128 "vaddfp128" VX128 0x14000010 { vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128 };
    Vsubfp128 "vsubfp128" VX128 0x14000050 { vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128 };
    Vmulfp128 "vmulfp128" VX128 0x14000090 { vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128 };
    Vmaddfp128 "vmaddfp128" VX128 0x140000D0 { vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128 };
    Vmaddcfp128 "vmaddcfp128" VX128 0x14000110 { vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128 };
    Vnmsubfp128 "vnmsubfp128" VX128 0x14000150 { vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128 };
    Vmsum3fp128 "vmsum3fp128" VX128 0x14000190 { vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128 };
    Vmsum4fp128 "vmsum4fp128" VX128 0x140001D0 { vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128 };
    Vpkshss128 "vpkshss128" VX128 0x14000200 { vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128 };
    Vand128 "vand128" VX128 0x14000210 { vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128 };
    Vpkshus128 "vpkshus128" VX128 0x14000240 { vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128 };
    Vandc128 "vandc128" VX128 0x14000250 { vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128 };
    Vpkswss128 "vpkswss128" VX128 0x14000280 { vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128 };
    Vnor128 "vnor128" VX128 0x14000290 { vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128 };
    Vpkswus128 "vpkswus128" VX128 0x140002C0 { vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128 };
    Vor128 "vor128" VX128 0x140002D0 { vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128 };
    Vpkuhum128 "vpkuhum128" VX128 0x14000300 { vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128 };
    Vxor128 "vxor128" VX128 0x14000310 { vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128 };
    Vpkuhus128 "vpkuhus128" VX128 0x14000340 { vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128 };
    Vsel128 "vsel128" VX128 0x14000350 { vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128 };
    Vpkuwum128 "vpkuwum128" VX128 0x14000380 { vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128 };
    Vslo128 "vslo128" VX128 0x14000390 { vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128 };
    Vpkuwus128 "vpkuwus128" VX128 0x140003C0 { vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128 };
    Vsro128 "vsro128" VX128 0x140003D0 { vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128 };

    // VMX128: VX128_R.
    Vcmpeqfp128 "vcmpeqfp128" VX128_R 0x18000000 {
        vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128, rc: bool = VRC128
    };
    Vcmpgefp128 "vcmpgefp128" VX128_R 0x18000080 {
        vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128, rc: bool = VRC128
    };
    Vcmpgtfp128 "vcmpgtfp128" VX128_R 0x18000100 {
        vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128, rc: bool = VRC128
    };
    Vcmpbfp128 "vcmpbfp128" VX128_R 0x18000180 {
        vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128, rc: bool = VRC128
    };
    Vcmpequw128 "vcmpequw128" VX128_R 0x18000200 {
        vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128, rc: bool = VRC128
    };

    // VMX128: VX128, primary opcode 6.
    Vrlw128 "vrlw128" VX128 0x18000050 { vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128 };
    Vslw128 "vslw128" VX128 0x180000D0 { vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128 };
    Vsraw128 "vsraw128" VX128 0x18000150 { vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128 };
    Vsrw128 "vsrw128" VX128 0x180001D0 { vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128 };
    Vmaxfp128 "vmaxfp128" VX128 0x18000280 { vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128 };
    Vminfp128 "vminfp128" VX128 0x180002C0 { vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128 };
    Vmrghw128 "vmrghw128" VX128 0x18000300 { vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128 };
    Vmrglw128 "vmrglw128" VX128 0x18000340 { vd: Vr = VD128, va: Vr = VA128, vb: Vr = VB128 };
    Vupkhsb128 "vupkhsb128" VX128 0x18000380 {
        vd: Vr = VD128, vb: Vr = VB128, ignored: u8 = VA128_HIDDEN
    };
    Vupklsb128 "vupklsb128" VX128 0x180003C0 {
        vd: Vr = VD128, vb: Vr = VB128, ignored: u8 = VA128_HIDDEN
    };

    // VMX128: VX128_3.
    Vcfpsxws128 "vcfpsxws128" VX128_3 0x18000230 {
        vd: Vr = VD128, vb: Vr = VB128, simm: i16 = VSIMM128
    };
    Vcfpuxws128 "vcfpuxws128" VX128_3 0x18000270 {
        vd: Vr = VD128, vb: Vr = VB128, uimm: u8 = VIMM128
    };
    Vcsxwfp128 "vcsxwfp128" VX128_3 0x180002B0 {
        vd: Vr = VD128, vb: Vr = VB128, simm: i16 = VSIMM128
    };
    Vcuxwfp128 "vcuxwfp128" VX128_3 0x180002F0 {
        vd: Vr = VD128, vb: Vr = VB128, uimm: u8 = VIMM128
    };
    Vrfim128 "vrfim128" VX128_3 0x18000330 {
        vd: Vr = VD128, vb: Vr = VB128, ignored: u8 = VIMM128_HIDDEN
    };
    Vrfin128 "vrfin128" VX128_3 0x18000370 {
        vd: Vr = VD128, vb: Vr = VB128, ignored: u8 = VIMM128_HIDDEN
    };
    Vrfip128 "vrfip128" VX128_3 0x180003B0 {
        vd: Vr = VD128, vb: Vr = VB128, ignored: u8 = VIMM128_HIDDEN
    };
    Vrfiz128 "vrfiz128" VX128_3 0x180003F0 {
        vd: Vr = VD128, vb: Vr = VB128, ignored: u8 = VIMM128_HIDDEN
    };
    Vrefp128 "vrefp128" VX128_3 0x18000630 {
        vd: Vr = VD128, vb: Vr = VB128, ignored: u8 = VIMM128_HIDDEN
    };
    Vrsqrtefp128 "vrsqrtefp128" VX128_3 0x18000670 {
        vd: Vr = VD128, vb: Vr = VB128, ignored: u8 = VIMM128_HIDDEN
    };
    Vexptefp128 "vexptefp128" VX128_3 0x180006B0 {
        vd: Vr = VD128, vb: Vr = VB128, ignored: u8 = VIMM128_HIDDEN
    };
    Vlogefp128 "vlogefp128" VX128_3 0x180006F0 {
        vd: Vr = VD128, vb: Vr = VB128, ignored: u8 = VIMM128_HIDDEN
    };
    Vspltw128 "vspltw128" VX128_3 0x18000730 { vd: Vr = VD128, vb: Vr = VB128, uimm: u8 = VIMM128 };
    Vspltisw128 "vspltisw128" VX128_3 0x18000770 {
        vd: Vr = VD128, vb: Vr = VB128, simm: i16 = VSIMM128
    };
    Vupkd3d128 "vupkd3d128" VX128_3 0x180007F0 {
        vd: Vr = VD128, vb: Vr = VB128, uimm: u8 = VIMM128
    };

    // VMX128: VX128_P.
    Vpermwi128 "vpermwi128" VX128_P 0x18000210 {
        vd: Vr = VD128, vb: Vr = VB128, perm: u8 = VPERM128
    };

    // VMX128: VX128_4.
    Vpkd3d128 "vpkd3d128" VX128_4 0x18000610 {
        vd: Vr = VD128, vb: Vr = VB128, imm: u8 = VIMM128, z: u8 = VZ128
    };
    Vrlimi128 "vrlimi128" VX128_4 0x18000710 {
        vd: Vr = VD128, vb: Vr = VB128, imm: u8 = VIMM128, z: u8 = VZ128
    };
}
