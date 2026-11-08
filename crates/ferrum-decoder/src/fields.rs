// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Operand types and the bit layout of instruction fields.
//!
//! A [`Field`] says where an operand lives in the word and how it prints. Bit positions here count
//! from the least significant bit, unlike the PowerPC manuals, so `shift` is what a `>>` would use.

/// A general purpose register, `r0` to `r31`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Gpr(pub u8);

/// A floating point register, `f0` to `f31`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fpr(pub u8);

/// A vector register: `v0` to `v31` in VMX, `v0` to `v127` in VMX128.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Vr(pub u8);

/// A condition register field, `cr0` to `cr7`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CrField(pub u8);

/// One bit of the condition register, numbered from 0 as in `4*cr1+eq`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CrBit(pub u8);

/// How a field shows up in the text of an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Print {
    /// Not an operand of its own: the field only matters to simplified mnemonics.
    Hidden,
    /// Reserved bits that objdump lets vary and does not show.
    Ignored,
    /// `r3`.
    Gpr,
    /// `r3`, but `0` for register 0, as for the base register of a load.
    GprOrZero,
    /// `f3`.
    Fpr,
    /// `v3`.
    Vr,
    /// `cr3`.
    Cr,
    /// `4*cr3+eq`.
    CrBit,
    /// A decimal number.
    Int,
    /// A decimal number, left out when it and every other optional operand are zero.
    Optional,
    /// A displacement, written `16(` so that the next operand closes the parenthesis.
    Disp,
    /// A branch target relative to the instruction.
    Relative,
    /// The byte count of `lswi` and `stswi`, where 0 means 32.
    ByteCount,
    /// The `o` of an overflow-enabled mnemonic.
    SuffixOe,
    /// The `.` of a mnemonic that records its result in the condition register.
    SuffixRc,
    /// The `l` of a branch that sets the link register.
    SuffixLk,
    /// The `a` of a branch to an absolute address.
    SuffixAa,
}

/// A run of bits of one field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Part {
    shift: u8,
    width: u8,
}

/// An operand of an instruction: its bits, how to turn them into a value, and how it prints.
///
/// A field can be split over the word, as in `mfspr` and VMX128. Its parts are listed from the
/// least significant bits of the value up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Field {
    parts: [Part; 3],
    signed: bool,
    scale: u8,
    pub(crate) print: Print,
}

const NO_PART: Part = Part { shift: 0, width: 0 };

impl Field {
    /// A field in one run of bits.
    pub(crate) const fn new(shift: u8, width: u8, print: Print) -> Self {
        Self::split(shift, width, 0, 0, print)
    }

    /// A field whose low bits and high bits are apart.
    pub(crate) const fn split(
        low_shift: u8,
        low_width: u8,
        high_shift: u8,
        high_width: u8,
        print: Print,
    ) -> Self {
        Self {
            parts: [
                Part {
                    shift: low_shift,
                    width: low_width,
                },
                Part {
                    shift: high_shift,
                    width: high_width,
                },
                NO_PART,
            ],
            signed: false,
            scale: 0,
            print,
        }
    }

    /// A field in three runs of bits, from the lowest bits of the value up.
    pub(crate) const fn split3(parts: [(u8, u8); 3], print: Print) -> Self {
        let mut field = Self::split(parts[0].0, parts[0].1, parts[1].0, parts[1].1, print);
        field.parts[2] = Part {
            shift: parts[2].0,
            width: parts[2].1,
        };
        field
    }

    /// Makes the value a signed two's complement number.
    pub(crate) const fn signed(mut self) -> Self {
        self.signed = true;
        self
    }

    /// Multiplies the value by `1 << scale`, as for displacements counted in words.
    pub(crate) const fn scaled(mut self, scale: u8) -> Self {
        self.scale = scale;
        self
    }

    /// The bits of the word this field takes up.
    pub(crate) const fn mask(&self) -> u32 {
        let mut mask = 0;
        let mut i = 0;
        while i < self.parts.len() {
            let part = self.parts[i];
            mask |= low_bits(part.width) << part.shift;
            i += 1;
        }
        mask
    }

    /// Reads the value of the field out of a word.
    pub(crate) const fn get(&self, word: u32) -> i32 {
        let mut raw = 0u32;
        let mut position = 0;
        let mut i = 0;
        while i < self.parts.len() {
            let part = self.parts[i];
            raw |= ((word >> part.shift) & low_bits(part.width)) << position;
            position += part.width;
            i += 1;
        }
        // The cast reinterprets the bits, and fields are at most 26 bits wide, so it loses nothing.
        let value = raw as i32;
        let value = if self.signed {
            let unused = 32 - position as u32;
            (value << unused) >> unused
        } else {
            value
        };
        value << self.scale
    }

    /// Returns the bits of a word that hold `value`, keeping only what fits in the field.
    pub(crate) const fn put(&self, value: i32) -> u32 {
        // The cast reinterprets the bits. Bits that do not fit are dropped by the masks below.
        let mut raw = (value >> self.scale) as u32;
        let mut word = 0;
        let mut i = 0;
        while i < self.parts.len() {
            let part = self.parts[i];
            word |= (raw & low_bits(part.width)) << part.shift;
            raw >>= part.width;
            i += 1;
        }
        word
    }
}

/// A value with the lowest `width` bits set.
const fn low_bits(width: u8) -> u32 {
    (1u32 << width) - 1
}

/// Returns the fixed bits of a row: the ones no field takes up.
pub(crate) const fn fixed_bits(fields: &[Field]) -> u32 {
    let mut used = 0;
    let mut i = 0;
    while i < fields.len() {
        used |= fields[i].mask();
        i += 1;
    }
    !used
}

/// The conversion between the value of a field and the type of an [`Insn`](crate::Insn) field.
///
/// The casts below only ever narrow values that fit, because a field is narrower than its type.
pub(crate) trait FieldValue: Copy {
    /// Converts from the value [`Field::get`] returned.
    fn from_field(value: i32) -> Self;
    /// Converts to the value [`Field::put`] takes.
    fn to_field(self) -> i32;
}

macro_rules! field_value {
    ($($ty:ty => $value:ident: $from:expr, $to:expr;)*) => {
        $(impl FieldValue for $ty {
            fn from_field($value: i32) -> Self {
                $from
            }
            fn to_field(self) -> i32 {
                let $value = self;
                $to
            }
        })*
    };
}

field_value! {
    bool => value: value != 0, i32::from(value);
    u8 => value: value as u8, i32::from(value);
    u16 => value: value as u16, i32::from(value);
    i16 => value: value as i16, i32::from(value);
    i32 => value: value, value;
    Gpr => value: Gpr(value as u8), i32::from(value.0);
    Fpr => value: Fpr(value as u8), i32::from(value.0);
    Vr => value: Vr(value as u8), i32::from(value.0);
    CrField => value: CrField(value as u8), i32::from(value.0);
    CrBit => value: CrBit(value as u8), i32::from(value.0);
}

// Registers and fields shared by most forms.
pub(crate) const RT: Field = Field::new(21, 5, Print::Gpr);
pub(crate) const RS: Field = Field::new(21, 5, Print::Gpr);
pub(crate) const RA: Field = Field::new(16, 5, Print::Gpr);
pub(crate) const RA0: Field = Field::new(16, 5, Print::GprOrZero);
pub(crate) const RB: Field = Field::new(11, 5, Print::Gpr);
pub(crate) const FRT: Field = Field::new(21, 5, Print::Fpr);
pub(crate) const FRS: Field = Field::new(21, 5, Print::Fpr);
pub(crate) const FRA: Field = Field::new(16, 5, Print::Fpr);
pub(crate) const FRB: Field = Field::new(11, 5, Print::Fpr);
pub(crate) const FRC: Field = Field::new(6, 5, Print::Fpr);
pub(crate) const OE: Field = Field::new(10, 1, Print::SuffixOe);
pub(crate) const RC: Field = Field::new(0, 1, Print::SuffixRc);
pub(crate) const AA: Field = Field::new(1, 1, Print::SuffixAa);
pub(crate) const LK: Field = Field::new(0, 1, Print::SuffixLk);

// Immediates and displacements.
pub(crate) const SI: Field = Field::new(0, 16, Print::Int).signed();
pub(crate) const UI: Field = Field::new(0, 16, Print::Int);
pub(crate) const D: Field = Field::new(0, 16, Print::Disp).signed();
pub(crate) const DS: Field = Field::new(2, 14, Print::Disp).signed().scaled(2);

// Branches.
pub(crate) const LI: Field = Field::new(2, 24, Print::Relative).signed().scaled(2);
pub(crate) const BD: Field = Field::new(2, 14, Print::Relative).signed().scaled(2);
pub(crate) const BO: Field = Field::new(21, 5, Print::Int);
pub(crate) const BI: Field = Field::new(16, 5, Print::CrBit);
pub(crate) const BH: Field = Field::new(11, 2, Print::Optional);
pub(crate) const LEV: Field = Field::new(5, 7, Print::Optional);

// Condition register.
pub(crate) const BF: Field = Field::new(23, 3, Print::Cr);
pub(crate) const BFA: Field = Field::new(18, 3, Print::Cr);
pub(crate) const BT: Field = Field::new(21, 5, Print::CrBit);
pub(crate) const BA: Field = Field::new(16, 5, Print::CrBit);
pub(crate) const BB: Field = Field::new(11, 5, Print::CrBit);
pub(crate) const CMP_L: Field = Field::new(21, 1, Print::Hidden);
pub(crate) const FXM: Field = Field::new(12, 8, Print::Int);

// Reserved bits that objdump lets vary, kept so that a word and its instruction stay one to one.
pub(crate) const ATTN_IGNORED: Field = Field::new(11, 15, Print::Ignored);
pub(crate) const SC_IGNORED: Field = Field::split(2, 3, 12, 4, Print::Ignored);
pub(crate) const CMP_IGNORED: Field = Field::new(22, 1, Print::Ignored);
pub(crate) const DST_IGNORED: Field = Field::split(0, 1, 23, 2, Print::Ignored);
pub(crate) const DSS_IGNORED: Field = Field::split3([(0, 1), (11, 10), (23, 2)], Print::Ignored);

// Traps.
pub(crate) const TO: Field = Field::new(21, 5, Print::Int);

// Shifts and rotates.
pub(crate) const SH: Field = Field::new(11, 5, Print::Int);
pub(crate) const MB: Field = Field::new(6, 5, Print::Int);
pub(crate) const ME: Field = Field::new(1, 5, Print::Int);
pub(crate) const SH6: Field = Field::split(11, 5, 1, 1, Print::Int);
pub(crate) const MB6: Field = Field::split(6, 5, 5, 1, Print::Int);

// Special purpose registers: the two halves of the number are swapped in the word.
pub(crate) const SPR: Field = Field::split(16, 5, 11, 5, Print::Int);

// Floating point status.
pub(crate) const FLM: Field = Field::new(17, 8, Print::Int);
pub(crate) const MTFSF_L: Field = Field::new(25, 1, Print::Optional);
pub(crate) const MTFSF_W: Field = Field::new(16, 1, Print::Optional);
pub(crate) const FPSCR_U: Field = Field::new(12, 4, Print::Int);
pub(crate) const MTFSFI_BF: Field = Field::new(23, 3, Print::Int);

// Memory and cache control.
pub(crate) const NB: Field = Field::new(11, 5, Print::ByteCount);
pub(crate) const TH: Field = Field::new(21, 5, Print::Optional);
pub(crate) const EH: Field = Field::new(0, 1, Print::Optional);
pub(crate) const CACHE_L: Field = Field::new(21, 2, Print::Hidden);
pub(crate) const TLB_L: Field = Field::new(21, 1, Print::Optional);
pub(crate) const MSR_L: Field = Field::new(16, 1, Print::Optional);
pub(crate) const SYNC_L: Field = Field::new(21, 2, Print::Optional);
pub(crate) const STREAM: Field = Field::new(21, 2, Print::Int);
pub(crate) const DST_T: Field = Field::new(25, 1, Print::Hidden);

// VMX.
pub(crate) const VD: Field = Field::new(21, 5, Print::Vr);
pub(crate) const VS: Field = Field::new(21, 5, Print::Vr);
pub(crate) const VA: Field = Field::new(16, 5, Print::Vr);
pub(crate) const VB: Field = Field::new(11, 5, Print::Vr);
pub(crate) const VC: Field = Field::new(6, 5, Print::Vr);
pub(crate) const VSHB: Field = Field::new(6, 4, Print::Int);
pub(crate) const VUIM5: Field = Field::new(16, 5, Print::Int);
pub(crate) const VUIM4: Field = Field::new(16, 4, Print::Int);
pub(crate) const VUIM3: Field = Field::new(16, 3, Print::Int);
pub(crate) const VUIM2: Field = Field::new(16, 2, Print::Int);
pub(crate) const VSIM: Field = Field::new(16, 5, Print::Int).signed();
pub(crate) const VRC: Field = Field::new(10, 1, Print::SuffixRc);

// VMX128: registers go up to 127, so their high bits sit elsewhere in the word.
pub(crate) const VD128: Field = Field::split(21, 5, 2, 2, Print::Vr);
pub(crate) const VA128: Field = Field::split3([(16, 5), (5, 1), (10, 1)], Print::Vr);
pub(crate) const VB128: Field = Field::split(11, 5, 0, 2, Print::Vr);
pub(crate) const VC128: Field = Field::new(6, 3, Print::Vr);
pub(crate) const VSH128: Field = Field::new(6, 4, Print::Int);
pub(crate) const VRC128: Field = Field::new(6, 1, Print::SuffixRc);
pub(crate) const VA128_HIDDEN: Field = Field::split3([(16, 5), (5, 1), (10, 1)], Print::Ignored);
pub(crate) const VSIMM128: Field = Field::new(16, 5, Print::Int).signed();
pub(crate) const VIMM128: Field = Field::new(16, 5, Print::Int);
pub(crate) const VIMM128_HIDDEN: Field = Field::new(16, 5, Print::Ignored);
pub(crate) const VPERM128: Field = Field::split(16, 5, 6, 3, Print::Int);
pub(crate) const VZ128: Field = Field::new(6, 2, Print::Int);
