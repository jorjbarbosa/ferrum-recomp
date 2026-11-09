// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Instructions for the unit tests, built with `Insn::encode`.

use ferrum_decoder::{CrBit, CrField, Gpr, Insn};

pub(crate) fn li(rt: u8, si: i16) -> Insn {
    addi(rt, 0, si)
}

pub(crate) fn addi(rt: u8, ra: u8, si: i16) -> Insn {
    Insn::Addi {
        rt: Gpr(rt),
        ra: Gpr(ra),
        si,
    }
}

pub(crate) fn lis(rt: u8, si: i16) -> Insn {
    Insn::Addis {
        rt: Gpr(rt),
        ra: Gpr(0),
        si,
    }
}

/// `lis` and `addi` that load `value` into `rt`.
pub(crate) fn load_address(rt: u8, value: u32) -> [Insn; 2] {
    // The low half is added as a signed number, so the high half makes up for it. Both casts
    // keep the bits on purpose.
    let low = value as u16 as i16;
    let high = (value.wrapping_sub(low as i32 as u32) >> 16) as u16 as i16;
    [lis(rt, high), addi(rt, rt, low)]
}

pub(crate) fn slwi(ra: u8, rs: u8, sh: u8) -> Insn {
    Insn::Rlwinm {
        ra: Gpr(ra),
        rs: Gpr(rs),
        sh,
        mb: 0,
        me: 31 - sh,
        rc: false,
    }
}

pub(crate) fn add(rt: u8, ra: u8, rb: u8) -> Insn {
    Insn::Add {
        rt: Gpr(rt),
        ra: Gpr(ra),
        rb: Gpr(rb),
        oe: false,
        rc: false,
    }
}

pub(crate) fn lwzx(rt: u8, ra: u8, rb: u8) -> Insn {
    Insn::Lwzx {
        rt: Gpr(rt),
        ra: Gpr(ra),
        rb: Gpr(rb),
    }
}

pub(crate) fn lhzx(rt: u8, ra: u8, rb: u8) -> Insn {
    Insn::Lhzx {
        rt: Gpr(rt),
        ra: Gpr(ra),
        rb: Gpr(rb),
    }
}

pub(crate) fn lbzx(rt: u8, ra: u8, rb: u8) -> Insn {
    Insn::Lbzx {
        rt: Gpr(rt),
        ra: Gpr(ra),
        rb: Gpr(rb),
    }
}

pub(crate) fn lwz(rt: u8, d: i16, ra: u8) -> Insn {
    Insn::Lwz {
        rt: Gpr(rt),
        d,
        ra: Gpr(ra),
    }
}

pub(crate) fn stw(rs: u8, d: i16, ra: u8) -> Insn {
    Insn::Stw {
        rs: Gpr(rs),
        d,
        ra: Gpr(ra),
    }
}

pub(crate) fn nop() -> Insn {
    Insn::Ori {
        ra: Gpr(0),
        rs: Gpr(0),
        ui: 0,
    }
}

pub(crate) fn mtctr(rs: u8) -> Insn {
    Insn::Mtspr {
        spr: 9,
        rs: Gpr(rs),
    }
}

pub(crate) fn bctr() -> Insn {
    Insn::Bcctr {
        bo: 20,
        bi: CrBit(0),
        bh: 0,
        lk: false,
    }
}

pub(crate) fn cmplwi(bf: u8, ra: u8, ui: u16) -> Insn {
    Insn::Cmpli {
        bf: CrField(bf),
        ignored: false,
        l: false,
        ra: Gpr(ra),
        ui,
    }
}

pub(crate) fn cmpwi(bf: u8, ra: u8, si: i16) -> Insn {
    Insn::Cmpi {
        bf: CrField(bf),
        ignored: false,
        l: false,
        ra: Gpr(ra),
        si,
    }
}

pub(crate) fn blr() -> Insn {
    bclr(20, 0)
}

pub(crate) fn bclr(bo: u8, bi: u8) -> Insn {
    Insn::Bclr {
        bo,
        bi: CrBit(bi),
        bh: 0,
        lk: false,
    }
}

pub(crate) fn b(li: i32, lk: bool) -> Insn {
    Insn::B { li, aa: false, lk }
}

pub(crate) fn bc(bo: u8, bi: u8, bd: i16) -> Insn {
    Insn::Bc {
        bo,
        bi: CrBit(bi),
        bd,
        aa: false,
        lk: false,
    }
}

/// `bgt crN` to a displacement.
pub(crate) fn bgt(cr: u8, bd: i16) -> Insn {
    bc(12, 4 * cr + 1, bd)
}

pub(crate) fn assemble(insns: &[Insn]) -> Vec<u8> {
    insns
        .iter()
        .flat_map(|insn| insn.encode().to_be_bytes())
        .collect()
}
