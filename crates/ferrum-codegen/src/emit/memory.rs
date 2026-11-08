// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Loads, stores, the reservation, and cache control.
//!
//! An effective address is the low word of `(rA|0) + d` or `(rA|0) + rB`, as in 32-bit mode; an
//! update form still writes the whole 64-bit sum into rA. A floating-point load or store of a
//! single converts through the runtime (`ops::single_to_double`, `ops::double_to_single`), bit for
//! bit as Book I 4.6.2 and 4.6.3 describe; a double moves its bits unchanged.

use ferrum_decoder::{Fpr, Gpr, Insn};

use super::{Emitter, plus, r, w};
use crate::error::Error;

/// The size of a memory access.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Size {
    Byte,
    Half,
    Word,
    Double,
}

impl Size {
    fn bits(self) -> u32 {
        match self {
            Size::Byte => 8,
            Size::Half => 16,
            Size::Word => 32,
            Size::Double => 64,
        }
    }
}

/// How the address of an access is formed.
#[derive(Clone, Copy)]
pub(super) enum Address {
    /// `(rA|0) + d`.
    Displacement(Gpr, i16),
    /// `(rA|0) + rB`.
    Indexed(Gpr, Gpr),
}

impl Address {
    /// The effective address, a `u32`.
    pub(super) fn ea(self) -> String {
        match self {
            // The low word of the sign-extended displacement.
            Address::Displacement(ra, d) if ra.0 == 0 => format!("{:#x}u32", i32::from(d) as u32),
            Address::Displacement(ra, d) => plus(&w(ra), i64::from(d)),
            Address::Indexed(ra, rb) if ra.0 == 0 => w(rb),
            Address::Indexed(ra, rb) => format!("{}.wrapping_add({})", w(ra), w(rb)),
        }
    }

    /// The 64-bit sum an update form writes back into rA.
    fn sum(self) -> String {
        match self {
            Address::Displacement(ra, d) => plus(&r(ra), i64::from(d)),
            Address::Indexed(ra, rb) => format!("{}.wrapping_add({})", r(ra), r(rb)),
        }
    }

    fn base(self) -> Gpr {
        match self {
            Address::Displacement(ra, _) | Address::Indexed(ra, _) => ra,
        }
    }
}

/// A load or store: its size, whether a load sign-extends, and whether the bytes are reversed.
#[derive(Clone, Copy)]
struct Access {
    size: Size,
    signed: bool,
    reversed: bool,
}

const fn plain(size: Size) -> Access {
    Access {
        size,
        signed: false,
        reversed: false,
    }
}

const fn algebraic(size: Size) -> Access {
    Access {
        size,
        signed: true,
        reversed: false,
    }
}

const fn reversed(size: Size) -> Access {
    Access {
        size,
        signed: false,
        reversed: true,
    }
}

/// What a floating-point load or store moves.
#[derive(Clone, Copy)]
enum Fp {
    /// A single in memory, a double in the FPR.
    Single,
    /// A double, bit for bit.
    Double,
    /// The low word of the FPR's bits, without conversion (`stfiwx`).
    Word,
}

/// Emits `insn` if it belongs to this family, and returns whether it did.
pub(super) fn emit(e: &mut Emitter<'_>, at: u32, insn: &Insn) -> Result<bool, Error> {
    use Address::{Displacement as D, Indexed as X};
    use Size::{Byte, Double, Half, Word};
    let d = |ra, d| D(ra, d);
    match *insn {
        Insn::Lbz { rt, d: o, ra } => load(e, at, rt, d(ra, o), plain(Byte), false)?,
        Insn::Lbzu { rt, d: o, ra } => load(e, at, rt, d(ra, o), plain(Byte), true)?,
        Insn::Lbzx { rt, ra, rb } => load(e, at, rt, X(ra, rb), plain(Byte), false)?,
        Insn::Lbzux { rt, ra, rb } => load(e, at, rt, X(ra, rb), plain(Byte), true)?,
        Insn::Lhz { rt, d: o, ra } => load(e, at, rt, d(ra, o), plain(Half), false)?,
        Insn::Lhzu { rt, d: o, ra } => load(e, at, rt, d(ra, o), plain(Half), true)?,
        Insn::Lhzx { rt, ra, rb } => load(e, at, rt, X(ra, rb), plain(Half), false)?,
        Insn::Lhzux { rt, ra, rb } => load(e, at, rt, X(ra, rb), plain(Half), true)?,
        Insn::Lha { rt, d: o, ra } => load(e, at, rt, d(ra, o), algebraic(Half), false)?,
        Insn::Lhau { rt, d: o, ra } => load(e, at, rt, d(ra, o), algebraic(Half), true)?,
        Insn::Lhax { rt, ra, rb } => load(e, at, rt, X(ra, rb), algebraic(Half), false)?,
        Insn::Lhaux { rt, ra, rb } => load(e, at, rt, X(ra, rb), algebraic(Half), true)?,
        Insn::Lwz { rt, d: o, ra } => load(e, at, rt, d(ra, o), plain(Word), false)?,
        Insn::Lwzu { rt, d: o, ra } => load(e, at, rt, d(ra, o), plain(Word), true)?,
        Insn::Lwzx { rt, ra, rb } => load(e, at, rt, X(ra, rb), plain(Word), false)?,
        Insn::Lwzux { rt, ra, rb } => load(e, at, rt, X(ra, rb), plain(Word), true)?,
        Insn::Lwa { rt, ds, ra } => load(e, at, rt, d(ra, ds), algebraic(Word), false)?,
        Insn::Lwax { rt, ra, rb } => load(e, at, rt, X(ra, rb), algebraic(Word), false)?,
        Insn::Lwaux { rt, ra, rb } => load(e, at, rt, X(ra, rb), algebraic(Word), true)?,
        Insn::Ld { rt, ds, ra } => load(e, at, rt, d(ra, ds), plain(Double), false)?,
        Insn::Ldu { rt, ds, ra } => load(e, at, rt, d(ra, ds), plain(Double), true)?,
        Insn::Ldx { rt, ra, rb } => load(e, at, rt, X(ra, rb), plain(Double), false)?,
        Insn::Ldux { rt, ra, rb } => load(e, at, rt, X(ra, rb), plain(Double), true)?,
        Insn::Lhbrx { rt, ra, rb } => load(e, at, rt, X(ra, rb), reversed(Half), false)?,
        Insn::Lwbrx { rt, ra, rb } => load(e, at, rt, X(ra, rb), reversed(Word), false)?,
        Insn::Ldbrx { rt, ra, rb } => load(e, at, rt, X(ra, rb), reversed(Double), false)?,
        Insn::Stb { rs, d: o, ra } => store(e, at, rs, d(ra, o), plain(Byte), false)?,
        Insn::Stbu { rs, d: o, ra } => store(e, at, rs, d(ra, o), plain(Byte), true)?,
        Insn::Stbx { rs, ra, rb } => store(e, at, rs, X(ra, rb), plain(Byte), false)?,
        Insn::Stbux { rs, ra, rb } => store(e, at, rs, X(ra, rb), plain(Byte), true)?,
        Insn::Sth { rs, d: o, ra } => store(e, at, rs, d(ra, o), plain(Half), false)?,
        Insn::Sthu { rs, d: o, ra } => store(e, at, rs, d(ra, o), plain(Half), true)?,
        Insn::Sthx { rs, ra, rb } => store(e, at, rs, X(ra, rb), plain(Half), false)?,
        Insn::Sthux { rs, ra, rb } => store(e, at, rs, X(ra, rb), plain(Half), true)?,
        Insn::Stw { rs, d: o, ra } => store(e, at, rs, d(ra, o), plain(Word), false)?,
        Insn::Stwu { rs, d: o, ra } => store(e, at, rs, d(ra, o), plain(Word), true)?,
        Insn::Stwx { rs, ra, rb } => store(e, at, rs, X(ra, rb), plain(Word), false)?,
        Insn::Stwux { rs, ra, rb } => store(e, at, rs, X(ra, rb), plain(Word), true)?,
        Insn::Std { rs, ds, ra } => store(e, at, rs, d(ra, ds), plain(Double), false)?,
        Insn::Stdu { rs, ds, ra } => store(e, at, rs, d(ra, ds), plain(Double), true)?,
        Insn::Stdx { rs, ra, rb } => store(e, at, rs, X(ra, rb), plain(Double), false)?,
        Insn::Stdux { rs, ra, rb } => store(e, at, rs, X(ra, rb), plain(Double), true)?,
        Insn::Sthbrx { rs, ra, rb } => store(e, at, rs, X(ra, rb), reversed(Half), false)?,
        Insn::Stwbrx { rs, ra, rb } => store(e, at, rs, X(ra, rb), reversed(Word), false)?,
        Insn::Stdbrx { rs, ra, rb } => store(e, at, rs, X(ra, rb), reversed(Double), false)?,
        Insn::Lmw { rt, d: o, ra } => multiple(e, at, rt, d(ra, o), true)?,
        Insn::Stmw { rs, d: o, ra } => multiple(e, at, rs, d(ra, o), false)?,
        _ => return Ok(float(e, at, insn)? || reservation(e, insn) || cache(e, insn)),
    }
    Ok(true)
}

/// The floating-point loads and stores.
fn float(e: &mut Emitter<'_>, at: u32, insn: &Insn) -> Result<bool, Error> {
    use Address::{Displacement as D, Indexed as X};
    match *insn {
        Insn::Lfs { frt, d, ra } => fp_load(e, at, frt, D(ra, d), Fp::Single, false)?,
        Insn::Lfsu { frt, d, ra } => fp_load(e, at, frt, D(ra, d), Fp::Single, true)?,
        Insn::Lfsx { frt, ra, rb } => fp_load(e, at, frt, X(ra, rb), Fp::Single, false)?,
        Insn::Lfsux { frt, ra, rb } => fp_load(e, at, frt, X(ra, rb), Fp::Single, true)?,
        Insn::Lfd { frt, d, ra } => fp_load(e, at, frt, D(ra, d), Fp::Double, false)?,
        Insn::Lfdu { frt, d, ra } => fp_load(e, at, frt, D(ra, d), Fp::Double, true)?,
        Insn::Lfdx { frt, ra, rb } => fp_load(e, at, frt, X(ra, rb), Fp::Double, false)?,
        Insn::Lfdux { frt, ra, rb } => fp_load(e, at, frt, X(ra, rb), Fp::Double, true)?,
        Insn::Stfs { frs, d, ra } => fp_store(e, at, frs, D(ra, d), Fp::Single, false)?,
        Insn::Stfsu { frs, d, ra } => fp_store(e, at, frs, D(ra, d), Fp::Single, true)?,
        Insn::Stfsx { frs, ra, rb } => fp_store(e, at, frs, X(ra, rb), Fp::Single, false)?,
        Insn::Stfsux { frs, ra, rb } => fp_store(e, at, frs, X(ra, rb), Fp::Single, true)?,
        Insn::Stfd { frs, d, ra } => fp_store(e, at, frs, D(ra, d), Fp::Double, false)?,
        Insn::Stfdu { frs, d, ra } => fp_store(e, at, frs, D(ra, d), Fp::Double, true)?,
        Insn::Stfdx { frs, ra, rb } => fp_store(e, at, frs, X(ra, rb), Fp::Double, false)?,
        Insn::Stfdux { frs, ra, rb } => fp_store(e, at, frs, X(ra, rb), Fp::Double, true)?,
        Insn::Stfiwx { frs, ra, rb } => fp_store(e, at, frs, X(ra, rb), Fp::Word, false)?,
        _ => return Ok(false),
    }
    Ok(true)
}

/// The value a floating-point load puts in frT, read from `ea`.
fn fp_read(kind: Fp, ea: &str) -> String {
    match kind {
        Fp::Single => format!("ops::single_to_double(mem.read_u32({ea}))"),
        Fp::Double => format!("f64::from_bits(mem.read_u64({ea}))"),
        Fp::Word => unreachable!("no load moves an integer word into an FPR"),
    }
}

/// The statement that stores frS to `ea`.
fn fp_write(kind: Fp, frs: Fpr, ea: &str) -> String {
    let f = format!("ctx.f[{}]", frs.0);
    match kind {
        Fp::Single => format!("mem.write_u32({ea}, ops::double_to_single({f}));"),
        Fp::Double => format!("mem.write_u64({ea}, {f}.to_bits());"),
        // The low word of the bits: the truncation is the definition of stfiwx.
        Fp::Word => format!("mem.write_u32({ea}, {f}.to_bits() as u32);"),
    }
}

fn fp_load(
    e: &mut Emitter<'_>,
    at: u32,
    frt: Fpr,
    address: Address,
    kind: Fp,
    update: bool,
) -> Result<(), Error> {
    if !update {
        e.set_f(frt, fp_read(kind, &address.ea()), false);
        return Ok(());
    }
    // frT is an FPR, so it cannot be rA: only rA = 0 is invalid.
    check_update(at, "load with update", address, None)?;
    e.open("{");
    e.line(format!("let ea = {};", address.sum()));
    e.set_f(frt, fp_read(kind, "ea as u32"), false);
    e.set(address.base(), "ea");
    e.close("}");
    Ok(())
}

fn fp_store(
    e: &mut Emitter<'_>,
    at: u32,
    frs: Fpr,
    address: Address,
    kind: Fp,
    update: bool,
) -> Result<(), Error> {
    if !update {
        e.line(fp_write(kind, frs, &address.ea()));
        return Ok(());
    }
    check_update(at, "store with update", address, None)?;
    e.open("{");
    e.line(format!("let ea = {};", address.sum()));
    e.line(fp_write(kind, frs, "ea as u32"));
    e.set(address.base(), "ea");
    e.close("}");
    Ok(())
}

/// The value a load puts in rT, read from `ea`.
fn read(access: Access, ea: &str) -> String {
    let mut value = format!("mem.read_u{}({ea})", access.size.bits());
    if access.reversed {
        value.push_str(".swap_bytes()");
    }
    match (access.size, access.signed) {
        (Size::Double, _) => value,
        (_, false) => format!("u64::from({value})"),
        (Size::Half, true) => format!("{value} as i16 as i64 as u64"),
        (Size::Word, true) => format!("{value} as i32 as i64 as u64"),
        (Size::Byte, true) => unreachable!("there is no algebraic byte load"),
    }
}

/// The statement that stores rS to `ea`.
fn write(access: Access, rs: Gpr, ea: &str) -> String {
    let bits = access.size.bits();
    let mut value = if access.size == Size::Double {
        r(rs)
    } else {
        // A store takes the low bits of the register.
        format!("({} as u{bits})", r(rs))
    };
    if access.reversed {
        value.push_str(".swap_bytes()");
    }
    format!("mem.write_u{bits}({ea}, {value});")
}

/// Rejects an update form that the ISA calls invalid: rA = 0, or a load into rA itself.
fn check_update(
    at: u32,
    mnemonic: &'static str,
    address: Address,
    rt: Option<Gpr>,
) -> Result<(), Error> {
    let ra = address.base();
    if ra.0 == 0 || rt == Some(ra) {
        return Err(Error::InvalidForm {
            addr: at,
            mnemonic,
            why: "an update form needs rA other than r0 and the target",
        });
    }
    Ok(())
}

fn load(
    e: &mut Emitter<'_>,
    at: u32,
    rt: Gpr,
    address: Address,
    access: Access,
    update: bool,
) -> Result<(), Error> {
    if !update {
        e.set(rt, read(access, &address.ea()));
        return Ok(());
    }
    check_update(at, "load with update", address, Some(rt))?;
    e.open("{");
    e.line(format!("let ea = {};", address.sum()));
    e.set(rt, read(access, "ea as u32"));
    e.set(address.base(), "ea");
    e.close("}");
    Ok(())
}

fn store(
    e: &mut Emitter<'_>,
    at: u32,
    rs: Gpr,
    address: Address,
    access: Access,
    update: bool,
) -> Result<(), Error> {
    if !update {
        e.line(write(access, rs, &address.ea()));
        return Ok(());
    }
    check_update(at, "store with update", address, None)?;
    e.open("{");
    e.line(format!("let ea = {};", address.sum()));
    e.line(write(access, rs, "ea as u32"));
    e.set(address.base(), "ea");
    e.close("}");
    Ok(())
}

/// `lmw` and `stmw`: the words of registers from `first` to r31, at consecutive addresses.
fn multiple(
    e: &mut Emitter<'_>,
    at: u32,
    first: Gpr,
    address: Address,
    load: bool,
) -> Result<(), Error> {
    if load && address.base().0 >= first.0 {
        return Err(Error::InvalidForm {
            addr: at,
            mnemonic: "lmw",
            why: "rA is among the registers it loads",
        });
    }
    e.open("{");
    e.line(format!("let ea = {};", address.ea()));
    for (index, reg) in (first.0..32).enumerate() {
        let at = plus("ea", 4 * index as i64);
        if load {
            e.set(Gpr(reg), format!("u64::from(mem.read_u32({at}))"));
        } else {
            e.line(format!("mem.write_u32({at}, ctx.r[{reg}] as u32);"));
        }
    }
    e.close("}");
    Ok(())
}

/// `lwarx`, `ldarx`, `stwcx.` and `stdcx.`, through the runtime's reservation.
fn reservation(e: &mut Emitter<'_>, insn: &Insn) -> bool {
    match *insn {
        Insn::Lwarx { rt, ra, rb, .. } => {
            let ea = Address::Indexed(ra, rb).ea();
            e.set(rt, format!("u64::from(ctx.load_reserved_u32(mem, {ea}))"));
        }
        Insn::Ldarx { rt, ra, rb, .. } => {
            let ea = Address::Indexed(ra, rb).ea();
            e.set(rt, format!("ctx.load_reserved_u64(mem, {ea})"));
        }
        Insn::StwcxDot { rs, ra, rb } => {
            let ea = Address::Indexed(ra, rb).ea();
            e.line(format!(
                "ctx.store_conditional_u32(mem, {ea}, {} as u32);",
                r(rs)
            ));
        }
        Insn::StdcxDot { rs, ra, rb } => {
            let ea = Address::Indexed(ra, rb).ea();
            e.line(format!("ctx.store_conditional_u64(mem, {ea}, {});", r(rs)));
        }
        _ => return false,
    }
    true
}

/// Cache control. `dcbz` zeroes the 128-byte block that holds the address, the Xenon's data cache
/// block, and so does `dcbz128`, the Xenon's form that names the size (Xenia's
/// `InstrEmit_dcbz128` in `src/xenia/cpu/ppc/ppc_emit_memory.cc`); the hints and flushes have no
/// effect on one coherent memory.
fn cache(e: &mut Emitter<'_>, insn: &Insn) -> bool {
    match *insn {
        Insn::Dcbz { ra, rb } | Insn::Dcbz128 { ra, rb } => {
            let ea = Address::Indexed(ra, rb).ea();
            e.line(format!("mem.write_bytes({ea} & !0x7f, &[0; 128]);"));
        }
        Insn::Dcbf { .. }
        | Insn::Dcbst { .. }
        | Insn::Dcbt { .. }
        | Insn::Dcbtst { .. }
        | Insn::Icbi { .. } => {}
        _ => return false,
    }
    true
}
