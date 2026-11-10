// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The text of a few instructions whose operands change the shape of the code.

use ferrum_analysis::{Code, Function, SaveRestore};
use ferrum_decoder::{CrBit, CrField, Fpr, Gpr, Insn};

use super::{Emitter, emit};
use crate::error::Error;
use crate::program::ControlFlow;
use crate::program::Program;

/// The statements `insn` becomes, without indentation.
fn text(insn: Insn) -> String {
    let bytes = insn.encode().to_be_bytes();
    let routines = SaveRestore::new();
    let function = Function {
        addr: 0x8200_0000,
        size: 4,
    };
    let program = Program::new(Code::new(0x8200_0000, &bytes), [function], &routines);
    let mut e = Emitter::new(&program, function, 0..=u32::MAX, ControlFlow::Dispatch);
    emit(&mut e, 0x8200_0000, &insn).unwrap();
    let text = e.finish().unwrap();
    text.lines().map(str::trim).collect::<Vec<_>>().join("\n")
}

#[test]
fn register_zero_reads_as_zero_in_addresses_and_addi() {
    let (r0, r3, r4) = (Gpr(0), Gpr(3), Gpr(4));
    assert_eq!(
        text(Insn::Addi {
            rt: r3,
            ra: r0,
            si: -1
        }),
        "ctx.r[3] = 0xffffffffffffffff;"
    );
    assert_eq!(
        text(Insn::Addis {
            rt: r3,
            ra: r0,
            si: -0x8000
        }),
        "ctx.r[3] = 0xffffffff80000000;"
    );
    assert_eq!(
        text(Insn::Addi {
            rt: r3,
            ra: r4,
            si: -8
        }),
        "ctx.r[3] = ctx.r[4].wrapping_sub(0x8);"
    );
    assert_eq!(
        text(Insn::Lwz {
            rt: r3,
            d: -8,
            ra: r0
        }),
        "ctx.r[3] = u64::from(mem.read_u32(0xfffffff8u32));"
    );
    assert_eq!(
        text(Insn::Lbzx {
            rt: r3,
            ra: r0,
            rb: r4
        }),
        "ctx.r[3] = u64::from(mem.read_u8((ctx.r[4] as u32)));"
    );
}

#[test]
fn update_forms_write_the_whole_sum_back() {
    assert_eq!(
        text(Insn::Lhau {
            rt: Gpr(3),
            d: 2,
            ra: Gpr(4)
        }),
        "{\nlet ea = ctx.r[4].wrapping_add(0x2);\nctx.r[3] = mem.read_u16(ea as u32) as i16 as i64 as u64;\nctx.r[4] = ea;\n}"
    );
}

#[test]
fn the_fences_follow_the_l_field() {
    let fence = |ordering: &str| {
        format!("std::sync::atomic::fence(std::sync::atomic::Ordering::{ordering});")
    };
    assert_eq!(text(Insn::Sync { l: 0 }), fence("SeqCst"));
    assert_eq!(text(Insn::Sync { l: 1 }), fence("AcqRel"));
    assert_eq!(text(Insn::Sync { l: 2 }), fence("SeqCst"));
    assert_eq!(text(Insn::Eieio {}), fence("AcqRel"));
    assert_eq!(text(Insn::Isync {}), "");
}

/// FPR `n`.
fn fr(n: u8) -> Fpr {
    Fpr(n)
}

#[test]
fn floating_point_loads_and_stores() {
    let (r0, r1, r3, r4) = (Gpr(0), Gpr(1), Gpr(3), Gpr(4));
    let f1 = fr(1);
    let update =
        |ea: &str, op: &str, ra: u8| format!("{{\nlet ea = {ea};\n{op}\nctx.r[{ra}] = ea;\n}}");
    let cases = [
        (
            Insn::Lfs { frt: f1, d: -8, ra: r3 },
            "ctx.f[1] = ops::single_to_double(mem.read_u32((ctx.r[3] as u32).wrapping_sub(0x8)));"
                .to_owned(),
        ),
        (
            Insn::Lfsu { frt: f1, d: -8, ra: r3 },
            update(
                "ctx.r[3].wrapping_sub(0x8)",
                "ctx.f[1] = ops::single_to_double(mem.read_u32(ea as u32));",
                3,
            ),
        ),
        (
            Insn::Lfsx { frt: f1, ra: r3, rb: r4 },
            "ctx.f[1] = ops::single_to_double(mem.read_u32((ctx.r[3] as u32).wrapping_add((ctx.r[4] as u32))));"
                .to_owned(),
        ),
        (
            Insn::Lfsux { frt: f1, ra: r3, rb: r4 },
            update(
                "ctx.r[3].wrapping_add(ctx.r[4])",
                "ctx.f[1] = ops::single_to_double(mem.read_u32(ea as u32));",
                3,
            ),
        ),
        (
            Insn::Lfd { frt: f1, d: 16, ra: r0 },
            "ctx.f[1] = f64::from_bits(mem.read_u64(0x10u32));".to_owned(),
        ),
        (
            Insn::Lfdu { frt: f1, d: 8, ra: r3 },
            update(
                "ctx.r[3].wrapping_add(0x8)",
                "ctx.f[1] = f64::from_bits(mem.read_u64(ea as u32));",
                3,
            ),
        ),
        (
            Insn::Lfdx { frt: f1, ra: r0, rb: r4 },
            "ctx.f[1] = f64::from_bits(mem.read_u64((ctx.r[4] as u32)));".to_owned(),
        ),
        (
            Insn::Lfdux { frt: f1, ra: r3, rb: r4 },
            update(
                "ctx.r[3].wrapping_add(ctx.r[4])",
                "ctx.f[1] = f64::from_bits(mem.read_u64(ea as u32));",
                3,
            ),
        ),
        (
            Insn::Stfs { frs: f1, d: 4, ra: r3 },
            "mem.write_u32((ctx.r[3] as u32).wrapping_add(0x4), ops::double_to_single(ctx.f[1]));"
                .to_owned(),
        ),
        (
            Insn::Stfsu { frs: f1, d: 4, ra: r3 },
            update(
                "ctx.r[3].wrapping_add(0x4)",
                "mem.write_u32(ea as u32, ops::double_to_single(ctx.f[1]));",
                3,
            ),
        ),
        (
            Insn::Stfsx { frs: f1, ra: r3, rb: r4 },
            "mem.write_u32((ctx.r[3] as u32).wrapping_add((ctx.r[4] as u32)), ops::double_to_single(ctx.f[1]));"
                .to_owned(),
        ),
        (
            Insn::Stfsux { frs: f1, ra: r3, rb: r4 },
            update(
                "ctx.r[3].wrapping_add(ctx.r[4])",
                "mem.write_u32(ea as u32, ops::double_to_single(ctx.f[1]));",
                3,
            ),
        ),
        (
            Insn::Stfd { frs: f1, d: 0, ra: r3 },
            "mem.write_u64((ctx.r[3] as u32), ctx.f[1].to_bits());".to_owned(),
        ),
        (
            Insn::Stfdu { frs: f1, d: -16, ra: r1 },
            update(
                "ctx.r[1].wrapping_sub(0x10)",
                "mem.write_u64(ea as u32, ctx.f[1].to_bits());",
                1,
            ),
        ),
        (
            Insn::Stfdx { frs: f1, ra: r3, rb: r4 },
            "mem.write_u64((ctx.r[3] as u32).wrapping_add((ctx.r[4] as u32)), ctx.f[1].to_bits());"
                .to_owned(),
        ),
        (
            Insn::Stfdux { frs: f1, ra: r3, rb: r4 },
            update(
                "ctx.r[3].wrapping_add(ctx.r[4])",
                "mem.write_u64(ea as u32, ctx.f[1].to_bits());",
                3,
            ),
        ),
        (
            Insn::Stfiwx { frs: f1, ra: r3, rb: r4 },
            "mem.write_u32((ctx.r[3] as u32).wrapping_add((ctx.r[4] as u32)), ctx.f[1].to_bits() as u32);"
                .to_owned(),
        ),
    ];
    for (insn, expected) in cases {
        assert_eq!(text(insn), expected, "{insn:?}");
    }
}

#[test]
fn floating_point_moves_and_arithmetic_call_the_runtime() {
    let (t, a, b, c) = (fr(1), fr(2), fr(3), fr(4));
    let two = |name: &str, x: u8, y: u8| {
        format!("ctx.f[1] = ops::{name}(&mut ctx.fpscr, ctx.f[{x}], ctx.f[{y}]);")
    };
    let three = |name: &str| {
        format!("ctx.f[1] = ops::{name}(&mut ctx.fpscr, ctx.f[2], ctx.f[4], ctx.f[3]);")
    };
    let one = |name: &str| format!("ctx.f[1] = ops::{name}(&mut ctx.fpscr, ctx.f[3]);");
    let rc = false;
    let cases = [
        (
            Insn::Fmr { frt: t, frb: b, rc },
            "ctx.f[1] = ctx.f[3];".to_owned(),
        ),
        (
            Insn::Fneg { frt: t, frb: b, rc },
            "ctx.f[1] = ops::fneg(ctx.f[3]);".to_owned(),
        ),
        (
            Insn::Fabs { frt: t, frb: b, rc },
            "ctx.f[1] = ops::fabs(ctx.f[3]);".to_owned(),
        ),
        (
            Insn::Fnabs { frt: t, frb: b, rc },
            "ctx.f[1] = ops::fnabs(ctx.f[3]);".to_owned(),
        ),
        (
            Insn::Fsel {
                frt: t,
                fra: a,
                frc: c,
                frb: b,
                rc,
            },
            "ctx.f[1] = ops::fsel(ctx.f[2], ctx.f[4], ctx.f[3]);".to_owned(),
        ),
        (
            Insn::Fadd {
                frt: t,
                fra: a,
                frb: b,
                rc,
            },
            two("fadd", 2, 3),
        ),
        (
            Insn::Fadds {
                frt: t,
                fra: a,
                frb: b,
                rc,
            },
            two("fadds", 2, 3),
        ),
        (
            Insn::Fsub {
                frt: t,
                fra: a,
                frb: b,
                rc,
            },
            two("fsub", 2, 3),
        ),
        (
            Insn::Fsubs {
                frt: t,
                fra: a,
                frb: b,
                rc,
            },
            two("fsubs", 2, 3),
        ),
        (
            Insn::Fmul {
                frt: t,
                fra: a,
                frc: c,
                rc,
            },
            two("fmul", 2, 4),
        ),
        (
            Insn::Fmuls {
                frt: t,
                fra: a,
                frc: c,
                rc,
            },
            two("fmuls", 2, 4),
        ),
        (
            Insn::Fdiv {
                frt: t,
                fra: a,
                frb: b,
                rc,
            },
            two("fdiv", 2, 3),
        ),
        (
            Insn::Fdivs {
                frt: t,
                fra: a,
                frb: b,
                rc,
            },
            two("fdivs", 2, 3),
        ),
        (
            Insn::Fmadd {
                frt: t,
                fra: a,
                frc: c,
                frb: b,
                rc,
            },
            three("fmadd"),
        ),
        (
            Insn::Fmadds {
                frt: t,
                fra: a,
                frc: c,
                frb: b,
                rc,
            },
            three("fmadds"),
        ),
        (
            Insn::Fmsub {
                frt: t,
                fra: a,
                frc: c,
                frb: b,
                rc,
            },
            three("fmsub"),
        ),
        (
            Insn::Fmsubs {
                frt: t,
                fra: a,
                frc: c,
                frb: b,
                rc,
            },
            three("fmsubs"),
        ),
        (
            Insn::Fnmadd {
                frt: t,
                fra: a,
                frc: c,
                frb: b,
                rc,
            },
            three("fnmadd"),
        ),
        (
            Insn::Fnmadds {
                frt: t,
                fra: a,
                frc: c,
                frb: b,
                rc,
            },
            three("fnmadds"),
        ),
        (
            Insn::Fnmsub {
                frt: t,
                fra: a,
                frc: c,
                frb: b,
                rc,
            },
            three("fnmsub"),
        ),
        (
            Insn::Fnmsubs {
                frt: t,
                fra: a,
                frc: c,
                frb: b,
                rc,
            },
            three("fnmsubs"),
        ),
        (Insn::Fsqrt { frt: t, frb: b, rc }, one("fsqrt")),
        (Insn::Fsqrts { frt: t, frb: b, rc }, one("fsqrts")),
        (Insn::Fres { frt: t, frb: b, rc }, one("fres")),
        (Insn::Frsqrte { frt: t, frb: b, rc }, one("frsqrte")),
        (Insn::Frsp { frt: t, frb: b, rc }, one("frsp")),
        (Insn::Fctiw { frt: t, frb: b, rc }, one("fctiw")),
        (Insn::Fctiwz { frt: t, frb: b, rc }, one("fctiwz")),
        (Insn::Fctid { frt: t, frb: b, rc }, one("fctid")),
        (Insn::Fctidz { frt: t, frb: b, rc }, one("fctidz")),
        (
            Insn::Fcfid { frt: t, frb: b, rc },
            "ctx.f[1] = ops::fcfid(ctx.f[3]);".to_owned(),
        ),
    ];
    for (insn, expected) in cases {
        assert_eq!(text(insn), expected, "{insn:?}");
    }
}

#[test]
fn floating_point_compares_and_the_fpscr_go_through_ctx_fpscr() {
    let rc = false;
    let cases = [
        (
            Insn::Fcmpu {
                bf: CrField(6),
                fra: fr(2),
                frb: fr(3),
            },
            "ctx.cr.set_field(6, ctx.fpscr.fcmpu(ctx.f[2], ctx.f[3]));",
        ),
        (
            Insn::Fcmpo {
                bf: CrField(0),
                fra: fr(2),
                frb: fr(3),
            },
            "ctx.cr.set_field(0, ctx.fpscr.fcmpo(ctx.f[2], ctx.f[3]));",
        ),
        (
            Insn::Mcrfs {
                bf: CrField(2),
                bfa: CrField(1),
            },
            "ctx.cr.set_field(2, ctx.fpscr.mcrfs(1));",
        ),
        (
            Insn::Mffs { frt: fr(1), rc },
            "ctx.f[1] = ctx.fpscr.mffs();",
        ),
        (
            Insn::Mtfsf {
                flm: 0xFF,
                frb: fr(3),
                l: 0,
                w: 0,
                rc,
            },
            "ctx.fpscr.mtfsf(0xff, ctx.f[3]);",
        ),
        (
            Insn::Mtfsfi {
                bf: 7,
                u: 1,
                w: 0,
                rc,
            },
            "ctx.fpscr.mtfsfi(7, 0x1);",
        ),
        (Insn::Mtfsb0 { bt: CrBit(30), rc }, "ctx.fpscr.mtfsb0(30);"),
        (Insn::Mtfsb1 { bt: CrBit(31), rc }, "ctx.fpscr.mtfsb1(31);"),
    ];
    for (insn, expected) in cases {
        assert_eq!(text(insn), expected, "{insn:?}");
    }
}

#[test]
fn floating_point_record_forms_copy_the_fpscr_into_cr1_after_the_operation() {
    let cr1 = "ctx.cr.set_field(1, ctx.fpscr.record());";
    let rc = true;
    assert_eq!(
        text(Insn::Fadd {
            frt: fr(1),
            fra: fr(2),
            frb: fr(3),
            rc
        }),
        format!("ctx.f[1] = ops::fadd(&mut ctx.fpscr, ctx.f[2], ctx.f[3]);\n{cr1}")
    );
    assert_eq!(
        text(Insn::Fabs {
            frt: fr(1),
            frb: fr(1),
            rc
        }),
        format!("ctx.f[1] = ops::fabs(ctx.f[1]);\n{cr1}")
    );
    assert_eq!(
        text(Insn::Mtfsb1 { bt: CrBit(7), rc }),
        format!("ctx.fpscr.mtfsb1(7);\n{cr1}")
    );
}

#[test]
fn mtfsf_fields_after_version_2_02_are_invalid() {
    let bytes = [0; 4];
    let routines = SaveRestore::new();
    let function = Function {
        addr: 0x8200_0000,
        size: 4,
    };
    let program = Program::new(Code::new(0x8200_0000, &bytes), [function], &routines);
    for insn in [
        Insn::Mtfsf {
            flm: 0xFF,
            frb: fr(1),
            l: 1,
            w: 0,
            rc: false,
        },
        Insn::Mtfsf {
            flm: 0xFF,
            frb: fr(1),
            l: 0,
            w: 1,
            rc: false,
        },
        Insn::Mtfsfi {
            bf: 7,
            u: 0,
            w: 1,
            rc: false,
        },
    ] {
        let mut e = Emitter::new(&program, function, 0..=u32::MAX, ControlFlow::Dispatch);
        assert!(
            matches!(
                emit(&mut e, 0x8200_0000, &insn),
                Err(Error::InvalidForm { .. })
            ),
            "{insn:?}"
        );
    }
}

#[test]
fn a_floating_point_update_form_with_ra_zero_is_invalid() {
    let bytes = [0; 4];
    let routines = SaveRestore::new();
    let function = Function {
        addr: 0x8200_0000,
        size: 4,
    };
    let program = Program::new(Code::new(0x8200_0000, &bytes), [function], &routines);
    for insn in [
        Insn::Lfdu {
            frt: fr(1),
            d: 8,
            ra: Gpr(0),
        },
        Insn::Stfsux {
            frs: fr(1),
            ra: Gpr(0),
            rb: Gpr(4),
        },
    ] {
        let mut e = Emitter::new(&program, function, 0..=u32::MAX, ControlFlow::Dispatch);
        assert!(
            matches!(
                emit(&mut e, 0x8200_0000, &insn),
                Err(Error::InvalidForm { .. })
            ),
            "{insn:?}"
        );
    }
}

#[test]
fn dcbz128_zeroes_the_block_as_dcbz_does() {
    let (r3, r4) = (Gpr(3), Gpr(4));
    let dcbz = text(Insn::Dcbz { ra: r3, rb: r4 });
    assert_eq!(dcbz, text(Insn::Dcbz128 { ra: r3, rb: r4 }));
    assert!(dcbz.contains("& !0x7f, &[0; 128]);"), "{dcbz}");
}

#[test]
fn mftb_reads_the_time_base_through_the_spr_policy() {
    assert_eq!(
        text(Insn::Mftb {
            rt: Gpr(3),
            tbr: 268
        }),
        "ctx.r[3] = ctx.mfspr(Spr::Tbl);"
    );
    assert_eq!(
        text(Insn::Mftb {
            rt: Gpr(4),
            tbr: 269
        }),
        "ctx.r[4] = ctx.mfspr(Spr::Tbu);"
    );
}
