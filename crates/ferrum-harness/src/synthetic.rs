// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Programs for what the suites do not exercise: calls, indirect calls, tail calls, conditional
//! returns, CTR loops, save and restore routines, a function that falls off its end, the
//! floating-point instructions that the `instr_f*` files leave out, the vector instructions that
//! the `instr_v*` files leave out, and `setjmp` and `longjmp` across frames.
//!
//! Each one is a list of instructions loaded at [`BASE`], with its functions as word offsets and
//! sizes. The build script generates them like the test files, and `tests/suite.rs` runs them with
//! its own inputs and expected values. Shared with the build script through `#[path]`, so it uses
//! only `ferrum-decoder`.

use ferrum_decoder::{CrBit, CrField, Fpr, Gpr, Insn, Vr};

/// Where every synthetic program is loaded: the start of the harness's code region.
pub const BASE: u32 = 0x8000_0000;

/// One synthetic program.
#[derive(Debug, Clone, Default)]
pub struct Synthetic {
    /// A name, which is also the name of its generated module.
    pub name: &'static str,
    /// The instructions, from [`BASE`] on.
    pub insns: Vec<Insn>,
    /// Each function as the word offset of its entry and its size in words.
    pub functions: Vec<(u32, u32)>,
    /// The word offset of the function that stands for the C runtime's `setjmp`, if any.
    pub setjmp: Option<u32>,
    /// The word offset of the function that stands for the C runtime's `longjmp`, if any.
    pub longjmp: Option<u32>,
    /// Imported functions, each with a thunk in the program.
    pub imports: Vec<SyntheticImport>,
    /// Functions the test overrides: word offset of the entry and name.
    pub overrides: Vec<(u32, &'static str)>,
    /// Mid-asm hooks.
    pub midasm: Vec<SyntheticHook>,
}

/// An import of a synthetic program.
#[derive(Debug, Clone)]
pub struct SyntheticImport {
    /// The word offset of its thunk.
    pub thunk: u32,
    /// The guest address of its slot.
    pub slot: u32,
    /// The ordinal, in `xboxkrnl.exe`.
    pub ordinal: u16,
    /// The name, a method of the runtime's `Xboxkrnl`.
    pub name: &'static str,
}

/// What happens after a mid-asm hook of a synthetic program; jumps go to word offsets.
#[derive(Debug, Clone, Copy)]
pub enum SyntheticAction {
    /// Goes on.
    Continue,
    /// Returns from the function.
    Return,
    /// Goes to a word.
    Jump(u32),
    /// Returns if the hook returned true.
    ReturnIfTrue,
    /// Goes to a word if the hook returned true.
    JumpIfTrue(u32),
}

/// A mid-asm hook of a synthetic program.
#[derive(Debug, Clone)]
pub struct SyntheticHook {
    /// The word offset of the instruction.
    pub word: u32,
    /// The name.
    pub name: &'static str,
    /// Whether the call comes after the instruction.
    pub after: bool,
    /// What happens when it returns.
    pub action: SyntheticAction,
}

impl Synthetic {
    /// The bytes of the program, in memory order.
    pub fn bytes(&self) -> Vec<u8> {
        self.insns
            .iter()
            .flat_map(|insn| insn.encode().to_be_bytes())
            .collect()
    }

    /// The address of the function that starts at word `offset`.
    pub fn entry(offset: u32) -> u32 {
        BASE + 4 * offset
    }
}

fn li(rt: u8, si: i16) -> Insn {
    Insn::Addi {
        rt: Gpr(rt),
        ra: Gpr(0),
        si,
    }
}

fn addi(rt: u8, ra: u8, si: i16) -> Insn {
    Insn::Addi {
        rt: Gpr(rt),
        ra: Gpr(ra),
        si,
    }
}

/// `lis rT, 0x8000; ori rT, rT, offset`: the address of a word of the program.
fn load_address(rt: u8, offset: u16) -> [Insn; 2] {
    [
        Insn::Addis {
            rt: Gpr(rt),
            ra: Gpr(0),
            si: i16::MIN,
        },
        Insn::Ori {
            ra: Gpr(rt),
            rs: Gpr(rt),
            ui: offset,
        },
    ]
}

fn mflr(rt: u8) -> Insn {
    Insn::Mfspr {
        rt: Gpr(rt),
        spr: 8,
    }
}

fn mtlr(rs: u8) -> Insn {
    Insn::Mtspr {
        spr: 8,
        rs: Gpr(rs),
    }
}

fn mtctr(rs: u8) -> Insn {
    Insn::Mtspr {
        spr: 9,
        rs: Gpr(rs),
    }
}

/// A branch from word `from` to word `to`, with or without the link.
fn b(from: u32, to: u32, lk: bool) -> Insn {
    // Word offsets of a small program, so the difference fits easily.
    let li = (to as i32 - from as i32) * 4;
    Insn::B { li, aa: false, lk }
}

/// A conditional branch from word `from` to word `to`.
fn bc(bo: u8, bi: u8, from: u32, to: u32) -> Insn {
    let bd = ((to as i32 - from as i32) * 4) as i16;
    Insn::Bc {
        bo,
        bi: CrBit(bi),
        bd,
        aa: false,
        lk: false,
    }
}

fn bclr(bo: u8, bi: u8, lk: bool) -> Insn {
    Insn::Bclr {
        bo,
        bi: CrBit(bi),
        bh: 0,
        lk,
    }
}

fn blr() -> Insn {
    bclr(20, 0, false)
}

fn bcctr(lk: bool) -> Insn {
    Insn::Bcctr {
        bo: 20,
        bi: CrBit(0),
        bh: 0,
        lk,
    }
}

fn cmpwi(ra: u8, si: i16) -> Insn {
    Insn::Cmpi {
        bf: CrField(0),
        ignored: false,
        l: false,
        ra: Gpr(ra),
        si,
    }
}

/// The GPR save and restore routines with the layout of the ABI: r14 at -0x98 off r1, LR at -0x8.
/// `__savegprlr_N` is word N - 14, and `__restgprlr_N` word N + 6.
fn gpr_routines() -> Vec<Insn> {
    let slot = |r: u8| -0x98 + 8 * (i16::from(r) - 14);
    let mut insns: Vec<Insn> = (14..32)
        .map(|r| Insn::Std {
            rs: Gpr(r),
            ds: slot(r),
            ra: Gpr(1),
        })
        .collect();
    insns.push(Insn::Stw {
        rs: Gpr(12),
        d: -8,
        ra: Gpr(1),
    });
    insns.push(blr());
    insns.extend((14..32).map(|r| Insn::Ld {
        rt: Gpr(r),
        ds: slot(r),
        ra: Gpr(1),
    }));
    insns.push(Insn::Lwz {
        rt: Gpr(12),
        d: -8,
        ra: Gpr(1),
    });
    insns.push(mtlr(12));
    insns.push(blr());
    insns
}

/// Every synthetic program.
pub fn programs() -> Vec<Synthetic> {
    vec![
        calls(),
        indirect(),
        tails(),
        returns(),
        loops(),
        save_restore(),
        fall_off(),
        compares(),
        dcbz(),
        fp_loads(),
        fp_stores(),
        fp_ops(),
        fp_compare(),
        fpscr(),
        fpr_save_restore(),
        vector_ops(),
        vmx_save_restore(),
        setjmp(),
        imports(),
        hooks(),
    ]
}

/// The slot of the import of `imports`, in the data region.
pub const IMPORT_SLOT: u32 = 0x1000_1100;

/// An import, `NtClose`, called through its thunk (word 8) with `bl`, then through its slot with
/// `bctrl`, then with a tail call. The program loads the slot, which `load` of the generated
/// imports fills with the thunk's address.
fn imports() -> Synthetic {
    let slot_high = (IMPORT_SLOT >> 16) as u16 as i16;
    let slot_low = IMPORT_SLOT as u16;
    let insns = vec![
        mflr(20),
        b(1, 8, true),
        Insn::Addis {
            rt: Gpr(11),
            ra: Gpr(0),
            si: slot_high,
        },
        Insn::Lwz {
            rt: Gpr(11),
            d: slot_low as i16,
            ra: Gpr(11),
        },
        mtctr(11),
        bcctr(true),
        mtlr(20),
        b(7, 8, false),
        // The thunk: its records, then `mtctr r11; bctr`, as the console's loader leaves it.
        Insn::Tdi {
            to: 0,
            ra: Gpr(0),
            si: 0x19,
        },
        Insn::Tdi {
            to: 0,
            ra: Gpr(0),
            si: 0,
        },
        mtctr(11),
        bcctr(false),
    ];
    Synthetic {
        name: "imports",
        insns,
        functions: vec![(0, 8)],
        imports: vec![SyntheticImport {
            thunk: 8,
            slot: IMPORT_SLOT,
            ordinal: 0x19,
            name: "NtClose",
        }],
        ..Synthetic::default()
    }
}

/// An override and each action of a mid-asm hook. `main` (word 0) calls `overridden` (word 12),
/// which would set r3 to 99, then adds 1 to r3 (word 3), sets r4 (word 4), r5 to 1 (word 5) and
/// then 2 (word 6), r6 (word 7) and r7 to 4 (word 8) and then 5 (word 9), and returns:
///
/// - `before`, before word 3: continue.
/// - `maybe_return`, before word 4: return if true.
/// - `skip`, before word 5: jump to word 8 if true.
/// - `after`, after word 7: continue.
/// - `jump`, before word 8: jump to word 10, past both writes of r7.
fn hooks() -> Synthetic {
    let insns = vec![
        mflr(20),
        li(3, 0),
        b(2, 12, true),
        addi(3, 3, 1),
        li(4, 7),
        li(5, 1),
        li(5, 2),
        li(6, 3),
        li(7, 4),
        li(7, 5),
        mtlr(20),
        blr(),
        // overridden
        li(3, 99),
        blr(),
    ];
    let hook = |word, name, after, action| SyntheticHook {
        word,
        name,
        after,
        action,
    };
    Synthetic {
        name: "hooks",
        insns,
        functions: vec![(0, 12), (12, 2)],
        overrides: vec![(12, "overridden")],
        midasm: vec![
            hook(3, "before", false, SyntheticAction::Continue),
            hook(4, "maybe_return", false, SyntheticAction::ReturnIfTrue),
            hook(5, "skip", false, SyntheticAction::JumpIfTrue(8)),
            hook(7, "after", true, SyntheticAction::Continue),
            hook(8, "jump", false, SyntheticAction::Jump(10)),
        ],
        ..Synthetic::default()
    }
}

/// `main` calls `leaf` with `bl`. `leaf` reads LR, which the call wrote first.
fn calls() -> Synthetic {
    let insns = vec![
        mflr(20),
        li(3, 0),
        b(2, 7, true),
        addi(3, 3, 1),
        mflr(22),
        mtlr(20),
        blr(),
        // leaf
        mflr(21),
        li(3, 10),
        blr(),
    ];
    Synthetic {
        name: "calls",
        insns,
        functions: vec![(0, 7), (7, 3)],
        ..Synthetic::default()
    }
}

/// `main` calls `leaf` through CTR with `bctrl`, then through LR with `blrl`.
fn indirect() -> Synthetic {
    let [lis, ori] = load_address(12, 10 * 4);
    let insns = vec![
        mflr(20),
        lis,
        ori,
        mtctr(12),
        bcctr(true),
        Insn::Or {
            ra: Gpr(23),
            rs: Gpr(21),
            rb: Gpr(21),
            rc: false,
        },
        mtlr(12),
        bclr(20, 0, true),
        mtlr(20),
        blr(),
        // leaf
        mflr(21),
        addi(3, 3, 10),
        blr(),
    ];
    Synthetic {
        name: "indirect",
        insns,
        functions: vec![(0, 10), (10, 3)],
        ..Synthetic::default()
    }
}

/// Tail calls to `target` (word 13): with `b`, through CTR with `bctr`, and with `beq`. The
/// instruction after each would set r3 to 99 if the tail call came back.
fn tails() -> Synthetic {
    let [lis, ori] = load_address(12, 13 * 4);
    let insns = vec![
        // direct
        li(3, 1),
        b(1, 13, false),
        li(3, 99),
        blr(),
        // through CTR
        lis,
        ori,
        mtctr(12),
        bcctr(false),
        li(3, 99),
        // conditional
        cmpwi(4, 0),
        bc(12, 2, 10, 13),
        li(3, 99),
        blr(),
        // target
        mflr(21),
        addi(3, 3, 5),
        blr(),
    ];
    Synthetic {
        name: "tails",
        insns,
        functions: vec![(0, 4), (4, 5), (9, 4), (13, 3)],
        ..Synthetic::default()
    }
}

/// `beqlr`: returns early when r4 is zero.
fn returns() -> Synthetic {
    let insns = vec![cmpwi(4, 0), bclr(12, 2, false), li(3, 7), blr()];
    Synthetic {
        name: "returns",
        insns,
        functions: vec![(0, 4)],
        ..Synthetic::default()
    }
}

/// A `bdnz` loop that adds 3 to r3, r4 times; and a `bdz` that tests the low word of CTR.
fn loops() -> Synthetic {
    let insns = vec![
        // count
        li(3, 0),
        mtctr(4),
        addi(3, 3, 3),
        bc(16, 0, 3, 2),
        blr(),
        // bdz
        mtctr(4),
        bc(18, 0, 6, 9),
        li(3, 1),
        blr(),
        li(3, 2),
        blr(),
    ];
    Synthetic {
        name: "loops",
        insns,
        functions: vec![(0, 5), (5, 6)],
        ..Synthetic::default()
    }
}

/// `main` (word 41) saves r29 to r31 and LR through `bl __savegprlr_29`, overwrites them, calls
/// `leaf`, and returns through `b __restgprlr_29`.
fn save_restore() -> Synthetic {
    let mut insns = gpr_routines();
    assert_eq!(insns.len(), 41);
    insns.extend([
        mflr(12),
        b(42, 29 - 14, true),
        li(29, 1),
        li(30, 2),
        li(31, 3),
        b(46, 49, true),
        b(47, 29 + 6, false),
        li(3, 99),
        // leaf
        mflr(21),
        li(3, 42),
        blr(),
    ]);
    Synthetic {
        name: "save_restore",
        insns,
        functions: vec![(41, 8), (49, 3)],
        ..Synthetic::default()
    }
}

/// A function with no return at its end.
fn fall_off() -> Synthetic {
    Synthetic {
        name: "fall_off",
        insns: vec![li(3, 1)],
        functions: vec![(0, 1)],
        ..Synthetic::default()
    }
}

/// Every compare, word and doubleword, signed and unsigned, register and immediate, one per CR
/// field, then `mfcr r12`. The suites never compare operands whose order depends on the sign.
fn compares() -> Synthetic {
    let cmp = |bf, l, ra, rb| Insn::Cmp {
        bf: CrField(bf),
        l,
        ra: Gpr(ra),
        rb: Gpr(rb),
    };
    let cmpl = |bf, l, ra, rb| Insn::Cmpl {
        bf: CrField(bf),
        l,
        ra: Gpr(ra),
        rb: Gpr(rb),
    };
    let cmpi = |bf, l, ra, si| Insn::Cmpi {
        bf: CrField(bf),
        ignored: false,
        l,
        ra: Gpr(ra),
        si,
    };
    let cmpli = |bf, l, ra, ui| Insn::Cmpli {
        bf: CrField(bf),
        ignored: false,
        l,
        ra: Gpr(ra),
        ui,
    };
    let insns = vec![
        cmp(0, false, 3, 4),
        cmpl(1, false, 3, 4),
        cmp(2, true, 5, 6),
        cmpl(3, true, 5, 6),
        cmpi(4, false, 3, 1),
        cmpli(5, false, 3, 1),
        cmpi(6, true, 5, 1),
        cmpli(7, true, 5, 1),
        Insn::Mfcr { rt: Gpr(12) },
        blr(),
    ];
    Synthetic {
        name: "compares",
        insns,
        functions: vec![(0, 10)],
        ..Synthetic::default()
    }
}

/// `dcbz r3, r4`.
fn dcbz() -> Synthetic {
    let insns = vec![
        Insn::Dcbz {
            ra: Gpr(3),
            rb: Gpr(4),
        },
        blr(),
        // dcbz128, from word 2.
        Insn::Dcbz128 {
            ra: Gpr(3),
            rb: Gpr(4),
        },
        blr(),
        // mftb r5 (TBL) and mftbu r6 (TBU), from word 4.
        Insn::Mftb {
            rt: Gpr(5),
            tbr: 268,
        },
        Insn::Mftb {
            rt: Gpr(6),
            tbr: 269,
        },
        blr(),
    ];
    Synthetic {
        name: "dcbz",
        insns,
        functions: vec![(0, 2), (2, 2), (4, 3)],
        ..Synthetic::default()
    }
}

fn mr(ra: u8, rs: u8) -> Insn {
    Insn::Or {
        ra: Gpr(ra),
        rs: Gpr(rs),
        rb: Gpr(rs),
        rc: false,
    }
}

/// The floating-point loads, from the data at r3, with the index in r4 (0x10). The update forms
/// work on copies of r3: r5 to r8.
fn fp_loads() -> Synthetic {
    let (r3, r4) = (Gpr(3), Gpr(4));
    let insns = vec![
        Insn::Lfd {
            frt: Fpr(1),
            d: 0,
            ra: r3,
        },
        Insn::Lfs {
            frt: Fpr(2),
            d: 8,
            ra: r3,
        },
        Insn::Lfdx {
            frt: Fpr(3),
            ra: r3,
            rb: r4,
        },
        Insn::Lfsx {
            frt: Fpr(4),
            ra: r3,
            rb: r4,
        },
        mr(5, 3),
        Insn::Lfdu {
            frt: Fpr(5),
            d: 0x18,
            ra: Gpr(5),
        },
        mr(6, 3),
        Insn::Lfsu {
            frt: Fpr(6),
            d: 0x20,
            ra: Gpr(6),
        },
        mr(7, 3),
        Insn::Lfdux {
            frt: Fpr(7),
            ra: Gpr(7),
            rb: r4,
        },
        mr(8, 3),
        Insn::Lfsux {
            frt: Fpr(8),
            ra: Gpr(8),
            rb: r4,
        },
        blr(),
    ];
    let words = insns.len() as u32;
    Synthetic {
        name: "fp_loads",
        insns,
        functions: vec![(0, words)],
        ..Synthetic::default()
    }
}

/// The floating-point stores, of f1 to f9, to the data at r3: at r3 + 0, 8, r9 (0x10), r10
/// (0x18), 0x20 and 0x28 off copies in r5 and r6, r11 (0x30) and r12 (0x38) off copies in r7 and
/// r8, and r14 (0x40) for `stfiwx`.
fn fp_stores() -> Synthetic {
    let r3 = Gpr(3);
    let insns = vec![
        Insn::Stfd {
            frs: Fpr(1),
            d: 0,
            ra: r3,
        },
        Insn::Stfs {
            frs: Fpr(2),
            d: 8,
            ra: r3,
        },
        Insn::Stfdx {
            frs: Fpr(3),
            ra: r3,
            rb: Gpr(9),
        },
        Insn::Stfsx {
            frs: Fpr(4),
            ra: r3,
            rb: Gpr(10),
        },
        mr(5, 3),
        Insn::Stfdu {
            frs: Fpr(5),
            d: 0x20,
            ra: Gpr(5),
        },
        mr(6, 3),
        Insn::Stfsu {
            frs: Fpr(6),
            d: 0x28,
            ra: Gpr(6),
        },
        mr(7, 3),
        Insn::Stfdux {
            frs: Fpr(7),
            ra: Gpr(7),
            rb: Gpr(11),
        },
        mr(8, 3),
        Insn::Stfsux {
            frs: Fpr(8),
            ra: Gpr(8),
            rb: Gpr(12),
        },
        Insn::Stfiwx {
            frs: Fpr(9),
            ra: r3,
            rb: Gpr(14),
        },
        blr(),
    ];
    let words = insns.len() as u32;
    Synthetic {
        name: "fp_stores",
        insns,
        functions: vec![(0, words)],
        ..Synthetic::default()
    }
}

/// Every floating-point instruction with a result in an FPR, with frT = f1, frA = f2, frB = f3
/// and frC = f4, by name. `fdiv.` is the record form.
fn fp_insns() -> Vec<(&'static str, Insn)> {
    let (t, a, b, c) = (Fpr(1), Fpr(2), Fpr(3), Fpr(4));
    let rc = false;
    vec![
        ("fmr", Insn::Fmr { frt: t, frb: b, rc }),
        ("fneg", Insn::Fneg { frt: t, frb: b, rc }),
        ("fabs", Insn::Fabs { frt: t, frb: b, rc }),
        ("fnabs", Insn::Fnabs { frt: t, frb: b, rc }),
        (
            "fsel",
            Insn::Fsel {
                frt: t,
                fra: a,
                frc: c,
                frb: b,
                rc,
            },
        ),
        (
            "fadd",
            Insn::Fadd {
                frt: t,
                fra: a,
                frb: b,
                rc,
            },
        ),
        (
            "fadds",
            Insn::Fadds {
                frt: t,
                fra: a,
                frb: b,
                rc,
            },
        ),
        (
            "fsub",
            Insn::Fsub {
                frt: t,
                fra: a,
                frb: b,
                rc,
            },
        ),
        (
            "fsubs",
            Insn::Fsubs {
                frt: t,
                fra: a,
                frb: b,
                rc,
            },
        ),
        (
            "fmul",
            Insn::Fmul {
                frt: t,
                fra: a,
                frc: c,
                rc,
            },
        ),
        (
            "fmuls",
            Insn::Fmuls {
                frt: t,
                fra: a,
                frc: c,
                rc,
            },
        ),
        (
            "fdiv",
            Insn::Fdiv {
                frt: t,
                fra: a,
                frb: b,
                rc,
            },
        ),
        (
            "fdivs",
            Insn::Fdivs {
                frt: t,
                fra: a,
                frb: b,
                rc,
            },
        ),
        ("fsqrt", Insn::Fsqrt { frt: t, frb: b, rc }),
        ("fsqrts", Insn::Fsqrts { frt: t, frb: b, rc }),
        ("fres", Insn::Fres { frt: t, frb: b, rc }),
        ("frsqrte", Insn::Frsqrte { frt: t, frb: b, rc }),
        (
            "fmadd",
            Insn::Fmadd {
                frt: t,
                fra: a,
                frc: c,
                frb: b,
                rc,
            },
        ),
        (
            "fmadds",
            Insn::Fmadds {
                frt: t,
                fra: a,
                frc: c,
                frb: b,
                rc,
            },
        ),
        (
            "fmsub",
            Insn::Fmsub {
                frt: t,
                fra: a,
                frc: c,
                frb: b,
                rc,
            },
        ),
        (
            "fmsubs",
            Insn::Fmsubs {
                frt: t,
                fra: a,
                frc: c,
                frb: b,
                rc,
            },
        ),
        (
            "fnmadd",
            Insn::Fnmadd {
                frt: t,
                fra: a,
                frc: c,
                frb: b,
                rc,
            },
        ),
        (
            "fnmadds",
            Insn::Fnmadds {
                frt: t,
                fra: a,
                frc: c,
                frb: b,
                rc,
            },
        ),
        (
            "fnmsub",
            Insn::Fnmsub {
                frt: t,
                fra: a,
                frc: c,
                frb: b,
                rc,
            },
        ),
        (
            "fnmsubs",
            Insn::Fnmsubs {
                frt: t,
                fra: a,
                frc: c,
                frb: b,
                rc,
            },
        ),
        ("frsp", Insn::Frsp { frt: t, frb: b, rc }),
        ("fctiw", Insn::Fctiw { frt: t, frb: b, rc }),
        ("fctiwz", Insn::Fctiwz { frt: t, frb: b, rc }),
        ("fctid", Insn::Fctid { frt: t, frb: b, rc }),
        ("fctidz", Insn::Fctidz { frt: t, frb: b, rc }),
        ("fcfid", Insn::Fcfid { frt: t, frb: b, rc }),
        (
            "fdiv.",
            Insn::Fdiv {
                frt: t,
                fra: a,
                frb: b,
                rc: true,
            },
        ),
    ]
}

/// The entry of the function of `fp_ops` that runs the instruction `name`.
pub fn fp_op_entry(name: &str) -> u32 {
    let index = fp_insns()
        .iter()
        .position(|&(n, _)| n == name)
        .unwrap_or_else(|| panic!("no floating-point program for {name}"));
    // Two words a function: the instruction and blr.
    Synthetic::entry(2 * index as u32)
}

/// One function per instruction of [`fp_insns`]: the instruction, then `blr`.
fn fp_ops() -> Synthetic {
    let list = fp_insns();
    let insns = list.iter().flat_map(|&(_, insn)| [insn, blr()]).collect();
    let functions = (0..list.len() as u32).map(|i| (2 * i, 2)).collect();
    Synthetic {
        name: "fp_ops",
        insns,
        functions,
        ..Synthetic::default()
    }
}

/// `fcmpu cr1, f2, f3; fcmpo cr6, f2, f3`.
fn fp_compare() -> Synthetic {
    let insns = vec![
        Insn::Fcmpu {
            bf: CrField(1),
            fra: Fpr(2),
            frb: Fpr(3),
        },
        Insn::Fcmpo {
            bf: CrField(6),
            fra: Fpr(2),
            frb: Fpr(3),
        },
        blr(),
    ];
    Synthetic {
        name: "fp_compare",
        insns,
        functions: vec![(0, 3)],
        ..Synthetic::default()
    }
}

/// The FPSCR instructions in a row: `mtfsfi 6, 0xF; mtfsb0 25; mtfsb1 7; mffs f1; mcrfs cr2, 1;
/// mtfsf 0x81, f3; mffs f2`.
fn fpscr() -> Synthetic {
    let rc = false;
    let insns = vec![
        Insn::Mtfsfi {
            bf: 6,
            u: 0xF,
            w: 0,
            rc,
        },
        Insn::Mtfsb0 { bt: CrBit(25), rc },
        Insn::Mtfsb1 { bt: CrBit(7), rc },
        Insn::Mffs { frt: Fpr(1), rc },
        Insn::Mcrfs {
            bf: CrField(2),
            bfa: CrField(1),
        },
        Insn::Mtfsf {
            flm: 0x81,
            frb: Fpr(3),
            l: 0,
            w: 0,
            rc,
        },
        Insn::Mffs { frt: Fpr(2), rc },
        blr(),
    ];
    Synthetic {
        name: "fpscr",
        insns,
        functions: vec![(0, 8)],
        ..Synthetic::default()
    }
}

/// The FPR save and restore routines with the layout of the ABI, off r12: f14 at -0x90.
/// `__savefpr_N` is word N - 14, and `__restfpr_N` word N + 5.
fn fpr_routines() -> Vec<Insn> {
    let slot = |f: u8| -0x90 + 8 * (i16::from(f) - 14);
    let mut insns: Vec<Insn> = (14..32)
        .map(|f| Insn::Stfd {
            frs: Fpr(f),
            d: slot(f),
            ra: Gpr(12),
        })
        .collect();
    insns.push(blr());
    insns.extend((14..32).map(|f| Insn::Lfd {
        frt: Fpr(f),
        d: slot(f),
        ra: Gpr(12),
    }));
    insns.push(blr());
    insns
}

/// `main` (word 38) points r12 at the stack, saves f29 to f31 through `bl __savefpr_29`,
/// overwrites them with f1, and restores them through `bl __restfpr_29`.
fn fpr_save_restore() -> Synthetic {
    let mut insns = fpr_routines();
    assert_eq!(insns.len(), 38);
    let fmr = |frt: u8| Insn::Fmr {
        frt: Fpr(frt),
        frb: Fpr(1),
        rc: false,
    };
    insns.extend([
        mr(12, 1),
        mflr(20),
        b(40, 29 - 14, true),
        fmr(29),
        fmr(30),
        fmr(31),
        b(44, 29 + 5, true),
        mtlr(20),
        blr(),
    ]);
    Synthetic {
        name: "fpr_save_restore",
        insns,
        functions: vec![(38, 9)],
        ..Synthetic::default()
    }
}

/// The registers of `vector_ops`: vD = v1, vA = v2, vB = v3, vC = v4 for VMX, and vD = v100,
/// vA = v64, vB = v127 for VMX128, whose vC (`vperm128`) is v4; addresses are r3 + r4.
const VD: Vr = Vr(1);
const VA: Vr = Vr(2);
const VB: Vr = Vr(3);
const VC: Vr = Vr(4);
const VD7: Vr = Vr(100);
const VA7: Vr = Vr(64);
const VB7: Vr = Vr(127);

/// Pairs of names and three-register VMX instructions, `vD, vA, vB`.
macro_rules! three {
    ($($name:literal => $variant:ident),* $(,)?) => {
        vec![$(($name, Insn::$variant { vd: VD, va: VA, vb: VB })),*]
    };
}

/// Pairs of names and three-register VMX128 instructions.
macro_rules! three128 {
    ($($name:literal => $variant:ident),* $(,)?) => {
        vec![$(($name, Insn::$variant { vd: VD7, va: VA7, vb: VB7 })),*]
    };
}

/// Pairs of names and four-register VMX instructions, `vD, vA, vB, vC`.
macro_rules! four {
    ($($name:literal => $variant:ident),* $(,)?) => {
        vec![$(($name, Insn::$variant { vd: VD, va: VA, vb: VB, vc: VC })),*]
    };
}

/// Pairs of names and VMX compares, `vD, vA, vB` with Rc.
macro_rules! compares {
    ($($name:literal => $variant:ident, $rc:expr),* $(,)?) => {
        vec![$(($name, Insn::$variant { vd: VD, va: VA, vb: VB, rc: $rc })),*]
    };
}

/// The vector instructions that the suite leaves out, and some it runs, one function each.
fn vector_insns() -> Vec<(&'static str, Insn)> {
    let mut list = three! {
        "vaddubm" => Vaddubm, "vadduhm" => Vadduhm, "vadduwm" => Vadduwm,
        "vsububm" => Vsububm, "vsubuhm" => Vsubuhm, "vsubuwm" => Vsubuwm,
        "vaddubs" => Vaddubs, "vaddsbs" => Vaddsbs, "vadduhs" => Vadduhs,
        "vaddshs" => Vaddshs, "vadduws" => Vadduws, "vaddsws" => Vaddsws,
        "vsububs" => Vsububs, "vsubsbs" => Vsubsbs, "vsubuhs" => Vsubuhs,
        "vsubshs" => Vsubshs, "vsubuws" => Vsubuws, "vsubsws" => Vsubsws,
        "vavgub" => Vavgub, "vavgsb" => Vavgsb, "vavguh" => Vavguh,
        "vavgsh" => Vavgsh, "vavguw" => Vavguw, "vavgsw" => Vavgsw,
        "vmaxub" => Vmaxub, "vmaxsb" => Vmaxsb, "vmaxuh" => Vmaxuh,
        "vmaxsh" => Vmaxsh, "vmaxuw" => Vmaxuw, "vmaxsw" => Vmaxsw,
        "vminub" => Vminub, "vminsb" => Vminsb, "vminuh" => Vminuh,
        "vminsh" => Vminsh, "vminuw" => Vminuw, "vminsw" => Vminsw,
        "vrlb" => Vrlb, "vrlh" => Vrlh, "vrlw" => Vrlw,
        "vslb" => Vslb, "vslh" => Vslh, "vslw" => Vslw,
        "vsrb" => Vsrb, "vsrh" => Vsrh, "vsrw" => Vsrw,
        "vsrab" => Vsrab, "vsrah" => Vsrah, "vsraw" => Vsraw,
        "vaddcuw" => Vaddcuw, "vsubcuw" => Vsubcuw, "vnor" => Vnor,
        "vmuleub" => Vmuleub, "vmuleuh" => Vmuleuh, "vmulesb" => Vmulesb,
        "vmulesh" => Vmulesh, "vmuloub" => Vmuloub, "vmulouh" => Vmulouh,
        "vmulosb" => Vmulosb, "vmulosh" => Vmulosh,
        "vsumsws" => Vsumsws, "vsum2sws" => Vsum2sws, "vsum4ubs" => Vsum4ubs,
        "vsum4sbs" => Vsum4sbs, "vsum4shs" => Vsum4shs,
        "vpkpx" => Vpkpx, "vpkuhum" => Vpkuhum,
        "vaddfp" => Vaddfp, "vsubfp" => Vsubfp, "vmaxfp" => Vmaxfp, "vminfp" => Vminfp,
    };
    // The compares, with and without Rc.
    list.extend(compares! {
        "vcmpequb" => Vcmpequb, false,
        "vcmpequh" => Vcmpequh, false,
        "vcmpequw" => Vcmpequw, false,
        "vcmpgtub" => Vcmpgtub, false, "vcmpgtuh" => Vcmpgtuh, false,
        "vcmpgtuw" => Vcmpgtuw, false, "vcmpgtsb" => Vcmpgtsb, false,
        "vcmpgtsh" => Vcmpgtsh, false, "vcmpgtsw" => Vcmpgtsw, false,
        "vcmpequb." => Vcmpequb, true, "vcmpequh." => Vcmpequh, true,
        "vcmpequw." => Vcmpequw, true, "vcmpgtub." => Vcmpgtub, true,
        "vcmpgtuh." => Vcmpgtuh, true, "vcmpgtuw." => Vcmpgtuw, true,
        "vcmpgtsb." => Vcmpgtsb, true, "vcmpgtsh." => Vcmpgtsh, true,
        "vcmpgtsw." => Vcmpgtsw, true,
        "vcmpeqfp" => Vcmpeqfp, false, "vcmpgefp" => Vcmpgefp, false,
        "vcmpgtfp" => Vcmpgtfp, false, "vcmpbfp" => Vcmpbfp, false,
        "vcmpgefp." => Vcmpgefp, true, "vcmpgtfp." => Vcmpgtfp, true,
    });
    for (name, insn) in [
        ("vupkhpx", Insn::Vupkhpx { vd: VD, vb: VB }),
        ("vupklpx", Insn::Vupklpx { vd: VD, vb: VB }),
        ("vupkhsh", Insn::Vupkhsh { vd: VD, vb: VB }),
        ("vupklsh", Insn::Vupklsh { vd: VD, vb: VB }),
        ("vrefp", Insn::Vrefp { vd: VD, vb: VB }),
        ("vrsqrtefp", Insn::Vrsqrtefp { vd: VD, vb: VB }),
        ("vexptefp", Insn::Vexptefp { vd: VD, vb: VB }),
        ("vlogefp", Insn::Vlogefp { vd: VD, vb: VB }),
        ("vrfin", Insn::Vrfin { vd: VD, vb: VB }),
        ("vrfiz", Insn::Vrfiz { vd: VD, vb: VB }),
        ("vrfip", Insn::Vrfip { vd: VD, vb: VB }),
        ("vrfim", Insn::Vrfim { vd: VD, vb: VB }),
        (
            "vcfux",
            Insn::Vcfux {
                vd: VD,
                vb: VB,
                uim: 1,
            },
        ),
        (
            "vctsxs",
            Insn::Vctsxs {
                vd: VD,
                vb: VB,
                uim: 1,
            },
        ),
        (
            "vctuxs",
            Insn::Vctuxs {
                vd: VD,
                vb: VB,
                uim: 1,
            },
        ),
        ("mfvscr", Insn::Mfvscr { vd: VD }),
        ("mtvscr", Insn::Mtvscr { vb: VB }),
    ] {
        list.push((name, insn));
    }
    list.extend(four! {
        "vmhaddshs" => Vmhaddshs, "vmhraddshs" => Vmhraddshs, "vmladduhm" => Vmladduhm,
        "vmsumubm" => Vmsumubm, "vmsummbm" => Vmsummbm, "vmsumuhm" => Vmsumuhm,
        "vmsumuhs" => Vmsumuhs, "vmsumshm" => Vmsumshm, "vmsumshs" => Vmsumshs,
    });
    list.push((
        "vmaddfp",
        Insn::Vmaddfp {
            vd: VD,
            va: VA,
            vc: VC,
            vb: VB,
        },
    ));
    list.push((
        "vnmsubfp",
        Insn::Vnmsubfp {
            vd: VD,
            va: VA,
            vc: VC,
            vb: VB,
        },
    ));
    list.extend(vmx128_insns());
    list.extend(vector_memory_insns());
    list
}

/// The VMX128 instructions of `vector_ops`.
fn vmx128_insns() -> Vec<(&'static str, Insn)> {
    let mut list = three128! {
        "vmulfp128" => Vmulfp128, "vmaddfp128" => Vmaddfp128, "vmaddcfp128" => Vmaddcfp128,
        "vnmsubfp128" => Vnmsubfp128, "vnor128" => Vnor128, "vsel128" => Vsel128,
        "vslo128" => Vslo128, "vsro128" => Vsro128, "vrlw128" => Vrlw128,
        "vslw128" => Vslw128, "vsraw128" => Vsraw128, "vsrw128" => Vsrw128,
        "vmrghw128" => Vmrghw128, "vmrglw128" => Vmrglw128, "vpkuhum128" => Vpkuhum128,
    };
    let (vd, vb) = (VD7, VB7);
    for (name, insn) in [
        (
            "vsldoi128",
            Insn::Vsldoi128 {
                vd,
                va: VA7,
                vb,
                sh: 4,
            },
        ),
        (
            "vperm128",
            Insn::Vperm128 {
                vd,
                va: VA7,
                vb,
                vc: VC,
            },
        ),
        ("vcfpsxws128", Insn::Vcfpsxws128 { vd, vb, simm: 1 }),
        ("vcfpuxws128", Insn::Vcfpuxws128 { vd, vb, uimm: 1 }),
        ("vcsxwfp128", Insn::Vcsxwfp128 { vd, vb, simm: 1 }),
        ("vcuxwfp128", Insn::Vcuxwfp128 { vd, vb, uimm: 1 }),
        ("vrfin128", Insn::Vrfin128 { vd, vb, ignored: 0 }),
        ("vrfiz128", Insn::Vrfiz128 { vd, vb, ignored: 0 }),
        ("vrfip128", Insn::Vrfip128 { vd, vb, ignored: 0 }),
        ("vrfim128", Insn::Vrfim128 { vd, vb, ignored: 0 }),
        ("vrefp128", Insn::Vrefp128 { vd, vb, ignored: 0 }),
        ("vrsqrtefp128", Insn::Vrsqrtefp128 { vd, vb, ignored: 0 }),
        ("vexptefp128", Insn::Vexptefp128 { vd, vb, ignored: 0 }),
        ("vlogefp128", Insn::Vlogefp128 { vd, vb, ignored: 0 }),
        ("vspltw128", Insn::Vspltw128 { vd, vb, uimm: 2 }),
        ("vspltisw128", Insn::Vspltisw128 { vd, vb, simm: -2 }),
        // The hidden vA field 0x60 makes them halfword unpacks.
        (
            "vupkhsh128",
            Insn::Vupkhsb128 {
                vd,
                vb,
                ignored: 0x60,
            },
        ),
        (
            "vupklsh128",
            Insn::Vupklsb128 {
                vd,
                vb,
                ignored: 0x60,
            },
        ),
        (
            "vcmpeqfp128",
            Insn::Vcmpeqfp128 {
                vd,
                va: VA7,
                vb,
                rc: false,
            },
        ),
        (
            "vcmpgefp128.",
            Insn::Vcmpgefp128 {
                vd,
                va: VA7,
                vb,
                rc: true,
            },
        ),
        (
            "vcmpgtfp128.",
            Insn::Vcmpgtfp128 {
                vd,
                va: VA7,
                vb,
                rc: true,
            },
        ),
        (
            "vcmpbfp128",
            Insn::Vcmpbfp128 {
                vd,
                va: VA7,
                vb,
                rc: false,
            },
        ),
        (
            "vcmpequw128.",
            Insn::Vcmpequw128 {
                vd,
                va: VA7,
                vb,
                rc: true,
            },
        ),
    ] {
        list.push((name, insn));
    }
    list
}

/// The vector loads and stores of `vector_ops`, at r3 + r4: v1, or v100 for VMX128.
fn vector_memory_insns() -> Vec<(&'static str, Insn)> {
    let (ra, rb) = (Gpr(3), Gpr(4));
    let (v, v7) = (VD, VD7);
    vec![
        ("lvx", Insn::Lvx { vd: v, ra, rb }),
        ("lvxl", Insn::Lvxl { vd: v, ra, rb }),
        ("lvx128", Insn::Lvx128 { vd: v7, ra, rb }),
        ("lvxl128", Insn::Lvxl128 { vd: v7, ra, rb }),
        ("lvebx", Insn::Lvebx { vd: v, ra, rb }),
        ("stvx", Insn::Stvx { vs: v, ra, rb }),
        ("stvxl", Insn::Stvxl { vs: v, ra, rb }),
        ("stvx128", Insn::Stvx128 { vs: v7, ra, rb }),
        ("stvxl128", Insn::Stvxl128 { vs: v7, ra, rb }),
        ("stvebx", Insn::Stvebx { vs: v, ra, rb }),
        ("stvehx", Insn::Stvehx { vs: v, ra, rb }),
        ("stvewx128", Insn::Stvewx128 { vs: v7, ra, rb }),
        ("lvlxl", Insn::Lvlxl { vd: v, ra, rb }),
        ("lvlx128", Insn::Lvlx128 { vd: v7, ra, rb }),
        ("lvlxl128", Insn::Lvlxl128 { vd: v7, ra, rb }),
        ("lvrxl", Insn::Lvrxl { vd: v, ra, rb }),
        ("lvrx128", Insn::Lvrx128 { vd: v7, ra, rb }),
        ("lvrxl128", Insn::Lvrxl128 { vd: v7, ra, rb }),
        ("stvlxl", Insn::Stvlxl { vs: v, ra, rb }),
        ("stvlx128", Insn::Stvlx128 { vs: v7, ra, rb }),
        ("stvlxl128", Insn::Stvlxl128 { vs: v7, ra, rb }),
        ("stvrxl", Insn::Stvrxl { vs: v, ra, rb }),
        ("stvrx128", Insn::Stvrx128 { vs: v7, ra, rb }),
        ("stvrxl128", Insn::Stvrxl128 { vs: v7, ra, rb }),
        ("lvsl128", Insn::Lvsl128 { vd: v7, ra, rb }),
        ("lvsr128", Insn::Lvsr128 { vd: v7, ra, rb }),
        (
            "dst",
            Insn::Dst {
                t: true,
                ra,
                rb,
                strm: 1,
                ignored: 0,
            },
        ),
        (
            "dstst",
            Insn::Dstst {
                t: false,
                ra,
                rb,
                strm: 2,
                ignored: 0,
            },
        ),
        (
            "dss",
            Insn::Dss {
                all: true,
                strm: 0,
                ignored: 0,
            },
        ),
    ]
}

/// The entry of the function of `vector_ops` that runs the instruction `name`.
pub fn vector_op_entry(name: &str) -> u32 {
    let index = vector_insns()
        .iter()
        .position(|&(n, _)| n == name)
        .unwrap_or_else(|| panic!("no vector program for {name}"));
    // Two words a function: the instruction and blr.
    Synthetic::entry(2 * index as u32)
}

/// One function per instruction of [`vector_insns`]: the instruction, then `blr`.
fn vector_ops() -> Synthetic {
    let list = vector_insns();
    let insns = list.iter().flat_map(|&(_, insn)| [insn, blr()]).collect();
    let functions = (0..list.len() as u32).map(|i| (2 * i, 2)).collect();
    Synthetic {
        name: "vector_ops",
        insns,
        functions,
        ..Synthetic::default()
    }
}

/// A VMX save (`save`) or restore routine with the layout of the ABI: for `count` registers from
/// `first`, pairs of `li r11, offset` and `stvx`/`lvx` (`stvx128`/`lvx128` when `first` is 64)
/// of vN at r11 + r12, the last register at -0x10, then `blr`.
fn vmx_routine(first: u8, count: u8, save: bool) -> Vec<Insn> {
    let mut insns = Vec::new();
    for k in 0..count {
        let n = first + k;
        insns.push(li(11, -16 * (i16::from(count) - i16::from(k))));
        let (v, ra, rb) = (Vr(n), Gpr(11), Gpr(12));
        insns.push(match (save, first >= 64) {
            (true, false) => Insn::Stvx { vs: v, ra, rb },
            (true, true) => Insn::Stvx128 { vs: v, ra, rb },
            (false, false) => Insn::Lvx { vd: v, ra, rb },
            (false, true) => Insn::Lvx128 { vd: v, ra, rb },
        });
    }
    insns.push(blr());
    insns
}

/// `__savevmx_N` and `__restvmx_N` for v14 to v31 (words 0 and 37 up) and v64 to v127 (words 74
/// and 203 up), then `main` (word 332): it saves v29 to v31 off r12 = r1 and v125 to v127 off
/// r12 = r1 - 0x200, overwrites them with v1, and restores them.
fn vmx_save_restore() -> Synthetic {
    let mut insns = vmx_routine(14, 18, true);
    insns.extend(vmx_routine(14, 18, false));
    insns.extend(vmx_routine(64, 64, true));
    insns.extend(vmx_routine(64, 64, false));
    assert_eq!(insns.len(), 332);
    let copy = |vd: u8| Insn::Vor128 {
        vd: Vr(vd),
        va: Vr(1),
        vb: Vr(1),
    };
    let save_low = 2 * (29 - 14);
    let restore_low = 37 + 2 * (29 - 14);
    let save_high = 74 + 2 * (125 - 64);
    let restore_high = 203 + 2 * (125 - 64);
    insns.extend([
        mflr(20),
        mr(12, 1),
        b(334, save_low, true),
        addi(12, 1, -0x200),
        b(336, save_high, true),
        copy(29),
        copy(30),
        copy(31),
        copy(125),
        copy(126),
        copy(127),
        mr(12, 1),
        b(344, restore_low, true),
        addi(12, 1, -0x200),
        b(346, restore_high, true),
        mtlr(20),
        blr(),
    ]);
    Synthetic {
        name: "vmx_save_restore",
        insns,
        functions: vec![(332, 17)],
        ..Synthetic::default()
    }
}

fn stw(rs: u8, d: i16, ra: u8) -> Insn {
    Insn::Stw {
        rs: Gpr(rs),
        d,
        ra: Gpr(ra),
    }
}

fn stwu(rs: u8, d: i16, ra: u8) -> Insn {
    Insn::Stwu {
        rs: Gpr(rs),
        d,
        ra: Gpr(ra),
    }
}

fn lwz(rt: u8, d: i16, ra: u8) -> Insn {
    Insn::Lwz {
        rt: Gpr(rt),
        d,
        ra: Gpr(ra),
    }
}

/// `bne` from word `from` to word `to`, on CR0.
fn bne(from: u32, to: u32) -> Insn {
    bc(4, 2, from, to)
}

/// `beq` from word `from` to word `to`, on CR0.
fn beq(from: u32, to: u32) -> Insn {
    bc(12, 2, from, to)
}

/// The start of a function with a 16-byte frame: LR saved at -8 off the caller's r1.
fn frame() -> [Insn; 3] {
    [mflr(12), stw(12, -8, 1), stwu(1, -16, 1)]
}

/// The end of a function with the frame of [`frame`].
fn unframe() -> [Insn; 4] {
    [addi(1, 1, 16), lwz(12, -8, 1), mtlr(12), blr()]
}

/// `setjmp` and `longjmp` across frames.
///
/// - `setjmp` (word 0) stores r1 in the buffer and returns 0; `longjmp` (word 3) is not generated.
/// - `jumper` (word 4) sets r20 and calls `longjmp(r3, r4)` from a frame of its own.
/// - `main` (word 6), with the buffer in r30 and the value in r29: r31 = 0x77, `setjmp`, then
///   r31 = 0x55 and `jumper`. When `setjmp` returns again, r28 takes its value; r27 = 99 would mean
///   that `jumper` came back. A count at buffer + 24, which `longjmp` does not restore, lets
///   `jumper` run once, so that a `setjmp` that returns 0 again ends the program instead of
///   looping.
/// - `outer` (word 29) calls `setjmp` with r30, then `inner` (word 44), which calls `setjmp` with
///   r29 and then `jumper` with the buffer in r26 and the value in r25. `outer` puts the value of
///   its second return in r22, `inner` puts its own in r21, and r23 = 0x11 says that `inner`
///   returned to `outer`.
/// - `rec` (word 60), with n in r3 and the buffer in r30, calls `setjmp` at every level and
///   recurses down to 0, which calls `longjmp(buffer, 5)`. A level that returns from `setjmp` a
///   second time stores its n + 1 at buffer + 16 and counts itself at buffer + 20.
fn setjmp() -> Synthetic {
    let mut insns = vec![stw(1, 0, 3), li(3, 0), blr()]; // setjmp
    insns.push(blr()); // longjmp
    insns.extend([li(20, 0x20), b(5, 3, true)]); // jumper
    insns.extend(frame()); // main, from word 6
    insns.extend([
        li(31, 0x77),
        mr(3, 30),
        b(11, 0, true),
        cmpwi(3, 0),
        bne(13, 24),
        lwz(11, 24, 30), // word 14: the count
        addi(11, 11, 1),
        stw(11, 24, 30),
        cmpwi(11, 1),
        bne(18, 24),
        li(31, 0x55),
        mr(3, 30),
        mr(4, 29),
        b(22, 4, true),
        li(27, 99),
        mr(28, 3), // word 24
    ]);
    insns.extend(unframe());
    insns.extend(frame()); // outer, from word 29
    insns.extend([
        mr(3, 30),
        b(33, 0, true),
        cmpwi(3, 0),
        bne(35, 39),
        b(36, 44, true),
        li(23, 0x11),
        b(38, 40, false),
        mr(22, 3),
    ]);
    insns.extend(unframe());
    insns.extend(frame()); // inner, from word 44
    insns.extend([
        mr(3, 29),
        b(48, 0, true),
        cmpwi(3, 0),
        bne(50, 55),
        mr(3, 26),
        mr(4, 25),
        b(53, 4, true),
        li(27, 99),
        mr(21, 3),
    ]);
    insns.extend(unframe());
    // rec, from word 60: the frame also saves r31, which holds n.
    insns.extend([mflr(12), stw(12, -8, 1), stw(31, -12, 1), stwu(1, -16, 1)]);
    insns.extend([
        mr(31, 3),
        mr(3, 30),
        b(66, 0, true),
        cmpwi(3, 0),
        bne(68, 77),
        cmpwi(31, 0),
        beq(70, 74),
        addi(3, 31, -1),
        b(72, 60, true),
        b(73, 83, false),
        mr(3, 30), // word 74: the bottom level
        li(4, 5),
        b(76, 4, true),
        addi(11, 31, 1), // word 77: a second return from setjmp
        stw(11, 16, 30),
        lwz(10, 20, 30),
        addi(10, 10, 1),
        stw(10, 20, 30),
        mr(28, 3),
        addi(1, 1, 16), // word 83
        lwz(31, -12, 1),
        lwz(12, -8, 1),
        mtlr(12),
        blr(),
    ]);
    Synthetic {
        name: "setjmp",
        insns,
        functions: vec![
            (0, 3),
            (3, 1),
            (4, 2),
            (6, 23),
            (29, 15),
            (44, 16),
            (60, 28),
        ],
        setjmp: Some(0),
        longjmp: Some(3),
        ..Synthetic::default()
    }
}
