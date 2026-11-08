// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The shape of generated functions and the errors of generation. What the code does when it runs
//! is tested by the harness crate, which compiles it.

use std::collections::{BTreeMap, BTreeSet};

use ferrum_analysis::{Code, Function, Rules, SaveRestore, find_save_restore};
use ferrum_decoder::{CrBit, CrField, Fpr, Gpr, Insn, Vr};

use crate::{Action, Error, Hooks, Import, Library, MidAsm, NonLocal, Override, Program};

const BASE: u32 = 0x8200_0000;

fn li(rt: u8, si: i16) -> Insn {
    Insn::Addi {
        rt: Gpr(rt),
        ra: Gpr(0),
        si,
    }
}

fn blr() -> Insn {
    Insn::Bclr {
        bo: 20,
        bi: CrBit(0),
        bh: 0,
        lk: false,
    }
}

fn b(li: i32, lk: bool) -> Insn {
    Insn::B { li, aa: false, lk }
}

fn bc(bo: u8, bi: u8, bd: i16) -> Insn {
    Insn::Bc {
        bo,
        bi: CrBit(bi),
        bd,
        aa: false,
        lk: false,
    }
}

fn bcctr(bo: u8, lk: bool) -> Insn {
    Insn::Bcctr {
        bo,
        bi: CrBit(0),
        bh: 0,
        lk,
    }
}

fn assemble(insns: &[Insn]) -> Vec<u8> {
    insns
        .iter()
        .flat_map(|insn| insn.encode().to_be_bytes())
        .collect()
}

/// Generates the functions at the given word offsets and sizes in words.
fn generate(
    insns: &[Insn],
    functions: &[(u32, u32)],
    routines: &SaveRestore,
) -> Result<String, Error> {
    let bytes = assemble(insns);
    let functions = functions.iter().map(|&(offset, words)| Function {
        addr: BASE + 4 * offset,
        size: 4 * words,
    });
    Program::new(Code::new(BASE, &bytes), functions, routines).generate()
}

fn generate_one(insns: &[Insn]) -> Result<String, Error> {
    generate(insns, &[(0, insns.len() as u32)], &SaveRestore::new())
}

/// The trimmed lines of `text`, without the comments.
fn code_lines(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("//"))
        .collect()
}

/// Asserts that `expected` appear in this order among the lines of `text`, contiguously.
fn assert_run(text: &str, expected: &[&str]) {
    let lines = code_lines(text);
    let found = lines
        .windows(expected.len())
        .any(|window| window == expected);
    assert!(found, "{expected:#?}\nnot found in:\n{text}");
}

#[test]
fn a_function_is_a_loop_over_its_blocks() {
    let text = generate_one(&[li(3, 1), blr()]).unwrap();
    assert_run(
        &text,
        &[
            "#[inline(never)]",
            "pub fn sub_82000000(ctx: &mut PpcContext, mem: &Memory, k: &Kernels<'_>) {",
            "let mut pc: u32 = 0x82000000;",
            "loop {",
            "match pc {",
            "0x82000000 => {",
            "ctx.r[3] = 0x1;",
            "return;",
            "}",
            "_ => unreachable!(\"sub_82000000: no block at {pc:#010x}\"),",
        ],
    );
    assert!(text.contains("// 82000000: li      r3,1\n"), "{text}");
}

#[test]
fn a_conditional_jump_inside_picks_the_next_block() {
    let text = generate_one(&[li(3, 0), bc(4, 2, 8), li(3, 1), blr()]).unwrap();
    assert_run(
        &text,
        &[
            "if !ctx.cr.eq(0) {",
            "pc = 0x8200000c;",
            "} else {",
            "pc = 0x82000008;",
            "}",
        ],
    );
    assert_run(
        &text,
        &[
            "0x82000008 => {",
            "ctx.r[3] = 0x1;",
            "pc = 0x8200000c;",
            "}",
        ],
    );
}

#[test]
fn a_decrementing_branch_decrements_before_the_test() {
    let text = generate_one(&[li(3, 0), bc(16, 0, 0), blr()]).unwrap();
    assert_run(
        &text,
        &[
            "ctx.ctr = ctx.ctr.wrapping_sub(1);",
            "if (ctx.ctr as u32) != 0 {",
            "pc = 0x82000004;",
        ],
    );
    // bdzt: CTR reaches zero and the condition holds.
    let text = generate_one(&[bc(10, 1, 8), blr(), blr()]).unwrap();
    assert_run(&text, &["if (ctx.ctr as u32) == 0 && ctx.cr.gt(0) {"]);
}

#[test]
fn lr_is_written_before_a_call() {
    let insns = [b(8, true), blr(), li(3, 7), blr()];
    let text = generate(&insns, &[(0, 2), (2, 2)], &SaveRestore::new()).unwrap();
    assert_run(
        &text,
        &[
            "{",
            "ctx.lr = 0x82000004;",
            "sub_82000008(ctx, mem, k);",
            "}",
            "return;",
        ],
    );
}

#[test]
fn a_branch_out_of_the_function_is_a_tail_call() {
    let insns = [b(8, false), li(3, 1), li(3, 7), blr()];
    let text = generate(&insns, &[(0, 2), (2, 2)], &SaveRestore::new()).unwrap();
    assert_run(
        &text,
        &[
            "0x82000000 => {",
            "sub_82000008(ctx, mem, k);",
            "return;",
            "}",
        ],
    );
    // A conditional one returns only when taken.
    let insns = [bc(12, 2, 8), blr(), li(3, 7), blr()];
    let text = generate(&insns, &[(0, 2), (2, 2)], &SaveRestore::new()).unwrap();
    assert_run(
        &text,
        &[
            "if ctx.cr.eq(0) {",
            "sub_82000008(ctx, mem, k);",
            "return;",
            "}",
            "pc = 0x82000004;",
        ],
    );
}

#[test]
fn branches_to_ctr_and_lr_go_through_the_table() {
    let text = generate_one(&[bcctr(20, true), bcctr(20, false)]).unwrap();
    assert_run(
        &text,
        &[
            "ctx.lr = 0x82000004;",
            "(k.table.lookup(ctx.ctr as u32, ctx.lr))(ctx, mem, k);",
            "}",
            "(k.table.lookup(ctx.ctr as u32, ctx.lr))(ctx, mem, k);",
            "return;",
        ],
    );
    let blrl = Insn::Bclr {
        bo: 20,
        bi: CrBit(0),
        bh: 0,
        lk: true,
    };
    let text = generate_one(&[blrl, blr()]).unwrap();
    assert_run(
        &text,
        &[
            "let target = ctx.lr as u32;",
            "ctx.lr = 0x82000004;",
            "(k.table.lookup(target, ctx.lr))(ctx, mem, k);",
        ],
    );
}

#[test]
fn a_conditional_call_writes_lr_whether_or_not_it_calls() {
    let bcl = Insn::Bc {
        bo: 12,
        bi: CrBit(2),
        bd: 8,
        aa: false,
        lk: true,
    };
    let text = generate(&[bcl, blr(), blr()], &[(0, 2), (2, 1)], &SaveRestore::new()).unwrap();
    assert_run(
        &text,
        &[
            "ctx.lr = 0x82000004;",
            "if ctx.cr.eq(0) {",
            "sub_82000008(ctx, mem, k);",
            "}",
        ],
    );
}

#[test]
fn falling_off_the_end_is_unreachable() {
    let text = generate_one(&[li(3, 1)]).unwrap();
    assert_run(
        &text,
        &[
            "ctx.r[3] = 0x1;",
            "unreachable!(\"fell off the end of sub_82000000\");",
        ],
    );
}

#[test]
fn running_into_the_next_function_is_a_tail_call() {
    let text = generate(&[li(3, 1), blr()], &[(0, 1), (1, 1)], &SaveRestore::new()).unwrap();
    assert_run(
        &text,
        &["ctx.r[3] = 0x1;", "sub_82000004(ctx, mem, k);", "return;"],
    );
}

/// `cmplwi cr6,r10,1; bgt cr6,+0x24; lis r12; addi r12; slwi r0,r10,2; lwzx r0,r12,r0;
/// mtctr r0; bctr`, a table of two words, then `li r3,1; blr`.
fn switch() -> Vec<u8> {
    let table = BASE + 0x20;
    let insns = [
        Insn::Cmpli {
            bf: CrField(6),
            ignored: false,
            l: false,
            ra: Gpr(10),
            ui: 1,
        },
        bc(12, 25, 0x24),
        Insn::Addis {
            rt: Gpr(12),
            ra: Gpr(0),
            si: (table >> 16) as u16 as i16,
        },
        Insn::Addi {
            rt: Gpr(12),
            ra: Gpr(12),
            si: 0x20,
        },
        Insn::Rlwinm {
            ra: Gpr(0),
            rs: Gpr(10),
            sh: 2,
            mb: 0,
            me: 29,
            rc: false,
        },
        Insn::Lwzx {
            rt: Gpr(0),
            ra: Gpr(12),
            rb: Gpr(0),
        },
        Insn::Mtspr { spr: 9, rs: Gpr(0) },
        bcctr(20, false),
    ];
    let mut bytes = assemble(&insns);
    bytes.extend((BASE + 0x2C).to_be_bytes());
    bytes.extend((BASE + 0x28).to_be_bytes());
    bytes.extend(assemble(&[li(3, 1), blr()]));
    bytes
}

#[test]
fn a_resolved_jump_table_dispatches_on_ctr() {
    let bytes = switch();
    let function = Function {
        addr: BASE,
        size: bytes.len() as u32,
    };
    let routines = SaveRestore::new();
    let text = Program::new(Code::new(BASE, &bytes), [function], &routines)
        .generate()
        .unwrap();
    assert_run(
        &text,
        &[
            "pc = ctx.ctr as u32;",
            "}",
            "0x82000028 => {",
            "ctx.r[3] = 0x1;",
            "pc = 0x8200002c;",
        ],
    );
    assert!(!text.contains("k.table.lookup(ctx.ctr"), "{text}");
}

/// `main` (words 0 to 4) calls `setjmp` (word 5) and then `longjmp` (word 7), which `rules` say
/// never returns.
fn setjmp_program(non_local: NonLocal) -> Result<String, Error> {
    let insns = [
        li(3, 0x100), // main
        b(0x10, true),
        li(4, 1),
        b(0x10, true),
        blr(),
        li(3, 0), // setjmp
        blr(),
        blr(), // longjmp, never generated
    ];
    let bytes = assemble(&insns);
    let functions = [(0, 5), (5, 2), (7, 1)].map(|(offset, words)| Function {
        addr: BASE + 4 * offset,
        size: 4 * words,
    });
    let routines = SaveRestore::new();
    let rules = Rules {
        no_return: BTreeSet::from([BASE + 0x1C]),
        ..Rules::default()
    };
    let program = Program::new(Code::new(BASE, &bytes), functions, &routines)
        .with_rules(rules)
        .with_non_local(non_local);
    assert_eq!(program.table_path(BASE).as_deref(), Some("sub_82000000"));
    let longjmp_path = program.table_path(BASE + 0x1C).unwrap();
    let text = program.generate()?;
    Ok(format!("{longjmp_path}\n{text}"))
}

#[test]
fn a_function_that_calls_setjmp_resumes_after_it_when_a_longjmp_unwinds() {
    let text = setjmp_program(NonLocal {
        setjmp: Some(BASE + 0x14),
        longjmp: Some(BASE + 0x1C),
    })
    .unwrap();
    assert_eq!(text.lines().next(), Some("ferrum_runtime::longjmp"));
    assert_run(
        &text,
        &[
            "pub fn sub_82000000(ctx: &mut PpcContext, mem: &Memory, k: &Kernels<'_>) {",
            "let mut pc: u32 = 0x82000000;",
            "let mut jumps = ferrum_runtime::Jumps::new();",
            "loop {",
            "let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| loop {",
            "match pc {",
        ],
    );
    assert_run(
        &text,
        &[
            "ctx.lr = 0x82000008;",
            "jumps.set(ctx, 0x82000008);",
            "sub_82000014(ctx, mem, k);",
            "}",
            "pc = 0x82000008;",
            "}",
            "0x82000008 => {",
        ],
    );
    assert_run(
        &text,
        &[
            "ctx.lr = 0x82000010;",
            "ferrum_runtime::longjmp(ctx, mem, k);",
            "}",
            "unreachable!(\"sub_82000000: a call that never returns came back\");",
        ],
    );
    assert_run(
        &text,
        &[
            "}));",
            "match run {",
            "Ok(()) => return,",
            "Err(payload) => pc = jumps.resume(payload, ctx),",
            "}",
        ],
    );
    // setjmp is plain code, and longjmp is not generated.
    assert!(!text.contains("pub fn sub_8200001c"), "{text}");
    let setjmp = &text[text.find("pub fn sub_82000014").unwrap()..];
    assert!(!setjmp.contains("catch_unwind"), "{setjmp}");
}

#[test]
fn without_setjmp_and_longjmp_both_are_plain_functions() {
    let text = setjmp_program(NonLocal::default()).unwrap();
    assert_eq!(text.lines().next(), Some("sub_8200001c"));
    assert!(!text.contains("catch_unwind"), "{text}");
    assert!(!text.contains("jumps.set"), "{text}");
    assert!(text.contains("pub fn sub_8200001c"), "{text}");
}

#[test]
fn a_tail_call_to_setjmp_is_an_error() {
    let insns = [b(8, false), blr(), li(3, 0), blr()];
    let bytes = assemble(&insns);
    let functions = [(0, 2), (2, 2)].map(|(offset, words)| Function {
        addr: BASE + 4 * offset,
        size: 4 * words,
    });
    let routines = SaveRestore::new();
    let program =
        Program::new(Code::new(BASE, &bytes), functions, &routines).with_non_local(NonLocal {
            setjmp: Some(BASE + 8),
            longjmp: None,
        });
    assert_eq!(
        program.generate(),
        Err(Error::SetjmpTailCall { addr: BASE })
    );
}

#[test]
fn a_call_that_never_returns_ends_its_block() {
    let bytes = assemble(&[b(8, true), Insn::Mfcr { rt: Gpr(3) }, blr()]);
    let functions = [
        Function {
            addr: BASE,
            size: 8,
        },
        Function {
            addr: BASE + 8,
            size: 4,
        },
    ];
    let routines = SaveRestore::new();
    let rules = Rules {
        no_return: BTreeSet::from([BASE + 8]),
        ..Rules::default()
    };
    let text = Program::new(Code::new(BASE, &bytes), functions, &routines)
        .with_rules(rules)
        .generate()
        .unwrap();
    assert_run(
        &text,
        &[
            "sub_82000008(ctx, mem, k);",
            "}",
            "unreachable!(\"sub_82000000: a call that never returns came back\");",
        ],
    );
    assert!(!text.contains("mfcr"), "{text}");
}

#[test]
fn bcctr_cannot_decrement_ctr() {
    assert_eq!(
        generate_one(&[bcctr(16, false)]),
        Err(Error::InvalidForm {
            addr: BASE,
            mnemonic: "bcctr",
            why: "it decrements CTR"
        })
    );
}

#[test]
fn a_call_to_an_unknown_address_is_an_error() {
    assert_eq!(
        generate_one(&[b(0x40, true), blr()]),
        Err(Error::UnknownTarget {
            addr: BASE,
            target: BASE + 0x40
        })
    );
    assert_eq!(
        generate_one(&[b(0x40, false)]),
        Err(Error::UnknownTarget {
            addr: BASE,
            target: BASE + 0x40
        })
    );
}

#[test]
fn opcodes_without_emit_are_counted_over_every_function() {
    // frin decodes, but the Xenon does not have it, so it has no emit_*.
    let frin = Insn::Frin {
        frt: Fpr(1),
        frb: Fpr(3),
        rc: false,
    };
    let addo = Insn::Add {
        rt: Gpr(3),
        ra: Gpr(4),
        rb: Gpr(5),
        oe: true,
        rc: false,
    };
    let insns = [frin, frin, blr(), frin, addo, blr()];
    let error = generate(&insns, &[(0, 3), (3, 3)], &SaveRestore::new()).unwrap_err();
    let counts = BTreeMap::from([("addo".to_owned(), 1), ("frin".to_owned(), 3)]);
    assert_eq!(error, Error::MissingEmit { counts });
    assert_eq!(
        error.to_string(),
        "opcodes without emit_*: addo x1, frin x3"
    );
}

#[test]
fn an_spr_outside_the_policy_is_an_error() {
    let mftbl = Insn::Mfspr {
        rt: Gpr(3),
        spr: 268,
    };
    let mtpvr = Insn::Mtspr {
        spr: 287,
        rs: Gpr(3),
    };
    assert!(generate_one(&[mftbl, blr()]).is_ok());
    assert_eq!(
        generate_one(&[
            Insn::Mfspr {
                rt: Gpr(3),
                spr: 1013
            },
            blr()
        ]),
        Err(Error::UnmappedSpr {
            addr: BASE,
            op: "mfspr",
            spr: 1013
        })
    );
    assert_eq!(
        generate_one(&[mtpvr, blr()]),
        Err(Error::UnmappedSpr {
            addr: BASE,
            op: "mtspr",
            spr: 287
        })
    );
}

#[test]
fn update_forms_that_the_isa_calls_invalid_are_errors() {
    let lwzu = |rt, ra| Insn::Lwzu {
        rt: Gpr(rt),
        d: 4,
        ra: Gpr(ra),
    };
    assert!(generate_one(&[lwzu(3, 4), blr()]).is_ok());
    for insn in [
        lwzu(3, 3),
        lwzu(3, 0),
        Insn::Stwu {
            rs: Gpr(3),
            d: 4,
            ra: Gpr(0),
        },
    ] {
        assert!(
            matches!(generate_one(&[insn, blr()]), Err(Error::InvalidForm { .. })),
            "{insn:?}"
        );
    }
    let lmw = Insn::Lmw {
        rt: Gpr(30),
        d: 0,
        ra: Gpr(31),
    };
    assert!(matches!(
        generate_one(&[lmw, blr()]),
        Err(Error::InvalidForm { .. })
    ));
}

/// A caller of the GPR save and restore routines, laid out after them.
fn with_gpr_routines(caller: &[Insn]) -> (Vec<Insn>, u32) {
    let mut insns: Vec<Insn> = (14..32)
        .map(|r| Insn::Std {
            rs: Gpr(r),
            ds: -0x98 + 8 * (i16::from(r) - 14),
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
        ds: -0x98 + 8 * (i16::from(r) - 14),
        ra: Gpr(1),
    }));
    insns.push(Insn::Lwz {
        rt: Gpr(12),
        d: -8,
        ra: Gpr(1),
    });
    insns.push(Insn::Mtspr {
        spr: 8,
        rs: Gpr(12),
    });
    insns.push(blr());
    let start = insns.len() as u32;
    insns.extend_from_slice(caller);
    (insns, start)
}

#[test]
fn calls_into_save_and_restore_routines_are_inlined() {
    // The caller starts at word 41: bl __savegprlr_30 (word 16), then b __restgprlr_30 (word 36).
    let caller = [b((16 - 41) * 4, true), li(30, 5), b((36 - 43) * 4, false)];
    let (insns, start) = with_gpr_routines(&caller);
    assert_eq!(start, 41);
    let bytes = assemble(&insns);
    let routines = find_save_restore(&Code::new(BASE, &bytes));
    let text = generate(&insns, &[(start, 3)], &routines).unwrap();
    assert_run(
        &text,
        &[
            "{",
            "ctx.lr = 0x820000a8;",
            "mem.write_u64((ctx.r[1] as u32).wrapping_sub(0x18), ctx.r[30]);",
            "mem.write_u64((ctx.r[1] as u32).wrapping_sub(0x10), ctx.r[31]);",
            "mem.write_u32((ctx.r[1] as u32).wrapping_sub(0x8), (ctx.r[12] as u32));",
            "}",
            "ctx.r[30] = 0x5;",
            "ctx.r[30] = mem.read_u64((ctx.r[1] as u32).wrapping_sub(0x18));",
            "ctx.r[31] = mem.read_u64((ctx.r[1] as u32).wrapping_sub(0x10));",
            "ctx.r[12] = u64::from(mem.read_u32((ctx.r[1] as u32).wrapping_sub(0x8)));",
            "ctx.lr = ctx.r[12];",
            "return;",
        ],
    );
    assert!(
        !text.contains("sub_82000040"),
        "no call into the routine:\n{text}"
    );
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

#[test]
fn calls_into_fpr_routines_are_inlined() {
    // The caller starts at word 38: bl __savefpr_30 (word 16), fmr f30, f1, bl __restfpr_30
    // (word 35), blr. Both routines end in blr, so each call goes on after itself.
    let mut insns = fpr_routines();
    let start = insns.len() as u32;
    assert_eq!(start, 38);
    insns.extend([
        b((16 - 38) * 4, true),
        Insn::Fmr {
            frt: Fpr(30),
            frb: Fpr(1),
            rc: false,
        },
        b((35 - 40) * 4, true),
        blr(),
    ]);
    let bytes = assemble(&insns);
    let routines = find_save_restore(&Code::new(BASE, &bytes));
    let text = generate(&insns, &[(start, 4)], &routines).unwrap();
    assert_run(
        &text,
        &[
            "{",
            "ctx.lr = 0x8200009c;",
            "mem.write_u64((ctx.r[12] as u32).wrapping_sub(0x10), ctx.f[30].to_bits());",
            "mem.write_u64((ctx.r[12] as u32).wrapping_sub(0x8), ctx.f[31].to_bits());",
            "}",
            "ctx.f[30] = ctx.f[1];",
            "{",
            "ctx.lr = 0x820000a4;",
            "ctx.f[30] = f64::from_bits(mem.read_u64((ctx.r[12] as u32).wrapping_sub(0x10)));",
            "ctx.f[31] = f64::from_bits(mem.read_u64((ctx.r[12] as u32).wrapping_sub(0x8)));",
            "}",
            "return;",
        ],
    );
    assert!(
        !text.contains("sub_82000040") && !text.contains("sub_8200008c"),
        "no call into a routine:\n{text}"
    );
}

/// A VMX save (`save`) or restore routine for v14 to v31 with the layout of the ABI: pairs of
/// `li r11, offset` and `stvx`/`lvx` of vN at r11 + r12, v14 at -0x120, then `blr`. Entry N is
/// word 2 × (N - 14).
fn vmx_routine(save: bool) -> Vec<Insn> {
    let mut insns = Vec::new();
    for n in 14..32u8 {
        let offset = -0x120 + 16 * (i16::from(n) - 14);
        insns.push(li(11, offset));
        let (v, ra, rb) = (Vr(n), Gpr(11), Gpr(12));
        insns.push(if save {
            Insn::Stvx { vs: v, ra, rb }
        } else {
            Insn::Lvx { vd: v, ra, rb }
        });
    }
    insns.push(blr());
    insns
}

#[test]
fn calls_into_vmx_routines_are_inlined() {
    // __savevmx_30 is word 32 and __restvmx_30 word 37 + 32 = 69. The caller starts at word 74:
    // bl __savevmx_30, vor v30, v1, v1, bl __restvmx_30, blr. Both routines end in blr.
    let mut insns = vmx_routine(true);
    insns.extend(vmx_routine(false));
    let start = insns.len() as u32;
    assert_eq!(start, 74);
    insns.extend([
        b((32 - 74) * 4, true),
        Insn::Vor {
            vd: Vr(30),
            va: Vr(1),
            vb: Vr(1),
        },
        b((69 - 76) * 4, true),
        blr(),
    ]);
    let bytes = assemble(&insns);
    let routines = find_save_restore(&Code::new(BASE, &bytes));
    let text = generate(&insns, &[(start, 4)], &routines).unwrap();
    let ea = "(ctx.r[11] as u32).wrapping_add((ctx.r[12] as u32)) & !0xf";
    let save = |v: u8| format!("mem.write_v128({ea}, ctx.v[{v}]);");
    let restore = |v: u8| format!("ctx.v[{v}] = mem.read_v128({ea});");
    let expected = [
        "{".to_owned(),
        "ctx.lr = 0x8200012c;".to_owned(),
        "ctx.r[11] = 0xffffffffffffffe0;".to_owned(),
        save(30),
        "ctx.r[11] = 0xfffffffffffffff0;".to_owned(),
        save(31),
        "}".to_owned(),
        "ctx.v[30] = ops::vor(ctx.v[1], ctx.v[1]);".to_owned(),
        "{".to_owned(),
        "ctx.lr = 0x82000134;".to_owned(),
        "ctx.r[11] = 0xffffffffffffffe0;".to_owned(),
        restore(30),
        "ctx.r[11] = 0xfffffffffffffff0;".to_owned(),
        restore(31),
        "}".to_owned(),
        "return;".to_owned(),
    ];
    let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
    assert_run(&text, &expected);
    assert!(
        !text.contains("sub_82000080") && !text.contains("sub_82000114"),
        "no call into a routine:\n{text}"
    );
}

/// The bytes of `words`: instructions, or raw words for data such as a thunk's records.
fn assemble_words(words: &[Result<Insn, u32>]) -> Vec<u8> {
    words
        .iter()
        .flat_map(|word| match word {
            Ok(insn) => insn.encode().to_be_bytes(),
            Err(raw) => raw.to_be_bytes(),
        })
        .collect()
}

fn functions_at(list: &[(u32, u32)]) -> Vec<Function> {
    list.iter()
        .map(|&(offset, words)| Function {
            addr: BASE + 4 * offset,
            size: 4 * words,
        })
        .collect()
}

#[test]
fn calls_to_a_thunk_call_the_kernel() {
    // bl thunk; li r3,1; b thunk; then the thunk, whose first words are its records.
    let words = [
        Ok(b(0x10, true)),
        Ok(li(3, 1)),
        Ok(b(8, false)),
        Ok(blr()),
        Err(0x0100_0019),
        Err(0x0200_0019),
        Ok(Insn::Mtspr {
            spr: 9,
            rs: Gpr(11),
        }),
        Ok(bcctr(20, false)),
    ];
    let bytes = assemble_words(&words);
    let routines = SaveRestore::new();
    let imports = vec![Import {
        library: Library::Xboxkrnl,
        ordinal: 0x19,
        name: Some("NtClose".to_owned()),
        function: true,
        slot: Some(BASE + 0x40),
        thunk: Some(BASE + 0x10),
    }];
    let text = Program::new(Code::new(BASE, &bytes), functions_at(&[(0, 4)]), &routines)
        .with_imports(imports)
        .generate()
        .unwrap();
    assert_run(
        &text,
        &[
            "{",
            "ctx.lr = 0x82000004;",
            "k.krnl.NtClose(ctx, mem, k);",
            "}",
        ],
    );
    assert_run(
        &text,
        &["ctx.r[3] = 0x1;", "k.krnl.NtClose(ctx, mem, k);", "return;"],
    );
}

#[test]
fn an_overridden_function_is_called_through_the_table_and_not_generated() {
    let insns = [b(8, true), blr(), li(3, 5), blr()];
    let bytes = assemble(&insns);
    let routines = SaveRestore::new();
    let hooks = Hooks {
        overrides: vec![Override {
            addr: BASE + 8,
            name: "my_fn".to_owned(),
        }],
        midasm: Vec::new(),
    };
    let program = Program::new(
        Code::new(BASE, &bytes),
        functions_at(&[(0, 2), (2, 2)]),
        &routines,
    )
    .with_hooks(hooks);
    assert_eq!(program.table_path(BASE + 8), None);
    let text = program.generate().unwrap();
    assert!(!text.contains("pub fn sub_82000008"), "{text}");
    assert_run(
        &text,
        &[
            "ctx.lr = 0x82000004;",
            "(k.table.lookup(0x82000008, ctx.lr))(ctx, mem, k); // sub_82000008",
        ],
    );
}

/// `li r3,1; li r4,2; blr; li r3,9; blr` with `midasm` hooks.
fn hooked(midasm: Vec<MidAsm>) -> Result<String, Error> {
    let insns = [li(3, 1), li(4, 2), blr(), li(3, 9), blr()];
    let bytes = assemble(&insns);
    let routines = SaveRestore::new();
    let hooks = Hooks {
        overrides: Vec::new(),
        midasm,
    };
    Program::new(Code::new(BASE, &bytes), functions_at(&[(0, 5)]), &routines)
        .with_hooks(hooks)
        .generate()
}

fn midasm(word: u32, name: &str, after: bool, action: Action) -> MidAsm {
    MidAsm {
        addr: BASE + 4 * word,
        name: name.to_owned(),
        after,
        action,
    }
}

#[test]
fn mid_asm_hooks_come_before_or_after_their_instruction_and_act() {
    let text = hooked(vec![
        midasm(0, "jump", false, Action::JumpIfTrue(BASE + 12)),
        midasm(1, "before", false, Action::Continue),
        midasm(1, "after", true, Action::ReturnIfTrue),
    ])
    .unwrap();
    assert_run(
        &text,
        &[
            "0x82000000 => {",
            "if k.hooks.call(0x82000000, \"jump\", ctx, mem, k) { pc = 0x8200000c; continue; }",
            "ctx.r[3] = 0x1;",
            "k.hooks.call(0x82000004, \"before\", ctx, mem, k);",
            "ctx.r[4] = 0x2;",
            "if k.hooks.call(0x82000004, \"after\", ctx, mem, k) { return; }",
            "return;",
            "}",
            "0x8200000c => {",
            "ctx.r[3] = 0x9;",
        ],
    );
}

#[test]
fn hooks_that_the_code_cannot_honor_are_errors() {
    let why = |hooks| match hooked(hooks) {
        Err(Error::InvalidHook { why, .. }) => why,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        why(vec![midasm(3, "h", false, Action::Continue)]),
        "no path of a function reaches it"
    );
    assert_eq!(
        why(vec![midasm(2, "h", true, Action::Continue)]),
        "it comes after a branch"
    );
    assert_eq!(
        why(vec![midasm(0, "h", false, Action::Jump(BASE + 0x100))]),
        "its jump leaves the function"
    );
    // A jump target makes the unreached half a block, where a hook may sit.
    assert!(
        hooked(vec![
            midasm(0, "j", false, Action::JumpIfTrue(BASE + 12)),
            midasm(3, "h", false, Action::Continue),
        ])
        .is_ok()
    );
}

#[test]
fn a_mid_asm_hook_in_an_overridden_function_is_an_error() {
    let insns = [li(3, 1), blr()];
    let bytes = assemble(&insns);
    let routines = SaveRestore::new();
    let hooks = Hooks {
        overrides: vec![Override {
            addr: BASE,
            name: "o".to_owned(),
        }],
        midasm: vec![midasm(0, "h", false, Action::Continue)],
    };
    let error = Program::new(Code::new(BASE, &bytes), functions_at(&[(0, 2)]), &routines)
        .with_hooks(hooks)
        .generate()
        .unwrap_err();
    assert!(
        matches!(
            error,
            Error::InvalidHook {
                why: "it lies in an overridden function",
                ..
            }
        ),
        "{error}"
    );
}

#[test]
fn trap_as_nop_drops_the_trap_and_counts_stay_per_mnemonic() {
    let twi = Insn::Twi {
        to: 31,
        ra: Gpr(3),
        si: 0,
    };
    let insns = [twi, li(3, 1), li(4, 1), blr()];
    let bytes = assemble(&insns);
    let routines = SaveRestore::new();
    let program = |nop| {
        Program::new(Code::new(BASE, &bytes), functions_at(&[(0, 4)]), &routines)
            .with_trap_as_nop(nop)
    };
    assert!(
        program(false)
            .generate()
            .unwrap()
            .contains("ops::trap(0x82000000)")
    );
    assert!(!program(true).generate().unwrap().contains("ops::trap"));
    let statistics = program(false).statistics().unwrap();
    assert_eq!(
        statistics.opcodes,
        BTreeMap::from([("addi", 2), ("bclr", 1), ("twi", 1)])
    );
    assert_eq!(
        (statistics.jump_tables, statistics.unresolved_tables),
        (0, 0)
    );
}
