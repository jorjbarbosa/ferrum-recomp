// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

// The tests that run generated code. `suite.rs` includes this file twice, in a module that names
// `FILES` and `SYNTHETIC` for the code generated with a dispatcher, and in one that names them for
// the structured code, so every test here runs on both.

/// The failures of every case of a group, by `<file>:<symbol>`, and how many cases ran.
struct Outcome {
    failures: BTreeMap<String, Vec<String>>,
    cases: usize,
}

fn run_group(group: Group) -> Outcome {
    let harness = harness();
    let mut outcome = Outcome {
        failures: BTreeMap::new(),
        cases: 0,
    };
    for file in FILES.iter().filter(|file| file.group == group) {
        let (cases, functions) = cases_of(file.name);
        let offsets: BTreeMap<&str, u32> = functions
            .iter()
            .map(|f| (f.name.as_str(), f.offset))
            .collect();
        outcome.cases += cases.len();
        let functions = match file.code {
            Generated::Code(functions) => functions,
            Generated::Failed(error) => {
                for case in &cases {
                    let key = format!("{}:{}", file.name, case.symbol);
                    outcome
                        .failures
                        .insert(key, vec![format!("codegen: {error}")]);
                }
                continue;
            }
        };
        let mut table = FnTable::new();
        table.register(CODE_BASE, functions).unwrap();
        let bin = suite_file(file.name, "bin");
        for case in &cases {
            let entry = CODE_BASE + offsets[case.symbol.as_str()];
            let failures = harness.run_case(&bin, &table, case, entry);
            if !failures.is_empty() {
                outcome
                    .failures
                    .insert(format!("{}:{}", file.name, case.symbol), failures);
            }
        }
    }
    outcome
}

/// Every case of `group` passes, apart from the exclusions of the manifest whose file is in that
/// group, each of which has to fail. Returns how many cases ran.
fn accept(group: Group) -> usize {
    let outcome = run_group(group);
    let manifest = manifest();
    let excluded: BTreeMap<String, String> = manifest
        .exclusions
        .into_iter()
        .filter(|exclusion| {
            let (file, _) = exclusion.case.split_once(':').expect("<file>:<symbol>");
            manifest.files.get(file) == Some(&group)
        })
        .map(|exclusion| (exclusion.case, exclusion.reason))
        .collect();
    println!(
        "{} {group:?} cases, {} failed",
        outcome.cases,
        outcome.failures.len()
    );
    let mut unexpected = Vec::new();
    for (case, failures) in &outcome.failures {
        let line = format!("{case}: {}", failures.join("; "));
        println!("  {line}");
        if !excluded.contains_key(case) {
            unexpected.push(line);
        }
    }
    let passing: Vec<&String> = excluded
        .keys()
        .filter(|case| !outcome.failures.contains_key(*case))
        .collect();
    assert!(
        unexpected.is_empty(),
        "failing cases:
{}",
        unexpected.join(
            "
"
        )
    );
    assert!(passing.is_empty(), "excluded cases that pass: {passing:?}");
    outcome.cases
}

/// Every case of the integer files passes, apart from the exclusions of the manifest, each of
/// which has to fail.
#[test]
fn every_integer_case_passes_apart_from_the_exclusions() {
    let cases = accept(Group::Integer);
    assert!(cases > 1600, "only {cases} cases ran");
}

/// Every case of the `instr_f*` files passes, apart from the exclusions of the manifest for those
/// files, each of which has to fail.
#[test]
fn every_float_case_passes_apart_from_the_exclusions() {
    // 47 labels in the ten files; the three of instr_frsqrte have their instructions commented out.
    assert_eq!(accept(Group::Float), 47);
}

/// Every case of the VMX and VMX128 files passes, apart from the exclusions of the manifest for
/// those files, each of which has to fail.
#[test]
fn every_vector_case_passes_apart_from_the_exclusions() {
    let cases = accept(Group::Vector);
    assert!(cases > 300, "only {cases} cases ran");
}

/// `seq_jumptable_constants` runs to the end without a panic, through its jump table.
#[test]
fn every_discovery_case_passes_apart_from_the_exclusions() {
    assert_eq!(accept(Group::Discovery), 1);
}

/// The program called `name` and a table of its functions.
fn synthetic(name: &str) -> (Synthetic, FnTable) {
    let program = programs().into_iter().find(|p| p.name == name).unwrap();
    let (_, functions) = SYNTHETIC.iter().find(|(n, _)| *n == name).unwrap();
    let mut table = FnTable::new();
    table.register(CODE_BASE, functions).unwrap();
    (program, table)
}

/// Runs the function of `name` at word `entry` with the given registers, then `check` with the
/// context after the call, the result of the call and the harness.
fn run(
    name: &str,
    entry: u32,
    inputs: &[(usize, u64)],
    check: impl FnOnce(&PpcContext, Result<(), String>, &Harness),
) {
    let harness = harness();
    let (program, table) = synthetic(name);
    harness.reset(&program.bytes());
    let mut ctx = Harness::context();
    for &(r, value) in inputs {
        ctx.r[r] = value;
    }
    let result = harness.call(&mut ctx, &table, Synthetic::entry(entry));
    check(&ctx, result, &harness);
    harness.check_outside().unwrap();
}

mod imports_and_hooks {
    //! The `imports` and `hooks` programs: words and registers as their doc comments in
    //! `synthetic.rs` say.

    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;
    use ferrum_harness::generated::synthetic::imports::imports as generated_imports;
    use ferrum_harness::synthetic::IMPORT_SLOT;
    use ferrum_runtime::{HookTable, Kernels, Unimplemented, Xam, Xboxkrnl};

    /// A kernel that counts the calls to `NtClose`.
    #[derive(Default)]
    struct Counter {
        calls: AtomicU32,
    }

    impl Xboxkrnl for Counter {
        #[allow(non_snake_case)]
        fn NtClose(&self, ctx: &mut PpcContext, _: &Memory, _: &Kernels<'_>) {
            let calls = self.calls.fetch_add(1, Ordering::Relaxed) + 1;
            ctx.r[3] = u64::from(calls);
        }
    }

    impl Xam for Counter {}

    #[test]
    fn an_import_is_called_through_its_thunk_its_slot_and_a_tail_call() {
        let harness = harness();
        let (program, table) = synthetic("imports");
        harness.reset(&program.bytes());
        let counter = Counter::default();
        let kernels = Kernels {
            krnl: &counter,
            xam: &Unimplemented,
            table: &table,
            hooks: HookTable::empty(),
        };
        let mem = harness.memory();
        generated_imports::load(mem, &kernels);
        assert_eq!(
            mem.read_u32(IMPORT_SLOT),
            Synthetic::entry(8),
            "load puts the thunk's address in the slot"
        );
        let mut ctx = Harness::context();
        harness
            .call_with(&mut ctx, &kernels, Synthetic::entry(0))
            .unwrap();
        assert_eq!(counter.calls.load(Ordering::Relaxed), 3);
        assert_eq!(ctx.r[3], 3);
        assert_eq!(ctx.lr, SENTINEL_LR);
        mem.write_u32(IMPORT_SLOT, 0);
    }

    fn overridden(ctx: &mut PpcContext, _: &Memory, _: &Kernels<'_>) {
        ctx.r[3] = 41;
    }

    fn before(ctx: &mut PpcContext, _: &Memory, _: &Kernels<'_>) -> bool {
        ctx.r[10] = ctx.r[3];
        false
    }

    fn maybe_return(ctx: &mut PpcContext, _: &Memory, _: &Kernels<'_>) -> bool {
        ctx.r[8] != 0
    }

    fn skip(ctx: &mut PpcContext, _: &Memory, _: &Kernels<'_>) -> bool {
        ctx.r[9] != 0
    }

    fn after(ctx: &mut PpcContext, _: &Memory, _: &Kernels<'_>) -> bool {
        ctx.r[11] = ctx.r[6];
        false
    }

    fn jump(_: &mut PpcContext, _: &Memory, _: &Kernels<'_>) -> bool {
        false
    }

    fn hook_table() -> HookTable {
        let mut hooks = HookTable::new();
        hooks.set(Synthetic::entry(3), before);
        hooks.set(Synthetic::entry(4), maybe_return);
        hooks.set(Synthetic::entry(5), skip);
        hooks.set(Synthetic::entry(7), after);
        hooks.set(Synthetic::entry(8), jump);
        hooks
    }

    /// Runs `main` of `hooks` with r8 and r9 as given, the override installed if `install`.
    fn run_hooks(
        r8: u64,
        r9: u64,
        install: bool,
        hooks: &HookTable,
    ) -> (PpcContext, Result<(), String>) {
        let harness = harness();
        let (program, mut table) = synthetic("hooks");
        harness.reset(&program.bytes());
        if install {
            table.set(Synthetic::entry(12), overridden).unwrap();
        }
        let kernels = Kernels {
            krnl: &Unimplemented,
            xam: &Unimplemented,
            table: &table,
            hooks,
        };
        let mut ctx = Harness::context();
        ctx.r[8] = r8;
        ctx.r[9] = r9;
        let result = harness.call_with(&mut ctx, &kernels, Synthetic::entry(0));
        (ctx, result)
    }

    #[test]
    fn hooks_run_where_the_config_puts_them_and_act() {
        let hooks = hook_table();
        let (ctx, result) = run_hooks(0, 0, true, &hooks);
        result.unwrap();
        assert_eq!(ctx.r[10], 41, "before saw r3 from the override");
        assert_eq!(ctx.r[3], 42, "then the instruction ran");
        assert_eq!(ctx.r[4], 7);
        assert_eq!(ctx.r[5], 2);
        assert_eq!((ctx.r[6], ctx.r[11]), (3, 3), "after saw r6 set");
        assert_eq!(ctx.r[7], 0, "the jump skipped both writes of r7");
        assert_eq!(ctx.lr, SENTINEL_LR);

        let (ctx, result) = run_hooks(0, 1, true, &hooks);
        result.unwrap();
        assert_eq!((ctx.r[4], ctx.r[5], ctx.r[6], ctx.r[11]), (7, 0, 0, 0));
        assert_eq!(ctx.r[7], 0);

        let (ctx, result) = run_hooks(1, 0, true, &hooks);
        result.unwrap();
        assert_eq!(
            (ctx.r[3], ctx.r[4], ctx.r[5]),
            (42, 0, 0),
            "returned before r4"
        );
    }

    #[test]
    fn a_missing_override_or_hook_panics_with_its_address() {
        let hooks = hook_table();
        let (_, result) = run_hooks(0, 0, false, &hooks);
        let message = result.unwrap_err();
        assert!(
            message.contains("no guest function at 0x80000030"),
            "{message}"
        );
        let (_, result) = run_hooks(0, 0, true, HookTable::empty());
        let message = result.unwrap_err();
        assert!(
            message.contains("the hook before at 0x8000000c is not installed"),
            "{message}"
        );
    }
}

mod setjmp {
    //! The `setjmp` program: words and registers as its doc comment in `synthetic.rs` says.

    use super::*;
    use ferrum_harness::runner::DATA_BASE;

    const BUFFER: u64 = DATA_BASE as u64;
    const OTHER: u64 = DATA_BASE as u64 + 0x40;

    #[test]
    fn longjmp_returns_from_setjmp_again_with_its_registers() {
        run(
            "setjmp",
            6,
            &[(30, BUFFER), (29, 7)],
            |ctx, result, harness| {
                result.unwrap();
                assert_eq!(ctx.r[28], 7, "the value of longjmp, from setjmp");
                assert_eq!(ctx.r[31], 0x77, "r31 as it was at setjmp, not 0x55");
                assert_eq!(
                    ctx.r[20], 0,
                    "r20 as it was at setjmp, before jumper set it"
                );
                assert_eq!(ctx.r[27], 0, "jumper never came back");
                assert_eq!(ctx.lr, SENTINEL_LR, "main returned through its frame");
                assert_eq!(ctx.r[1], u64::from(STACK_BASE));
                // setjmp stored r1 inside main's frame; longjmp left memory alone.
                let mem = harness.memory();
                assert_eq!(mem.read_u32(DATA_BASE), STACK_BASE - 16);
                assert_eq!(mem.read_u32(DATA_BASE + 24), 1, "jumper ran once");
            },
        );
    }

    #[test]
    fn longjmp_with_0_makes_setjmp_return_1() {
        run(
            "setjmp",
            6,
            &[(30, BUFFER), (29, 0)],
            |ctx, result, harness| {
                result.unwrap();
                assert_eq!(ctx.r[28], 1);
                assert_eq!(harness.memory().read_u32(DATA_BASE + 24), 1);
            },
        );
    }

    #[test]
    fn longjmp_unwinds_through_a_frame_with_another_buffer() {
        let inputs = [(30, BUFFER), (29, OTHER), (26, BUFFER), (25, 3)];
        run("setjmp", 29, &inputs, |ctx, result, _| {
            result.unwrap();
            assert_eq!(ctx.r[22], 3, "outer returned from its setjmp again");
            assert_eq!(ctx.r[21], 0, "inner did not");
            assert_eq!(ctx.r[23], 0, "inner never returned to outer");
            assert_eq!(ctx.lr, SENTINEL_LR);
        });
    }

    #[test]
    fn longjmp_to_the_inner_buffer_resumes_the_inner_frame() {
        let inputs = [(30, BUFFER), (29, OTHER), (26, OTHER), (25, 4)];
        run("setjmp", 29, &inputs, |ctx, result, _| {
            result.unwrap();
            assert_eq!(ctx.r[21], 4, "inner returned from its setjmp again");
            assert_eq!(ctx.r[23], 0x11, "then returned to outer");
            assert_eq!(ctx.r[22], 0, "outer's setjmp returned once");
            assert_eq!(ctx.lr, SENTINEL_LR);
        });
    }

    #[test]
    fn a_recursive_function_resumes_at_its_innermost_frame() {
        run(
            "setjmp",
            60,
            &[(3, 3), (30, BUFFER)],
            |ctx, result, harness| {
                result.unwrap();
                let mem = harness.memory();
                assert_eq!(
                    mem.read_u32(DATA_BASE + 16),
                    1,
                    "the level with n = 0 resumed"
                );
                assert_eq!(mem.read_u32(DATA_BASE + 20), 1, "and no other");
                assert_eq!(ctx.r[28], 5);
                assert_eq!(ctx.r[31], 0, "every level restored r31 from its frame");
                assert_eq!(ctx.lr, SENTINEL_LR);
            },
        );
    }

    #[test]
    fn a_longjmp_that_no_frame_resumes_reaches_the_top() {
        // jumper alone: no live frame set the buffer.
        run("setjmp", 4, &[(3, BUFFER), (4, 1)], |_, result, _| {
            assert!(result.is_err());
        });
    }
}

#[test]
fn a_call_writes_lr_first_and_comes_back() {
    run("calls", 0, &[], |ctx, result, _| {
        result.unwrap();
        assert_eq!(
            ctx.r[3], 11,
            "the leaf ran, then the instruction after the call"
        );
        assert_eq!(
            ctx.r[21],
            u64::from(Synthetic::entry(3)),
            "LR in the callee"
        );
        assert_eq!(
            ctx.r[22],
            u64::from(Synthetic::entry(3)),
            "LR after the return"
        );
        assert_eq!(ctx.lr, SENTINEL_LR);
    });
}

#[test]
fn indirect_calls_go_through_the_table() {
    run("indirect", 0, &[(3, 0)], |ctx, result, _| {
        result.unwrap();
        assert_eq!(ctx.r[3], 20, "bctrl and blrl both called the leaf");
        assert_eq!(
            ctx.r[23],
            u64::from(Synthetic::entry(5)),
            "LR in the callee of bctrl"
        );
        assert_eq!(
            ctx.r[21],
            u64::from(Synthetic::entry(8)),
            "LR in the callee of blrl"
        );
        assert_eq!(ctx.lr, SENTINEL_LR);
    });
}

#[test]
fn tail_calls_do_not_come_back() {
    run("tails", 0, &[], |ctx, result, _| {
        result.unwrap();
        assert_eq!(ctx.r[3], 6, "b went to the target and did not come back");
        assert_eq!(ctx.r[21], SENTINEL_LR, "b leaves LR alone");
    });
    run("tails", 4, &[(3, 0)], |ctx, result, _| {
        result.unwrap();
        assert_eq!(ctx.r[3], 5, "bctr went to the target and did not come back");
        assert_eq!(ctx.r[21], SENTINEL_LR, "bctr leaves LR alone");
    });
    run("tails", 9, &[(3, 0), (4, 0)], |ctx, result, _| {
        result.unwrap();
        assert_eq!(ctx.r[3], 5, "beq taken");
    });
    run("tails", 9, &[(3, 0), (4, 1)], |ctx, result, _| {
        result.unwrap();
        assert_eq!(ctx.r[3], 99, "beq not taken");
    });
}

#[test]
fn a_conditional_return_returns_only_when_it_holds() {
    run("returns", 0, &[(3, 1), (4, 0)], |ctx, result, _| {
        result.unwrap();
        assert_eq!(ctx.r[3], 1);
    });
    run("returns", 0, &[(3, 1), (4, 1)], |ctx, result, _| {
        result.unwrap();
        assert_eq!(ctx.r[3], 7);
    });
}

#[test]
fn ctr_loops_count_on_the_low_word() {
    run("loops", 0, &[(4, 5)], |ctx, result, _| {
        result.unwrap();
        assert_eq!((ctx.r[3], ctx.ctr), (15, 0));
    });
    run("loops", 5, &[(4, 0x1_0000_0001)], |ctx, result, _| {
        result.unwrap();
        assert_eq!(ctx.r[3], 2, "bdz sees zero in the low word");
        assert_eq!(ctx.ctr, 0x1_0000_0000);
    });
    run("loops", 5, &[(4, 3)], |ctx, result, _| {
        result.unwrap();
        assert_eq!((ctx.r[3], ctx.ctr), (1, 2));
    });
}

#[test]
fn a_cycle_entered_at_two_blocks_starts_at_the_one_chosen() {
    let added = |entry_a: u64, count: u64| {
        let mut sum = None;
        run("two_entries", 0, &[(3, 0), (4, entry_a), (5, count)], |ctx, result, _| {
            result.unwrap();
            sum = Some(ctx.r[3]);
        });
        sum.unwrap()
    };
    assert_eq!(added(1, 3), 1 + 16 + 1);
    assert_eq!(added(0, 3), 16 + 1 + 16);
    assert_eq!(added(1, 4), 1 + 16 + 1 + 16);
    assert_eq!(added(0, 1), 16);
    assert_eq!(added(1, 0), 0);
}

#[test]
fn an_inner_loop_leaves_both_loops_at_once() {
    let sum = |outer: u64, inner: u64, stop: u64| {
        let mut sum = None;
        run("nested_loops", 0, &[(4, outer), (5, inner), (6, stop)], |ctx, result, _| {
            result.unwrap();
            sum = Some(ctx.r[3]);
        });
        sum.unwrap()
    };
    assert_eq!(sum(2, 3, 1000), 3 + 100 + 3 + 100);
    assert_eq!(sum(2, 3, 105), 105, "left both loops when r3 reached r6");
    assert_eq!(sum(3, 0, 1000), 300);
    assert_eq!(sum(0, 3, 1000), 0);
}

#[test]
fn save_and_restore_routines_are_inlined() {
    let inputs = [(29, 0x29), (30, 0x30), (31, 0x31)];
    run("save_restore", 41, &inputs, |ctx, result, harness| {
        result.unwrap();
        assert_eq!(
            (ctx.r[29], ctx.r[30], ctx.r[31]),
            (0x29, 0x30, 0x31),
            "restored"
        );
        assert_eq!(ctx.r[3], 42, "the call in between ran");
        assert_eq!(
            ctx.r[21],
            u64::from(Synthetic::entry(47)),
            "LR in that call"
        );
        assert_eq!(ctx.lr, SENTINEL_LR, "LR reloaded from the frame");
        assert_eq!(ctx.r[12], SENTINEL_LR);
        let mem = harness.memory();
        assert_eq!(mem.read_u64(STACK_BASE - 0x20), 0x29);
        assert_eq!(mem.read_u64(STACK_BASE - 0x18), 0x30);
        assert_eq!(mem.read_u64(STACK_BASE - 0x10), 0x31);
        assert_eq!(u64::from(mem.read_u32(STACK_BASE - 0x8)), SENTINEL_LR);
        assert_eq!(mem.read_u64(STACK_BASE - 0x28), 0, "r28 was not saved");
    });
}

#[test]
fn falling_off_the_end_panics() {
    run("fall_off", 0, &[], |_, result, _| {
        let message = result.unwrap_err();
        assert!(
            message.contains("fell off the end of sub_80000000"),
            "{message}"
        );
    });
}

#[test]
fn compares_order_by_width_and_sign() {
    // r3: -1 as a word but positive as a doubleword. r5: negative as a doubleword, 1 as a word.
    let inputs = [(3, 0xFFFF_FFFF), (4, 1), (5, 0x8000_0000_0000_0001), (6, 1)];
    run("compares", 0, &inputs, |ctx, result, _| {
        result.unwrap();
        // LT for the signed compares and GT for the unsigned ones, field by field: cmpw, cmplw,
        // cmpd, cmpld, cmpwi, cmplwi, cmpdi, cmpldi.
        assert_eq!(ctx.r[12], 0x8484_8484, "{:#010x}", ctx.r[12]);
    });
}

/// `dcbz` zeroes the 128-byte block that holds EA: the Xenon's data cache block. The suites
/// cannot tell it from a 32-byte one.
#[test]
fn dcbz_zeroes_the_128_byte_block() {
    use ferrum_harness::runner::DATA_BASE;
    let harness = harness();
    let (program, table) = synthetic("dcbz");
    // dcbz at word 0 and dcbz128 at word 2 zero the same block.
    for entry in [0, 2] {
        harness.reset(&program.bytes());
        let mem = harness.memory();
        mem.write_bytes(DATA_BASE, &[0xFF; 0x200]);
        let mut ctx = Harness::context();
        ctx.r[3] = u64::from(DATA_BASE);
        ctx.r[4] = 0xC8;
        harness
            .call(&mut ctx, &table, Synthetic::entry(entry))
            .unwrap();
        let mut bytes = [0; 0x200];
        mem.read_bytes(DATA_BASE, &mut bytes);
        assert!(bytes[..0x80].iter().all(|&b| b == 0xFF), "below the block");
        assert!(
            bytes[0x80..0x100].iter().all(|&b| b == 0),
            "the block holding EA, entry {entry}"
        );
        assert!(bytes[0x100..].iter().all(|&b| b == 0xFF), "above the block");
        mem.write_bytes(DATA_BASE, &[0; 0x200]);
    }
}

/// A time base that always reads the same value.
struct FixedTimeBase(u64);

impl ferrum_runtime::TimeBase for FixedTimeBase {
    fn read(&self) -> u64 {
        self.0
    }
}

#[test]
fn mftb_reads_the_whole_time_base_and_mftbu_its_upper_word() {
    let harness = harness();
    let (program, table) = synthetic("dcbz");
    harness.reset(&program.bytes());
    let mut ctx = Harness::context();
    ctx.time_base = std::sync::Arc::new(FixedTimeBase(0x1234_5678_9ABC_DEF0));
    harness.call(&mut ctx, &table, Synthetic::entry(4)).unwrap();
    assert_eq!(
        ctx.r[5], 0x1234_5678_9ABC_DEF0,
        "TBL on a 64-bit implementation"
    );
    assert_eq!(ctx.r[6], 0x1234_5678, "TBU");
}

/// The code and the table of a compiled file.
fn compiled(name: &str) -> (Vec<u8>, FnTable) {
    let file = FILES.iter().find(|file| file.name == name).unwrap();
    let Generated::Code(functions) = file.code else {
        panic!("{name} was not compiled");
    };
    let mut table = FnTable::new();
    table.register(CODE_BASE, functions).unwrap();
    (suite_file(name, "bin"), table)
}

/// The harness itself: a case fails when any bit of a register it names, or any byte of memory,
/// differs from the expectation.
#[test]
fn a_case_fails_on_any_wrong_bit_or_byte() {
    let harness = harness();
    let name = "xenia-canary-ppc/instr_stw";
    let (cases, functions) = cases_of(name);
    let (code, table) = compiled(name);
    let (case, entry) = (&cases[0], CODE_BASE + functions[0].offset);
    assert_eq!(case.symbol, "test_stw_1");
    assert!(harness.run_case(&code, &table, case, entry).is_empty());
    let mut checked = 0;
    for (index, annotation) in case.annotations.iter().enumerate() {
        let wrong: Vec<Annotation> = match annotation {
            Annotation::RegisterOut(register, value) => [0, 31, 32, 63]
                .iter()
                .map(|bit| Annotation::RegisterOut(*register, value ^ (1 << bit)))
                .collect(),
            Annotation::MemoryOut(addr, bytes) => (0..bytes.len())
                .map(|at| {
                    let mut bytes = bytes.clone();
                    bytes[at] ^= 0x01;
                    Annotation::MemoryOut(*addr, bytes)
                })
                .collect(),
            _ => continue,
        };
        for annotation in wrong {
            let mut changed = case.clone();
            changed.annotations[index] = annotation.clone();
            let failures = harness.run_case(&code, &table, &changed, entry);
            assert_eq!(failures.len(), 1, "{annotation:?}: {failures:?}");
            checked += 1;
        }
    }
    assert_eq!(checked, 2 * 4 + 4, "two registers and four bytes");
}

/// The harness compares an FPR on all its bits: changing any bit of an expectation makes the case
/// fail, the sign of a zero written in decimal included (`0.0` in `test_fadd_3`), which a
/// comparison of doubles would let pass.
#[test]
fn a_case_fails_on_any_wrong_fpr_bit() {
    let harness = harness();
    for (name, symbol) in [
        ("xenia-ppc/instr_fctixz", "test_fctiwz_1"),
        ("xenia-ppc/instr_fadd", "test_fadd_3"),
    ] {
        let (cases, functions) = cases_of(name);
        let (code, table) = compiled(name);
        let index = cases.iter().position(|case| case.symbol == symbol).unwrap();
        let (case, entry) = (&cases[index], CODE_BASE + functions[index].offset);
        assert!(
            harness.run_case(&code, &table, case, entry).is_empty(),
            "{symbol}"
        );
        let mut checked = 0;
        for (at, annotation) in case.annotations.iter().enumerate() {
            let &Annotation::RegisterOut(register @ Register::Fpr(_), bits) = annotation else {
                continue;
            };
            for bit in [0, 31, 32, 63] {
                let mut changed = case.clone();
                changed.annotations[at] = Annotation::RegisterOut(register, bits ^ (1 << bit));
                let failures = harness.run_case(&code, &table, &changed, entry);
                assert_eq!(failures.len(), 1, "{symbol}, bit {bit}: {failures:?}");
                checked += 1;
            }
        }
        assert!(checked >= 4, "{symbol} names an FPR");
    }
}

/// The harness compares a VR on all its bits: changing any bit of any word of an expectation makes
/// the case fail. `test_vaddfp_1` expects +0 in word 0, so a comparison of the lanes as floats
/// would let -0 pass, and `test_vctsxs_1` expects zeros everywhere.
#[test]
fn a_case_fails_on_any_wrong_vr_bit() {
    let harness = harness();
    for (name, symbol) in [
        ("xenia-ppc/instr_vaddfp", "test_vaddfp_1"),
        ("xenia-ppc/instr_vctsxs", "test_vctsxs_1"),
    ] {
        let (cases, functions) = cases_of(name);
        let (code, table) = compiled(name);
        let index = cases.iter().position(|case| case.symbol == symbol).unwrap();
        let (case, entry) = (&cases[index], CODE_BASE + functions[index].offset);
        assert!(
            harness.run_case(&code, &table, case, entry).is_empty(),
            "{symbol}"
        );
        let mut checked = 0;
        for (at, annotation) in case.annotations.iter().enumerate() {
            let &Annotation::VectorOut(n, words) = annotation else {
                continue;
            };
            for word in 0..4 {
                for bit in [0, 22, 31] {
                    let mut wrong = words;
                    wrong[word] ^= 1 << bit;
                    let mut changed = case.clone();
                    changed.annotations[at] = Annotation::VectorOut(n, wrong);
                    let failures = harness.run_case(&code, &table, &changed, entry);
                    assert_eq!(failures.len(), 1, "{symbol}, word {word}: {failures:?}");
                    checked += 1;
                }
            }
        }
        assert!(checked >= 12, "{symbol} names a VR");
    }
}

/// The harness notices a write next to its regions, and clears it. With the `trace` feature such
/// a write panics instead, so there is nothing to check here.
#[cfg(not(feature = "trace"))]
#[test]
fn a_write_next_to_the_regions_is_noticed() {
    use ferrum_harness::runner::{CODE_END, DATA_BASE, DATA_END, PCR_BASE};
    let harness = harness();
    harness.reset(&[]);
    for addr in [
        DATA_BASE - 8,
        DATA_END,
        PCR_BASE - 0x8000,
        CODE_END + 0x7FF8,
    ] {
        harness.memory().write_u64(addr, 1);
        let error = harness.check_outside().unwrap_err();
        assert!(error.contains("outside the harness's regions"), "{error}");
        harness.check_outside().unwrap();
    }
}

/// Runs the function at the address `entry` of the program `name` after `setup` on a fresh
/// context and the reset memory, then `check` with the context and the memory.
fn run_fp(
    name: &str,
    entry: u32,
    setup: impl FnOnce(&mut PpcContext, &Memory),
    check: impl FnOnce(&PpcContext, &Memory),
) {
    let harness = harness();
    let (program, table) = synthetic(name);
    harness.reset(&program.bytes());
    let mut ctx = Harness::context();
    setup(&mut ctx, harness.memory());
    harness.call(&mut ctx, &table, entry).unwrap();
    check(&ctx, harness.memory());
    harness.check_outside().unwrap();
}

/// Runs the instruction `name` of `fp_ops` with frA = `a`, frB = `b` and frC = `c`, given as
/// bits, on a clear FPSCR, and returns the bits of frT and the FPSCR.
fn fp_op(name: &str, a: u64, b: u64, c: u64) -> (u64, u32) {
    let mut out = (0, 0);
    run_fp(
        "fp_ops",
        fp_op_entry(name),
        |ctx, _| {
            ctx.f[2] = f64::from_bits(a);
            ctx.f[3] = f64::from_bits(b);
            ctx.f[4] = f64::from_bits(c);
        },
        |ctx, _| out = (ctx.f[1].to_bits(), ctx.fpscr.to_u32()),
    );
    out
}

/// Bits of a few doubles, for the floating-point programs.
mod bits {
    pub const ONE: u64 = 0x3FF0_0000_0000_0000;
    pub const TWO: u64 = 0x4000_0000_0000_0000;
    pub const THREE: u64 = 0x4008_0000_0000_0000;
    pub const FOUR: u64 = 0x4010_0000_0000_0000;
    pub const NEG_ZERO: u64 = 0x8000_0000_0000_0000;
    pub const INF: u64 = 0x7FF0_0000_0000_0000;
    pub const NEG_INF: u64 = 0xFFF0_0000_0000_0000;
    pub const QNAN_B: u64 = 0x7FF8_0000_0000_00BB;
    pub const QNAN_C: u64 = 0x7FF8_0000_0000_00CC;
    pub const SNAN: u64 = 0x7FF0_0000_0000_00BB;
    pub const DEFAULT_NAN: u64 = 0x7FF8_0000_0000_0000;
}

/// The loads read big-endian bytes: a double unchanged, a single converted bit for bit.
#[test]
fn floating_point_loads_read_big_endian() {
    use ferrum_harness::runner::DATA_BASE;
    let data: [u8; 0x24] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // +0x00
        0x7F, 0x80, 0x00, 0x01, 0, 0, 0, 0, // +0x08: a single signaling NaN
        0x3F, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // +0x10
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // +0x18: -2.0
        0x00, 0x00, 0x00, 0x01, // +0x20: the smallest single denormal
    ];
    let base = u64::from(DATA_BASE);
    run_fp(
        "fp_loads",
        Synthetic::entry(0),
        |ctx, mem| {
            mem.write_bytes(DATA_BASE, &data);
            ctx.r[3] = base;
            ctx.r[4] = 0x10;
        },
        |ctx, _| {
            let f = |n: usize| ctx.f[n].to_bits();
            assert_eq!(f(1), 0x0123_4567_89AB_CDEF, "lfd");
            // The fraction moves up 29 bits and the quiet bit stays clear (Book I 4.6.2).
            assert_eq!(f(2), 0x7FF0_0000_2000_0000, "lfs of a signaling NaN");
            assert_eq!(f(3), 0x3F80_0000_0000_0001, "lfdx");
            assert_eq!(f(4), bits::ONE, "lfsx of 0x3F800000");
            assert_eq!(
                (f(5), ctx.r[5]),
                (0xC000_0000_0000_0000, base + 0x18),
                "lfdu"
            );
            // 2^-149 is a normal double: biased exponent 1023 - 149 = 874 = 0x36A.
            assert_eq!(
                (f(6), ctx.r[6]),
                (0x36A0_0000_0000_0000, base + 0x20),
                "lfsu"
            );
            assert_eq!(
                (f(7), ctx.r[7]),
                (0x3F80_0000_0000_0001, base + 0x10),
                "lfdux"
            );
            assert_eq!((f(8), ctx.r[8]), (bits::ONE, base + 0x10), "lfsux");
        },
    );
}

/// The stores write big-endian bytes; a single is selected from the bits, not rounded.
#[test]
fn floating_point_stores_write_big_endian_and_truncate_singles() {
    use ferrum_harness::runner::DATA_BASE;
    let base = DATA_BASE + 0x100;
    let fprs: [u64; 9] = [
        0x0123_4567_89AB_CDEF,
        // 1 + 2^-24 + 2^-52: above the midpoint between two singles, so rounding would give
        // 0x3F800001; stfs keeps bits 0:1 and 5:34, which give 0x3F800000.
        0x3FF0_0000_1000_0001,
        bits::NEG_ZERO,
        // A single signaling NaN: bits 5:34 keep it signaling.
        0x7FF0_0000_2000_0000,
        bits::ONE,
        // 2^-127, a single denormal: the significand shifted right once, 0x00400000.
        0x3800_0000_0000_0000,
        0xDEAD_BEEF_CAFE_BABE,
        // 2^200, past single range: bits 0:1 (0b01) and 5:34 give 0x63800000.
        0x4C70_0000_0000_0000,
        0xDEAD_BEEF_1234_5678,
    ];
    run_fp(
        "fp_stores",
        Synthetic::entry(0),
        |ctx, _| {
            for (n, value) in fprs.iter().enumerate() {
                ctx.f[n + 1] = f64::from_bits(*value);
            }
            ctx.r[3] = u64::from(base);
            for (r, offset) in [(9, 0x10), (10, 0x18), (11, 0x30), (12, 0x38), (14, 0x40)] {
                ctx.r[r] = offset;
            }
        },
        |ctx, mem| {
            let mut bytes = [0; 0x44];
            mem.read_bytes(base, &mut bytes);
            let at = |offset: usize, len: usize| bytes[offset..offset + len].to_vec();
            assert_eq!(at(0x00, 8), 0x0123_4567_89AB_CDEFu64.to_be_bytes(), "stfd");
            assert_eq!(at(0x08, 4), [0x3F, 0x80, 0x00, 0x00], "stfs truncates");
            assert_eq!(at(0x10, 8), bits::NEG_ZERO.to_be_bytes(), "stfdx");
            assert_eq!(
                at(0x18, 4),
                [0x7F, 0x80, 0x00, 0x01],
                "stfsx of a signaling NaN"
            );
            assert_eq!(at(0x20, 8), bits::ONE.to_be_bytes(), "stfdu");
            assert_eq!(at(0x28, 4), [0x00, 0x40, 0x00, 0x00], "stfsu of 2^-127");
            assert_eq!(
                at(0x30, 8),
                0xDEAD_BEEF_CAFE_BABEu64.to_be_bytes(),
                "stfdux"
            );
            assert_eq!(at(0x38, 4), [0x63, 0x80, 0x00, 0x00], "stfsux of 2^200");
            assert_eq!(at(0x40, 4), [0x12, 0x34, 0x56, 0x78], "stfiwx");
            let base = u64::from(base);
            assert_eq!(
                (ctx.r[5], ctx.r[6], ctx.r[7], ctx.r[8]),
                (base + 0x20, base + 0x28, base + 0x30, base + 0x38),
                "the update forms"
            );
        },
    );
}

#[test]
fn moves_and_fsel_copy_bits() {
    use bits::*;
    // A move copies a signaling NaN without quieting it (Book I 4.6.4).
    assert_eq!(fp_op("fmr", 0, SNAN, 0), (SNAN, 0));
    assert_eq!(fp_op("fneg", 0, 0, 0), (NEG_ZERO, 0));
    assert_eq!(fp_op("fabs", 0, NEG_INF, 0), (INF, 0));
    assert_eq!(fp_op("fnabs", 0, ONE, 0), (0xBFF0_0000_0000_0000, 0));
    // fsel frT, frA, frC, frB: -0 is not less than zero, so it selects frC (5.2.2).
    assert_eq!(fp_op("fsel", NEG_ZERO, FOUR, THREE), (THREE, 0));
    assert_eq!(fp_op("fsel", 0xBFF0_0000_0000_0000, FOUR, THREE), (FOUR, 0));
    assert_eq!(
        fp_op("fsel", QNAN_B, FOUR, THREE),
        (FOUR, 0),
        "a NaN selects frB"
    );
}

#[test]
fn double_arithmetic_runs_through_the_runtime() {
    use bits::*;
    assert_eq!(
        fp_op("fsub", 0x4014_0000_0000_0000, THREE, 0),
        (TWO, 0),
        "5 - 3"
    );
    assert_eq!(
        fp_op("fmul", TWO, 0, THREE),
        (0x4018_0000_0000_0000, 0),
        "2 x 3"
    );
    // A finite number over zero: an infinity, and ZX with FX (4.4.2).
    assert_eq!(fp_op("fdiv", ONE, 0, 0), (INF, 0x8400_0000));
    // The square root of -1 generates the positive default NaN, with VXSQRT, VX and FX.
    assert_eq!(
        fp_op("fsqrt", 0, 0xBFF0_0000_0000_0000, 0),
        (DEFAULT_NAN, 0xA000_0200)
    );
    assert_eq!(fp_op("fres", 0, FOUR, 0), (0x3FD0_0000_0000_0000, 0), "1/4");
    assert_eq!(
        fp_op("frsqrte", 0, 0x4030_0000_0000_0000, 0).0,
        0x3FD0_0000_0000_0000,
        "1/sqrt(16)"
    );
    // fmadd frT, frA, frC, frB with a NaN in frC and frB: frB wins (4.3.2).
    assert_eq!(fp_op("fmadd", ONE, QNAN_B, QNAN_C), (QNAN_B, 0));
}

/// `fmadd` rounds once: (1 + 2^-30)^2 - (1 + 2^-29) is 2^-60 exactly, which a multiply rounded
/// to double before the add loses (the suite's fmadd cases come out the same either way).
#[test]
fn fmadd_is_fused() {
    let a = 0x3FF0_0000_0040_0000; // 1 + 2^-30
    let b = 0x3FF0_0000_0080_0000; // 1 + 2^-29
    let two_to_minus_60 = 0x3C30_0000_0000_0000;
    assert_eq!(
        fp_op("fmadd", a, b | bits::NEG_ZERO, a),
        (two_to_minus_60, 0)
    );
    assert_eq!(fp_op("fmsub", a, b, a), (two_to_minus_60, 0));
    assert_eq!(
        fp_op("fnmadd", a, b | bits::NEG_ZERO, a).0,
        two_to_minus_60 | bits::NEG_ZERO
    );
    assert_eq!(fp_op("fnmsub", a, b, a).0, two_to_minus_60 | bits::NEG_ZERO);
}

/// The single forms round their exact result once to single.
#[test]
fn single_arithmetic_rounds_to_single() {
    use bits::*;
    // 1 + 2^-24 × (1 + 2^-23) is above the midpoint between 1 and 1 + 2^-23, so it rounds up;
    // without the rounding to single it would stay 0x3FF0_0000_1000_0020.
    let above = 0x3E70_0000_2000_0000;
    assert_eq!(fp_op("fadds", ONE, above, 0), (0x3FF0_0000_2000_0000, 0));
    assert_eq!(
        fp_op("fsubs", ONE, above | NEG_ZERO, 0),
        (0x3FF0_0000_2000_0000, 0)
    );
    // (1 + 2^-12)^2 = 1 + 2^-11 + 2^-24 ties to the even 1 + 2^-11.
    let a = 0x3FF0_0100_0000_0000;
    assert_eq!(fp_op("fmuls", a, 0, a), (0x3FF0_0200_0000_0000, 0));
    // 1/3 and sqrt(2) as singles, 0x3EAAAAAB and 0x3FB504F3, widened.
    assert_eq!(fp_op("fdivs", ONE, THREE, 0), (0x3FD5_5555_6000_0000, 0));
    assert_eq!(fp_op("fsqrts", 0, TWO, 0), (0x3FF6_A09E_6000_0000, 0));
}

/// The fused single forms round once: (1 + 2^-12)^2 + 2^-80 is just above a midpoint between two
/// singles, where a double fma would land exactly and tie to even (see the runtime's tests).
#[test]
fn fused_single_arithmetic_rounds_once() {
    let a = 0x3FF0_0100_0000_0000; // 1 + 2^-12
    let c = 0x3FF0_0300_0000_0000; // 1 + 3 × 2^-12
    let tiny = 0x3AF0_0000_0000_0000; // 2^-80
    let up = 0x3FF0_0200_2000_0000; // 1 + 2^-11 + 2^-23
    let down = 0x3FF0_0400_2000_0000; // 1 + 2^-10 + 2^-23
    assert_eq!(fp_op("fmadds", a, tiny, a), (up, 0));
    assert_eq!(fp_op("fmsubs", a, tiny, c), (down, 0));
    assert_eq!(fp_op("fnmadds", a, tiny, a), (up | bits::NEG_ZERO, 0));
    assert_eq!(
        fp_op("fnmsubs", a, tiny | bits::NEG_ZERO, a),
        (up | bits::NEG_ZERO, 0)
    );
}

#[test]
fn rounding_and_conversions_follow_appendix_a() {
    use bits::*;
    // frsp: 1 + 2^-24 ties to 1; one ulp more rounds to 1 + 2^-23.
    assert_eq!(fp_op("frsp", 0, 0x3FF0_0000_1000_0000, 0), (ONE, 0));
    assert_eq!(
        fp_op("frsp", 0, 0x3FF0_0000_1000_0001, 0),
        (0x3FF0_0000_2000_0000, 0)
    );
    let cvi = 0xA000_0100; // FX, VX and VXCVI
    // fctiw rounds 2.5 to the even 2; a NaN gives the smallest word, sign-extended, not 0.
    assert_eq!(fp_op("fctiw", 0, 0x4004_0000_0000_0000, 0), (2, 0));
    assert_eq!(fp_op("fctiw", 0, QNAN_B, 0), (0xFFFF_FFFF_8000_0000, cvi));
    assert_eq!(fp_op("fctiwz", 0, QNAN_B, 0), (0xFFFF_FFFF_8000_0000, cvi));
    // The signaling NaN also sets VXSNAN.
    assert_eq!(
        fp_op("fctiwz", 0, SNAN, 0),
        (0xFFFF_FFFF_8000_0000, cvi | 0x0100_0000)
    );
    // -2.9 truncates to -2, sign-extended into the high word.
    assert_eq!(
        fp_op("fctiwz", 0, 0xC007_3333_3333_3333, 0),
        (0xFFFF_FFFF_FFFF_FFFE, 0)
    );
    assert_eq!(
        fp_op("fctid", 0, 0x400C_0000_0000_0000, 0),
        (4, 0),
        "3.5 ties to 4"
    );
    assert_eq!(fp_op("fctidz", 0, NEG_INF, 0), (0x8000_0000_0000_0000, cvi));
    assert_eq!(
        fp_op("fcfid", 0, u64::MAX, 0),
        (0xBFF0_0000_0000_0000, 0),
        "-1"
    );
}

/// A record form copies FPSCR bits 0:3 into CR1: after 1/0, FX (Book I 2.3.1).
#[test]
fn a_floating_point_record_form_sets_cr1_from_the_fpscr() {
    run_fp(
        "fp_ops",
        fp_op_entry("fdiv."),
        |ctx, _| {
            ctx.f[2] = 1.0;
            ctx.f[3] = 0.0;
            ctx.cr = ferrum_runtime::Cr::from_u32(0x0F00_0000);
        },
        |ctx, _| {
            assert_eq!(ctx.f[1], f64::INFINITY);
            assert_eq!(ctx.cr.to_u32(), 0x0800_0000, "FX, and no FEX, VX or OX");
        },
    );
}

/// `fcmpu` and `fcmpo` order with NaNs unordered and ±0 equal; `fcmpo` with a NaN is invalid.
#[test]
fn floating_point_compares_have_an_unordered_result() {
    let compare = |a: f64, b: f64| {
        let mut out = (0, 0, 0);
        run_fp(
            "fp_compare",
            Synthetic::entry(0),
            |ctx, _| {
                ctx.f[2] = a;
                ctx.f[3] = b;
            },
            |ctx, _| out = (ctx.cr.field(1), ctx.cr.field(6), ctx.fpscr.to_u32()),
        );
        out
    };
    // FPCC follows the last compare: FL, FE or FU in bits 16:19.
    assert_eq!(compare(1.0, 2.0), (0b1000, 0b1000, 0x0000_8000));
    assert_eq!(compare(2.0, 1.0), (0b0100, 0b0100, 0x0000_4000));
    assert_eq!(compare(0.0, -0.0), (0b0010, 0b0010, 0x0000_2000));
    // Unordered, and fcmpo sets VXVC, so VX and FX too.
    let nan = f64::from_bits(bits::QNAN_B);
    assert_eq!(compare(nan, 1.0), (0b0001, 0b0001, 0xA008_1000));
}

/// The FPSCR instructions in a row, each value worked out from Book I 4.2.2 and 4.6.8.
#[test]
fn the_fpscr_instructions_write_and_read_the_register() {
    run_fp(
        "fpscr",
        Synthetic::entry(0),
        |ctx, _| ctx.f[3] = f64::from_bits(0xFFFF_FFFF_0000_0008),
        |ctx, _| {
            // mtfsfi 6, 0xF sets VE OE UE ZE (0xF0); mtfsb0 25 clears OE (0xB0); mtfsb1 7 sets
            // VXSNAN, which is new, so FX, and VX, and FEX since VE is set: 0xE10000B0.
            assert_eq!(ctx.f[1].to_bits(), 0x0000_0000_E100_00B0, "mffs");
            // mcrfs cr2, 1 copies UX ZX XX VXSNAN (0b0001) and clears VXSNAN, so VX and FEX.
            assert_eq!(ctx.cr.field(2), 0b0001);
            // mtfsf 0x81 writes field 0 (FX goes) and field 7 (XE) from the low word.
            assert_eq!(ctx.f[2].to_bits(), 0x0000_0000_0000_00B8, "mffs");
            assert_eq!(ctx.fpscr.to_u32(), 0x0000_00B8);
        },
    );
}

/// `bl __savefpr_29` and `bl __restfpr_29` are inlined: f29 to f31 go to the stack and come back.
#[test]
fn fpr_save_and_restore_routines_are_inlined() {
    let saved = [
        0x2929_2929_2929_2929u64,
        0x3030_3030_3030_3030,
        0x3131_3131_3131_3131,
    ];
    run_fp(
        "fpr_save_restore",
        Synthetic::entry(38),
        |ctx, _| {
            ctx.f[1] = 1.0;
            for (n, value) in saved.iter().enumerate() {
                ctx.f[29 + n] = f64::from_bits(*value);
            }
        },
        |ctx, mem| {
            let restored: Vec<u64> = (29..32).map(|n| ctx.f[n].to_bits()).collect();
            assert_eq!(restored, saved, "restored");
            assert_eq!(ctx.lr, SENTINEL_LR);
            // __savefpr_29 stores f29 at -0x18(r12), with r12 = r1, and the rest above it.
            for (n, value) in saved.iter().enumerate() {
                let slot = STACK_BASE - 0x18 + 8 * n as u32;
                assert_eq!(mem.read_u64(slot), *value, "f{}", 29 + n);
            }
            assert_eq!(mem.read_u64(STACK_BASE - 0x20), 0, "f28 was not saved");
        },
    );
}

/// Runs the instruction `name` of `vector_ops` after `setup` on a fresh context and the reset
/// memory, and returns the context afterwards.
fn vec_run(name: &str, setup: impl FnOnce(&mut PpcContext, &Memory)) -> PpcContext {
    let mut out = None;
    run_fp("vector_ops", vector_op_entry(name), setup, |ctx, _| {
        out = Some(ctx.clone())
    });
    out.unwrap()
}

/// Runs the register instruction `name` of `vector_ops` with vA = `a`, vB = `b`, vC = `c` and vD =
/// `d` (v2, v3, v4 and v1, or v64, v127, v4 and v100 for the VMX128 forms), and returns vD, the
/// VSCR and CR6.
fn vec_op(name: &str, a: V128, b: V128, c: V128, d: V128) -> (V128, Vscr, u8) {
    let ctx = vec_run(name, |ctx, _| {
        (ctx.v[1], ctx.v[2], ctx.v[3], ctx.v[4]) = (d, a, b, c);
        (ctx.v[100], ctx.v[64], ctx.v[127]) = (d, a, b);
    });
    let vd = if name.contains("128") { 100 } else { 1 };
    (ctx.v[vd], ctx.vscr, ctx.cr.field(6))
}

/// The four words as a vector.
fn vw(words: [u32; 4]) -> V128 {
    V128(words)
}

/// The inputs of the integer table: vA, vB and vC.
const VEC_A: [u32; 4] = [0x80FF_7F01, 0x0002_FFFE, 0x7FFF_8000, 0x1234_5678];
const VEC_B: [u32; 4] = [0x017F_80FF, 0xFFFE_0003, 0x0001_8001, 0x9ABC_DEF0];
const VEC_C: [u32; 4] = [0x0001_0203, 0x0405_0607, 0x0809_0A0B, 0x0C0D_0E0F];

/// The integer instructions, and the halfword unpacks of VMX128, against values computed from the
/// definitions of Book I chapter 6 (Power ISA v3.1C) with an independent model in Python: exact
/// integer arithmetic per element, then wrapping or clamping as each definition says. The flag is
/// whether the instruction saturates on these inputs and so sets SAT.
#[test]
fn vector_integer_instructions_follow_the_isa() {
    let table: &[(&str, [u32; 4], bool)] = &[
        (
            "vaddubm",
            [0x817E_FF00, 0xFF00_FF01, 0x7F00_0001, 0xACF0_3468],
            false,
        ),
        (
            "vsububm",
            [0x7F80_FF02, 0x0104_FFFB, 0x7FFE_00FF, 0x7878_7888],
            false,
        ),
        (
            "vaddubs",
            [0x81FF_FFFF, 0xFFFF_FFFF, 0x7FFF_FF01, 0xACF0_FFFF],
            true,
        ),
        (
            "vaddsbs",
            [0x817E_FF00, 0xFF00_FF01, 0x7F00_8001, 0xACF0_3468],
            true,
        ),
        (
            "vsububs",
            [0x7F80_0000, 0x0000_FFFB, 0x7FFE_0000, 0x0000_0000],
            true,
        ),
        (
            "vsubsbs",
            [0x8080_7F02, 0x0104_FFFB, 0x7FFE_00FF, 0x7878_787F],
            true,
        ),
        (
            "vavgub",
            [0x41BF_8080, 0x8080_8081, 0x4080_8001, 0x5678_9AB4],
            false,
        ),
        (
            "vavgsb",
            [0xC13F_0000, 0x0000_0001, 0x4000_8001, 0xD6F8_1A34],
            false,
        ),
        (
            "vmaxub",
            [0x80FF_80FF, 0xFFFE_FFFE, 0x7FFF_8001, 0x9ABC_DEF0],
            false,
        ),
        (
            "vmaxsb",
            [0x017F_7F01, 0x0002_0003, 0x7F01_8001, 0x1234_5678],
            false,
        ),
        (
            "vminub",
            [0x017F_7F01, 0x0002_0003, 0x0001_8000, 0x1234_5678],
            false,
        ),
        (
            "vminsb",
            [0x80FF_80FF, 0xFFFE_FFFE, 0x00FF_8000, 0x9ABC_DEF0],
            false,
        ),
        (
            "vrlb",
            [0x01FF_7F80, 0x0080_FFF7, 0x7FFF_8000, 0x4843_9578],
            false,
        ),
        (
            "vslb",
            [0x0080_7F80, 0x0080_FFF0, 0x7FFE_8000, 0x4840_8078],
            false,
        ),
        (
            "vsrb",
            [0x4001_7F00, 0x0000_FF1F, 0x7F7F_8000, 0x0403_0178],
            false,
        ),
        (
            "vsrab",
            [0xC0FF_7F00, 0x0000_FFFF, 0x7FFF_8000, 0x0403_0178],
            false,
        ),
        (
            "vcmpequb",
            [0x0000_0000, 0x0000_0000, 0x0000_FF00, 0x0000_0000],
            false,
        ),
        (
            "vcmpgtub",
            [0xFFFF_0000, 0x0000_FFFF, 0xFFFF_0000, 0x0000_0000],
            false,
        ),
        (
            "vcmpgtsb",
            [0x0000_FFFF, 0xFFFF_0000, 0xFF00_0000, 0xFFFF_FFFF],
            false,
        ),
        (
            "vadduhm",
            [0x827E_0000, 0x0000_0001, 0x8000_0001, 0xACF0_3568],
            false,
        ),
        (
            "vsubuhm",
            [0x7F80_FE02, 0x0004_FFFB, 0x7FFE_FFFF, 0x7778_7788],
            false,
        ),
        (
            "vadduhs",
            [0x827E_FFFF, 0xFFFF_FFFF, 0x8000_FFFF, 0xACF0_FFFF],
            true,
        ),
        (
            "vaddshs",
            [0x827E_0000, 0x0000_0001, 0x7FFF_8000, 0xACF0_3568],
            true,
        ),
        (
            "vsubuhs",
            [0x7F80_0000, 0x0000_FFFB, 0x7FFE_0000, 0x0000_0000],
            true,
        ),
        (
            "vsubshs",
            [0x8000_7FFF, 0x0004_FFFB, 0x7FFE_FFFF, 0x7778_7788],
            true,
        ),
        (
            "vavguh",
            [0x413F_8000, 0x8000_8001, 0x4000_8001, 0x5678_9AB4],
            false,
        ),
        (
            "vavgsh",
            [0xC13F_0000, 0x0000_0001, 0x4000_8001, 0xD678_1AB4],
            false,
        ),
        (
            "vmaxuh",
            [0x80FF_80FF, 0xFFFE_FFFE, 0x7FFF_8001, 0x9ABC_DEF0],
            false,
        ),
        (
            "vmaxsh",
            [0x017F_7F01, 0x0002_0003, 0x7FFF_8001, 0x1234_5678],
            false,
        ),
        (
            "vminuh",
            [0x017F_7F01, 0x0002_0003, 0x0001_8000, 0x1234_5678],
            false,
        ),
        (
            "vminsh",
            [0x80FF_80FF, 0xFFFE_FFFE, 0x0001_8000, 0x9ABC_DEF0],
            false,
        ),
        (
            "vrlh",
            [0xC07F_BF80, 0x8000_FFF7, 0xFFFE_0001, 0x4123_5678],
            false,
        ),
        (
            "vslh",
            [0x8000_8000, 0x8000_FFF0, 0xFFFE_0000, 0x4000_5678],
            false,
        ),
        (
            "vsrh",
            [0x0001_0000, 0x0000_1FFF, 0x3FFF_4000, 0x0001_5678],
            false,
        ),
        (
            "vsrah",
            [0xFFFF_0000, 0x0000_FFFF, 0x3FFF_C000, 0x0001_5678],
            false,
        ),
        (
            "vcmpequh",
            [0x0000_0000, 0x0000_0000, 0x0000_0000, 0x0000_0000],
            false,
        ),
        (
            "vcmpgtuh",
            [0xFFFF_0000, 0x0000_FFFF, 0xFFFF_0000, 0x0000_0000],
            false,
        ),
        (
            "vcmpgtsh",
            [0x0000_FFFF, 0xFFFF_0000, 0xFFFF_0000, 0xFFFF_FFFF],
            false,
        ),
        (
            "vadduwm",
            [0x827F_0000, 0x0001_0001, 0x8001_0001, 0xACF1_3568],
            false,
        ),
        (
            "vsubuwm",
            [0x7F7F_FE02, 0x0004_FFFB, 0x7FFD_FFFF, 0x7777_7788],
            false,
        ),
        (
            "vadduws",
            [0x827F_0000, 0xFFFF_FFFF, 0x8001_0001, 0xACF1_3568],
            true,
        ),
        (
            "vaddsws",
            [0x827F_0000, 0x0001_0001, 0x7FFF_FFFF, 0xACF1_3568],
            true,
        ),
        (
            "vsubuws",
            [0x7F7F_FE02, 0x0000_0000, 0x7FFD_FFFF, 0x0000_0000],
            true,
        ),
        (
            "vsubsws",
            [0x8000_0000, 0x0004_FFFB, 0x7FFD_FFFF, 0x7777_7788],
            true,
        ),
        (
            "vavguw",
            [0x413F_8000, 0x8000_8001, 0x4000_8001, 0x5678_9AB4],
            false,
        ),
        (
            "vavgsw",
            [0xC13F_8000, 0x0000_8001, 0x4000_8001, 0xD678_9AB4],
            false,
        ),
        (
            "vmaxuw",
            [0x80FF_7F01, 0xFFFE_0003, 0x7FFF_8000, 0x9ABC_DEF0],
            false,
        ),
        (
            "vmaxsw",
            [0x017F_80FF, 0x0002_FFFE, 0x7FFF_8000, 0x1234_5678],
            false,
        ),
        (
            "vminuw",
            [0x017F_80FF, 0x0002_FFFE, 0x0001_8001, 0x1234_5678],
            false,
        ),
        (
            "vminsw",
            [0x80FF_7F01, 0xFFFE_0003, 0x0001_8001, 0x9ABC_DEF0],
            false,
        ),
        (
            "vrlw",
            [0xC07F_BF80, 0x0017_FFF0, 0xFFFF_0000, 0x5678_1234],
            false,
        ),
        (
            "vslw",
            [0x8000_0000, 0x0017_FFF0, 0xFFFF_0000, 0x5678_0000],
            false,
        ),
        (
            "vsrw",
            [0x0000_0001, 0x0000_5FFF, 0x3FFF_C000, 0x0000_1234],
            false,
        ),
        (
            "vsraw",
            [0xFFFF_FFFF, 0x0000_5FFF, 0x3FFF_C000, 0x0000_1234],
            false,
        ),
        (
            "vcmpequw",
            [0x0000_0000, 0x0000_0000, 0x0000_0000, 0x0000_0000],
            false,
        ),
        (
            "vcmpgtuw",
            [0xFFFF_FFFF, 0x0000_0000, 0xFFFF_FFFF, 0x0000_0000],
            false,
        ),
        (
            "vcmpgtsw",
            [0x0000_0000, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF],
            false,
        ),
        (
            "vaddcuw",
            [0x0000_0000, 0x0000_0001, 0x0000_0000, 0x0000_0000],
            false,
        ),
        (
            "vsubcuw",
            [0x0000_0001, 0x0000_0000, 0x0000_0001, 0x0000_0000],
            false,
        ),
        (
            "vnor",
            [0x7E00_0000, 0x0001_0000, 0x8000_7FFE, 0x6543_2107],
            false,
        ),
        (
            "vmuleub",
            [0x0080_3F80, 0x0000_0000, 0x0000_4000, 0x0AD4_4A94],
            false,
        ),
        (
            "vmuleuh",
            [0x00C0_FD81, 0x0001_FFFC, 0x0000_7FFF, 0x0B00_A630],
            false,
        ),
        (
            "vmulesb",
            [0xFF80_C080, 0x0000_0000, 0x0000_4000, 0xF8D4_F494],
            false,
        ),
        (
            "vmulesh",
            [0xFF41_FD81, 0xFFFF_FFFC, 0x0000_7FFF, 0xF8CC_A630],
            false,
        ),
        (
            "vmuloub",
            [0x7E81_00FF, 0x01FC_02FA, 0x00FF_0000, 0x2630_7080],
            false,
        ),
        (
            "vmulouh",
            [0x3FFF_01FF, 0x0002_FFFA, 0x4000_8000, 0x4B4D_2080],
            false,
        ),
        (
            "vmulosb",
            [0xFF81_FFFF, 0xFFFC_FFFA, 0xFFFF_0000, 0xF230_F880],
            false,
        ),
        (
            "vmulosh",
            [0xC0FE_01FF, 0xFFFF_FFFA, 0x3FFF_8000, 0xF4D5_2080],
            false,
        ),
        (
            "vmhaddshs",
            [0xFE84_83FF, 0x0404_0606, 0x0809_7FFF, 0xFDA6_F7B9],
            true,
        ),
        (
            "vmhraddshs",
            [0xFE85_83FF, 0x0405_0607, 0x080A_7FFF, 0xFDA6_F7B9],
            true,
        ),
        (
            "vmladduhm",
            [0xFD82_0402, 0x0401_0601, 0x8808_8A0B, 0xB23D_2E8F],
            false,
        ),
        (
            "vmsumubm",
            [0x0001_C183, 0x0405_0AFD, 0x0809_4B0A, 0x0C0D_FA27],
            false,
        ),
        (
            "vmsummbm",
            [0x0001_4183, 0x0405_07FD, 0x0808_CA0A, 0x0C0D_FA27],
            false,
        ),
        (
            "vmsumuhm",
            [0x40C1_0183, 0x040A_05FD, 0x480A_0A0A, 0x625A_D4BF],
            false,
        ),
        (
            "vmsumuhs",
            [0x40C1_0183, 0x040A_05FD, 0x480A_0A0A, 0x625A_D4BF],
            false,
        ),
        (
            "vmsumshm",
            [0xC041_0183, 0x0405_05FD, 0x4809_0A0A, 0xF9AE_D4BF],
            false,
        ),
        (
            "vmsumshs",
            [0xC041_0183, 0x0405_05FD, 0x4809_0A0A, 0xF9AE_D4BF],
            false,
        ),
        (
            "vsumsws",
            [0x0000_0000, 0x0000_0000, 0x0000_0000, 0xADF3_3467],
            false,
        ),
        (
            "vsum2sws",
            [0x0000_0000, 0x8100_7F02, 0x0000_0000, 0x2CF0_B568],
            false,
        ),
        (
            "vsum4ubs",
            [0x017F_82FE, 0xFFFE_0202, 0x0001_81FF, 0x9ABC_E004],
            false,
        ),
        (
            "vsum4sbs",
            [0x017F_80FE, 0xFFFE_0002, 0x0001_7FFF, 0x9ABC_E004],
            false,
        ),
        (
            "vsum4shs",
            [0x017F_80FF, 0xFFFE_0003, 0x0001_8000, 0x9ABD_479C],
            false,
        ),
        (
            "vpkpx",
            [0x7DE0_03FF, 0xFE00_194F, 0xBE1F_FC00, 0x0200_5F7E],
            false,
        ),
        (
            "vupkhpx",
            [0x0000_0B1F, 0xFF00_071F, 0xFF1F_1F1E, 0x0000_0003],
            false,
        ),
        (
            "vupklpx",
            [0x0000_0001, 0xFF00_0001, 0xFF06_151C, 0xFF17_1710],
            false,
        ),
        (
            "vupkhsh",
            [0x0000_017F, 0xFFFF_80FF, 0xFFFF_FFFE, 0x0000_0003],
            false,
        ),
        (
            "vupklsh",
            [0x0000_0001, 0xFFFF_8001, 0xFFFF_9ABC, 0xFFFF_DEF0],
            false,
        ),
        (
            "vpkuhum",
            [0xFF01_02FE, 0xFF00_3478, 0x7FFF_FE03, 0x0101_BCF0],
            false,
        ),
        (
            "vupkhsh128",
            [0x0000_017F, 0xFFFF_80FF, 0xFFFF_FFFE, 0x0000_0003],
            false,
        ),
        (
            "vupklsh128",
            [0x0000_0001, 0xFFFF_8001, 0xFFFF_9ABC, 0xFFFF_DEF0],
            false,
        ),
    ];
    let model: BTreeMap<&str, ([u32; 4], bool)> = table
        .iter()
        .map(|&(name, words, sat)| (name, (words, sat)))
        .collect();
    for &(name, expected, saturates) in table {
        let (r, vscr, _) = vec_op(name, vw(VEC_A), vw(VEC_B), vw(VEC_C), vw([0xDDDD_DDDD; 4]));
        assert_eq!(r, vw(expected), "{name}");
        assert_eq!(vscr.sat(), saturates, "{name}: SAT");
    }
    // The VMX128 forms that widen a VMX one give the same result.
    for (wide, narrow) in [
        ("vrlw128", "vrlw"),
        ("vnor128", "vnor"),
        ("vslw128", "vslw"),
        ("vsraw128", "vsraw"),
        ("vsrw128", "vsrw"),
        ("vpkuhum128", "vpkuhum"),
    ] {
        let (r, _, _) = vec_op(wide, vw(VEC_A), vw(VEC_B), vw(VEC_C), V128::ZERO);
        assert_eq!(r, vw(model[narrow].0), "{wide}");
    }
}

/// Singles used by the vector programs.
mod single {
    pub const ONE: u32 = 0x3F80_0000;
    pub const TWO: u32 = 0x4000_0000;
    pub const THREE: u32 = 0x4040_0000;
    pub const FOUR: u32 = 0x4080_0000;
    pub const NEG_ZERO: u32 = 0x8000_0000;
    pub const NEG_INF: u32 = 0xFF80_0000;
    pub const QNAN_B: u32 = 0x7FC0_00BB;
    pub const QNAN_C: u32 = 0xFFC0_00CC;
    pub const DENORMAL: u32 = 0x0000_0001;
}

/// The record forms set CR6 to all-true or all-false; Rc = 0 leaves it alone.
#[test]
fn vector_compare_records_set_cr6() {
    let ones = vw([u32::MAX; 4]);
    let twos = vw([0x0202_0202; 4]);
    for name in [
        "vcmpgtub.",
        "vcmpgtuh.",
        "vcmpgtuw.",
        "vcmpgtsb.",
        "vcmpgtsh.",
        "vcmpgtsw.",
    ] {
        // 2 > 1 everywhere, signed or not; 1 > 2 nowhere; and a mix.
        let one = vw([0x0101_0101; 4]);
        assert_eq!(
            vec_op(name, twos, one, V128::ZERO, V128::ZERO).2,
            0b1000,
            "{name}"
        );
        assert_eq!(
            vec_op(name, one, twos, V128::ZERO, V128::ZERO).2,
            0b0010,
            "{name}"
        );
        let mixed = vw([0x0202_0202, 0, 0, 0]);
        assert_eq!(
            vec_op(name, mixed, one, V128::ZERO, V128::ZERO).2,
            0,
            "{name}"
        );
    }
    for name in ["vcmpequb.", "vcmpequh.", "vcmpequw.", "vcmpequw128."] {
        assert_eq!(
            vec_op(name, twos, twos, V128::ZERO, V128::ZERO).2,
            0b1000,
            "{name}"
        );
        assert_eq!(
            vec_op(name, twos, ones, V128::ZERO, V128::ZERO).2,
            0b0010,
            "{name}"
        );
    }
    use single::*;
    // 1, 2, NaN and -0 against 1, 1, 1 and +0.
    let a = vw([ONE, TWO, QNAN_B, NEG_ZERO]);
    let b = vw([ONE, ONE, ONE, 0]);
    let all = |x: u32| vw([x; 4]);
    for (name, mixed) in [
        ("vcmpgefp.", [u32::MAX, u32::MAX, 0, u32::MAX]),
        ("vcmpgtfp.", [0, u32::MAX, 0, 0]),
        ("vcmpgefp128.", [u32::MAX, u32::MAX, 0, u32::MAX]),
        ("vcmpgtfp128.", [0, u32::MAX, 0, 0]),
    ] {
        assert_eq!(
            vec_op(name, a, b, V128::ZERO, V128::ZERO),
            (vw(mixed), Vscr::default(), 0)
        );
        assert_eq!(
            vec_op(name, all(TWO), all(ONE), V128::ZERO, V128::ZERO).2,
            0b1000
        );
        assert_eq!(
            vec_op(name, all(QNAN_B), all(ONE), V128::ZERO, V128::ZERO).2,
            0b0010
        );
    }
    // The forms without Rc: CR6 keeps what it held.
    for (name, expected) in [
        ("vcmpeqfp", [u32::MAX, 0, 0, u32::MAX]),
        ("vcmpeqfp128", [u32::MAX, 0, 0, u32::MAX]),
        ("vcmpgefp", [u32::MAX, u32::MAX, 0, u32::MAX]),
        ("vcmpgtfp", [0, u32::MAX, 0, 0]),
        ("vcmpbfp", [0, 0x8000_0000, 0xC000_0000, 0]),
        ("vcmpbfp128", [0, 0x8000_0000, 0xC000_0000, 0]),
    ] {
        let ctx = vec_run(name, |ctx, _| {
            (ctx.v[2], ctx.v[3], ctx.v[64], ctx.v[127]) = (a, b, a, b);
            ctx.cr.set_field(6, 0b0101);
        });
        let vd = if name.contains("128") { 100 } else { 1 };
        assert_eq!(ctx.v[vd], vw(expected), "{name}");
        assert_eq!(ctx.cr.field(6), 0b0101, "{name} leaves CR6 alone");
    }
}

/// `mtvscr` and `mfvscr` move the VSCR through word 3, and SAT stays set until `mtvscr`.
#[test]
fn the_vscr_moves_through_word_3() {
    let ctx = vec_run("mfvscr", |ctx, _| ctx.vscr.saturate_if(true));
    assert_eq!(ctx.v[1], vw([0, 0, 0, 0x0001_0001]));
    let ctx = vec_run("mtvscr", |ctx, _| {
        ctx.vscr.saturate_if(true);
        ctx.v[3] = vw([u32::MAX, u32::MAX, u32::MAX, 0x0001_0000]);
    });
    assert_eq!(ctx.vscr.to_u32(), 0x0001_0000, "SAT cleared, NJ kept");
    // A saturating instruction that does not saturate leaves SAT set.
    let ctx = vec_run("vaddubs", |ctx, _| ctx.vscr.saturate_if(true));
    assert!(ctx.vscr.sat());
}

/// Non-Java mode flushes denormal inputs and tiny results to zeros of their sign; with NJ
/// cleared, as an `mtvscr` of zero leaves it, they are kept.
#[test]
fn vector_floating_point_honors_nj() {
    use single::*;
    // -1.5 Ã— 2^-126 + 2^-126 is -2^-127, a denormal.
    let a = vw([DENORMAL, DENORMAL | NEG_ZERO, ONE, 0x0080_0000]);
    let b = vw([0, NEG_ZERO, DENORMAL, 0x80C0_0000]);
    let (r, _, _) = vec_op("vaddfp", a, b, V128::ZERO, V128::ZERO);
    assert_eq!(r, vw([0, NEG_ZERO, ONE, NEG_ZERO]));
    let ctx = vec_run("vaddfp", |ctx, _| {
        (ctx.v[2], ctx.v[3]) = (a, b);
        ctx.vscr.mtvscr(V128::ZERO);
    });
    assert_eq!(
        ctx.v[1],
        vw([DENORMAL, DENORMAL | NEG_ZERO, ONE, 0x8040_0000])
    );
    // A denormal input equals zero only in non-Java mode; no result to flush here.
    let (a, b) = (vw([DENORMAL; 4]), V128::ZERO);
    let (r, _, _) = vec_op("vcmpeqfp", a, b, V128::ZERO, V128::ZERO);
    assert_eq!(r, vw([u32::MAX; 4]));
    let ctx = vec_run("vcmpeqfp", |ctx, _| {
        (ctx.v[2], ctx.v[3]) = (a, b);
        ctx.vscr.mtvscr(V128::ZERO);
    });
    assert_eq!(ctx.v[1], V128::ZERO);
}

/// The floating-point instructions the suite leaves out, with values worked out from the ISA:
/// exact arithmetic on small values, and the estimates' correctly rounded results (2^0.25 from
/// 60-digit decimal arithmetic).
#[test]
fn vector_floating_point_instructions_follow_the_isa() {
    use single::*;
    let op = |name: &str, a: [u32; 4], b: [u32; 4], c: [u32; 4]| {
        vec_op(name, vw(a), vw(b), vw(c), vw([ONE; 4])).0
    };
    let estimates = [FOUR, 0x3E80_0000, NEG_ZERO, 0x4100_0000]; // 4, 0.25, -0, 8
    for (name, expected) in [
        ("vrefp", [0x3E80_0000, FOUR, NEG_INF, 0x3E00_0000]),
        ("vrsqrtefp", [0x3F00_0000, TWO, NEG_INF, 0x3EB5_04F3]),
        ("vexptefp", [0x4180_0000, 0x3F98_37F0, ONE, 0x4380_0000]),
        ("vlogefp", [TWO, 0xC000_0000, NEG_INF, THREE]),
        ("vrefp128", [0x3E80_0000, FOUR, NEG_INF, 0x3E00_0000]),
        ("vrsqrtefp128", [0x3F00_0000, TWO, NEG_INF, 0x3EB5_04F3]),
        ("vexptefp128", [0x4180_0000, 0x3F98_37F0, ONE, 0x4380_0000]),
        ("vlogefp128", [TWO, 0xC000_0000, NEG_INF, THREE]),
    ] {
        assert_eq!(op(name, [0; 4], estimates, [0; 4]), vw(expected), "{name}");
    }
    let halves = [0x3FC0_0000, 0xC020_0000, 0x3F00_0000, 0xBF00_0000]; // 1.5, -2.5, 0.5, -0.5
    for (name, expected) in [
        ("vrfin", [TWO, 0xC000_0000, 0, NEG_ZERO]),
        ("vrfiz", [ONE, 0xC000_0000, 0, NEG_ZERO]),
        ("vrfip", [TWO, 0xC000_0000, ONE, NEG_ZERO]),
        ("vrfim", [ONE, 0xC040_0000, 0, 0xBF80_0000]),
        ("vrfin128", [TWO, 0xC000_0000, 0, NEG_ZERO]),
        ("vrfiz128", [ONE, 0xC000_0000, 0, NEG_ZERO]),
        ("vrfip128", [TWO, 0xC000_0000, ONE, NEG_ZERO]),
        ("vrfim128", [ONE, 0xC040_0000, 0, 0xBF80_0000]),
    ] {
        assert_eq!(op(name, [0; 4], halves, [0; 4]), vw(expected), "{name}");
    }
    // vmaddfp vD, vA, vC, vB is 2 Ã— 4 + 3; vnmsubfp is -(2 Ã— 4 - 3).
    let (two, three, four) = ([TWO; 4], [THREE; 4], [FOUR; 4]);
    assert_eq!(op("vmaddfp", two, three, four), vw([0x4130_0000; 4]));
    assert_eq!(op("vnmsubfp", two, three, four), vw([0xC0A0_0000; 4]));
    // A NaN in vB (the addend) ranks before one in vC (the multiplier).
    assert_eq!(
        op("vmaddfp", [ONE; 4], [QNAN_B; 4], [QNAN_C; 4]),
        vw([QNAN_B; 4])
    );
    // vmaxfp and vminfp quiet a signaling NaN of vA.
    assert_eq!(
        op("vmaxfp", [0x7F80_0001; 4], [ONE; 4], [0; 4]),
        vw([0x7FC0_0001; 4])
    );
    assert_eq!(
        op("vminfp", [0; 4], [NEG_ZERO; 4], [0; 4]),
        vw([NEG_ZERO; 4])
    );
}

/// The VMX128 floating-point forms that read vD: here vA = 2, vB = 3 and vD = 1.
#[test]
fn vmx128_multiply_adds_take_vd_in_its_role() {
    use single::*;
    let (a, b, d) = (vw([TWO; 4]), vw([THREE; 4]), vw([ONE; 4]));
    let r = |name: &str| vec_op(name, a, b, V128::ZERO, d).0;
    assert_eq!(r("vmulfp128"), vw([0x40C0_0000; 4]), "2 Ã— 3");
    assert_eq!(r("vmaddfp128"), vw([0x40E0_0000; 4]), "2 Ã— 3 + 1");
    assert_eq!(r("vmaddcfp128"), vw([0x40A0_0000; 4]), "2 Ã— 1 + 3");
    assert_eq!(r("vnmsubfp128"), vw([0xC0A0_0000; 4]), "-(2 Ã— 3 - 1)");
    // vsel128 selects with vD.
    let (a, b, d) = (
        vw([0x0F0F_0F0F; 4]),
        vw([0xF0F0_F0F0; 4]),
        vw([0xFF00_FF00; 4]),
    );
    assert_eq!(
        vec_op("vsel128", a, b, V128::ZERO, d).0,
        vw([0xF00F_F00F; 4])
    );
}

/// The conversions, with a scale of 1, saturating where the ISA says.
#[test]
fn vector_conversions_scale_and_saturate() {
    use single::*;
    let ints = vw([6, (-2i32) as u32, 1, 0]);
    let (r, _, _) = vec_op("vcsxwfp128", V128::ZERO, ints, V128::ZERO, V128::ZERO);
    assert_eq!(
        r,
        vw([THREE, 0xBF80_0000, 0x3F00_0000, 0]),
        "6, -2, 1, 0 halved"
    );
    // 0xFFFFFFFF / 2 = 2147483647.5 rounds to 2^31.
    let unsigned = vw([3, u32::MAX, 0, 1]);
    let expected = vw([0x3FC0_0000, 0x4F00_0000, 0, 0x3F00_0000]);
    assert_eq!(
        vec_op("vcfux", V128::ZERO, unsigned, V128::ZERO, V128::ZERO).0,
        expected
    );
    assert_eq!(
        vec_op("vcuxwfp128", V128::ZERO, unsigned, V128::ZERO, V128::ZERO).0,
        expected
    );
    // 1.5 Ã— 2 = 3; -1e10 and 2^30 Ã— 2 saturate; a NaN gives 0.
    let signed = vw([0x3FC0_0000, 0xD015_02F9, QNAN_B, 0x4E80_0000]);
    for name in ["vctsxs", "vcfpsxws128"] {
        let (r, vscr, _) = vec_op(name, V128::ZERO, signed, V128::ZERO, V128::ZERO);
        assert_eq!(r, vw([3, 0x8000_0000, 0, 0x7FFF_FFFF]), "{name}");
        assert!(vscr.sat(), "{name}");
        // Each bound sets SAT on its own: 2^30 × 2 above, -2^31 × 2 below.
        for (value, bound) in [(0x4E80_0000, 0x7FFF_FFFF), (0xCF00_0000, 0x8000_0000)] {
            let (r, vscr, _) = vec_op(name, V128::ZERO, vw([value; 4]), V128::ZERO, V128::ZERO);
            assert_eq!(
                (r, vscr.sat()),
                (vw([bound; 4]), true),
                "{name} of {value:#x}"
            );
        }
    }
    // 1.5 Ã— 2 = 3; -0.25 Ã— 2 truncates to 0 without saturating; -1 Ã— 2 and 2^31 Ã— 2 saturate.
    let values = vw([0x3FC0_0000, 0xBE80_0000, 0xBF80_0000, 0x4F00_0000]);
    for name in ["vctuxs", "vcfpuxws128"] {
        let (r, vscr, _) = vec_op(name, V128::ZERO, values, V128::ZERO, V128::ZERO);
        assert_eq!(r, vw([3, 0, 0, u32::MAX]), "{name}");
        assert!(vscr.sat(), "{name}");
        let (_, vscr, _) = vec_op(
            name,
            V128::ZERO,
            vw([0xBE80_0000; 4]),
            V128::ZERO,
            V128::ZERO,
        );
        assert!(!vscr.sat(), "{name}: -0.5 truncates to zero");
    }
}

/// The VMX128 permutes, shifts and splats the suite leaves out.
#[test]
fn vmx128_moves_follow_their_vmx_forms() {
    let (a, b) = (vw(VEC_A), vw(VEC_B));
    let r = |name: &str, c: V128| vec_op(name, a, b, c, V128::ZERO).0;
    // Byte 15 of vB is 0xF0: bits 121:124 are 14, so 14 bytes.
    assert_eq!(r("vslo128", V128::ZERO), vw([0x5678_0000, 0, 0, 0]));
    assert_eq!(r("vsro128", V128::ZERO), vw([0, 0, 0, 0x0000_80FF]));
    assert_eq!(
        r("vsldoi128", V128::ZERO),
        vw([VEC_A[1], VEC_A[2], VEC_A[3], VEC_B[0]])
    );
    assert_eq!(
        r("vmrghw128", V128::ZERO),
        vw([VEC_A[0], VEC_B[0], VEC_A[1], VEC_B[1]])
    );
    assert_eq!(
        r("vmrglw128", V128::ZERO),
        vw([VEC_A[2], VEC_B[2], VEC_A[3], VEC_B[3]])
    );
    // vperm128 with vC in v4: word 3 of vB reversed, word 0 of vA reversed, word 0 of vB, and
    // word 3 of vA reversed.
    let c = vw([0x1F1E_1D1C, 0x0302_0100, 0x1011_1213, 0x0F0E_0D0C]);
    assert_eq!(
        r("vperm128", c),
        vw([0xF0DE_BC9A, 0x017F_FF80, 0x017F_80FF, 0x7856_3412])
    );
    assert_eq!(r("vspltw128", V128::ZERO), vw([VEC_B[2]; 4]));
    assert_eq!(r("vspltisw128", V128::ZERO), vw([0xFFFF_FFFE; 4]));
}

/// The loads and stores the suite leaves out, at r3 + r4 with r3 at the data region, over bytes
/// 0x00, 0x01, ... there; stores write the bytes 0xA0 to 0xAF.
#[test]
fn vector_loads_and_stores_move_the_right_bytes() {
    use ferrum_harness::runner::DATA_BASE;
    let counting = |start: u8| V128::from_bytes(std::array::from_fn(|i| start + i as u8));
    let stored = counting(0xA0);
    let run = |name: &str, offset: u32| {
        let mut out = None;
        run_fp(
            "vector_ops",
            vector_op_entry(name),
            |ctx, mem| {
                let bytes: Vec<u8> = (0..=255u8).collect();
                mem.write_bytes(DATA_BASE, &bytes);
                ctx.r[3] = u64::from(DATA_BASE);
                ctx.r[4] = u64::from(offset);
                (ctx.v[1], ctx.v[100]) = (stored, stored);
            },
            |ctx, mem| {
                let mut bytes = [0; 256];
                mem.read_bytes(DATA_BASE, &mut bytes);
                out = Some((ctx.clone(), bytes));
            },
        );
        out.unwrap()
    };
    // The aligned loads clear the four low bits of EA.
    for (name, vd) in [("lvx", 1), ("lvxl", 1), ("lvx128", 100), ("lvxl128", 100)] {
        assert_eq!(run(name, 0x13).0.v[vd], counting(0x10), "{name}");
    }
    assert_eq!(
        run("lvebx", 0x25).0.v[1],
        counting(0x20),
        "the quadword holding EA"
    );
    // The aligned stores too, and they write nothing else.
    for (name, offset) in [
        ("stvx", 0x47),
        ("stvxl", 0x5F),
        ("stvx128", 0x6F),
        ("stvxl128", 0x7F),
    ] {
        let (_, bytes) = run(name, offset);
        let at = (offset & !15) as usize;
        let mut expected: Vec<u8> = (0..=255u8).collect();
        expected[at..at + 16].copy_from_slice(&stored.to_bytes());
        assert_eq!(bytes.as_slice(), expected.as_slice(), "{name}");
    }
    // The element stores write one element, at EA with its low bits cleared.
    for (name, offset, at, len) in [
        ("stvebx", 0x85, 0x85, 1),
        ("stvehx", 0x97, 0x96, 2),
        ("stvewx128", 0xAB, 0xA8, 4),
    ] {
        let (_, bytes) = run(name, offset);
        let mut expected: Vec<u8> = (0..=255u8).collect();
        expected[at..at + len].copy_from_slice(&stored.to_bytes()[at % 16..at % 16 + len]);
        assert_eq!(bytes.as_slice(), expected.as_slice(), "{name}");
    }
    // Left loads: EA to the end of its quadword; right loads: the start of the quadword up to EA.
    let left = V128([0x0B0C_0D0E, 0x0F00_0000, 0, 0]);
    let right = V128([0, 0x0010_1112, 0x1314_1516, 0x1718_191A]);
    for (name, vd, offset, expected) in [
        ("lvlxl", 1, 0x0B, left),
        ("lvlx128", 100, 0x0B, left),
        ("lvlxl128", 100, 0x0B, left),
        ("lvrxl", 1, 0x1B, right),
        ("lvrx128", 100, 0x1B, right),
        ("lvrxl128", 100, 0x1B, right),
        ("lvrx128", 100, 0x20, V128::ZERO),
    ] {
        assert_eq!(run(name, offset).0.v[vd], expected, "{name} at {offset:#x}");
    }
    // Left stores: the first bytes of vS from EA to the end of the quadword; right stores: the
    // last bytes up to EA.
    for (name, offset, at, from) in [
        ("stvlxl", 0xBC, 0xBC, 0),
        ("stvlx128", 0xBC, 0xBC, 0),
        ("stvlxl128", 0xBC, 0xBC, 0),
        ("stvrxl", 0xC3, 0xC0, 13),
        ("stvrx128", 0xC3, 0xC0, 13),
        ("stvrxl128", 0xC3, 0xC0, 13),
    ] {
        let (_, bytes) = run(name, offset);
        let mut expected: Vec<u8> = (0..=255u8).collect();
        let len = if from == 0 {
            16 - (offset % 16)
        } else {
            offset % 16
        } as usize;
        expected[at..at + len].copy_from_slice(&stored.to_bytes()[from..from + len]);
        assert_eq!(bytes.as_slice(), expected.as_slice(), "{name}");
    }
    assert_eq!(run("lvsl128", 0x13).0.v[100], counting(0x03));
    assert_eq!(run("lvsr128", 0x13).0.v[100], counting(0x0D));
    // The stream hints change nothing.
    for name in ["dst", "dstst", "dss"] {
        let (ctx, bytes) = run(name, 0x40);
        assert_eq!(bytes.to_vec(), (0..=255u8).collect::<Vec<_>>(), "{name}");
        assert_eq!((ctx.v[1], ctx.vscr), (stored, Vscr::default()), "{name}");
    }
}

/// `bl __savevmx_29`, `bl __savevmx_125` and the restores are inlined: v29 to v31 and v125 to
/// v127 go to the stack, through `stvx` and `stvx128`, and come back.
#[test]
fn vmx_save_and_restore_routines_are_inlined() {
    let value = |n: u32| V128([n, n + 1, n + 2, n + 3]);
    let registers = [29, 30, 31, 125, 126, 127];
    run_fp(
        "vmx_save_restore",
        Synthetic::entry(332),
        |ctx, _| {
            ctx.v[1] = V128([0xEEEE_EEEE; 4]);
            for n in registers {
                ctx.v[n] = value(n as u32 * 0x100);
            }
        },
        |ctx, mem| {
            for n in registers {
                assert_eq!(ctx.v[n], value(n as u32 * 0x100), "v{n} restored");
            }
            assert_eq!(ctx.lr, SENTINEL_LR);
            // v29 to v31 at r1 - 0x30 up; v125 to v127 at r1 - 0x200 - 0x30 up.
            for (k, n) in registers.iter().enumerate() {
                let base = if k < 3 {
                    STACK_BASE
                } else {
                    STACK_BASE - 0x200
                };
                let slot = base - 0x30 + 16 * (k as u32 % 3);
                assert_eq!(mem.read_v128(slot), value(*n as u32 * 0x100), "v{n}'s slot");
            }
            assert_eq!(
                mem.read_v128(STACK_BASE - 0x40),
                V128::ZERO,
                "v28 was not saved"
            );
        },
    );
}
