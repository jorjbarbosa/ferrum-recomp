// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! One generated Rust function per guest function: the code of its blocks, the branches that end
//! them, and calls, in a `loop { match pc }` body or, through [`crate::structured`], as structured
//! code.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::RangeInclusive;

use ferrum_analysis::{
    Block, Cfg, Code, Exit, Family, Flow, Function, Graph, Rules, SaveRestore, Structured, Target,
    branch_target, build, flow, links, structure,
};
use ferrum_decoder::{Insn, decode, format_at};

use crate::emit::{self, Emitter};
use crate::error::Error;
use crate::hooks::{Action, Hooks, MidAsm};
use crate::imports::Import;
use crate::sites::{self, SiteKind};
use crate::structured::{self, MAX_BRACE_DEPTH, brace_depth};

/// The `use` lines that generated functions need, for the module that holds them.
pub const PRELUDE: &str = "use ferrum_runtime::{ops, Kernels, Memory, PpcContext, Spr};\n";

/// The name of the generated function for the guest function at `addr`.
pub fn function_name(addr: u32) -> String {
    format!("sub_{addr:08x}")
}

/// The C runtime's `setjmp` and `longjmp`, from `[analysis] setjmp` and `longjmp`, which generated
/// code carries across frames by unwinding.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NonLocal {
    /// The guest's `setjmp`, which stays recompiled code; the functions that call it run their
    /// body under `catch_unwind`.
    pub setjmp: Option<u32>,
    /// The guest's `longjmp`, which is not generated: its calls and its table entry go to
    /// `ferrum_runtime::longjmp`.
    pub longjmp: Option<u32>,
}

/// How generated functions follow the guest's branches. A [`Program`] starts with a dispatcher;
/// `ferrum recomp` asks for structured code unless its config says otherwise.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ControlFlow {
    /// A loop over a `match` on the address of the next block.
    #[default]
    Dispatch,
    /// Labeled blocks, loops, `break`, `continue` and `if`, from the structured form of each
    /// function. A function that calls `setjmp`, or whose form fails its check or nests deeper than
    /// rustc can take, keeps the dispatcher.
    Structured,
}

/// What the generated functions of a program hold.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Statistics {
    /// How many instructions of each mnemonic the paths of the functions hold.
    pub opcodes: BTreeMap<&'static str, usize>,
    /// How many jump tables they resolve.
    pub jump_tables: usize,
    /// How many `bctr`s load CTR from a table that could not be resolved.
    pub unresolved_tables: usize,
    /// How many functions hold a cycle that several of their blocks enter, which the structured
    /// form reaches through a dispatch node.
    pub irreducible_functions: usize,
    /// How many dispatch nodes those cycles take, one per cycle.
    pub dispatch_nodes: usize,
    /// How many sites go to a dispatch node instead of an entry of its cycle.
    pub redirected_sites: usize,
    /// The functions whose structured form the check rejected, by entry, with why: bugs of the
    /// structuring, never of the guest code.
    pub rejected: Vec<(u32, String)>,
    /// The functions whose structured code would nest its braces deeper than generated code may,
    /// by entry, with how deep.
    pub deep: Vec<(u32, usize)>,
    /// How deep the braces of the deepest structured function nest.
    pub brace_depth: usize,
    /// How many functions structured code writes in structured form.
    pub structured_functions: usize,
    /// How many functions call `setjmp`, which structured code keeps in dispatch form.
    pub setjmp_functions: usize,
    /// How many functions the program was told to keep in dispatch form.
    pub listed_functions: usize,
}

/// The Rust path of the runtime's `longjmp`, which stands for the guest's.
const RUNTIME_LONGJMP: &str = "ferrum_runtime::longjmp";

/// The guest code to recompile, the functions in it, and its save and restore routines.
#[derive(Debug)]
pub struct Program<'a> {
    code: Code<'a>,
    functions: BTreeMap<u32, Function>,
    routines: &'a SaveRestore,
    rules: Rules,
    non_local: NonLocal,
    imports: Vec<Import>,
    /// The index in `imports` of the import whose thunk is at each address.
    thunks: BTreeMap<u32, usize>,
    hooks: Hooks,
    overridden: BTreeSet<u32>,
    midasm: BTreeMap<u32, Vec<MidAsm>>,
    trap_as_nop: bool,
    control_flow: ControlFlow,
    /// The functions kept in dispatch form whatever `control_flow` says.
    dispatch: BTreeSet<u32>,
}

impl<'a> Program<'a> {
    /// Describes a program: `functions` are the guest functions in `code`, and `routines` the save
    /// and restore routines that calls are inlined from, usually from
    /// [`ferrum_analysis::find_save_restore`].
    pub fn new(
        code: Code<'a>,
        functions: impl IntoIterator<Item = Function>,
        routines: &'a SaveRestore,
    ) -> Self {
        let functions = functions.into_iter().map(|f| (f.addr, f)).collect();
        Self {
            code,
            functions,
            routines,
            rules: Rules::default(),
            non_local: NonLocal::default(),
            imports: Vec::new(),
            thunks: BTreeMap::new(),
            hooks: Hooks::default(),
            overridden: BTreeSet::new(),
            midasm: BTreeMap::new(),
            trap_as_nop: false,
            control_flow: ControlFlow::Dispatch,
            dispatch: BTreeSet::new(),
        }
    }

    /// Wires the imports of the module: a call to the thunk of a function becomes a call to the
    /// kernel, and the workspace gets `imports.rs`.
    pub fn with_imports(mut self, imports: Vec<Import>) -> Self {
        self.thunks = imports
            .iter()
            .enumerate()
            .filter_map(|(index, import)| import.thunk.map(|thunk| (thunk, index)))
            .collect();
        self.imports = imports;
        self
    }

    /// Wires the hooks of the config. An overridden function joins the functions if it is not one
    /// already, and the target of a hook's jump starts a block.
    pub fn with_hooks(mut self, hooks: Hooks) -> Self {
        self.overridden = hooks.overrides.iter().map(|o| o.addr).collect();
        for &addr in &self.overridden {
            self.functions
                .entry(addr)
                .or_insert(Function { addr, size: 4 });
        }
        self.midasm = BTreeMap::new();
        for hook in &hooks.midasm {
            self.midasm.entry(hook.addr).or_default().push(hook.clone());
        }
        self.hooks = hooks;
        self.rules.joins.extend(self.hook_targets());
        self
    }

    /// Makes a trap whose condition holds a no-op instead of a panic
    /// (`[optimizations] trap_as_nop`).
    pub fn with_trap_as_nop(mut self, trap_as_nop: bool) -> Self {
        self.trap_as_nop = trap_as_nop;
        self
    }

    /// Generates the functions with `control_flow` (`[optimizations] control_flow`).
    pub fn with_control_flow(mut self, control_flow: ControlFlow) -> Self {
        self.control_flow = control_flow;
        self
    }

    /// Keeps the functions that start at `entries` in dispatch form under structured code
    /// (`[optimizations] dispatch`): a way around a bug of the structuring in one function.
    pub fn with_dispatch(mut self, entries: impl IntoIterator<Item = u32>) -> Self {
        self.dispatch = entries.into_iter().collect();
        self
    }

    /// Checks that a function starts at every entry of the list of functions to keep in dispatch
    /// form.
    pub fn check_dispatch(&self) -> Result<(), Error> {
        match self.dispatch.iter().find(|&&addr| !self.is_function(addr)) {
            Some(&addr) => Err(Error::NotAFunction { addr }),
            None => Ok(()),
        }
    }

    /// The addresses that the hooks' jumps go to.
    fn hook_targets(&self) -> Vec<u32> {
        self.hooks
            .midasm
            .iter()
            .filter_map(|hook| hook.action.target())
            .collect()
    }

    /// Wires the guest's `setjmp` and `longjmp`. `longjmp` joins the functions if it is not one
    /// already, so that the table has an entry for it, and the instruction after each call to
    /// `setjmp` starts a block, where a `longjmp` resumes.
    pub fn with_non_local(mut self, non_local: NonLocal) -> Self {
        self.rules.returns_twice.extend(non_local.setjmp);
        if let Some(longjmp) = non_local.longjmp {
            self.functions.entry(longjmp).or_insert(Function {
                addr: longjmp,
                size: 4,
            });
        }
        self.non_local = non_local;
        self
    }

    /// The Rust path of the function that the table holds for the guest function at `addr`: its
    /// generated function, or the runtime's `longjmp` for the guest's. An overridden function has
    /// none: the port puts its own in the table.
    pub fn table_path(&self, addr: u32) -> Option<String> {
        if self.overridden.contains(&addr) {
            None
        } else if self.non_local.longjmp == Some(addr) {
            Some(RUNTIME_LONGJMP.to_owned())
        } else {
            Some(function_name(addr))
        }
    }

    /// Builds the blocks of every function with `rules`, usually the ones discovery returned:
    /// the functions that never return and the counts of jump tables from the config.
    pub fn with_rules(mut self, mut rules: Rules) -> Self {
        rules.returns_twice.extend(self.non_local.setjmp);
        rules.joins.extend(self.hook_targets());
        self.rules = rules;
        self
    }

    /// Checks the mid-asm hooks against the code: each one has to be on a path of a function that
    /// is not overridden, not after a branch, and jump only inside its function.
    pub fn check_hooks(&self) -> Result<(), Error> {
        for hook in self.midasm.values().flatten() {
            let invalid = |why| Error::InvalidHook {
                addr: hook.addr,
                name: hook.name.clone(),
                why,
            };
            let mut reached = false;
            for &function in self.functions.values().filter(|f| f.contains(hook.addr)) {
                if self.overridden.contains(&function.addr) {
                    return Err(invalid("it lies in an overridden function"));
                }
                if self.non_local.longjmp == Some(function.addr) {
                    continue;
                }
                let cfg = self.blocks(function)?;
                let Some(&(at, insn)) = cfg
                    .blocks
                    .iter()
                    .flat_map(|block| &block.insns)
                    .find(|&&(at, _)| at == hook.addr)
                else {
                    continue;
                };
                reached = true;
                if hook.after && matches!(flow(&insn, at), Flow::Jump { .. }) {
                    return Err(invalid("it comes after a branch"));
                }
                if hook
                    .action
                    .target()
                    .is_some_and(|to| !function.contains(to))
                {
                    return Err(invalid("its jump leaves the function"));
                }
            }
            if !reached {
                return Err(invalid("no path of a function reaches it"));
            }
        }
        Ok(())
    }

    /// What the generated functions hold: the instructions of each mnemonic on their paths, their
    /// jump tables, and the cycles that several of their blocks enter; and the functions whose
    /// structured form failed its check.
    pub fn statistics(&self) -> Result<Statistics, Error> {
        let mut statistics = Statistics::default();
        for &function in self.functions.values() {
            if self.overridden.contains(&function.addr)
                || self.non_local.longjmp == Some(function.addr)
            {
                continue;
            }
            let cfg = self.blocks(function)?;
            for &(_, insn) in cfg.blocks.iter().flat_map(|block| &block.insns) {
                *statistics
                    .opcodes
                    .entry(insn.opcode().info().mnemonic)
                    .or_insert(0) += 1;
            }
            statistics.jump_tables += cfg.tables.len();
            statistics.unresolved_tables += cfg.unresolved.len();
            let kept = if self.calls_setjmp(&cfg) {
                statistics.setjmp_functions += 1;
                true
            } else if self.dispatch.contains(&function.addr) {
                statistics.listed_functions += 1;
                true
            } else {
                false
            };
            match structure(&self.graph(function, &cfg)) {
                Ok(structured) => {
                    if structured.dispatch_nodes > 0 {
                        statistics.irreducible_functions += 1;
                        statistics.dispatch_nodes += structured.dispatch_nodes;
                        statistics.redirected_sites += structured.redirected_sites;
                    }
                    let depth = brace_depth(&structured);
                    if kept {
                    } else if depth > MAX_BRACE_DEPTH {
                        statistics.deep.push((function.addr, depth));
                    } else {
                        statistics.structured_functions += 1;
                        statistics.brace_depth = statistics.brace_depth.max(depth);
                    }
                }
                // A rejected form is a bug, even in a function kept in dispatch form.
                Err(rejected) => statistics.rejected.push((function.addr, rejected.0)),
            }
        }
        Ok(statistics)
    }

    /// Generates every function, in address order, for one module: every call to a function of
    /// the list is a direct call.
    ///
    /// Opcodes without `emit_*` do not stop generation: the error lists all of them, with their
    /// counts over every function. Any other error stops at the first function that has it.
    pub fn generate(&self) -> Result<String, Error> {
        self.check_hooks()?;
        self.check_dispatch()?;
        self.generate_part(0..=u32::MAX)
    }

    /// Generates the functions whose entries lie in `part`, in address order, as one crate of the
    /// output workspace. A call or tail call to a function of the list outside `part` goes
    /// through `k.table`, since that function lives in another crate.
    ///
    /// Errors are as for [`Program::generate`], over the functions of `part`.
    pub fn generate_part(&self, part: RangeInclusive<u32>) -> Result<String, Error> {
        let mut text = String::new();
        let mut missing = BTreeMap::new();
        for &function in self.functions.range(part.clone()).map(|(_, f)| f) {
            if self.non_local.longjmp == Some(function.addr)
                || self.overridden.contains(&function.addr)
            {
                continue;
            }
            match self.generate_in(function, part.clone()) {
                Ok(function) => text.push_str(&function),
                Err(Error::MissingEmit { counts }) => {
                    for (name, count) in counts {
                        *missing.entry(name).or_insert(0) += count;
                    }
                }
                Err(other) => return Err(other),
            }
        }
        if missing.is_empty() {
            Ok(text)
        } else {
            Err(Error::MissingEmit { counts: missing })
        }
    }

    /// Generates one function, which need not be in the list, with direct calls to every function
    /// of the list.
    pub fn generate_function(&self, function: Function) -> Result<String, Error> {
        self.generate_in(function, 0..=u32::MAX)
    }

    /// Generates one function, calling the functions whose entries lie in `local` directly and
    /// the others through the table.
    fn generate_in(&self, function: Function, local: RangeInclusive<u32>) -> Result<String, Error> {
        let cfg = self.blocks(function)?;
        if let Some(structured) = self.structured(function, &cfg) {
            return structured::generate(self, function, &cfg, &structured, local);
        }
        let name = function_name(function.addr);
        let catches = self.calls_setjmp(&cfg);
        let mut e = Emitter::new(self, function, local, ControlFlow::Dispatch);
        e.line("#[inline(never)]");
        e.open(format!(
            "pub fn {name}(ctx: &mut PpcContext, mem: &Memory, k: &Kernels<'_>) {{"
        ));
        e.line(format!("let mut pc: u32 = {:#010x};", function.addr));
        if catches {
            // A longjmp to a buffer of this invocation unwinds to here, and the body starts
            // again after the setjmp that set it.
            e.line("let mut jumps = ferrum_runtime::Jumps::new();");
            e.open("loop {");
            e.open("let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| loop {");
        } else {
            e.open("loop {");
        }
        e.open("match pc {");
        for block in &cfg.blocks {
            e.open(format!("{:#010x} => {{", block.start));
            self.block(&mut e, function, &cfg, block)?;
            e.close("}");
        }
        e.line(format!(
            "_ => unreachable!(\"{name}: no block at {{pc:#010x}}\"),"
        ));
        e.close("}");
        if catches {
            e.close("}));");
            e.open("match run {");
            e.line("Ok(()) => return,");
            e.line("Err(payload) => pc = jumps.resume(payload, ctx),");
            e.close("}");
        }
        e.close("}");
        e.close("}");
        e.line("");
        e.finish()
    }

    /// The structured form to generate `function` from, whose blocks are `cfg`: none under a
    /// dispatcher, for a function that calls `setjmp`, whose `longjmp` resumes at a block by its
    /// address, for a function in the dispatch list, or when the form fails its check or would
    /// nest too deep, which [`Program::statistics`] lists.
    fn structured(&self, function: Function, cfg: &Cfg) -> Option<Structured> {
        if self.control_flow != ControlFlow::Structured
            || self.calls_setjmp(cfg)
            || self.dispatch.contains(&function.addr)
        {
            return None;
        }
        structure(&self.graph(function, cfg))
            .ok()
            .filter(|structured| brace_depth(structured) <= MAX_BRACE_DEPTH)
    }

    /// Writes the code of `block`, a block of `cfg`, into `e`: its instructions, the hooks at them,
    /// and its transfers to its sites, in the way `e` writes them.
    pub(crate) fn block(
        &self,
        e: &mut Emitter<'_>,
        function: Function,
        cfg: &Cfg,
        block: &Block,
    ) -> Result<(), Error> {
        e.begin_block(block.start, sites::transfers(self, function, cfg, block));
        let last = block.insns.len() - 1;
        for (index, &(at, insn)) in block.insns.iter().enumerate() {
            e.hooks(at, false);
            e.line(format!("// {at:08x}: {}", format_at(&insn, at).trim_end()));
            match flow(&insn, at) {
                Flow::Jump { .. } if cfg.tables.contains_key(&at) => {
                    debug_assert_eq!(index, last, "a jump ends its block");
                    // The guest code has loaded CTR from the table.
                    e.table(&cfg.tables[&at].targets);
                }
                Flow::Jump {
                    target,
                    conditional,
                } => {
                    debug_assert_eq!(index, last, "a jump ends its block");
                    e.jump(at, &insn, target, conditional, block.exit)?;
                }
                Flow::Next if links(&insn) => e.call(at, &insn)?,
                Flow::Next => emit::emit(e, at, &insn)?,
            }
            e.hooks(at, true);
        }
        let (at, insn) = block.insns[last];
        if !matches!(flow(&insn, at), Flow::Jump { .. }) {
            e.continue_to(block.exit);
        }
        e.end_block();
        Ok(())
    }

    /// Returns whether a path of the function calls `setjmp`.
    fn calls_setjmp(&self, cfg: &Cfg) -> bool {
        let Some(setjmp) = self.non_local.setjmp else {
            return false;
        };
        cfg.blocks.iter().flat_map(|b| &b.insns).any(|&(at, insn)| {
            links(&insn) && branch_target(&insn, at) == Some(Target::Address(setjmp))
        })
    }

    /// The basic blocks of `function`, with the rules of the program.
    pub(crate) fn blocks(&self, function: Function) -> Result<Cfg, Error> {
        Ok(build(&self.code, function, &self.rules)?)
    }

    /// The graph of `function`, whose blocks are `cfg`, for its structuring: the blocks the entry
    /// reaches, each with the blocks its sites go to, in the order its code writes them.
    pub(crate) fn graph(&self, function: Function, cfg: &Cfg) -> Graph {
        let blocks: Vec<(u32, Vec<u32>)> = cfg
            .blocks
            .iter()
            .map(|block| {
                let sites = sites::transfers(self, function, cfg, block);
                (block.start, sites.iter().map(|site| site.target).collect())
            })
            .collect();
        Graph::from_blocks(&blocks)
    }

    /// The mid-asm hooks at the instruction at `at`, in the order of the config.
    pub(crate) fn hooks_at(&self, at: u32) -> impl Iterator<Item = &MidAsm> {
        self.midasm.get(&at).into_iter().flatten()
    }

    /// Returns whether a guest function starts at `addr`.
    fn is_function(&self, addr: u32) -> bool {
        self.functions.contains_key(&addr)
    }

    /// The entries of the functions, in address order.
    pub(crate) fn entries(&self) -> impl Iterator<Item = u32> + '_ {
        self.functions.keys().copied()
    }

    /// The imports of the module.
    pub(crate) fn imports(&self) -> &[Import] {
        &self.imports
    }

    /// The text of the root crate's `imports.rs`: a function per thunk, named by
    /// [`crate::thunk_name`], the list `THUNKS` for the table, and `load`, which fills the slots.
    pub fn imports_file(&self) -> String {
        crate::imports::imports_file(&self.imports)
    }

    /// The text of the root crate's `hooks.rs`: the hooks by address and name, and `missing`.
    pub fn hooks_file(&self) -> String {
        crate::hooks::hooks_file(&self.hooks)
    }

    /// Whether a trap whose condition holds is a no-op.
    pub(crate) fn trap_as_nop(&self) -> bool {
        self.trap_as_nop
    }

    /// The guest code.
    pub(crate) fn code(&self) -> &Code<'a> {
        &self.code
    }
}

impl Emitter<'_> {
    /// The calls to the mid-asm hooks of the instruction at `at` that come before it, or after it
    /// with `after`.
    fn hooks(&mut self, at: u32, after: bool) {
        let program = self.program;
        for hook in program.hooks_at(at).filter(|hook| hook.after == after) {
            self.line(format!("// hook {}", hook.name));
            if let (ControlFlow::Structured, Action::JumpIfTrue(to)) =
                (self.control_flow, hook.action)
            {
                // The site's code may be a whole block, so it gets lines of its own.
                self.open(format!("if {} {{", hook.call()));
                for statement in self.goto(SiteKind::Hook, to, true) {
                    self.line(statement);
                }
                self.close("}");
                continue;
            }
            for statement in hook.statements(|to| self.goto(SiteKind::Hook, to, true)) {
                self.line(statement);
            }
        }
    }

    /// Writes the transfer of the next site of the block, a transfer of `kind` to `target`, the
    /// last code of the block.
    fn go(&mut self, kind: SiteKind, target: u32) {
        for statement in self.goto(kind, target, false) {
            self.line(statement);
        }
    }

    /// The code for a path that goes on past the last instruction of a block.
    fn continue_to(&mut self, exit: Exit) {
        let name = function_name(self.function.addr);
        match exit {
            Exit::Next(next) => self.go(SiteKind::Next, next),
            Exit::FallOff => match u32::try_from(self.function.end()) {
                // Running into another function is what the hardware does: a tail call.
                Ok(next) if self.program.is_function(next) => {
                    self.call_function(next);
                    self.line("return;");
                }
                _ => self.line(format!("unreachable!(\"fell off the end of {name}\");")),
            },
            Exit::NoReturn => {
                self.line(format!(
                    "unreachable!(\"{name}: a call that never returns came back\");"
                ));
            }
            Exit::Jump => unreachable!("only a jump ends a block with Exit::Jump"),
        }
    }

    /// A branch that does not link, at the end of a block.
    fn jump(
        &mut self,
        at: u32,
        insn: &Insn,
        target: Target,
        conditional: bool,
        exit: Exit,
    ) -> Result<(), Error> {
        let condition = self.condition(at, insn)?;
        debug_assert_eq!(condition.is_some(), conditional);
        match (target, condition) {
            (Target::Address(to), None) if self.function.contains(to) => {
                self.go(SiteKind::Branch, to);
            }
            (Target::Address(to), Some(condition))
                if self.function.contains(to) && self.control_flow == ControlFlow::Structured =>
            {
                // The taken side ends in a transfer, so the other side needs no `else`.
                self.open(format!("if {condition} {{"));
                for statement in self.goto(SiteKind::Branch, to, true) {
                    self.line(statement);
                }
                self.close("}");
                self.continue_to(exit);
            }
            (Target::Address(to), Some(condition)) if self.function.contains(to) => {
                self.open(format!("if {condition} {{"));
                self.go(SiteKind::Branch, to);
                self.reopen("} else {");
                self.continue_to(exit);
                self.close("}");
            }
            (target, None) => self.leave(at, target)?,
            (target, Some(condition)) => {
                self.open(format!("if {condition} {{"));
                self.leave(at, target)?;
                self.close("}");
                self.continue_to(exit);
            }
        }
        Ok(())
    }

    /// Leaves the function through a branch that does not link: a return, or a tail call.
    fn leave(&mut self, at: u32, target: Target) -> Result<(), Error> {
        match target {
            Target::Lr => {}
            Target::Ctr => self.line("(k.table.lookup(ctx.ctr as u32, ctx.lr))(ctx, mem, k);"),
            Target::Address(to) if self.program.non_local.setjmp == Some(to) => {
                return Err(Error::SetjmpTailCall { addr: at });
            }
            Target::Address(to) if self.program.thunks.contains_key(&to) => {
                let import = &self.program.imports[self.program.thunks[&to]];
                self.line(import.call());
            }
            Target::Address(to) => {
                if self.program.is_function(to) {
                    self.call_function(to);
                } else if self.program.routines.contains_key(&to) {
                    self.inline_routine(to)?;
                } else {
                    return Err(Error::UnknownTarget {
                        addr: at,
                        target: to,
                    });
                }
            }
        }
        self.line("return;");
        Ok(())
    }

    /// A branch that links: LR is written first, as the hardware does, then the call is made if the
    /// condition holds. A call to a restore routine returns, since the routine reloads LR and
    /// returns to the caller's caller.
    fn call(&mut self, at: u32, insn: &Insn) -> Result<(), Error> {
        let target = branch_target(insn, at).expect("a branch that links has a target");
        let ret = at.wrapping_add(4);
        self.open("{");
        if target == Target::Lr {
            // The target is the LR from before this instruction writes it.
            self.line("let target = ctx.lr as u32;");
        }
        let condition = self.condition(at, insn)?;
        self.line(format!("ctx.lr = {ret:#010x};"));
        if let Some(condition) = &condition {
            self.open(format!("if {condition} {{"));
        }
        if matches!(target, Target::Address(to) if Some(to) == self.program.non_local.setjmp) {
            // The registers as setjmp sees them, for a longjmp to put back.
            self.line(format!("jumps.set(ctx, {ret:#010x});"));
        }
        match target {
            Target::Lr => self.line("(k.table.lookup(target, ctx.lr))(ctx, mem, k);"),
            Target::Ctr => self.line("(k.table.lookup(ctx.ctr as u32, ctx.lr))(ctx, mem, k);"),
            Target::Address(to) if self.program.thunks.contains_key(&to) => {
                let import = &self.program.imports[self.program.thunks[&to]];
                self.line(import.call());
            }
            Target::Address(to) if self.program.is_function(to) => self.call_function(to),
            Target::Address(to) => match self.program.routines.get(&to) {
                Some(routine) => {
                    self.inline_routine(to)?;
                    if routine.family == Family::RestoreGprLr {
                        self.line("return;");
                    }
                }
                None => {
                    return Err(Error::UnknownTarget {
                        addr: at,
                        target: to,
                    });
                }
            },
        }
        if condition.is_some() {
            self.close("}");
        }
        self.close("}");
        Ok(())
    }

    /// Calls the guest function at `to`: directly if it is in this crate, and through the table if
    /// it is in another one.
    fn call_function(&mut self, to: u32) {
        if self.program.non_local.longjmp == Some(to) {
            self.line(format!("{RUNTIME_LONGJMP}(ctx, mem, k);"));
        } else if self.local.contains(&to) && !self.program.overridden.contains(&to) {
            self.line(format!("{}(ctx, mem, k);", function_name(to)));
        } else {
            self.line(format!(
                "(k.table.lookup({to:#010x}, ctx.lr))(ctx, mem, k); // {}",
                function_name(to)
            ));
        }
    }

    /// Emits the instructions of the save or restore routine entered at `entry`, up to the `blr`
    /// that ends it.
    fn inline_routine(&mut self, entry: u32) -> Result<(), Error> {
        let end = self.program.routines[&entry].end;
        let mut at = entry;
        while at != end {
            let word = self.program.code.word(at);
            let insn = word
                .and_then(decode)
                .expect("a routine was matched on decoded words of the code");
            self.line(format!("// {at:08x}: {}", format_at(&insn, at).trim_end()));
            emit::emit(self, at, &insn)?;
            at = at.wrapping_add(4);
        }
        Ok(())
    }

    /// The condition of a conditional branch, if it has one, after emitting the decrement of CTR
    /// that comes before the test. Branches to CTR cannot decrement it.
    fn condition(&mut self, at: u32, insn: &Insn) -> Result<Option<String>, Error> {
        let (bo, bi, to_ctr) = match *insn {
            Insn::B { .. } => return Ok(None),
            Insn::Bc { bo, bi, .. } | Insn::Bclr { bo, bi, .. } => (bo, bi.0, false),
            Insn::Bcctr { bo, bi, .. } => (bo, bi.0, true),
            _ => unreachable!("only branches have a condition"),
        };
        let mut terms = Vec::new();
        if bo & 0x04 == 0 {
            if to_ctr {
                return Err(Error::InvalidForm {
                    addr: at,
                    mnemonic: "bcctr",
                    why: "it decrements CTR",
                });
            }
            self.line("ctx.ctr = ctx.ctr.wrapping_sub(1);");
            // The test looks at the low word of CTR in 32-bit mode.
            terms.push(if bo & 0x02 == 0 {
                "(ctx.ctr as u32) != 0".to_owned()
            } else {
                "(ctx.ctr as u32) == 0".to_owned()
            });
        }
        if bo & 0x10 == 0 {
            let bit = cr_bit(bi);
            terms.push(if bo & 0x08 == 0 {
                format!("!{bit}")
            } else {
                bit
            });
        }
        Ok((!terms.is_empty()).then(|| terms.join(" && ")))
    }
}

/// The expression that reads condition register bit `bi`, by field and name.
pub(crate) fn cr_bit(bi: u8) -> String {
    let name = ["lt", "gt", "eq", "so"][usize::from(bi % 4)];
    format!("ctx.cr.{name}({})", bi / 4)
}
