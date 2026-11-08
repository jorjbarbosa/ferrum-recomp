// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The synthetic guest program: functions shaped like compiled C++, built with `Insn::encode`.
//!
//! No value here comes from a game. The weights are assumptions about compiled C++ at the scale
//! expected of an Xbox 360 title. The code is never run, only generated and compiled, so the
//! instructions only need to be valid and to have an `emit_*`; what they compute does not matter.

use ferrum_analysis::Function;
use ferrum_decoder::{CrBit, CrField, Gpr, Insn};

use crate::rng::Rng;

/// Where the program is loaded, as Xbox 360 titles are.
pub const BASE: u32 = 0x8200_0000;

/// The GPR save and restore routines take the first 41 words.
const ROUTINE_WORDS: u32 = 41;

/// Function sizes in instructions: weight in 1000, then the smallest and largest size of the
/// bucket, uniform within it. The median is about 13 instructions and the mean about 39.
const SIZES: [(u32, (u32, u32)); 10] = [
    (170, (2, 4)),
    (190, (5, 8)),
    (210, (9, 16)),
    (180, (17, 32)),
    (125, (33, 64)),
    (70, (65, 128)),
    (35, (129, 256)),
    (15, (257, 512)),
    (4, (513, 1024)),
    (1, (1025, 2048)),
];

/// Functions of up to this many instructions are leaves.
const LEAF_SIZE: u32 = 8;
/// Chance in 1000 that a larger function has a frame.
const FRAME: u32 = 800;
/// Chance in 1000 that a frame is saved through `__savegprlr_N` rather than `mflr`/`stw`.
const SAVE_ROUTINE: u32 = 700;
/// Chance in 1000 that a function without a save routine ends in a tail call.
const TAIL_CALL: u32 = 60;

/// One step of a function body.
#[derive(Debug, Clone, Copy)]
enum Step {
    /// One integer instruction.
    Op,
    /// `bl` to another function.
    Call,
    /// A call through a pointer loaded from memory: `lwz`, `lwz`, `mtctr`, `bctrl`.
    Indirect,
    /// A compare and a conditional branch over a nested sequence.
    If,
    /// A compare, a conditional branch to the `else` part, and a `b` over it.
    IfElse,
    /// `li`, `mtctr`, a nested sequence and `bdnz` back to it.
    Loop,
    /// A compare and a conditional `blr`.
    Return,
}

/// Steps with their weights in 1000. A step that does not fit, or a call in a leaf, becomes an
/// instruction, so a branch ends a block about every 6 instructions.
const STEPS: [(u32, Step); 7] = [
    (700, Step::Op),
    (90, Step::Call),
    (10, Step::Indirect),
    (120, Step::If),
    (40, Step::IfElse),
    (30, Step::Loop),
    (10, Step::Return),
];

/// One integer instruction of a body.
#[derive(Debug, Clone, Copy)]
enum Op {
    Lwz,
    Lbz,
    Lhz,
    Lha,
    Ld,
    Lwzx,
    Stw,
    Stb,
    Sth,
    Std,
    Addi,
    Li,
    Lis,
    Add,
    Subf,
    Neg,
    Mullw,
    Mulli,
    Divw,
    Divwu,
    Mr,
    Ori,
    And,
    Andc,
    Xor,
    Nor,
    AndiDot,
    Rlwinm,
    Rlwimi,
    Slw,
    Srw,
    Srawi,
    Extsb,
    Extsh,
    Extsw,
    Cntlzw,
}

/// Instructions with their weights: about 38% loads and stores, 31% arithmetic, 17% logical
/// and 14% rotates, shifts and extensions.
const OPS: [(u32, Op); 36] = [
    (16, Op::Lwz),
    (3, Op::Lbz),
    (2, Op::Lhz),
    (1, Op::Lha),
    (2, Op::Ld),
    (1, Op::Lwzx),
    (8, Op::Stw),
    (2, Op::Stb),
    (1, Op::Sth),
    (2, Op::Std),
    (10, Op::Addi),
    (6, Op::Li),
    (2, Op::Lis),
    (4, Op::Add),
    (3, Op::Subf),
    (1, Op::Neg),
    (2, Op::Mullw),
    (1, Op::Mulli),
    (1, Op::Divw),
    (1, Op::Divwu),
    (8, Op::Mr),
    (2, Op::Ori),
    (2, Op::And),
    (1, Op::Andc),
    (1, Op::Xor),
    (1, Op::Nor),
    (2, Op::AndiDot),
    (6, Op::Rlwinm),
    (1, Op::Rlwimi),
    (1, Op::Slw),
    (1, Op::Srw),
    (1, Op::Srawi),
    (1, Op::Extsb),
    (1, Op::Extsh),
    (1, Op::Extsw),
    (1, Op::Cntlzw),
];

/// Registers that bodies compute in.
const REGS: [u8; 11] = [3, 4, 5, 6, 7, 8, 9, 10, 11, 30, 31];

/// A synthetic program: its instructions from [`BASE`], and its functions in address order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Synthetic {
    /// The instructions, the save and restore routines first.
    pub insns: Vec<Insn>,
    /// The functions, back to back after the routines.
    pub functions: Vec<Function>,
}

impl Synthetic {
    /// The bytes of the program, in memory order.
    pub fn bytes(&self) -> Vec<u8> {
        self.insns
            .iter()
            .flat_map(|insn| insn.encode().to_be_bytes())
            .collect()
    }

    /// How many instructions the functions hold, without the routines.
    pub fn function_insns(&self) -> u64 {
        self.functions.iter().map(|f| u64::from(f.size / 4)).sum()
    }
}

/// Generates `count` functions from `seed`. The same seed and count always give the same program.
pub fn generate(seed: u64, count: usize) -> Synthetic {
    let mut rng = Rng::new(seed);
    let bodies: Vec<Body> = (0..count)
        .map(|index| Builder::function(&mut rng, index, count))
        .collect();
    let mut starts = Vec::with_capacity(count);
    let mut word = ROUTINE_WORDS;
    for body in &bodies {
        starts.push(word);
        word += body.insns.len() as u32;
    }
    // `b` reaches 32 MiB either way; a program within 32 MiB never needs more.
    assert!(
        u64::from(word) * 4 < 1 << 25,
        "{count} functions take more than 32 MiB"
    );
    let mut insns = gpr_routines();
    let mut functions = Vec::with_capacity(count);
    for (body, &start) in bodies.into_iter().zip(&starts) {
        let mut code = body.insns;
        for patch in body.patches {
            let to = match patch.target {
                Target::Function(index) => starts[index],
                Target::Word(word) => word,
            };
            code[patch.at] = branch(start + patch.at as u32, to, patch.link);
        }
        functions.push(Function {
            addr: BASE + 4 * start,
            size: 4 * code.len() as u32,
        });
        insns.extend(code);
    }
    Synthetic { insns, functions }
}

/// How a function sets up its frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Frame {
    /// No frame, no calls.
    Leaf,
    /// `mflr r12; stw r12,-8(r1); stwu r1,-F(r1)`, and the reverse before `blr`.
    Plain,
    /// `mflr r12; bl __savegprlr_N; stwu r1,-F(r1)`, and `b __restgprlr_N` to return. Holds N.
    Save(u8),
}

/// Where a branch goes whose displacement is only known once the functions are laid out.
#[derive(Debug, Clone, Copy)]
enum Target {
    Function(usize),
    Word(u32),
}

/// A branch to fill in at instruction `at` of a body.
#[derive(Debug, Clone, Copy)]
struct Patch {
    at: usize,
    target: Target,
    link: bool,
}

/// One function before layout.
struct Body {
    insns: Vec<Insn>,
    patches: Vec<Patch>,
}

/// Builds the body of one function.
struct Builder<'r> {
    rng: &'r mut Rng,
    index: usize,
    count: usize,
    frame: Frame,
    insns: Vec<Insn>,
    patches: Vec<Patch>,
}

impl Builder<'_> {
    /// Draws function `index` of `count`.
    fn function(rng: &mut Rng, index: usize, count: usize) -> Body {
        let (low, high) = rng.pick(&SIZES);
        let size = rng.between(low, high);
        let frame = if size <= LEAF_SIZE || !rng.chance(FRAME) {
            Frame::Leaf
        } else if rng.chance(SAVE_ROUTINE) {
            let saved = (1 + rng.below(size / 8 + 1)).min(18);
            Frame::Save(32 - saved as u8)
        } else {
            Frame::Plain
        };
        let tail = count > 1 && !matches!(frame, Frame::Save(_)) && rng.chance(TAIL_CALL);
        let mut b = Builder {
            rng,
            index,
            count,
            frame,
            insns: Vec::with_capacity(size as usize),
            patches: Vec::new(),
        };
        let frame_size = -(0x60 + 0x10 * b.rng.below(16) as i16);
        let (prologue, epilogue) = match frame {
            Frame::Leaf => (0, 1),
            Frame::Plain => (3, 4),
            Frame::Save(_) => (3, 2),
        };
        b.prologue(frame_size);
        b.sequence(size.saturating_sub(prologue + epilogue).max(1));
        b.epilogue(frame_size, tail);
        Body {
            insns: b.insns,
            patches: b.patches,
        }
    }

    fn prologue(&mut self, frame_size: i16) {
        match self.frame {
            Frame::Leaf => return,
            Frame::Plain => {
                self.insns.push(mflr(12));
                self.insns.push(Insn::Stw {
                    rs: Gpr(12),
                    d: -8,
                    ra: Gpr(1),
                });
            }
            Frame::Save(first) => {
                self.insns.push(mflr(12));
                self.patch(Target::Word(u32::from(first) - 14), true);
            }
        }
        self.insns.push(Insn::Stwu {
            rs: Gpr(1),
            d: frame_size,
            ra: Gpr(1),
        });
    }

    fn epilogue(&mut self, frame_size: i16, tail: bool) {
        if self.frame != Frame::Leaf {
            self.insns.push(addi(1, 1, -frame_size));
        }
        match self.frame {
            Frame::Save(first) => {
                self.patch(Target::Word(u32::from(first) + 6), false);
                return;
            }
            Frame::Plain => {
                self.insns.push(Insn::Lwz {
                    rt: Gpr(12),
                    d: -8,
                    ra: Gpr(1),
                });
                self.insns.push(Insn::Mtspr {
                    spr: 8,
                    rs: Gpr(12),
                });
            }
            Frame::Leaf => {}
        }
        if tail {
            let callee = self.callee();
            self.patch(Target::Function(callee), false);
        } else {
            self.insns.push(bclr(20, 0, false));
        }
    }

    /// Emits steps for exactly `budget` instructions.
    fn sequence(&mut self, budget: u32) {
        let mut left = budget;
        while left > 0 {
            left -= self.step(left);
        }
    }

    /// Emits one step of at most `left` instructions, and returns how many it took.
    fn step(&mut self, left: u32) -> u32 {
        let start = self.insns.len();
        let calls = self.frame != Frame::Leaf && self.count > 1;
        match self.rng.pick(&STEPS) {
            Step::Call if calls => {
                let callee = self.callee();
                self.patch(Target::Function(callee), true);
            }
            Step::Indirect if calls && left >= 4 => self.indirect(),
            Step::If if left >= 3 => {
                let (bo, bi) = self.compare();
                let at = self.placeholder();
                let nested = 1 + self.rng.below((left - 2).min(8));
                self.sequence(nested);
                self.insns[at] = bc(bo, bi, at, self.insns.len());
            }
            Step::IfElse if left >= 5 => {
                let (bo, bi) = self.compare();
                let to_else = self.placeholder();
                let then = 1 + self.rng.below((left - 4).min(6));
                self.sequence(then);
                let to_end = self.placeholder();
                self.insns[to_else] = bc(bo, bi, to_else, self.insns.len());
                let other = 1 + self.rng.below((left - 3 - then).min(6));
                self.sequence(other);
                self.insns[to_end] = jump(to_end, self.insns.len());
            }
            Step::Loop if left >= 4 => {
                let count = self.rng.between(2, 16) as i16;
                self.insns.push(addi(10, 0, count));
                self.insns.push(Insn::Mtspr {
                    spr: 9,
                    rs: Gpr(10),
                });
                let body = self.insns.len();
                let nested = 1 + self.rng.below((left - 3).min(6));
                self.sequence(nested);
                let at = self.insns.len();
                self.insns.push(bc(16, 0, at, body));
            }
            Step::Return if self.frame == Frame::Leaf && left >= 2 => {
                let (bo, bi) = self.compare();
                self.insns.push(bclr(bo, bi, false));
            }
            _ => {
                let insn = self.op();
                self.insns.push(insn);
            }
        }
        (self.insns.len() - start) as u32
    }

    /// A function to call: a neighbor, one of 256 common functions spread over the program, or
    /// any function. Never the caller itself.
    fn callee(&mut self) -> usize {
        let count = self.count;
        let draw = self.rng.below(1000);
        let callee = if draw < 300 {
            let distance = self.rng.between(1, 64) as usize;
            if self.rng.chance(500) {
                self.index.saturating_sub(distance)
            } else {
                (self.index + distance).min(count - 1)
            }
        } else if draw < 500 {
            self.rng.below(256) as usize * count / 256
        } else {
            self.rng.below(count as u32) as usize
        };
        if callee == self.index {
            (callee + 1) % count
        } else {
            callee
        }
    }

    /// `lwz r11,0(r3); lwz r11,D(r11); mtctr r11; bctrl`.
    fn indirect(&mut self) {
        let slot = self.disp(4);
        self.insns.push(Insn::Lwz {
            rt: Gpr(11),
            d: 0,
            ra: Gpr(3),
        });
        self.insns.push(Insn::Lwz {
            rt: Gpr(11),
            d: slot,
            ra: Gpr(11),
        });
        self.insns.push(Insn::Mtspr {
            spr: 9,
            rs: Gpr(11),
        });
        self.insns.push(Insn::Bcctr {
            bo: 20,
            bi: CrBit(0),
            bh: 0,
            lk: true,
        });
    }

    /// Emits a compare and returns the BO and BI of a branch on its result.
    fn compare(&mut self) -> (u8, u8) {
        let bf = self.rng.pick(&[(75, 0), (15, 6), (10, 7)]);
        let ra = self.reg();
        let insn = match self.rng.below(10) {
            0..=4 => Insn::Cmpi {
                bf: CrField(bf),
                ignored: false,
                l: false,
                ra,
                si: self.rng.between(0, 80) as i16 - 16,
            },
            5..=6 => Insn::Cmpli {
                bf: CrField(bf),
                ignored: false,
                l: false,
                ra,
                ui: self.rng.below(256) as u16,
            },
            7..=8 => Insn::Cmp {
                bf: CrField(bf),
                l: false,
                ra,
                rb: self.reg(),
            },
            _ => Insn::Cmpl {
                bf: CrField(bf),
                l: false,
                ra,
                rb: self.reg(),
            },
        };
        self.insns.push(insn);
        let bit = self.rng.below(3) as u8;
        let bo = if self.rng.chance(500) { 12 } else { 4 };
        (bo, 4 * bf + bit)
    }

    /// One integer instruction.
    fn op(&mut self) -> Insn {
        let rt = self.reg();
        match self.rng.pick(&OPS) {
            Op::Lwz => Insn::Lwz {
                rt,
                d: self.disp(4),
                ra: self.base(),
            },
            Op::Lbz => Insn::Lbz {
                rt,
                d: self.disp(1),
                ra: self.base(),
            },
            Op::Lhz => Insn::Lhz {
                rt,
                d: self.disp(2),
                ra: self.base(),
            },
            Op::Lha => Insn::Lha {
                rt,
                d: self.disp(2),
                ra: self.base(),
            },
            Op::Ld => Insn::Ld {
                rt,
                ds: self.disp(8),
                ra: self.base(),
            },
            Op::Lwzx => Insn::Lwzx {
                rt,
                ra: self.reg(),
                rb: self.reg(),
            },
            Op::Stw => Insn::Stw {
                rs: rt,
                d: self.disp(4),
                ra: self.base(),
            },
            Op::Stb => Insn::Stb {
                rs: rt,
                d: self.disp(1),
                ra: self.base(),
            },
            Op::Sth => Insn::Sth {
                rs: rt,
                d: self.disp(2),
                ra: self.base(),
            },
            Op::Std => Insn::Std {
                rs: rt,
                ds: self.disp(8),
                ra: self.base(),
            },
            Op::Addi => Insn::Addi {
                rt,
                ra: self.reg(),
                si: self.small(),
            },
            Op::Li => Insn::Addi {
                rt,
                ra: Gpr(0),
                si: self.small(),
            },
            Op::Lis => Insn::Addis {
                rt,
                ra: Gpr(0),
                // 0x8200 to 0x82FF, the upper half of an address in the image.
                si: -0x7E00 + self.rng.below(0x100) as i16,
            },
            Op::Add => Insn::Add {
                rt,
                ra: self.reg(),
                rb: self.reg(),
                oe: false,
                rc: false,
            },
            Op::Subf => Insn::Subf {
                rt,
                ra: self.reg(),
                rb: self.reg(),
                oe: false,
                rc: false,
            },
            Op::Neg => Insn::Neg {
                rt,
                ra: self.reg(),
                oe: false,
                rc: false,
            },
            Op::Mullw => Insn::Mullw {
                rt,
                ra: self.reg(),
                rb: self.reg(),
                oe: false,
                rc: false,
            },
            Op::Mulli => Insn::Mulli {
                rt,
                ra: self.reg(),
                si: self.small(),
            },
            Op::Divw => Insn::Divw {
                rt,
                ra: self.reg(),
                rb: self.reg(),
                oe: false,
                rc: false,
            },
            Op::Divwu => Insn::Divwu {
                rt,
                ra: self.reg(),
                rb: self.reg(),
                oe: false,
                rc: false,
            },
            Op::Mr => {
                let rs = self.reg();
                Insn::Or {
                    ra: rt,
                    rs,
                    rb: rs,
                    rc: false,
                }
            }
            Op::Ori => Insn::Ori {
                ra: rt,
                rs: self.reg(),
                ui: self.rng.below(0x1_0000) as u16,
            },
            Op::And => Insn::And {
                ra: rt,
                rs: self.reg(),
                rb: self.reg(),
                rc: false,
            },
            Op::Andc => Insn::Andc {
                ra: rt,
                rs: self.reg(),
                rb: self.reg(),
                rc: false,
            },
            Op::Xor => Insn::Xor {
                ra: rt,
                rs: self.reg(),
                rb: self.reg(),
                rc: false,
            },
            Op::Nor => Insn::Nor {
                ra: rt,
                rs: self.reg(),
                rb: self.reg(),
                rc: false,
            },
            Op::AndiDot => Insn::AndiDot {
                ra: rt,
                rs: self.reg(),
                ui: self.rng.below(0x100) as u16,
            },
            Op::Rlwinm => Insn::Rlwinm {
                ra: rt,
                rs: self.reg(),
                sh: self.rng.below(32) as u8,
                mb: self.rng.below(32) as u8,
                me: self.rng.below(32) as u8,
                rc: self.rng.chance(100),
            },
            Op::Rlwimi => Insn::Rlwimi {
                ra: rt,
                rs: self.reg(),
                sh: self.rng.below(32) as u8,
                mb: self.rng.below(32) as u8,
                me: self.rng.below(32) as u8,
                rc: false,
            },
            Op::Slw => Insn::Slw {
                ra: rt,
                rs: self.reg(),
                rb: self.reg(),
                rc: false,
            },
            Op::Srw => Insn::Srw {
                ra: rt,
                rs: self.reg(),
                rb: self.reg(),
                rc: false,
            },
            Op::Srawi => Insn::Srawi {
                ra: rt,
                rs: self.reg(),
                sh: self.rng.below(32) as u8,
                rc: false,
            },
            Op::Extsb => Insn::Extsb {
                ra: rt,
                rs: self.reg(),
                rc: false,
            },
            Op::Extsh => Insn::Extsh {
                ra: rt,
                rs: self.reg(),
                rc: false,
            },
            Op::Extsw => Insn::Extsw {
                ra: rt,
                rs: self.reg(),
                rc: false,
            },
            Op::Cntlzw => Insn::Cntlzw {
                ra: rt,
                rs: self.reg(),
                rc: false,
            },
        }
    }

    fn reg(&mut self) -> Gpr {
        Gpr(REGS[self.rng.below(REGS.len() as u32) as usize])
    }

    /// A base register for a load or store: the stack pointer, a computed address, the PCR in
    /// r13, or `this` kept in r31.
    fn base(&mut self) -> Gpr {
        match self.rng.below(100) {
            0..=29 => Gpr(1),
            30..=79 => self.reg(),
            80..=84 => Gpr(13),
            _ => Gpr(31),
        }
    }

    /// A displacement from 0 to 0x1FF, a multiple of `align`.
    fn disp(&mut self, align: u32) -> i16 {
        (self.rng.below(0x200 / align) * align) as i16
    }

    /// An immediate from -64 to 255.
    fn small(&mut self) -> i16 {
        self.rng.below(320) as i16 - 64
    }

    /// Reserves a word for a branch filled in later in the same body.
    fn placeholder(&mut self) -> usize {
        self.insns.push(bclr(20, 0, false));
        self.insns.len() - 1
    }

    /// Emits a branch to fill in once the functions are laid out.
    fn patch(&mut self, target: Target, link: bool) {
        self.patches.push(Patch {
            at: self.insns.len(),
            target,
            link,
        });
        self.insns.push(Insn::B {
            li: 0,
            aa: false,
            lk: link,
        });
    }
}

fn addi(rt: u8, ra: u8, si: i16) -> Insn {
    Insn::Addi {
        rt: Gpr(rt),
        ra: Gpr(ra),
        si,
    }
}

fn mflr(rt: u8) -> Insn {
    Insn::Mfspr {
        rt: Gpr(rt),
        spr: 8,
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

/// A conditional branch from instruction `from` to instruction `to` of the same body.
fn bc(bo: u8, bi: u8, from: usize, to: usize) -> Insn {
    // Bodies hold at most 2048 instructions, so the distance fits in BD.
    let bd = ((to as i64 - from as i64) * 4) as i16;
    Insn::Bc {
        bo,
        bi: CrBit(bi),
        bd,
        aa: false,
        lk: false,
    }
}

/// `b` from instruction `from` to instruction `to` of the same body.
fn jump(from: usize, to: usize) -> Insn {
    branch(from as u32, to as u32, false)
}

/// `b` or `bl` from word `from` to word `to` of the program.
fn branch(from: u32, to: u32, lk: bool) -> Insn {
    // `generate` keeps the program within the reach of `b`.
    let li = ((i64::from(to) - i64::from(from)) * 4) as i32;
    Insn::B { li, aa: false, lk }
}

/// The GPR save and restore routines with the layout of the ABI: r14 at -0x98 off r1, LR at -8.
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
    insns.push(bclr(20, 0, false));
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
    insns.push(Insn::Mtspr {
        spr: 8,
        rs: Gpr(12),
    });
    insns.push(bclr(20, 0, false));
    debug_assert_eq!(insns.len() as u32, ROUTINE_WORDS);
    insns
}

#[cfg(test)]
mod tests;
