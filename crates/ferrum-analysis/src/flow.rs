// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! What an instruction does to the flow of control.

use ferrum_decoder::Insn;

/// Where a branch goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Target {
    /// A fixed address, from the displacement of `b` or `bc`.
    Address(u32),
    /// The address in the link register (`bclr`).
    Lr,
    /// The address in the count register (`bcctr`).
    Ctr,
}

/// What an instruction does to the flow of control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// Execution goes on with the next instruction: the instruction is no branch, or a branch that
    /// sets the link register, a call, which comes back there.
    Next,
    /// A branch that does not set the link register, which ends a basic block. A conditional one
    /// may also go on with the next instruction.
    Jump {
        /// Where the branch goes.
        target: Target,
        /// Whether the branch depends on a condition or on the count register.
        conditional: bool,
    },
}

/// Returns whether a BO field branches always: it ignores the condition and does not decrement
/// CTR.
pub fn is_unconditional(bo: u8) -> bool {
    bo & 0x14 == 0x14
}

/// Returns where a branch at `addr` goes, or `None` if `insn` is no branch.
///
/// Addresses wrap at 4 GiB: generated code runs in 32-bit mode, where the high half of a branch
/// target is zero.
pub fn branch_target(insn: &Insn, addr: u32) -> Option<Target> {
    let relative = |displacement: i32, absolute: bool| {
        // Reinterpreting the displacement as unsigned and wrapping is the 32-bit address
        // arithmetic of the mode.
        let displacement = displacement as u32;
        Target::Address(if absolute {
            displacement
        } else {
            addr.wrapping_add(displacement)
        })
    };
    match *insn {
        Insn::B { li, aa, .. } => Some(relative(li, aa)),
        Insn::Bc { bd, aa, .. } => Some(relative(i32::from(bd), aa)),
        Insn::Bclr { .. } => Some(Target::Lr),
        Insn::Bcctr { .. } => Some(Target::Ctr),
        _ => None,
    }
}

/// Returns whether `insn` is a branch that sets the link register.
pub fn links(insn: &Insn) -> bool {
    matches!(
        *insn,
        Insn::B { lk: true, .. }
            | Insn::Bc { lk: true, .. }
            | Insn::Bclr { lk: true, .. }
            | Insn::Bcctr { lk: true, .. }
    )
}

/// Returns what the instruction at `addr` does to the flow of control.
pub fn flow(insn: &Insn, addr: u32) -> Flow {
    let Some(target) = branch_target(insn, addr) else {
        return Flow::Next;
    };
    if links(insn) {
        return Flow::Next;
    }
    let conditional = match *insn {
        Insn::B { .. } => false,
        Insn::Bc { bo, .. } | Insn::Bclr { bo, .. } | Insn::Bcctr { bo, .. } => {
            !is_unconditional(bo)
        }
        _ => unreachable!("only branches have a target"),
    };
    Flow::Jump {
        target,
        conditional,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_decoder::{CrBit, decode};

    fn at(word: u32) -> Insn {
        decode(word).unwrap()
    }

    #[test]
    fn targets_are_relative_unless_absolute_and_wrap() {
        // b .+0x10, b .-0x8, ba 0x100, beq .+0xc, bdnz .-0x4
        assert_eq!(
            branch_target(&at(0x4800_0010), 0x8000_0000),
            Some(Target::Address(0x8000_0010))
        );
        assert_eq!(
            branch_target(&at(0x4BFF_FFF8), 0x8000_0000),
            Some(Target::Address(0x7FFF_FFF8))
        );
        assert_eq!(
            branch_target(&at(0x4800_0102), 0x8000_0000),
            Some(Target::Address(0x100))
        );
        assert_eq!(
            branch_target(&at(0x4182_000C), 0x8000_0004),
            Some(Target::Address(0x8000_0010))
        );
        assert_eq!(
            branch_target(&at(0x4200_FFFC), 0x8000_0008),
            Some(Target::Address(0x8000_0004))
        );
        assert_eq!(
            branch_target(&at(0x4800_0010), 0xFFFF_FFF8),
            Some(Target::Address(8))
        );
        assert_eq!(branch_target(&at(0x4E80_0020), 0), Some(Target::Lr));
        assert_eq!(branch_target(&at(0x4E80_0420), 0), Some(Target::Ctr));
        assert_eq!(branch_target(&at(0x3860_0001), 0), None);
    }

    #[test]
    fn calls_go_on_and_other_branches_jump() {
        // bl, bctrl and blrl come back to the next instruction.
        for word in [0x4800_0011, 0x4E80_0421, 0x4E80_0021] {
            assert!(links(&at(word)));
            assert_eq!(flow(&at(word), 0), Flow::Next, "{word:#x}");
        }
        let jump = |target, conditional| Flow::Jump {
            target,
            conditional,
        };
        assert_eq!(
            flow(&at(0x4800_0010), 0),
            jump(Target::Address(0x10), false)
        );
        assert_eq!(flow(&at(0x4E80_0020), 0), jump(Target::Lr, false));
        assert_eq!(flow(&at(0x4E80_0420), 0), jump(Target::Ctr, false));
        // beq, beqlr, bdnz, and bc 20,... with a CR bit, which ignores it.
        assert_eq!(flow(&at(0x4182_0010), 0), jump(Target::Address(0x10), true));
        assert_eq!(flow(&at(0x4D82_0020), 0), jump(Target::Lr, true));
        assert_eq!(flow(&at(0x4200_0010), 0), jump(Target::Address(0x10), true));
        let always = Insn::Bc {
            bo: 20,
            bi: CrBit(2),
            bd: 0x10,
            aa: false,
            lk: false,
        };
        assert_eq!(flow(&always, 0), jump(Target::Address(0x10), false));
        assert_eq!(flow(&at(0x3860_0001), 0), Flow::Next);
    }
}
