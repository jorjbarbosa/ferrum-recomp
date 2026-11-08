// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The `#_` annotations of a test file, grouped by case.
//!
//! The rules are those of `ReadAnnotations` in Xenia's
//! `src/xenia/cpu/ppc/testing/ppc_testing_main.cc`: a line that starts, after spaces, with
//! `test_` and a colon begins a case; a line that starts with `#_` is an annotation `KEY VALUE`
//! of the current case, with trailing white space trimmed. Everything else is ignored, including
//! labels inside a case and commented-out annotations (`#  #_ ...`).

use crate::values::{parse_fpr, parse_memory, parse_register, parse_vector};

/// A register an annotation names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    /// `rN`.
    Gpr(u8),
    /// `fN`, as the bits of the double.
    Fpr(u8),
    /// `cr`, the eight fields packed into one word.
    Cr,
}

/// One annotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Annotation {
    /// `REGISTER_IN`: set before the case runs.
    RegisterIn(Register, u64),
    /// `REGISTER_OUT`: expected after it.
    RegisterOut(Register, u64),
    /// `REGISTER_IN` of `vN`: its four words, word 0 the most significant, set before the case.
    VectorIn(u8, [u32; 4]),
    /// `REGISTER_OUT` of `vN`: its four words, expected after the case.
    VectorOut(u8, [u32; 4]),
    /// `MEMORY_IN`: bytes written before the case runs.
    MemoryIn(u32, Vec<u8>),
    /// `MEMORY_OUT`: bytes expected after it.
    MemoryOut(u32, Vec<u8>),
}

/// A case of a test file: its symbol and its annotations, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Case {
    /// The label, `test_` and the case name.
    pub symbol: String,
    /// The annotations, in file order.
    pub annotations: Vec<Annotation>,
}

/// Reads the cases of a test file.
pub fn parse_cases(source: &str) -> Result<Vec<Case>, String> {
    let mut cases: Vec<Case> = Vec::new();
    for (index, line) in source.split('\n').enumerate() {
        let start = line.trim_start_matches(' ');
        let at = |message: String| format!("line {}: {message}", index + 1);
        if start.starts_with("test_") {
            let (label, _) = start
                .split_once(':')
                .ok_or_else(|| at(format!("a test label without a colon: {line:?}")))?;
            cases.push(Case {
                symbol: label.to_owned(),
                annotations: Vec::new(),
            });
        } else if start.len() > 3 && start.starts_with("#_") {
            // As in Xenia, the key starts at the fourth character and ends at the next space; a
            // line without that space is not an annotation.
            let Some((key, value)) = start[3..].split_once(' ') else {
                continue;
            };
            let value = value.trim_end_matches([' ', '\t', '\r']);
            let annotation = parse_annotation(key, value).map_err(at)?;
            cases
                .last_mut()
                .ok_or_else(|| at("an annotation before the first case".to_owned()))?
                .annotations
                .push(annotation);
        }
    }
    Ok(cases)
}

fn parse_annotation(key: &str, value: &str) -> Result<Annotation, String> {
    match key {
        "REGISTER_IN" | "REGISTER_OUT" => {
            let (name, number) = value
                .split_once(' ')
                .ok_or_else(|| format!("a register annotation without a value: {value:?}"))?;
            let input = key == "REGISTER_IN";
            let register = match parse_register_name(name)? {
                Name::Vector(n) => {
                    let words = parse_vector(number)?;
                    return Ok(if input {
                        Annotation::VectorIn(n, words)
                    } else {
                        Annotation::VectorOut(n, words)
                    });
                }
                Name::Scalar(register) => register,
            };
            let number = match register {
                Register::Fpr(_) => parse_fpr(number)?,
                Register::Gpr(_) | Register::Cr => parse_register(number)?,
            };
            Ok(if input {
                Annotation::RegisterIn(register, number)
            } else {
                Annotation::RegisterOut(register, number)
            })
        }
        "MEMORY_IN" => parse_memory(value).map(|(addr, bytes)| Annotation::MemoryIn(addr, bytes)),
        "MEMORY_OUT" => parse_memory(value).map(|(addr, bytes)| Annotation::MemoryOut(addr, bytes)),
        _ => Err(format!("unknown annotation {key:?}")),
    }
}

/// What a register name names: a register of 64 bits or fewer, or a vector register.
enum Name {
    Scalar(Register),
    Vector(u8),
}

fn parse_register_name(name: &str) -> Result<Name, String> {
    if name == "cr" {
        return Ok(Name::Scalar(Register::Cr));
    }
    let number = |prefix: char, count: u8| match name.strip_prefix(prefix)?.parse::<u8>() {
        Ok(n) if n < count => Some(n),
        _ => None,
    };
    if let Some(n) = number('r', 32) {
        return Ok(Name::Scalar(Register::Gpr(n)));
    }
    if let Some(n) = number('f', 32) {
        return Ok(Name::Scalar(Register::Fpr(n)));
    }
    if let Some(n) = number('v', 128) {
        return Ok(Name::Vector(n));
    }
    Err(format!("unknown register {name:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn annotations_follow_their_case_up_to_the_next() {
        let source = "test_a:\n  #_ REGISTER_IN r4 1\n  add r3, r4, r4\nlabel_inside:\n  blr\n  #_ REGISTER_OUT r3 2 \t\n\ntest_b:\n  #_ MEMORY_IN 10001000 0a\n  # #_ REGISTER_OUT r3 9\n  #_ REGISTER_OUT cr 0x20000000\n";
        let cases = parse_cases(source).unwrap();
        assert_eq!(
            cases,
            [
                Case {
                    symbol: "test_a".into(),
                    annotations: vec![
                        Annotation::RegisterIn(Register::Gpr(4), 1),
                        Annotation::RegisterOut(Register::Gpr(3), 2),
                    ],
                },
                Case {
                    symbol: "test_b".into(),
                    annotations: vec![
                        Annotation::MemoryIn(0x1000_1000, vec![0x0A]),
                        Annotation::RegisterOut(Register::Cr, 0x2000_0000),
                    ],
                },
            ]
        );
    }

    #[test]
    fn fpr_annotations_hold_the_bits() {
        let source = "test_f:\n  #_ REGISTER_IN f1 -1234.0\n  #_ REGISTER_IN f31 0x400C000000000000\n  #_ REGISTER_OUT f0 0.0\n";
        assert_eq!(
            parse_cases(source).unwrap()[0].annotations,
            [
                Annotation::RegisterIn(Register::Fpr(1), 0xC093_4800_0000_0000),
                Annotation::RegisterIn(Register::Fpr(31), 0x400C_0000_0000_0000),
                Annotation::RegisterOut(Register::Fpr(0), 0),
            ]
        );
    }

    #[test]
    fn vector_annotations_hold_four_words() {
        let source = "test_v:\n  #_ REGISTER_IN v3 [00010203, 04050607, 08090A0B, 0C0D0E0F]\n  #_ REGISTER_OUT v127 [ffffffff, 0, 1, 80000000]\n";
        assert_eq!(
            parse_cases(source).unwrap()[0].annotations,
            [
                Annotation::VectorIn(3, [0x0001_0203, 0x0405_0607, 0x0809_0A0B, 0x0C0D_0E0F]),
                Annotation::VectorOut(127, [u32::MAX, 0, 1, 0x8000_0000]),
            ]
        );
    }

    #[test]
    fn malformed_annotations_are_errors() {
        assert!(
            parse_cases("  #_ REGISTER_IN r3 1\n").is_err(),
            "before any case"
        );
        assert!(parse_cases("test_a:\n  #_ REGISTER_IN r32 1\n").is_err());
        assert!(parse_cases("test_a:\n  #_ REGISTER_IN v128 [0, 0, 0, 0]\n").is_err());
        assert!(parse_cases("test_a:\n  #_ REGISTER_IN v1 [0, 0, 0]\n").is_err());
        assert!(parse_cases("test_a:\n  #_ REGISTER_IN f32 1.0\n").is_err());
        assert!(parse_cases("test_a:\n  #_ REGISTER_IN f1 nan\n").is_err());
        assert!(parse_cases("test_a:\n  #_ REGISTER_IN r3\n").is_err());
        assert!(parse_cases("test_a:\n  #_ SOMETHING r3 1\n").is_err());
        assert!(parse_cases("test_a\n").is_err());
        // A `#_` line without a space after the key is not an annotation.
        assert_eq!(
            parse_cases("test_a:\n  #_ NOTHING\n").unwrap()[0].annotations,
            []
        );
    }
}
