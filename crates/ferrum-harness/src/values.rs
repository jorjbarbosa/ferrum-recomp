// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Annotation values, read as Xenia's harness reads them, since the expected values of the suites
//! were produced that way.
//!
//! Register values follow `string_util::from_string` in Xenia's `src/xenia/base/string_util.h`.
//! Memory lines follow `SetupTestState` and `CheckTestResults` in
//! `src/xenia/cpu/ppc/testing/ppc_testing_main.cc`: two characters at a time, skipping spaces,
//! each pair read by `strtoul` in base 16.

/// Reads an FPR value into the bits of its double, as `fpfs` in Xenia's `string_util.h` reads it.
///
/// A value with a `0x` prefix after an optional `-`, or with an `h` suffix, is the bit pattern,
/// read as [`parse_register`] reads a GPR value, so a `-` negates the integer. Anything else is a
/// decimal number, rounded to the nearest double as `from_chars` and `strtod` read it, and negated
/// if it had a `-`. A decimal text that is not a number, such as `nan` or `inf`, is an error: a
/// NaN can only be meant by its bits.
pub fn parse_fpr(text: &str) -> Result<u64, String> {
    let (negative, rest) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    if rest.starts_with("0x") || rest.ends_with('h') {
        return parse_register(text);
    }
    if !is_decimal(rest) {
        return Err(format!(
            "the FPR value {text:?} is neither a decimal number nor 0x bits"
        ));
    }
    let value: f64 = rest
        .parse()
        .map_err(|_| format!("the FPR value {text:?} is not a number"))?;
    Ok(if negative { -value } else { value }.to_bits())
}

/// Reads a VR value into its four words, word 0 being the most significant, as
/// `from_string<vec128_t>` in Xenia's `string_util.h` reads it.
///
/// A value that starts with `[`, or with neither `[` nor `(`, is four hexadecimal words; one that
/// starts with `(` is four decimal numbers, each rounded to the nearest single and negated by a
/// leading `-`, as [`parse_fpr`] reads decimals, so `-0.0` is the negative zero. Spaces and commas
/// separate the values. Xenia stops reading after the fourth; here only spaces and the closing
/// bracket may follow, and anything else is an error, like a word that does not fit in 32 bits.
pub fn parse_vector(text: &str) -> Result<[u32; 4], String> {
    let (hex, body, close) = match text.as_bytes().first() {
        Some(b'[') => (true, &text[1..], "]"),
        Some(b'(') => (false, &text[1..], ")"),
        _ => (true, text, ""),
    };
    let mut rest = body;
    let mut words = [0; 4];
    for word in &mut words {
        rest = rest.trim_start_matches([' ', ',']);
        let end = rest.find([' ', ',', ']', ')']).unwrap_or(rest.len());
        let (token, tail) = rest.split_at(end);
        *word = if hex {
            vector_hex(token)
        } else {
            vector_decimal(token)
        }
        .ok_or_else(|| format!("the VR value {text:?} has no word in {token:?}"))?;
        rest = tail;
    }
    match rest.trim_matches(' ') {
        "" => Ok(words),
        tail if tail == close => Ok(words),
        tail => Err(format!(
            "the VR value {text:?} goes on after four words: {tail:?}"
        )),
    }
}

/// One hexadecimal word of a VR value: digits only, as `from_chars` in base 16 reads them.
fn vector_hex(token: &str) -> Option<u32> {
    if token.is_empty() || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(token, 16).ok()
}

/// One decimal lane of a VR value: the bits of the nearest single, negated by a leading `-`.
fn vector_decimal(token: &str) -> Option<u32> {
    let (negative, digits) = match token.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, token),
    };
    if !is_decimal(digits) {
        return None;
    }
    let value: f32 = digits.parse().ok()?;
    Some(if negative { -value } else { value }.to_bits())
}

/// Whether `text` is a decimal number: digits with an optional point, at least one digit, then an
/// optional exponent.
fn is_decimal(text: &str) -> bool {
    let (mantissa, exponent) = match text.find(['e', 'E']) {
        Some(at) => (&text[..at], Some(&text[at + 1..])),
        None => (text, None),
    };
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    let mantissa_ok =
        digits(whole) && digits(fraction) && !(whole.is_empty() && fraction.is_empty());
    let exponent_ok = exponent.is_none_or(|e| {
        let e = e.strip_prefix(['+', '-']).unwrap_or(e);
        !e.is_empty() && digits(e)
    });
    mantissa_ok && exponent_ok
}

/// Reads a register value: an optional `-`, then a `0x` prefix or an `h` suffix for hexadecimal,
/// then the longest run of digits, so `0x0123456789ABCDEFull` stops at the suffix.
///
/// Xenia returns 0 for a value with no digit or one past 64 bits; here those are errors, since no
/// test means them.
pub fn parse_register(text: &str) -> Result<u64, String> {
    let (negative, rest) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let (mut hex, mut rest) = match rest.strip_prefix("0x") {
        Some(rest) => (true, rest),
        None => (false, rest),
    };
    if let Some(stripped) = rest.strip_suffix('h') {
        hex = true;
        rest = stripped;
    }
    let radix = if hex { 16 } else { 10 };
    let digits = rest
        .find(|c: char| !c.is_digit(radix))
        .map_or(rest, |end| &rest[..end]);
    if digits.is_empty() {
        return Err(format!("no digits in the register value {text:?}"));
    }
    let value = u64::from_str_radix(digits, radix)
        .map_err(|_| format!("the register value {text:?} does not fit in 64 bits"))?;
    Ok(if negative {
        value.wrapping_neg()
    } else {
        value
    })
}

/// What C's `strtoul` returns for `text` in base 16, as the low 64 bits: leading white space, an
/// optional sign, an optional `0x`, then hexadecimal digits up to the first other character. No
/// digit at all gives 0. A minus sign negates the result in unsigned arithmetic.
fn strtoul16(text: &[u8]) -> u64 {
    let mut rest = text;
    while let [first, tail @ ..] = rest {
        if matches!(first, b' ' | b'\t' | b'\n' | 0x0B | 0x0C | b'\r') {
            rest = tail;
        } else {
            break;
        }
    }
    let negative = rest.first() == Some(&b'-');
    if let [b'+' | b'-', tail @ ..] = rest {
        rest = tail;
    }
    if let [b'0', b'x' | b'X', next, ..] = rest
        && next.is_ascii_hexdigit()
    {
        rest = &rest[2..];
    }
    let mut value: u64 = 0;
    for &c in rest.iter().take_while(|c| c.is_ascii_hexdigit()) {
        let digit = char::from(c).to_digit(16).expect("a hexadecimal digit");
        value = value.wrapping_mul(16).wrapping_add(u64::from(digit));
    }
    if negative {
        value.wrapping_neg()
    } else {
        value
    }
}

/// Reads a memory line, `ADDRESS BYTES`, into the address and the bytes.
///
/// The address goes through `strtoul` in base 16. The bytes are read two characters at a time,
/// skipping spaces between pairs, each pair through `strtoul`. For the bracketed lines of the
/// Canary tests that is not what the line says, `[AB, CD` gives `00 0B CD 00`, but it is how their
/// expected values were made. Those lines end in a lone `]`, which Xenia reads with the string's
/// terminator as one byte of value 0 before reading past the end; here the line ends after that
/// byte.
pub fn parse_memory(text: &str) -> Result<(u32, Vec<u8>), String> {
    let (address, bytes) = text
        .split_once(' ')
        .ok_or_else(|| format!("no bytes in the memory line {text:?}"))?;
    let address = strtoul16(address.as_bytes());
    let address = u32::try_from(address)
        .map_err(|_| format!("the address of {text:?} does not fit in 32 bits"))?;
    let chars = bytes.as_bytes();
    let mut values = Vec::new();
    let mut at = 0;
    while at < chars.len() {
        if chars[at] == b' ' {
            at += 1;
            continue;
        }
        let pair = &chars[at..chars.len().min(at + 2)];
        // Truncation to a byte is what Xenia's store of the result does.
        values.push(strtoul16(pair) as u8);
        at += 2;
    }
    Ok((address, values))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_values_follow_xenia() {
        assert_eq!(parse_register("0"), Ok(0));
        assert_eq!(parse_register("25"), Ok(25));
        assert_eq!(parse_register("-1"), Ok(u64::MAX));
        assert_eq!(parse_register("-50"), Ok(50u64.wrapping_neg()));
        assert_eq!(parse_register("0x00000000FFFFFFFF"), Ok(0xFFFF_FFFF));
        assert_eq!(
            parse_register("0xffffffff9e2a83c1"),
            Ok(0xFFFF_FFFF_9E2A_83C1)
        );
        assert_eq!(
            parse_register("0x0123456789ABCDEFull"),
            Ok(0x0123_4567_89AB_CDEF)
        );
        assert_eq!(parse_register("-0x10"), Ok(16u64.wrapping_neg()));
        assert_eq!(parse_register("1Fh"), Ok(0x1F));
        // Decimal stops at the first non-digit, as `from_chars` does.
        assert_eq!(parse_register("12abc"), Ok(12));
        assert!(parse_register("").is_err());
        assert!(parse_register("0x").is_err());
        assert!(parse_register("x12").is_err());
        assert!(parse_register("0x1FFFFFFFFFFFFFFFF").is_err());
    }

    #[test]
    fn fpr_values_are_bits_or_the_nearest_double() {
        assert_eq!(parse_fpr("1.0"), Ok(0x3FF0_0000_0000_0000));
        assert_eq!(parse_fpr("0.0"), Ok(0));
        // A minus sign negates the double, so -0.0 is the negative zero.
        assert_eq!(parse_fpr("-0.0"), Ok(0x8000_0000_0000_0000));
        assert_eq!(parse_fpr("-1234.0"), Ok(0xC093_4800_0000_0000));
        // The nearest doubles, as Python's float.hex gives them: 0x1.7d81d1ff5dcc6p+26, and
        // 0x1.6a09e667f3bcdp-1 (sqrt(0.5)).
        assert_eq!(parse_fpr("100009799.9901"), Ok(0x4197_D81D_1FF5_DCC6));
        assert_eq!(parse_fpr("0.70710678118654757"), Ok(0x3FE6_A09E_667F_3BCD));
        assert_eq!(parse_fpr("1e3"), Ok(1000.0f64.to_bits()));
        assert_eq!(parse_fpr(".5"), Ok(0x3FE0_0000_0000_0000));
        // Bits, as for a GPR: the minus sign negates the integer.
        assert_eq!(parse_fpr("0x400C000000000000"), Ok(0x400C_0000_0000_0000));
        assert_eq!(parse_fpr("0xFFFFFFFF80000000"), Ok(0xFFFF_FFFF_8000_0000));
        assert_eq!(parse_fpr("-0x10"), Ok(16u64.wrapping_neg()));
        assert_eq!(parse_fpr("7FF8h"), Ok(0x7FF8));
        for text in [
            "", "-", "nan", "inf", "-inf", "1.0.0", "1e", "e5", ".", "+1.0", "1.0f",
        ] {
            assert!(parse_fpr(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn vector_values_are_four_words_in_order() {
        let words = [0x0001_0203, 0x0405_0607, 0x0809_0A0B, 0x0C0D_0E0F];
        assert_eq!(
            parse_vector("[00010203, 04050607, 08090A0B, 0C0D0E0F]"),
            Ok(words)
        );
        assert_eq!(
            parse_vector("00010203 04050607,08090a0b 0c0d0e0f"),
            Ok(words)
        );
        assert_eq!(
            parse_vector("[ffffffff, 0, 1, 80000000 ]"),
            Ok([u32::MAX, 0, 1, 0x8000_0000])
        );
        // The decimal form: the nearest singles, a minus sign giving the negative zero.
        assert_eq!(
            parse_vector("(1.0, -0.0, 0.1, -2.5)"),
            Ok([0x3F80_0000, 0x8000_0000, 0x3DCC_CCCD, 0xC020_0000])
        );
        for text in [
            "",
            "[0, 0, 0]",
            "[0, 0, 0, 0, 0]",
            "[0, 0, 0, 0] x",
            "[0x1, 0, 0, 0]",
            "[+1, 0, 0, 0]",
            "[100000000, 0, 0, 0]",
            "[0, 0, 0, 0)",
            "(nan, 0, 0, 0)",
            "(1.0, 2.0, 3.0)",
        ] {
            assert!(parse_vector(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn strtoul_reads_what_c_reads() {
        assert_eq!(strtoul16(b"AB"), 0xAB);
        assert_eq!(strtoul16(b"[A"), 0);
        assert_eq!(strtoul16(b"B,"), 0x0B);
        assert_eq!(strtoul16(b", "), 0);
        assert_eq!(strtoul16(b"]"), 0);
        assert_eq!(strtoul16(b"\t7"), 7);
        assert_eq!(strtoul16(b"-1"), u64::MAX);
        assert_eq!(strtoul16(b"+F"), 0xF);
        assert_eq!(strtoul16(b"0x"), 0);
        assert_eq!(strtoul16(b"0x0000000010001000"), 0x1000_1000);
        assert_eq!(strtoul16(b"10001000"), 0x1000_1000);
    }

    #[test]
    fn memory_lines_are_read_in_pairs() {
        assert_eq!(
            parse_memory("10001000 00 01 02 0a 0B"),
            Ok((0x1000_1000, vec![0, 1, 2, 0x0A, 0x0B]))
        );
        assert_eq!(
            parse_memory("10001004 ABCDEF12 34567890"),
            Ok((
                0x1000_1004,
                vec![0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90]
            ))
        );
        // The bracketed form, as test_lwz_1 writes it: [A, B, then CD, then ", " and so on.
        let (address, bytes) =
            parse_memory("0x0000000010001000 [AB, CD, EF, 12, 34, 56, 78, 9A]").unwrap();
        assert_eq!(address, 0x1000_1000);
        assert_eq!(
            bytes,
            [
                0x00, 0x0B, 0xCD, 0x00, 0xEF, 0x00, 0x12, 0x00, 0x34, 0x00, 0x56, 0x00, 0x78, 0x00,
                0x9A, 0x00
            ]
        );
        // So test_lwz_1 loads 0x000BCD00, as it expects.
        assert_eq!(
            u32::from_be_bytes(bytes[..4].try_into().unwrap()),
            0x000B_CD00
        );
        assert!(parse_memory("10001000").is_err());
        assert!(parse_memory("100010000 00").is_err());
    }
}
