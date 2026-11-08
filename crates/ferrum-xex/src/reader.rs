// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Bounds-checked reads that name the offset and field when they fail.

use std::borrow::Cow;

use crate::error::{Error, ErrorKind, Location, Result};

/// The address space a [`Reader`] reports its offsets in.
#[derive(Debug, Clone, Copy)]
enum Space {
    File,
    Image,
}

/// A view over a byte buffer whose offsets start at the buffer's first byte.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    space: Space,
}

impl<'a> Reader<'a> {
    /// Reads from a XEX file, or from its decrypted form, which has the same layout.
    pub(crate) fn file(data: &'a [u8]) -> Self {
        Self {
            data,
            space: Space::File,
        }
    }

    /// Reads from a reconstructed image.
    pub(crate) fn image(data: &'a [u8]) -> Self {
        Self {
            data,
            space: Space::Image,
        }
    }

    /// Builds an error located at `offset`.
    pub(crate) fn error(
        &self,
        offset: u64,
        field: impl Into<Cow<'static, str>>,
        kind: ErrorKind,
    ) -> Error {
        let location = match self.space {
            Space::File => Location::File(offset),
            Space::Image => Location::Image(offset),
        };
        Error {
            location,
            field: field.into(),
            kind,
        }
    }

    /// Returns `len` bytes at `offset`.
    pub(crate) fn bytes(
        &self,
        offset: u64,
        len: u64,
        field: impl Into<Cow<'static, str>>,
    ) -> Result<&'a [u8]> {
        let slice = offset.checked_add(len).and_then(|end| {
            let start = usize::try_from(offset).ok()?;
            let end = usize::try_from(end).ok()?;
            self.data.get(start..end)
        });
        slice.ok_or_else(|| {
            let available = (self.data.len() as u64).saturating_sub(offset);
            self.error(
                offset,
                field,
                ErrorKind::Truncated {
                    needed: len,
                    available,
                },
            )
        })
    }

    /// Returns the `N` bytes at `offset`.
    pub(crate) fn array<const N: usize>(
        &self,
        offset: u64,
        field: impl Into<Cow<'static, str>>,
    ) -> Result<[u8; N]> {
        let bytes = self.bytes(offset, N as u64, field)?;
        let mut out = [0; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    /// Reads a big-endian `u16`.
    pub(crate) fn be_u16(&self, offset: u64, field: impl Into<Cow<'static, str>>) -> Result<u16> {
        self.array(offset, field).map(u16::from_be_bytes)
    }

    /// Reads a big-endian `u32`.
    pub(crate) fn be_u32(&self, offset: u64, field: impl Into<Cow<'static, str>>) -> Result<u32> {
        self.array(offset, field).map(u32::from_be_bytes)
    }

    /// Reads a little-endian `u16`.
    pub(crate) fn le_u16(&self, offset: u64, field: impl Into<Cow<'static, str>>) -> Result<u16> {
        self.array(offset, field).map(u16::from_le_bytes)
    }

    /// Reads a little-endian `u32`.
    pub(crate) fn le_u32(&self, offset: u64, field: impl Into<Cow<'static, str>>) -> Result<u32> {
        self.array(offset, field).map(u32::from_le_bytes)
    }

    /// Reads a NUL-terminated string at `offset`. Bytes that are not UTF-8 are replaced.
    pub(crate) fn c_string(
        &self,
        offset: u64,
        field: impl Into<Cow<'static, str>>,
    ) -> Result<String> {
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        let rest = self.data.get(start..).unwrap_or_default();
        match rest.iter().position(|&byte| byte == 0) {
            Some(end) => Ok(String::from_utf8_lossy(&rest[..end]).into_owned()),
            None => Err(self.error(
                offset,
                field,
                ErrorKind::Truncated {
                    needed: rest.len() as u64 + 1,
                    available: rest.len() as u64,
                },
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_big_endian_values() {
        let reader = Reader::file(&[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(reader.be_u16(1, "f"), Ok(0x3456));
        assert_eq!(reader.be_u32(0, "f"), Ok(0x1234_5678));
    }

    #[test]
    fn out_of_bounds_reads_report_offset_field_and_sizes() {
        let reader = Reader::file(&[0; 4]);
        let err = reader.be_u32(2, "some.field").unwrap_err();
        assert_eq!(err.location, Location::File(2));
        assert_eq!(err.field, "some.field");
        assert_eq!(
            err.kind,
            ErrorKind::Truncated {
                needed: 4,
                available: 2
            }
        );
    }

    #[test]
    fn offset_past_the_end_reports_no_available_bytes() {
        let reader = Reader::image(&[0; 4]);
        let err = reader.bytes(9, 1, "f").unwrap_err();
        assert_eq!(err.location, Location::Image(9));
        assert_eq!(
            err.kind,
            ErrorKind::Truncated {
                needed: 1,
                available: 0
            }
        );
    }

    #[test]
    fn reads_little_endian_values() {
        let reader = Reader::image(&[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(reader.le_u16(1, "f"), Ok(0x5634));
        assert_eq!(reader.le_u32(0, "f"), Ok(0x7856_3412));
    }

    #[test]
    fn reads_c_strings_and_rejects_unterminated_ones() {
        let reader = Reader::image(b"abc\0def");
        assert_eq!(reader.c_string(0, "f").unwrap(), "abc");
        assert_eq!(reader.c_string(3, "f").unwrap(), "");
        let err = reader.c_string(4, "f").unwrap_err();
        assert_eq!(err.location, Location::Image(4));
        assert!(matches!(err.kind, ErrorKind::Truncated { .. }));
        assert!(reader.c_string(99, "f").is_err());
    }

    #[test]
    fn huge_offsets_do_not_overflow() {
        let reader = Reader::file(&[0; 4]);
        assert!(reader.bytes(u64::MAX, 2, "f").is_err());
        assert!(reader.bytes(2, u64::MAX, "f").is_err());
    }
}
