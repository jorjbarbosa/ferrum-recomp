// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The `ferrum dump` subcommand: a plain text listing of what a XEX file holds.
//!
//! The format is line-oriented and uses one fixed layout per section, so that it can be compared
//! with other tools and searched with ordinary text tools.

use std::fs;
use std::io::{self, BufWriter, ErrorKind, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use ferrum_xex::crypto::MasterKey;
use ferrum_xex::header::{Compression, Encryption, PageKind, key_name};
use ferrum_xex::{Image, ImportKind, ImportLibrary, Section, Warning, Xex};

/// Prints the contents of the XEX file at `path` to standard output.
///
/// Warnings go to standard error. With `strict`, they make the command fail instead.
pub fn run(path: &Path, strict: bool) -> Result<()> {
    let file = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    let xex = Xex::parse(&file).with_context(|| format!("cannot parse {}", path.display()))?;
    for warning in &xex.warnings {
        eprintln!("warning: {warning}");
    }
    if strict && !xex.warnings.is_empty() {
        bail!(
            "{}: {} warning(s) treated as errors by --strict",
            path.display(),
            xex.warnings.len()
        );
    }
    let mut out = BufWriter::new(io::stdout().lock());
    match write_dump(&mut out, &xex).and_then(|()| out.flush()) {
        // The reader went away, as with `ferrum dump game.xex | head`. That is not a failure.
        Err(error) if error.kind() == ErrorKind::BrokenPipe => Ok(()),
        result => result.context("cannot write the dump"),
    }
}

/// Writes the whole listing.
pub fn write_dump(out: &mut impl Write, xex: &Xex) -> io::Result<()> {
    write_header(out, xex)?;
    write_optional_headers(out, xex)?;
    write_image_summary(out, xex)?;
    write_pages(out, xex)?;
    write_sections(out, &xex.image)?;
    write_resources(out, xex)?;
    write_tls(out, &xex.image)?;
    write_pdata(out, &xex.image)?;
    write_imports(out, &xex.image)?;
    write_exports(out, &xex.image)
}

/// Writes the file header and the security info.
fn write_header(out: &mut impl Write, xex: &Xex) -> io::Result<()> {
    let header = &xex.header;
    let security = &header.security;
    writeln!(out, "== XEX2 header ==")?;
    let flags = header.module_flags;
    writeln!(out, "module flags:  {:#010x} {:?}", flags.0, flags.names())?;
    writeln!(out, "header size:   {:#x}", header.header_size)?;
    writeln!(out, "security info: {:#x}", header.security_offset)?;
    if let Some(name) = &header.original_pe_name {
        writeln!(out, "original PE:   {name}")?;
    }
    if let Some(info) = &header.execution_info {
        writeln!(out, "title id:      {:#010x}", info.title_id)?;
        writeln!(out, "version:       {}", info.version)?;
        writeln!(out, "base version:  {}", info.base_version)?;
        writeln!(
            out,
            "disc:          {}/{}",
            info.disc_number, info.disc_count
        )?;
    }
    if let Some(size) = header.default_stack_size {
        writeln!(out, "stack size:    {size:#x}")?;
    }
    if let Some(size) = header.default_heap_size {
        writeln!(out, "heap size:     {size:#x}")?;
    }
    if let Some(flags) = header.system_flags {
        writeln!(out, "system flags:  {flags:#010x}")?;
    }
    writeln!(out)?;
    writeln!(out, "== Security info ==")?;
    let image_flags = security.image_flags;
    writeln!(out, "image size:    {:#x}", security.image_size)?;
    writeln!(
        out,
        "image flags:   {:#010x} {:?}",
        image_flags.0,
        image_flags.names()
    )?;
    writeln!(out, "load address:  {:#010x}", security.load_address)?;
    writeln!(out, "page size:     {:#x}", security.page_size())?;
    writeln!(out, "export table:  {:#010x}", security.export_table)?;
    writeln!(out, "region:        {:#010x}", security.region)?;
    writeln!(out, "media types:   {:#010x}", security.allowed_media_types)?;
    writeln!(out, "import tables: {}", security.import_table_count)?;
    writeln!(out)
}

/// Writes the optional header directory.
fn write_optional_headers(out: &mut impl Write, xex: &Xex) -> io::Result<()> {
    let headers = &xex.header.optional_headers;
    writeln!(out, "== Optional headers ({}) ==", headers.len())?;
    for header in headers {
        let name = key_name(header.key).unwrap_or("unknown");
        writeln!(out, "{:#010x} {:#010x} {name}", header.key, header.value)?;
    }
    writeln!(out)
}

/// Writes what it took to get to the image, and how it checks out.
fn write_image_summary(out: &mut impl Write, xex: &Xex) -> io::Result<()> {
    let image = &xex.image;
    let encryption = match (xex.header.file_format.encryption, xex.key) {
        (Encryption::None, _) => "none",
        (Encryption::Normal, Some(MasterKey::Retail)) => "AES-128-CBC, retail key",
        (Encryption::Normal, Some(MasterKey::Devkit)) => "AES-128-CBC, devkit key",
        (Encryption::Normal, None) => "AES-128-CBC",
    };
    let compression = match &xex.header.file_format.compression {
        Compression::None => "none".to_owned(),
        Compression::Basic(blocks) => format!("basic, {} blocks", blocks.len()),
        Compression::Normal { window_size, .. } => format!("LZX, window {window_size:#x}"),
    };
    let digests = xex
        .warnings
        .iter()
        .any(|warning| matches!(warning, Warning::ImageDigestMismatch { .. }));
    writeln!(out, "== Image ==")?;
    writeln!(out, "base:          {:#010x}", image.base)?;
    writeln!(out, "entry point:   {:#010x}", image.entry)?;
    writeln!(out, "size:          {:#x}", image.data.len())?;
    writeln!(out, "encryption:    {encryption}")?;
    writeln!(out, "compression:   {compression}")?;
    let digests = if digests { "MISMATCH" } else { "ok" };
    writeln!(out, "page digests:  {digests}")?;
    writeln!(out, "PE timestamp:  {:#010x}", image.pe.time_date_stamp)?;
    writeln!(out)
}

/// Returns the name of a kind of pages.
fn page_kind_name(kind: PageKind) -> String {
    match kind {
        PageKind::Code => "code".to_owned(),
        PageKind::Data => "data".to_owned(),
        PageKind::ReadOnlyData => "read-only data".to_owned(),
        PageKind::Unknown(value) => format!("unknown ({value})"),
    }
}

/// Writes the memory map of the security info, joining neighbouring descriptors of the same kind.
fn write_pages(out: &mut impl Write, xex: &Xex) -> io::Result<()> {
    let security = &xex.header.security;
    let page_size = u64::from(security.page_size());
    let mut runs: Vec<(PageKind, u64, u64)> = Vec::new();
    let mut address = u64::from(xex.image.base);
    for descriptor in &security.page_descriptors {
        let end = address + u64::from(descriptor.page_count()) * page_size;
        match runs.last_mut() {
            Some(run) if run.0 == descriptor.kind() => run.2 = end,
            _ => runs.push((descriptor.kind(), address, end)),
        }
        address = end;
    }
    let count = security.page_descriptors.len();
    writeln!(out, "== Memory pages ({count} descriptors) ==")?;
    for (kind, start, end) in runs {
        writeln!(out, "{start:#010x}-{end:#010x} {}", page_kind_name(kind))?;
    }
    writeln!(out)
}

/// Returns a section's permissions in the usual `rwx` form.
fn permissions(section: &Section) -> String {
    let flag = |set: bool, letter| if set { letter } else { '-' };
    [
        flag(section.is_readable(), 'r'),
        flag(section.is_writable(), 'w'),
        flag(section.is_executable(), 'x'),
    ]
    .iter()
    .collect()
}

/// Writes the PE section table. The last column says how much of each section the image holds.
fn write_sections(out: &mut impl Write, image: &Image) -> io::Result<()> {
    writeln!(out, "== Sections ({}) ==", image.sections.len())?;
    writeln!(
        out,
        "name     address    end        vsize      raw-ptr    raw-size   flags      perm in-image"
    )?;
    for section in &image.sections {
        writeln!(
            out,
            "{:<8} {:#010x} {:#010x} {:#010x} {:#010x} {:#010x} {:#010x} {}  {:#x}",
            section.name,
            section.address,
            section.end(),
            section.virtual_size,
            section.raw_pointer,
            section.raw_size,
            section.characteristics,
            permissions(section),
            image.section_data(section).len(),
        )?;
    }
    writeln!(out)
}

/// Writes the resources.
fn write_resources(out: &mut impl Write, xex: &Xex) -> io::Result<()> {
    let resources = &xex.header.resources;
    writeln!(out, "== Resources ({}) ==", resources.len())?;
    for resource in resources {
        let (name, address, size) = (&resource.name, resource.address, resource.size);
        writeln!(out, "{address:#010x} {size:#010x} {name}")?;
    }
    writeln!(out)
}

/// Writes the thread-local storage layout.
fn write_tls(out: &mut impl Write, image: &Image) -> io::Result<()> {
    writeln!(out, "== TLS ==")?;
    match &image.tls {
        Some(tls) => {
            writeln!(out, "slots:         {}", tls.slot_count)?;
            writeln!(out, "data address:  {:#010x}", tls.raw_data_address)?;
            writeln!(out, "data size:     {:#x}", tls.data_size)?;
            writeln!(out, "raw data size: {:#x}", tls.raw_data_size)?;
        }
        None => writeln!(out, "none")?,
    }
    writeln!(out)
}

/// Writes `.pdata`.
fn write_pdata(out: &mut impl Write, image: &Image) -> io::Result<()> {
    writeln!(out, "== .pdata ({}) ==", image.pdata.len())?;
    writeln!(out, "begin      size       prolog flags")?;
    for function in &image.pdata {
        let mut flags = Vec::new();
        if function.is_32bit() {
            flags.push("32bit");
        }
        if function.has_exception_handler() {
            flags.push("eh");
        }
        writeln!(
            out,
            "{:#010x} {:#010x} {:<6} {}",
            function.begin,
            function.size(),
            function.prolog_words(),
            flags.join(",")
        )?;
    }
    writeln!(out)
}

/// Writes the imports, library by library.
fn write_imports(out: &mut impl Write, image: &Image) -> io::Result<()> {
    let total: usize = image.imports.iter().map(|lib| lib.imports.len()).sum();
    writeln!(out, "== Imports ({total}) ==")?;
    for library in &image.imports {
        write_import_library(out, library)?;
    }
    writeln!(out)
}

/// Writes the imports of one library.
fn write_import_library(out: &mut impl Write, library: &ImportLibrary) -> io::Result<()> {
    writeln!(
        out,
        "{} version {} min {} id {:#010x} ({} imports)",
        library.name,
        library.version,
        library.min_version,
        library.id,
        library.imports.len()
    )?;
    for import in &library.imports {
        let kind = match import.kind {
            ImportKind::Function => "function",
            ImportKind::Variable => "variable",
        };
        let address = |address: Option<u32>| match address {
            Some(address) => format!("{address:#010x}"),
            None => "-".to_owned(),
        };
        writeln!(
            out,
            "  {:#06x} {:<8} slot={} thunk={} {}",
            import.ordinal,
            kind,
            address(import.slot),
            address(import.thunk),
            import.name.unwrap_or("<unknown>"),
        )?;
    }
    Ok(())
}

/// Writes the exports.
fn write_exports(out: &mut impl Write, image: &Image) -> io::Result<()> {
    writeln!(out, "== Exports ({}) ==", image.exports.len())?;
    for export in &image.exports {
        let name = export.name.as_deref().unwrap_or("<unnamed>");
        writeln!(out, "{:<6} {:#010x} {name}", export.ordinal, export.address)?;
    }
    Ok(())
}
