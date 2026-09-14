//! Editing a PE/COFF image after the linker has written it.
//!
//! The EFI stub is the kernel as its own UEFI application: one file the firmware starts,
//! with no separate loader beside it on the partition. rustc and lld-link produce the
//! stub's own code as a PE; what they cannot do is put a *kernel* inside it, because the
//! kernel is a separate link for a different target, built minutes later and stamped with
//! its build ID after that.
//!
//! So kbuild adds it here, in two steps that are deliberately dumb:
//!
//! 1. [`add_section`] appends the kernel's bytes to the PE as one more section. The
//!    firmware loads every section it is told about, so the kernel arrives in memory with
//!    the stub and needs no filesystem to read.
//! 2. [`stamp`] writes where that section landed into a marked descriptor the stub
//!    declares, so the stub finds the kernel by reading a struct rather than by parsing
//!    its own headers in the boot path. The marker discipline is `buildid`'s: exactly one
//!    occurrence, or the build fails.
//!
//! # What is not touched
//!
//! The PE checksum stays whatever the linker wrote. Firmware does not verify it for an
//! application, and a checksum this code maintained would be one more thing to be wrong.
//! The timestamp stays too: lld-link is given `/Brepro`, which replaces it with a hash of
//! the input, so two builds of one tree produce the same bytes and editing that field
//! would be the only reason they did not.

/// Offsets into the headers, from the PE/COFF specification. Named rather than inlined
/// because a wrong constant here produces an image that loads and then does not run.
mod at {
    /// In the DOS header: the file offset of the PE signature.
    pub const E_LFANEW: usize = 0x3c;
    /// From the COFF header's start.
    pub const NUMBER_OF_SECTIONS: usize = 2;
    pub const SIZE_OF_OPTIONAL_HEADER: usize = 16;
    /// From the optional header's start, PE32+ only.
    pub const OPT_MAGIC: usize = 0;
    pub const SECTION_ALIGNMENT: usize = 32;
    pub const FILE_ALIGNMENT: usize = 36;
    pub const SIZE_OF_IMAGE: usize = 56;
    pub const SIZE_OF_HEADERS: usize = 60;
    /// From a section header's start.
    pub const SEC_VIRTUAL_SIZE: usize = 8;
    pub const SEC_VIRTUAL_ADDRESS: usize = 12;
    pub const SEC_SIZE_OF_RAW_DATA: usize = 16;
    pub const SEC_POINTER_TO_RAW_DATA: usize = 20;
    pub const SEC_CHARACTERISTICS: usize = 36;
}

/// Bytes in one section header.
const SECTION_HEADER: usize = 40;

/// Bytes in the COFF header, between the signature and the optional header.
const COFF_HEADER: usize = 20;

/// `IMAGE_NT_OPTIONAL_HDR64_MAGIC`: the only kind of image this edits.
const PE32PLUS: u16 = 0x20b;

/// Initialised data, readable, not writable and not executable: what a blob the stub only
/// reads should be. The firmware maps it as part of the image.
pub const DATA_SECTION: u32 = 0x4000_0040;

/// What precedes the words [`stamp`] writes into the EFI stub. Must match the `MARKER`
/// the stub declares in `boot/kinboot-stub/src/main.rs`.
///
/// Sixteen bytes, a multiple of the words' alignment, because [`stamp`] writes the words
/// immediately after the marker and the stub's struct puts them after its own padding.
/// The first version was twelve: the stub read every word four bytes late, and the first
/// boot reported a kernel of 2.3 petabytes. The stub now asserts the layout at compile time.
pub const KERNEL_BLOB_MARKER: &[u8] = b"KinTane-KERNEL:\0";

/// A PE image's geometry, as far as this module needs it.
#[derive(Debug)]
pub struct Headers {
    /// File offset of the PE signature.
    pub pe: usize,
    pub sections: usize,
    pub section_table: usize,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
}

fn u16_at(b: &[u8], at: usize) -> Result<u16, String> {
    b.get(at..at + 2)
        .and_then(|s| s.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or_else(|| format!("the PE image ends inside its headers, at {at:#x}"))
}

fn u32_at(b: &[u8], at: usize) -> Result<u32, String> {
    b.get(at..at + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| format!("the PE image ends inside its headers, at {at:#x}"))
}

fn put_u16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_u32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn align_up(v: u64, to: u64) -> Result<u64, String> {
    if to == 0 || !to.is_power_of_two() {
        return Err(format!("alignment {to:#x} in the PE headers is not a power of two"));
    }
    v.checked_add(to - 1)
        .map(|s| s & !(to - 1))
        .ok_or_else(|| format!("{v:#x} rounded up to {to:#x} overflows"))
}

impl Headers {
    /// Read the headers of `image`.
    pub fn parse(image: &[u8]) -> Result<Headers, String> {
        if image.get(..2) != Some(b"MZ") {
            return Err("not a PE image: no MZ signature".into());
        }
        let pe = u32_at(image, at::E_LFANEW)? as usize;
        if image.get(pe..pe + 4) != Some(b"PE\0\0") {
            return Err(format!("not a PE image: no PE signature at {pe:#x}"));
        }
        let coff = pe + 4;
        let sections = usize::from(u16_at(image, coff + at::NUMBER_OF_SECTIONS)?);
        let optional = usize::from(u16_at(image, coff + at::SIZE_OF_OPTIONAL_HEADER)?);
        let opt = coff + COFF_HEADER;
        let magic = u16_at(image, opt + at::OPT_MAGIC)?;
        if magic != PE32PLUS {
            return Err(format!(
                "the PE image is not PE32+ (optional header magic {magic:#x}); \
                 only the 64-bit form is edited here"
            ));
        }
        Ok(Headers {
            pe,
            sections,
            section_table: opt + optional,
            section_alignment: u32_at(image, opt + at::SECTION_ALIGNMENT)?,
            file_alignment: u32_at(image, opt + at::FILE_ALIGNMENT)?,
            size_of_image: u32_at(image, opt + at::SIZE_OF_IMAGE)?,
            size_of_headers: u32_at(image, opt + at::SIZE_OF_HEADERS)?,
        })
    }

    /// The name, address and size of each section, in table order.
    pub fn sections(&self, image: &[u8]) -> Result<Vec<(String, u32, u32)>, String> {
        let mut out = Vec::with_capacity(self.sections);
        for i in 0..self.sections {
            let h = self.section_table + i * SECTION_HEADER;
            let raw = image
                .get(h..h + 8)
                .ok_or_else(|| format!("the PE image ends inside section header {i}"))?;
            let name = raw
                .iter()
                .take_while(|b| **b != 0)
                .map(|b| char::from(*b))
                .collect();
            out.push((
                name,
                u32_at(image, h + at::SEC_VIRTUAL_ADDRESS)?,
                u32_at(image, h + at::SEC_VIRTUAL_SIZE)?,
            ));
        }
        Ok(out)
    }
}

/// Append `data` to `image` as a new section called `name`, and return the new image and
/// the address the section will have once the firmware has loaded it.
///
/// The address is a relative virtual address: what to add to the image base the firmware
/// chooses. The stub is relocatable — lld-link emits `.reloc` — so the base is not known
/// until it runs, and nothing here may assume one.
pub fn add_section(
    image: &[u8],
    name: &str,
    data: &[u8],
    characteristics: u32,
) -> Result<(Vec<u8>, u32), String> {
    let h = Headers::parse(image)?;
    if name.len() > 8 {
        return Err(format!("a PE section name is at most 8 bytes; `{name}` is {}", name.len()));
    }
    if h.sections(image)?.iter().any(|(n, _, _)| n == name) {
        return Err(format!("the PE image already has a `{name}` section"));
    }

    // The linker leaves the headers padded to SizeOfHeaders, which is normally room for
    // a dozen more section headers. Growing them instead would mean moving every
    // section's raw data and rewriting every pointer to it, so this refuses rather than
    // doing that silently.
    let table_end = h.section_table + (h.sections + 1) * SECTION_HEADER;
    if table_end > h.size_of_headers as usize {
        return Err(format!(
            "no room in the PE headers for another section: the table would end at \
             {table_end:#x}, past SizeOfHeaders {:#x}",
            h.size_of_headers
        ));
    }

    let file_alignment = u64::from(h.file_alignment);
    let section_alignment = u64::from(h.section_alignment);
    let raw_pointer = align_up(image.len() as u64, file_alignment)?;
    let raw_size = align_up(data.len() as u64, file_alignment)?;
    // SizeOfImage covers the headers and every section, already rounded to the section
    // alignment, so the next free address is exactly it.
    let rva = align_up(u64::from(h.size_of_image), section_alignment)?;
    let end = rva
        .checked_add(data.len() as u64)
        .ok_or("the PE image would extend past the end of its address space")?;
    let size_of_image = align_up(end, section_alignment)?;
    let fits = |v: u64, what: &str| {
        u32::try_from(v).map_err(|_| format!("{what} {v:#x} does not fit a PE header field"))
    };

    let mut out = image.to_vec();
    out.resize(raw_pointer as usize, 0);
    out.extend_from_slice(data);
    out.resize((raw_pointer + raw_size) as usize, 0);

    let head = h.section_table + h.sections * SECTION_HEADER;
    let mut header = [0u8; SECTION_HEADER];
    header[..name.len()].copy_from_slice(name.as_bytes());
    put_u32(&mut header, at::SEC_VIRTUAL_SIZE, fits(data.len() as u64, "a section's size")?);
    put_u32(&mut header, at::SEC_VIRTUAL_ADDRESS, fits(rva, "a section's address")?);
    put_u32(&mut header, at::SEC_SIZE_OF_RAW_DATA, fits(raw_size, "a section's raw size")?);
    put_u32(
        &mut header,
        at::SEC_POINTER_TO_RAW_DATA,
        fits(raw_pointer, "a section's file offset")?,
    );
    put_u32(&mut header, at::SEC_CHARACTERISTICS, characteristics);
    out[head..head + SECTION_HEADER].copy_from_slice(&header);

    let coff = h.pe + 4;
    put_u16(
        &mut out,
        coff + at::NUMBER_OF_SECTIONS,
        fits(h.sections as u64 + 1, "a section count")? as u16,
    );
    let opt = coff + COFF_HEADER;
    put_u32(&mut out, opt + at::SIZE_OF_IMAGE, fits(size_of_image, "SizeOfImage")?);
    Ok((out, fits(rva, "a section's address")?))
}

/// Write `values` into `image` after the one occurrence of `marker`, as little-endian
/// 64-bit words.
///
/// The stub declares the marker and the words after it as a static, and reads them at run
/// time. Two occurrences mean the marker is in the stub's own search code as well as in
/// its data, and one means neither; both are build failures rather than a stub that reads
/// the wrong bytes, which is the rule `buildid` already follows for the build ID.
pub fn stamp(image: &mut [u8], marker: &[u8], values: &[u64]) -> Result<(), String> {
    let mut found = Vec::new();
    let mut at = 0;
    while let Some(i) = image[at..].windows(marker.len()).position(|w| w == marker) {
        found.push(at + i);
        at += i + 1;
    }
    let text = String::from_utf8_lossy(marker).into_owned();
    match found.len() {
        1 => {}
        0 => return Err(format!("the image carries no `{text}` marker")),
        n => return Err(format!("the image carries {n} `{text}` markers; it must carry one")),
    }
    let start = found[0] + marker.len();
    let end = start + values.len() * 8;
    if end > image.len() {
        return Err(format!("the `{text}` marker is too close to the end of the image"));
    }
    for (i, v) in values.iter().enumerate() {
        image[start + i * 8..start + (i + 1) * 8].copy_from_slice(&v.to_le_bytes());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A PE32+ image with `sections` sections and room in its headers, laid out the way
    /// lld-link lays one out: headers padded to SizeOfHeaders, sections at increasing
    /// addresses.
    fn image(sections: usize, size_of_headers: u32) -> Vec<u8> {
        let pe = 0x80usize;
        let optional = 240usize;
        let table = pe + 4 + COFF_HEADER + optional;
        let mut v = vec![0u8; size_of_headers as usize];
        v[..2].copy_from_slice(b"MZ");
        put_u32(&mut v, at::E_LFANEW, pe as u32);
        v[pe..pe + 4].copy_from_slice(b"PE\0\0");
        let coff = pe + 4;
        put_u16(&mut v, coff + at::NUMBER_OF_SECTIONS, sections as u16);
        put_u16(&mut v, coff + at::SIZE_OF_OPTIONAL_HEADER, optional as u16);
        let opt = coff + COFF_HEADER;
        put_u16(&mut v, opt + at::OPT_MAGIC, PE32PLUS);
        put_u32(&mut v, opt + at::SECTION_ALIGNMENT, 0x1000);
        put_u32(&mut v, opt + at::FILE_ALIGNMENT, 0x200);
        put_u32(&mut v, opt + at::SIZE_OF_HEADERS, size_of_headers);
        for i in 0..sections {
            let h = table + i * SECTION_HEADER;
            let name = format!(".s{i}");
            v[h..h + name.len()].copy_from_slice(name.as_bytes());
            put_u32(&mut v, h + at::SEC_VIRTUAL_ADDRESS, 0x1000 * (i as u32 + 1));
            put_u32(&mut v, h + at::SEC_VIRTUAL_SIZE, 0x40);
            put_u32(&mut v, h + at::SEC_SIZE_OF_RAW_DATA, 0x200);
            put_u32(&mut v, h + at::SEC_POINTER_TO_RAW_DATA, size_of_headers + 0x200 * i as u32);
        }
        put_u32(&mut v, opt + at::SIZE_OF_IMAGE, 0x1000 * (sections as u32 + 1));
        // Raw data for each section, so the file is as long as its headers describe.
        v.resize(size_of_headers as usize + 0x200 * sections, 0);
        v
    }

    #[test]
    fn an_added_section_is_where_the_headers_say_it_is() {
        let before = image(4, 0x400);
        let data: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let (after, rva) = add_section(&before, ".kernel", &data, DATA_SECTION).unwrap();
        let h = Headers::parse(&after).unwrap();
        assert_eq!(h.sections, 5, "the section count grew by one");
        let (name, va, size) = h.sections(&after).unwrap().pop().unwrap();
        assert_eq!((name.as_str(), va, size), (".kernel", rva, data.len() as u32));
        // The raw data is where the header points, and the bytes are the ones given.
        let head = h.section_table + 4 * SECTION_HEADER;
        let ptr = u32_at(&after, head + at::SEC_POINTER_TO_RAW_DATA).unwrap() as usize;
        assert_eq!(&after[ptr..ptr + data.len()], &data[..]);
        assert_eq!(ptr % 0x200, 0, "raw data is file-aligned");
        assert_eq!(rva % 0x1000, 0, "the address is section-aligned");
        assert!(h.size_of_image >= rva + data.len() as u32, "SizeOfImage covers the section");
        assert_eq!(h.size_of_image % 0x1000, 0, "SizeOfImage is section-aligned");
    }

    #[test]
    fn a_full_header_area_is_refused_rather_than_grown() {
        // Headers sized to hold exactly the sections already there.
        let pe = 0x80 + 4 + COFF_HEADER + 240;
        let full = (pe + 4 * SECTION_HEADER) as u32;
        let before = image(4, full);
        let e = add_section(&before, ".kernel", b"x", DATA_SECTION).unwrap_err();
        assert!(e.contains("no room in the PE headers"), "{e}");
    }

    #[test]
    fn a_second_section_of_the_same_name_is_refused() {
        let before = image(2, 0x400);
        let (once, _) = add_section(&before, ".kernel", b"x", DATA_SECTION).unwrap();
        let e = add_section(&once, ".kernel", b"y", DATA_SECTION).unwrap_err();
        assert!(e.contains("already has"), "{e}");
    }

    #[test]
    fn only_a_pe32_plus_image_is_edited() {
        let mut v = image(1, 0x400);
        let opt = 0x80 + 4 + COFF_HEADER;
        put_u16(&mut v, opt + at::OPT_MAGIC, 0x10b);
        let e = Headers::parse(&v).unwrap_err();
        assert!(e.contains("not PE32+"), "{e}");
        let e = Headers::parse(b"not an image at all").unwrap_err();
        assert!(e.contains("no MZ signature"), "{e}");
    }

    #[test]
    fn stamping_needs_exactly_one_marker() {
        const M: &[u8] = b"KinTane-KRN:";
        let mut one = M.to_vec();
        one.extend_from_slice(&[0u8; 16]);
        stamp(&mut one, M, &[0x1234, 0x5678]).unwrap();
        assert_eq!(&one[M.len()..M.len() + 8], &0x1234u64.to_le_bytes());
        assert_eq!(&one[M.len() + 8..M.len() + 16], &0x5678u64.to_le_bytes());

        let none = &mut [0u8; 32][..];
        assert!(
            stamp(none, M, &[1])
                .unwrap_err()
                .contains("no `KinTane-KRN:` marker")
        );

        let mut twice = one.clone();
        twice.extend_from_slice(M);
        twice.extend_from_slice(&[0u8; 16]);
        assert!(
            stamp(&mut twice, M, &[1])
                .unwrap_err()
                .contains("2 `KinTane-KRN:` markers")
        );
    }

    #[test]
    fn stamping_past_the_end_is_refused() {
        const M: &[u8] = b"KinTane-KRN:";
        let mut short = M.to_vec();
        short.extend_from_slice(&[0u8; 4]);
        assert!(
            stamp(&mut short, M, &[1])
                .unwrap_err()
                .contains("too close to the end")
        );
    }
}
