//! The slice of the UEFI specification KinTane's loaders call.
//!
//! Written out by hand rather than taken from a crate: units cannot pull crates, and D8
//! keeps third-party code out of the boot path anyway. Only what is called is described,
//! but every table is laid out in full up to the last member used, because a function
//! pointer table with one entry missing is not a smaller binding, it is a wrong one that
//! calls the neighbouring function.
//!
//! Layouts and numbers are from the UEFI 2.10 specification. Every function uses the
//! `efiapi` calling convention, which is the Microsoft x64 ABI on x86_64.
//!
//! One unit, shared by `kinboot-efi` and the EFI stub, so there is one table rather than
//! two that can disagree. Nothing in the kernel links it.

#![no_std]

pub mod handover;

/// What the handover needs that is not UEFI: a console for after the firmware's is gone,
/// and the jump into the kernel.
#[cfg(target_arch = "x86_64")]
#[path = "x86_64.rs"]
pub mod arch;

use core::ffi::c_void;

pub type Handle = *mut c_void;

/// A UEFI status. The top bit marks an error.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct Status(pub usize);

const ERROR_BIT: usize = 1 << (usize::BITS - 1);

impl Status {
    pub const SUCCESS: Status = Status(0);
    pub const LOAD_ERROR: Status = Status(ERROR_BIT | 1);
    pub const INVALID_PARAMETER: Status = Status(ERROR_BIT | 2);
    pub const BUFFER_TOO_SMALL: Status = Status(ERROR_BIT | 5);
    pub const NOT_READY: Status = Status(ERROR_BIT | 6);
    pub const OUT_OF_RESOURCES: Status = Status(ERROR_BIT | 9);
    pub const NOT_FOUND: Status = Status(ERROR_BIT | 14);

    pub fn is_error(self) -> bool {
        self.0 & ERROR_BIT != 0
    }

    /// `Ok` for success and warnings, which the specification says a caller may treat as
    /// success.
    pub fn ok(self) -> Result<(), Status> {
        if self.is_error() { Err(self) } else { Ok(()) }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Guid(pub u32, pub u16, pub u16, pub [u8; 8]);

#[repr(C)]
pub struct TableHeader {
    pub signature: u64,
    pub revision: u32,
    pub header_size: u32,
    pub crc32: u32,
    pub reserved: u32,
}

#[repr(C)]
pub struct SystemTable {
    pub hdr: TableHeader,
    pub firmware_vendor: *const u16,
    pub firmware_revision: u32,
    pub console_in_handle: Handle,
    pub con_in: *mut SimpleTextInput,
    pub console_out_handle: Handle,
    pub con_out: *mut SimpleTextOutput,
    pub standard_error_handle: Handle,
    pub std_err: *mut SimpleTextOutput,
    pub runtime_services: *mut RuntimeServices,
    pub boot_services: *mut BootServices,
    pub number_of_table_entries: usize,
    pub configuration_table: *const ConfigurationTable,
}

#[repr(C)]
pub struct ConfigurationTable {
    pub vendor_guid: Guid,
    pub vendor_table: *mut c_void,
}

/// `EFI_ALLOCATE_TYPE`.
pub const ALLOCATE_MAX_ADDRESS: u32 = 1;
pub const ALLOCATE_ADDRESS: u32 = 2;

type Unused = usize;

#[repr(C)]
pub struct BootServices {
    pub hdr: TableHeader,
    pub raise_tpl: Unused,
    pub restore_tpl: Unused,
    pub allocate_pages: unsafe extern "efiapi" fn(
        kind: u32,
        memory_type: u32,
        pages: usize,
        address: *mut u64,
    ) -> Status,
    pub free_pages: unsafe extern "efiapi" fn(address: u64, pages: usize) -> Status,
    pub get_memory_map: unsafe extern "efiapi" fn(
        size: *mut usize,
        map: *mut u8,
        key: *mut usize,
        descriptor_size: *mut usize,
        descriptor_version: *mut u32,
    ) -> Status,
    pub allocate_pool:
        unsafe extern "efiapi" fn(memory_type: u32, size: usize, buffer: *mut *mut u8) -> Status,
    pub free_pool: unsafe extern "efiapi" fn(buffer: *mut u8) -> Status,
    pub create_event: Unused,
    pub set_timer: Unused,
    pub wait_for_event: Unused,
    pub signal_event: Unused,
    pub close_event: Unused,
    pub check_event: Unused,
    pub install_protocol_interface: Unused,
    pub reinstall_protocol_interface: Unused,
    pub uninstall_protocol_interface: Unused,
    pub handle_protocol: unsafe extern "efiapi" fn(
        handle: Handle,
        protocol: *const Guid,
        interface: *mut *mut c_void,
    ) -> Status,
    pub reserved: Unused,
    pub register_protocol_notify: Unused,
    pub locate_handle: Unused,
    pub locate_device_path: Unused,
    pub install_configuration_table: Unused,
    pub load_image: unsafe extern "efiapi" fn(
        boot_policy: bool,
        parent: Handle,
        device_path: *const DevicePath,
        source: *const u8,
        source_size: usize,
        image: *mut Handle,
    ) -> Status,
    pub start_image: unsafe extern "efiapi" fn(
        image: Handle,
        exit_data_size: *mut usize,
        exit_data: *mut *mut u16,
    ) -> Status,
    pub exit: Unused,
    pub unload_image: Unused,
    pub exit_boot_services: unsafe extern "efiapi" fn(image: Handle, map_key: usize) -> Status,
    pub get_next_monotonic_count: Unused,
    pub stall: unsafe extern "efiapi" fn(microseconds: usize) -> Status,
    pub set_watchdog_timer: unsafe extern "efiapi" fn(
        timeout: usize,
        code: u64,
        data_size: usize,
        data: *const u16,
    ) -> Status,
}

#[repr(C)]
pub struct RuntimeServices {
    pub hdr: TableHeader,
    pub get_time: Unused,
    pub set_time: Unused,
    pub get_wakeup_time: Unused,
    pub set_wakeup_time: Unused,
    pub set_virtual_address_map: Unused,
    pub convert_pointer: Unused,
    pub get_variable: Unused,
    pub get_next_variable_name: Unused,
    pub set_variable: Unused,
    pub get_next_high_monotonic_count: Unused,
    pub reset_system: unsafe extern "efiapi" fn(
        kind: u32,
        status: Status,
        data_size: usize,
        data: *const c_void,
    ) -> !,
}

/// `EFI_RESET_TYPE`.
pub const RESET_COLD: u32 = 0;

#[repr(C)]
pub struct SimpleTextInput {
    pub reset: Unused,
    pub read_key_stroke:
        unsafe extern "efiapi" fn(this: *mut SimpleTextInput, key: *mut InputKey) -> Status,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct InputKey {
    /// `SCAN_UP` is 1 and `SCAN_DOWN` 2; zero for a key that has a character.
    pub scan_code: u16,
    pub unicode_char: u16,
}

pub const SCAN_UP: u16 = 1;
pub const SCAN_DOWN: u16 = 2;

pub const DEVICE_PATH_GUID: Guid =
    Guid(0x0957_6E91, 0x6D3F, 0x11D2, [0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B]);

/// The header every device path node starts with. A path is a sequence of nodes ending in
/// one of type [`DEVICE_PATH_END`].
#[repr(C)]
pub struct DevicePath {
    pub kind: u8,
    pub sub_kind: u8,
    pub length: [u8; 2],
}

pub const DEVICE_PATH_END: u8 = 0x7F;
pub const DEVICE_PATH_END_ENTIRE: u8 = 0xFF;
pub const DEVICE_PATH_MEDIA: u8 = 4;
pub const DEVICE_PATH_MEDIA_FILE: u8 = 4;

#[repr(C)]
pub struct SimpleTextOutput {
    pub reset: Unused,
    pub output_string:
        unsafe extern "efiapi" fn(this: *mut SimpleTextOutput, s: *const u16) -> Status,
}

pub const LOADED_IMAGE_GUID: Guid =
    Guid(0x5B1B_31A1, 0x9562, 0x11D2, [0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B]);

#[repr(C)]
pub struct LoadedImage {
    pub revision: u32,
    pub parent_handle: Handle,
    pub system_table: *mut SystemTable,
    pub device_handle: Handle,
    pub file_path: *mut c_void,
    pub reserved: *mut c_void,
    pub load_options_size: u32,
    pub load_options: *mut c_void,
    pub image_base: *mut c_void,
    pub image_size: u64,
    pub image_code_type: u32,
    pub image_data_type: u32,
    pub unload: Unused,
}

pub const SIMPLE_FILE_SYSTEM_GUID: Guid =
    Guid(0x964E_5B22, 0x6459, 0x11D2, [0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B]);

#[repr(C)]
pub struct SimpleFileSystem {
    pub revision: u64,
    pub open_volume:
        unsafe extern "efiapi" fn(this: *mut SimpleFileSystem, root: *mut *mut File) -> Status,
}

pub const FILE_MODE_READ: u64 = 1;

#[repr(C)]
pub struct File {
    pub revision: u64,
    pub open: unsafe extern "efiapi" fn(
        this: *mut File,
        new: *mut *mut File,
        name: *const u16,
        mode: u64,
        attributes: u64,
    ) -> Status,
    pub close: unsafe extern "efiapi" fn(this: *mut File) -> Status,
    pub delete: Unused,
    pub read:
        unsafe extern "efiapi" fn(this: *mut File, size: *mut usize, buffer: *mut u8) -> Status,
    pub write: Unused,
    pub get_position: unsafe extern "efiapi" fn(this: *mut File, position: *mut u64) -> Status,
    pub set_position: unsafe extern "efiapi" fn(this: *mut File, position: u64) -> Status,
}

pub const ACPI_20_TABLE_GUID: Guid =
    Guid(0x8868_E871, 0xE4F1, 0x11D3, [0xBC, 0x22, 0x00, 0x80, 0xC7, 0x3C, 0x88, 0x81]);

pub const ACPI_10_TABLE_GUID: Guid =
    Guid(0xEB9D_2D30, 0x2D88, 0x11D3, [0x9A, 0x16, 0x00, 0x90, 0x27, 0x3F, 0xC1, 0x4D]);

/// `EFI_MEMORY_DESCRIPTOR`, as far as this version describes it. Walk a map by the
/// descriptor size the firmware reports, never by `size_of` this: firmware is allowed to
/// append fields, and does.
#[repr(C)]
pub struct MemoryDescriptor {
    pub kind: u32,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub number_of_pages: u64,
    pub attribute: u64,
}
