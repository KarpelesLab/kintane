//! How the kernel's exports and a module's imports are declared, and checked against each
//! other.
//!
//! Rust has no stable ABI, so nothing a module imports is a Rust function. The interface is
//! a list of `extern "C"` functions whose parameters are primitives, raw pointers to
//! primitives, and `extern "C"` function pointers built from those. For such a signature
//! the text *is* the ABI: there is no layout to hide behind a type name. So the interface
//! hash of a function is a hash of its signature as written, and two functions with the
//! same name and hash really are interchangeable. `docs/modules.md` once promised a
//! structural hash from rustc's type information; that is what this becomes if the
//! interface ever admits a `#[repr(C)]` struct, and not before.
//!
//! One declaration serves both sides. [`declare_interface!`] turns a list of signatures
//! into:
//!
//! * `imports`: the `extern "C"` declarations a module calls;
//! * `types`: one function-pointer type per function, which the kernel's export table casts each
//!   implementation to, so an implementation that does not match its declaration does not compile;
//! * `SIGNATURES`: each function's name and interface hash.
//!
//! A module built with [`crate::module!`] records `SIGNATURES` in its
//! [`crate::IMPORTS_SECTION`]. The loader requires every symbol the module leaves undefined
//! to appear there with the hash the kernel exports it under.

/// FNV-1a, 64-bit. Chosen because it is a few lines of `const fn`, so a hash is computed
/// where the signature is declared, by the compiler, on both sides. It guards against
/// mistakes, not adversaries: a module that wants to lie can lie about anything, and
/// module signing is the answer to that.
pub const fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut i = 0;
    while i < bytes.len() {
        h ^= bytes[i] as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
        i += 1;
    }
    h
}

/// The longest function name an [`ImportRecord`] holds.
pub const NAME_MAX: usize = 55;

/// One function a module may import, as recorded in its imports section.
///
/// Fixed-size and pointer-free, so the section needs no relocation to be read: the loader
/// takes it straight from the file.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ImportRecord {
    pub name: [u8; NAME_MAX],
    pub name_len: u8,
    pub hash: u64,
}

impl ImportRecord {
    /// The size of one record in the section.
    pub const SIZE: usize = 64;

    pub const fn new(name: &str, hash: u64) -> ImportRecord {
        let b = name.as_bytes();
        assert!(b.len() <= NAME_MAX, "an imported function's name is too long");
        let mut out = [0u8; NAME_MAX];
        let mut i = 0;
        while i < b.len() {
            out[i] = b[i];
            i += 1;
        }
        ImportRecord {
            name: out,
            name_len: b.len() as u8,
            hash,
        }
    }

    pub fn name(&self) -> &[u8] {
        &self.name[..(self.name_len as usize).min(NAME_MAX)]
    }

    /// Read a record from the section's bytes.
    pub fn read(bytes: &[u8]) -> Option<ImportRecord> {
        let b: &[u8; 64] = bytes.get(..Self::SIZE)?.try_into().ok()?;
        let mut name = [0u8; NAME_MAX];
        name.copy_from_slice(&b[..NAME_MAX]);
        Some(ImportRecord {
            name,
            name_len: b[NAME_MAX],
            hash: u64::from_le_bytes(b[56..64].try_into().ok()?),
        })
    }

    /// Records for every function in an interface's `SIGNATURES`.
    pub const fn all<const N: usize>(signatures: &[(&str, u64)]) -> [ImportRecord; N] {
        assert!(signatures.len() == N, "one import record per signature");
        let mut out = [ImportRecord {
            name: [0; NAME_MAX],
            name_len: 0,
            hash: 0,
        }; N];
        let mut i = 0;
        while i < N {
            out[i] = ImportRecord::new(signatures[i].0, signatures[i].1);
            i += 1;
        }
        out
    }
}

/// One function the kernel exports to modules.
#[derive(Clone, Copy, Debug)]
pub struct Export {
    pub name: &'static str,
    pub hash: u64,
    pub addr: usize,
}

/// The interface hash of `name` in `signatures`, for building an export table. Fails to
/// compile, when used in a `const`, for a name the interface does not declare.
pub const fn hash_of(signatures: &[(&str, u64)], name: &str) -> u64 {
    let mut i = 0;
    while i < signatures.len() {
        if eq(signatures[i].0.as_bytes(), name.as_bytes()) {
            return signatures[i].1;
        }
        i += 1;
    }
    panic!("not a function of this interface");
}

const fn eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Declare an interface. See the module documentation.
///
/// ```ignore
/// module::declare_interface! {
///     /// Write bytes to the kernel console.
///     fn kt_log(ptr: *const u8, len: usize);
/// }
/// ```
#[macro_export]
macro_rules! declare_interface {
    ($( $(#[$attr:meta])* fn $name:ident($($arg:ident: $ty:ty),* $(,)?) $(-> $ret:ty)?; )*) => {
        /// What a module calls.
        pub mod imports {
            #[allow(unused_imports)]
            use super::*;
            unsafe extern "C" {
                $( $(#[$attr])* pub fn $name($($arg: $ty),*) $(-> $ret)?; )*
            }
        }

        /// One function-pointer type per function, named after it.
        #[allow(non_camel_case_types)]
        pub mod types {
            #[allow(unused_imports)]
            use super::*;
            $( pub type $name = unsafe extern "C" fn($($ty),*) $(-> $ret)?; )*
        }

        /// Each function's name and interface hash, in declaration order.
        pub const SIGNATURES: &[(&str, u64)] = &[
            $((
                stringify!($name),
                $crate::interface::fnv1a64(
                    concat!(
                        "fn ", stringify!($name), "(", $(stringify!($ty), ",",)* ")",
                        $(" -> ", stringify!($ret),)?
                    ).as_bytes()
                ),
            ),)*
        ];
    };
}

/// Build a kernel export table entry for `$name`, an implementation of `$iface::$name`.
/// The implementation is cast to the declared type, so a signature that differs from the
/// declaration is a compile error rather than a module calling it wrongly.
#[macro_export]
macro_rules! export {
    ($iface:path, $name:ident) => {{
        use $iface as iface;
        let f: iface::types::$name = $name;
        $crate::interface::Export {
            name: stringify!($name),
            hash: const { $crate::interface::hash_of(iface::SIGNATURES, stringify!($name)) },
            addr: f as usize,
        }
    }};
}

/// Declare a module's entry points, its panic handler and its import records.
///
/// `init` is `fn(u32) -> i32`, called with the module's id; non-zero refuses the load.
/// `exit` is `fn(u32)`, called before unloading. `interface` defaults to [`crate::abi`],
/// the kernel's interface; a module names another only to test the loader's refusal.
#[macro_export]
macro_rules! module {
    (init = $init:path, exit = $exit:path $(,)?) => {
        $crate::module!(init = $init, exit = $exit, interface = $crate::abi);
    };
    (init = $init:path, exit = $exit:path, interface = $iface:path $(,)?) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn kt_module_init(module: u32) -> i32 {
            $init(module)
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn kt_module_exit(module: u32) {
            $exit(module)
        }

        #[used]
        #[unsafe(link_section = ".kintane.imports")]
        static KINTANE_IMPORTS: [$crate::interface::ImportRecord; {
            use $iface as iface;
            iface::SIGNATURES.len()
        }] = {
            use $iface as iface;
            $crate::interface::ImportRecord::all(iface::SIGNATURES)
        };

        #[panic_handler]
        fn kintane_module_panic(_info: &core::panic::PanicInfo) -> ! {
            const WHAT: &str = concat!("panic in module ", module_path!());
            // SAFETY: `kt_panic` takes any byte range that is valid for reading, and does
            // not return.
            unsafe { $crate::abi::imports::kt_panic(WHAT.as_ptr(), WHAT.len()) }
        }
    };
}
