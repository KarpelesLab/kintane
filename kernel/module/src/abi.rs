//! The kernel's interface to modules: every function a module may call.
//!
//! Adding a function is additive and changes nothing for modules that do not call it.
//! Changing a signature changes that function's interface hash, and every module that
//! imports it is refused until rebuilt, which is the point. Types stay FFI primitives, as
//! [`crate::interface`] explains.
//!
//! What a module holds on to is pinned by the kernel, not trusted to the module: a callback
//! registered with `kt_register_callback` takes a reference on the module, and the module
//! cannot unload until `kt_unregister_callback` gives it back. That is `docs/modules.md`'s
//! rule for function pointers into module text, in the one place today's interface has
//! one.

crate::declare_interface! {
    /// Write `len` bytes starting at `ptr` to the kernel console.
    fn kt_log(ptr: *const u8, len: usize);

    /// Register `callback` on behalf of `module`, which must be the id the module's init was
    /// given. Pins the module. Returns 0, or a negative value if the module already has a
    /// callback or the id is not a live module's.
    fn kt_register_callback(module: u32, callback: extern "C" fn(u64) -> u64) -> i32;

    /// Drop `module`'s callback and the reference it held. Returns 0, or a negative value if
    /// there was none.
    fn kt_unregister_callback(module: u32) -> i32;

    /// Report a panic inside a module and stop. A panic in kernel mode has nowhere to
    /// unwind to, module or not.
    fn kt_panic(ptr: *const u8, len: usize) -> !;
}
