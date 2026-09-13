//! A module compiled against a stale copy of the kernel's interface, in which
//! `kt_register_callback`'s callback takes and returns `u32`. Calling it with the kernel's
//! real function would pass a pointer to code with the wrong signature, so the loader must
//! refuse the module before any of its code runs.

#![no_std]

mod stale {
    module::declare_interface! {
        fn kt_log(ptr: *const u8, len: usize);
        fn kt_register_callback(module: u32, callback: extern "C" fn(u32) -> u32) -> i32;
        fn kt_unregister_callback(module: u32) -> i32;
        fn kt_panic(ptr: *const u8, len: usize) -> !;
    }
}

extern "C" fn callback(x: u32) -> u32 {
    x
}

fn init(id: u32) -> i32 {
    // SAFETY: this module is refused before it runs; the call exists so the module imports
    // the function whose interface is stale.
    unsafe { stale::imports::kt_register_callback(id, callback) }
}

fn exit(_id: u32) {}

module::module!(init = init, exit = exit, interface = stale);
