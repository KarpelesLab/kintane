//! A module that is correct in every way but one: kbuild builds it for another
//! configuration. Its code never runs; the loader must refuse it first.

#![no_std]

fn init(_id: u32) -> i32 {
    // Reads the configuration it was built for, so the build really used it.
    if kconfig::DEBUG_BUILD { 1 } else { 0 }
}

fn exit(_id: u32) {}

module::module!(init = init, exit = exit);
