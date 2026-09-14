//! `hwdomain` where there is no driver isolation: an empty library.
//!
//! The kernel image lists `hwdomain` among its dependencies in every configuration, so the
//! name needs a provider even where no domain program is built. Nothing reads this: the
//! kernel's isolation module is compiled only with `DRIVER_ISOLATION`, and it is the only
//! thing that would embed the program.

#![no_std]
#![deny(unsafe_code)]
