//! `blkdomain` where there is no block driver domain: an empty library.
//!
//! The kernel image lists `blkdomain` among its dependencies in every configuration, so the
//! name needs a provider even where no domain program is built. Nothing reads this: the
//! kernel's block-domain module is compiled only with `BLOCK_DOMAIN`, and it is the only thing
//! that would embed the program.

#![no_std]
#![deny(unsafe_code)]
