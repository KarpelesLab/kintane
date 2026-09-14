//! The unit's register offsets and the command and status bits (VT-d §10.4).

/// Register offsets from the unit's register base.
pub mod reg {
    /// Version.
    pub const VER: usize = 0x00;
    /// Capabilities (64-bit).
    pub const CAP: usize = 0x08;
    /// Extended capabilities (64-bit).
    pub const ECAP: usize = 0x10;
    /// Global command (32-bit, write-only, one-shot).
    pub const GCMD: usize = 0x18;
    /// Global status (32-bit).
    pub const GSTS: usize = 0x1c;
    /// Root-table address (64-bit).
    pub const RTADDR: usize = 0x20;
    /// Context command (64-bit).
    pub const CCMD: usize = 0x28;
    /// Fault status (32-bit).
    pub const FSTS: usize = 0x34;
    /// Fault event control (32-bit).
    pub const FECTL: usize = 0x38;
    /// Interrupt remapping table address (64-bit).
    pub const IRTA: usize = 0xb8;

    /// Extended capability bits (VT-d §10.4.3).
    pub mod ecap {
        /// Interrupt remapping is supported.
        pub const IR: u64 = 1 << 3;
        /// Extended interrupt mode: 32-bit destinations, for x2APIC IDs.
        pub const EIM: u64 = 1 << 4;
    }

    /// Global command bits (VT-d §10.4.4). Each is a one-shot: written into the GSTS-shaped
    /// value, its effect read back from [`GSTS`].
    pub mod gcmd {
        /// Set root-table pointer.
        pub const SRTP: u32 = 1 << 30;
        /// Translation enable.
        pub const TE: u32 = 1 << 31;
        /// Set interrupt remapping table pointer.
        pub const SIRTP: u32 = 1 << 24;
        /// Interrupt remapping enable.
        pub const IRE: u32 = 1 << 25;
    }

    /// Global status bits (VT-d §10.4.5).
    pub mod gsts {
        /// Root-table pointer status: the pointer written with [`super::gcmd::SRTP`] is latched.
        pub const RTPS: u32 = 1 << 30;
        /// Translation enable status.
        pub const TES: u32 = 1 << 31;
        /// Compatibility format interrupt status: set, compatibility-format interrupts pass;
        /// clear, they are blocked while remapping is on.
        pub const CFIS: u32 = 1 << 23;
        /// Interrupt remapping table pointer status: the table written to `IRTA` is latched.
        pub const IRTPS: u32 = 1 << 24;
        /// Interrupt remapping enable status.
        pub const IRES: u32 = 1 << 25;
        /// Queued invalidation enable status.
        pub const QIES: u32 = 1 << 26;
    }

    /// Fault status bits (VT-d §10.4.9).
    pub mod fsts {
        /// Primary pending fault: at least one fault-recording register holds a fault.
        pub const PPF: u32 = 1 << 1;
        /// Primary fault overflow: a fault was dropped because the log was full.
        pub const PFO: u32 = 1 << 0;
    }
}
