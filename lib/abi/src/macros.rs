//! The macro the system call table is written in. See the crate documentation.

/// Declare the system call table.
///
/// ```text
/// syscalls! {
///     /// What the call does.
///     3 => fn debug_write(console: Handle, bytes: UserPtr, len: usize);
/// }
/// ```
///
/// Every argument type must implement [`crate::Arg`]. At most six arguments, which is what
/// both calling conventions pass in registers; a seventh is a compile error in
/// [`dispatch`](crate::dispatch), where the argument array is indexed.
#[macro_export]
macro_rules! syscalls {
    ($(
        $(#[doc = $doc:literal])*
        $num:literal => fn $name:ident($($arg:ident: $ty:ty),* $(,)?);
    )*) => {
        /// The system call numbers, one constant per call, named after it.
        #[allow(non_upper_case_globals)]
        pub mod number {
            $(
                $(#[doc = $doc])*
                pub const $name: u64 = $num;
            )*
        }

        /// Every system call, as the kernel implements it. The arguments have already
        /// passed [`crate::Arg::decode`]; everything a type cannot check, the method must.
        pub trait Handler {
            $(
                $(#[doc = $doc])*
                fn $name(&mut self, $($arg: $ty),*) -> Result<u64, $crate::Error>;
            )*
        }

        /// Decode system call `nr`'s arguments from the raw argument registers and run it.
        ///
        /// An unknown number is [`Error::NoSuchCall`](crate::Error::NoSuchCall), and an
        /// argument that does not decode ends the call with that argument's error before
        /// `handler` sees it.
        pub fn dispatch<H: Handler + ?Sized>(
            handler: &mut H,
            nr: u64,
            args: [u64; 6],
        ) -> Result<u64, $crate::Error> {
            match nr {
                $(
                    $num => {
                        let mut raw = args.into_iter();
                        let _ = &mut raw;
                        $(let $arg = <$ty as $crate::Arg>::decode(raw.next().unwrap_or(0))?;)*
                        handler.$name($($arg),*)
                    }
                )*
                _ => Err($crate::Error::NoSuchCall),
            }
        }

        /// The table as data: `(number, name, argument count)`, in declaration order.
        pub const TABLE: &[(u64, &str, usize)] = &[
            $(($num, stringify!($name), 0 $(+ { let _ = stringify!($arg); 1 })*),)*
        ];

        /// The userspace bindings: one function per call, trapping into the kernel.
        pub mod call {
            #[allow(unused_imports)]
            use super::*;
            $(
                $(#[doc = $doc])*
                pub fn $name($($arg: $ty),*) -> Result<u64, $crate::Error> {
                    let mut raw = [0u64; 6];
                    let mut slots = raw.iter_mut();
                    let _ = &mut slots;
                    $(
                        if let Some(slot) = slots.next() {
                            *slot = <$ty as $crate::Arg>::encode($arg);
                        }
                    )*
                    // SAFETY: a system call is a well-defined trap into the kernel, which
                    // validates every argument itself; nothing it returns is trusted as
                    // more than two numbers.
                    unsafe { $crate::raw::invoke(super::number::$name, raw) }
                }
            )*
        }
    };
}
