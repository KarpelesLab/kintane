//! A program built for the hard-float target really does use floating-point instructions.
//!
//! `unit.float = "hard"` builds a user program, its `user`-layer closure and a `core` of its
//! own for `targets/<target>-hf.json` — the kernel's specification without `rustc-abi:
//! softfloat`, which is the field that rejects the floating-point features rather than the
//! feature string. If that ever silently stopped working — a dropped field, a flavor that
//! fell back to the kernel's target, a cache entry served across targets — the program would
//! still build and still pass, because `a * b` on a soft-float target is a call to
//! `__muldf3` that computes the same answer. Nothing about the program's behaviour would
//! say which target built it.
//!
//! So the image is checked from the outside, by disassembling it.
//!
//! # Why mnemonics and not register names
//!
//! The obvious check — "does a floating-point register appear" — does not work, and the way
//! it fails is worth recording. On aarch64 a *soft-float* `init` disassembles with 59 matches
//! for `\bd[0-9]+\b`, more than the hard-float program has, because objdump prints the
//! instruction's encoding beside it and `sub x9, x27, #1` encodes as `d1000769`. The `d1`
//! there is a byte, not a register. On x86_64 the same check happens to work (a soft-float
//! program has no `xmm` at all), which is exactly the sort of coincidence that makes a check
//! look sound on one port and meaningless on another.
//!
//! Arithmetic mnemonics discriminate on both: zero in every soft-float program, eight in each
//! hard-float one at the time of writing.

use std::path::Path;
use std::process::Command;

/// The instructions that only a hard-float build emits. Arithmetic and conversion, not
/// moves: a soft-float build moves floats around in general-purpose registers happily, and
/// on aarch64 it moves eight-byte values through `d` registers as well.
const X86_64: &[&str] = &[
    "mulsd",
    "addsd",
    "subsd",
    "divsd",
    "mulss",
    "addss",
    "cvtsi2sd",
    "cvttsd2si",
];
const AARCH64: &[&str] = &["fmul", "fadd", "fsub", "fdiv", "scvtf", "fcvtzs"];

/// The mnemonics to look for in a program built for `target_name`, or `None` where the
/// architecture has no hard-float specification and no program can ask for one.
fn mnemonics(target_name: &str) -> Option<&'static [&'static str]> {
    if target_name.starts_with("x86_64") {
        Some(X86_64)
    } else if target_name.starts_with("aarch64") {
        Some(AARCH64)
    } else {
        None
    }
}

/// Count the floating-point arithmetic instructions in a disassembly listing.
///
/// objdump prints `<address>: <encoding bytes> \t<mnemonic>\t<operands>`, separating the
/// mnemonic from the encoding with a tab. That separator is what this reads.
///
/// The obvious alternative — "the first field that is not hexadecimal", on the reasoning that
/// the encoding is hex and a mnemonic is not — is wrong, and wrong in a way that passes a
/// careless test. **`fadd` is four hexadecimal digits.** So are `fab`, `dead` and half the
/// floating-point mnemonics worth looking for: `fadd`, `fdiv`, `fcc`. On
/// `1e602821 fadd d1, d1, d0` that rule skips the encoding, skips `fadd` as more encoding,
/// and returns `d1,` — reporting no arithmetic on the very instruction it was written to
/// find. `fmul` survives it only because `m` is not a hexadecimal digit.
pub fn count_in_listing(listing: &str, mnemonics: &[&str]) -> usize {
    listing
        .lines()
        .filter(|line| {
            // Past the address, then past the encoding: the mnemonic is the field after the
            // tab that follows it, and objdump always writes that tab.
            let Some((_addr, rest)) = line.split_once(':') else {
                return false;
            };
            let Some((_encoding, after)) = rest.split_once('\t') else {
                return false;
            };
            let mnemonic = after.split(['\t', ' ']).next().unwrap_or_default();
            mnemonics.contains(&mnemonic)
        })
        .count()
}

/// Disassemble `program` and require floating-point arithmetic in it.
///
/// `Ok(None)` where this architecture has no hard-float target, so there is nothing to check.
pub fn verify(objdump: &Path, program: &Path, target_name: &str) -> Result<Option<usize>, String> {
    let Some(wanted) = mnemonics(target_name) else {
        return Ok(None);
    };
    let out = Command::new(objdump)
        .arg("-d")
        .arg(program)
        .output()
        .map_err(|e| format!("cannot run llvm-objdump: {e}"))?;
    if !out.status.success() {
        return Err(format!("llvm-objdump failed: {}", String::from_utf8_lossy(&out.stderr)));
    }
    let n = count_in_listing(&String::from_utf8_lossy(&out.stdout), wanted);
    if n == 0 {
        return Err(format!(
            "{} was built for the hard-float target but holds no floating-point arithmetic \
             ({}): it was built soft-float, so every float in it is a call into \
             compiler_builtins and the hard-float target is not doing anything",
            program.display(),
            wanted.join(", ")
        ));
    }
    Ok(Some(n))
}

#[cfg(test)]
mod tests {
    use super::{AARCH64, X86_64, count_in_listing};

    /// The line that broke the register-name check: `sub` whose encoding begins `d1`.
    #[test]
    fn an_encoding_that_looks_like_a_register_is_not_counted() {
        let listing = "8000012d14: d1000442   \tsub\tx2, x2, #0x1\n";
        assert_eq!(count_in_listing(listing, AARCH64), 0);
    }

    /// `fadd` is four hexadecimal digits, and so are `fdiv` and `fcc`. A rule that finds the
    /// mnemonic by looking for the first field that is *not* hexadecimal skips it as more
    /// encoding and returns the first operand, reporting no arithmetic on exactly the
    /// instruction it was written to find. That rule was in this file until this test.
    #[test]
    fn a_mnemonic_spelled_in_hexadecimal_digits_is_still_a_mnemonic() {
        let listing = "80000104: 1e602821   \tfadd\td1, d1, d0\n";
        assert_eq!(count_in_listing(listing, AARCH64), 1);
        let divide = "80000108: 1e601821   \tfdiv\td1, d1, d0\n";
        assert_eq!(count_in_listing(divide, AARCH64), 1);
    }

    #[test]
    fn arithmetic_is_counted_on_both_ports() {
        let arm =
            "80000100: 1e600842   \tfmul\td2, d2, d0\n80000104: 1e602821   \tfadd\td1, d1, d0\n";
        assert_eq!(count_in_listing(arm, AARCH64), 2);
        let x86 = "8000010000: f2 0f 59 c1  \tmulsd\t%xmm1, %xmm0\n";
        assert_eq!(count_in_listing(x86, X86_64), 1);
    }

    /// A soft-float program calls into compiler_builtins instead; the call is not arithmetic.
    #[test]
    fn a_call_to_the_soft_float_helper_is_not_arithmetic() {
        let listing = "80000100: 94000123   \tbl\t0x8000048c <__muldf3>\n";
        assert_eq!(count_in_listing(listing, AARCH64), 0);
    }

    #[test]
    fn a_mnemonic_named_in_an_operand_is_not_counted() {
        // `fmul` appearing as part of a symbol name in the operand field, not as the
        // instruction: still not arithmetic.
        let listing = "80000100: 94000123   \tbl\t0x8000048c <some_fmul_helper>\n";
        assert_eq!(count_in_listing(listing, AARCH64), 0);
    }
}
