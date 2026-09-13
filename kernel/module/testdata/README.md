# Loader test data

`test-x86_64.kmod` is a real module: `modules/test/roundtrip`, as
`kbuild modules --preset x86_64-qemu` builds it, copied from
`build/x86_64-kintane/out/modules/test-roundtrip.kmod`.

The host test that reads it takes the kernel identity from the module's own identity
section and builds an export table from `module::abi`. So it keeps passing when the
configuration changes, and needs replacing only when the module format or the interface
does. Replace it by rebuilding and copying the file again.
