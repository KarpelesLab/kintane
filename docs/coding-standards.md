# Coding Standards

## `unsafe`

The point of writing a kernel in Rust is that most of it is not `unsafe`. Protecting
that requires rules.

### Where it is allowed

| Location | `unsafe` policy |
|---|---|
| `arch/*` | allowed; this is where hardware is touched |
| `hal` | trait definitions may be `unsafe trait`; no `unsafe` bodies (there are no bodies) |
| `kernel/mm`, `kernel/kalloc`, `kernel/sync` | allowed in clearly delimited internal modules; public APIs are safe |
| `kernel/*` (everything else) | `#![deny(unsafe_code)]`, overridable per-module with written justification in the module doc comment |
| `drivers/*` | allowed only through the MMIO/DMA handle types; raw pointer dereference is denied |
| `lib/*` | `#![forbid(unsafe_code)]` |

### Rules

1. **Every `unsafe` block carries a `// SAFETY:` comment** stating the invariants that
   make it sound and who maintains them. CI rejects blocks without one. A comment
   that restates the code ("SAFETY: the pointer is valid") is not a comment; say
   *why* it is valid and what would make it stop being valid.

2. **Every `unsafe fn` carries a `/// # Safety` doc section** stating what the caller
   must guarantee. This is a contract, and contracts are written down.

3. **`unsafe` blocks are minimal.** Wrap the operation, not the function containing
   it. An `unsafe` block containing control flow is a smell.

4. **Safe abstractions over unsafe operations are the deliverable.** A driver author
   should never write `unsafe`. If they must, the abstraction is missing and that is
   the bug to fix.

5. **`static mut` is forbidden.** Use the per-CPU abstraction, an appropriate lock, or
   `SyncUnsafeCell` with a documented invariant.

6. **Transmute requires review.** Prefer `from_bytes`-style validated conversions.
   Anything reading a hardware or on-disk structure goes through a checked parser,
   not a cast.

7. **Epoch-protected data follows the reclamation contract** (`sync::epoch`):
   - A pointer readers load through `EpochPtr` is retired, never freed. The node is
     unlinked before it is retired, and it is retired exactly once.
   - Writers of one pointer are serialised by a lock of the writer's own.
   - A reference obtained through a guard never outlives the guard, which the borrow checker
     enforces. It is never stored anywhere.
   - Nothing sleeps, yields or waits for another CPU while holding a guard. A guard held
     indefinitely stops reclamation on every CPU, and is reported as a stall.
   - A `reclaim` function must be sound on any CPU with interrupts masked.

## Lints

Denied tree-wide:

```
unsafe_op_in_unsafe_fn
missing_docs                  (on public items)
clippy::undocumented_unsafe_blocks
clippy::multiple_unsafe_ops_per_block
clippy::panic
clippy::unwrap_used
clippy::expect_used
clippy::indexing_slicing      (use get()/get_mut(); panics are not an error strategy)
clippy::arithmetic_side_effects   (in address-handling modules)
clippy::as_conversions        (use TryFrom; silent truncation on 32-bit targets is
                               exactly the bug class i686 exists to catch)
```

Plus two custom lints enforced by `kbuild`:

- **`cfg_in_body`** — rejects `cfg` inside function bodies, struct fields, or match
  arms. See [portability.md](portability.md#where-cfg-is-still-allowed).
- **`layer_violation`** — rejects a dependency that crosses layers in the wrong
  direction, per each unit's declared `[layer]`.

## Panics and failure

`panic!` in the kernel is a last resort with a narrow definition: **a panic means an
invariant the code depends on has been violated and continuing would be unsafe.**

Not panics:
- allocation failure → `Result<_, AllocError>`
- malformed input from userspace, a device, a filesystem, or the network → an error
  returned to the caller
- a device behaving unexpectedly → log, fail the operation, mark the device
- a full queue, a timeout, a missing resource → errors

`unwrap()` and `expect()` are denied by lint. Where a case is genuinely impossible,
either restructure so the type system knows it, or use an explicit
`unreachable_checked!` macro that documents the reasoning and, in debug builds,
checks it.

## Naming and structure

- Modules are nouns describing a domain (`mm::paged`), not groupings of unrelated
  things (`utils`, `helpers`, `common`).
- Trait names describing a capability start with `Has` (`HasMmu`); traits describing
  a role are plain nouns (`IrqChip`, `PageTable`).
- Free functions with hardware side effects say so: `tlb_flush_all`, not `flush`.
- Types carrying a unit or address space carry it in the type, not the name:
  `PhysAddr`, `UserAddr`, `KernAddr` are distinct types with no implicit conversion.
  This is not pedantry; conflating them is one of the most common kernel bug classes.

## Documentation

- Every public item has a doc comment. Enforced.
- Every subsystem has a `//!` module-level comment explaining its model, its locking
  discipline, and its invariants — not a restatement of its function list.
- Locking order is documented at the subsystem level and checked at runtime in debug
  builds. A lock hierarchy that lives only in someone's head will be violated. The check
  sees a lock only if it has a class: create long-lived locks with `with_class` and a
  `static LockClass` named for the lock's role (`"ipc.channel"`), and give every
  `LockFamily::new` one, which the signature requires. A lock without a class is
  invisible to the checker, which should be a decision rather than an accident.
- Anything with a hardware reference cites it: manual name, revision, section.

## Commits and review

- Commits are single logical changes with a message explaining *why*. A commit that
  needs "and" in its subject line is two commits.
- Changes touching `arch/` state which targets were built and which were booted.
- Changes adding `unsafe` are reviewed with attention proportional to what the
  invariants protect.
- Changes adding a config symbol state what happens when it is off, and the
  randomized-config CI will eventually check whether that was true.

## Formatting

`rustfmt` with the in-tree `rustfmt.toml`, 100-column limit, enforced in CI. No
discussion; the time is better spent elsewhere.
