//! Who holds a loaded module.
//!
//! `docs/modules.md`'s unloading rules are a refcount problem, and a wrong answer is a
//! use-after-free in kernel text. So the rules are small and the table enforces them:
//!
//! * Anything that keeps a pointer into a module takes a reference first ([`Registry::acquire`]).
//! * A module unloads only with no references ([`Registry::begin_unload`]). There is no force.
//! * A module being unloaded takes no new references, so nothing can pin it between its exit
//!   running and its memory going away.
//! * An id names one module once. Slots are reused, and the generation in [`ModuleId`] makes a
//!   stale id refer to nothing rather than to the slot's next occupant.
//!
//! Plain data with `&mut self`: the kernel holds the table under its own lock.

/// A loaded module's id: a slot and the generation it was loaded in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ModuleId(u32);

impl ModuleId {
    const SLOT_BITS: u32 = 8;

    fn new(slot: usize, generation: u32) -> ModuleId {
        ModuleId((generation << Self::SLOT_BITS) | slot as u32)
    }
    fn slot(self) -> usize {
        (self.0 & ((1 << Self::SLOT_BITS) - 1)) as usize
    }
    fn generation(self) -> u32 {
        self.0 >> Self::SLOT_BITS
    }
    /// The id as a module's entry points receive it.
    pub fn raw(self) -> u32 {
        self.0
    }
    pub fn from_raw(raw: u32) -> ModuleId {
        ModuleId(raw)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RegistryError {
    /// Every slot is in use.
    Full,
    /// No live module has this id.
    NoSuchModule,
    /// References are outstanding; unloading would free text something still points into.
    Busy { refs: u32 },
    /// The module is being unloaded and takes no new references.
    Unloading,
    /// `release` without a matching `acquire`.
    NotHeld,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Empty,
    Live { refs: u32 },
    Unloading,
}

#[derive(Clone, Copy, Debug)]
struct Slot {
    state: State,
    generation: u32,
}

pub struct Registry<const N: usize> {
    slots: [Slot; N],
}

impl<const N: usize> Default for Registry<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Registry<N> {
    pub const fn new() -> Self {
        assert!(N > 0 && N <= 1 << ModuleId::SLOT_BITS, "slot count must fit a module id");
        Registry {
            slots: [Slot {
                state: State::Empty,
                generation: 0,
            }; N],
        }
    }

    /// Record a newly loaded module, with no references.
    pub fn insert(&mut self) -> Result<ModuleId, RegistryError> {
        let slot = self
            .slots
            .iter()
            .position(|s| s.state == State::Empty)
            .ok_or(RegistryError::Full)?;
        let s = &mut self.slots[slot];
        // Generations wrap after 2^24 loads into one slot; an id that old is long gone.
        s.generation = (s.generation + 1) & (u32::MAX >> ModuleId::SLOT_BITS);
        s.state = State::Live { refs: 0 };
        Ok(ModuleId::new(slot, s.generation))
    }

    fn slot(&mut self, id: ModuleId) -> Result<&mut Slot, RegistryError> {
        match self.slots.get_mut(id.slot()) {
            Some(s) if s.generation == id.generation() && s.state != State::Empty => Ok(s),
            _ => Err(RegistryError::NoSuchModule),
        }
    }

    /// Take a reference on a live module.
    pub fn acquire(&mut self, id: ModuleId) -> Result<(), RegistryError> {
        let s = self.slot(id)?;
        match &mut s.state {
            State::Live { refs } => {
                *refs = refs.checked_add(1).ok_or(RegistryError::Full)?;
                Ok(())
            }
            _ => Err(RegistryError::Unloading),
        }
    }

    /// Give a reference back.
    pub fn release(&mut self, id: ModuleId) -> Result<(), RegistryError> {
        let s = self.slot(id)?;
        match &mut s.state {
            State::Live { refs } if *refs > 0 => {
                *refs -= 1;
                Ok(())
            }
            _ => Err(RegistryError::NotHeld),
        }
    }

    pub fn refs(&mut self, id: ModuleId) -> Result<u32, RegistryError> {
        match self.slot(id)?.state {
            State::Live { refs } => Ok(refs),
            _ => Ok(0),
        }
    }

    /// Start unloading: refused while anything holds the module. From here no reference
    /// can be taken, and the caller runs the module's exit and frees its memory before
    /// [`Registry::remove`].
    pub fn begin_unload(&mut self, id: ModuleId) -> Result<(), RegistryError> {
        let s = self.slot(id)?;
        match s.state {
            State::Live { refs: 0 } => {
                s.state = State::Unloading;
                Ok(())
            }
            State::Live { refs } => Err(RegistryError::Busy { refs }),
            _ => Err(RegistryError::Unloading),
        }
    }

    /// Free the slot of a module whose unloading has finished.
    pub fn remove(&mut self, id: ModuleId) -> Result<(), RegistryError> {
        let s = self.slot(id)?;
        if s.state != State::Unloading {
            return Err(RegistryError::Busy { refs: 0 });
        }
        s.state = State::Empty;
        Ok(())
    }

    /// Whether any module is loaded or being unloaded.
    pub fn is_empty(&self) -> bool {
        self.slots.iter().all(|s| s.state == State::Empty)
    }
}
