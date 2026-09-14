//! A filesystem in memory: the reference implementation of [`FileSystem`].
//!
//! Every node is an entry in one fixed array, and a file's bytes live in a buffer the
//! caller lends it. So this allocates nothing, works before the heap exists, and its
//! capacity is visible in its type rather than in how much memory is left.
//!
//! It exists for two reasons. It is what the namespace's own tests run against, so a bug
//! in [`Vfs`](crate::Vfs) shows up without a disk, a driver or an emulator. And it is the
//! second implementation of the trait, which is what keeps the trait a trait: the on-disk
//! filesystem resolves nothing, parses no path and shares no code with this, and both
//! satisfy the same five operations.

use crate::{Entry, Error, FileSystem, Kind, MAX_NAME, NodeId, Stat};

/// The root, which [`MemFs::new`] creates and nothing can remove.
pub const ROOT: NodeId = 0;

struct Node<'a> {
    used: bool,
    kind: Kind,
    name: [u8; MAX_NAME],
    name_len: usize,
    /// Index of the directory holding this node. The root is its own parent, which is
    /// what `..` would mean there and what keeps a walk from running off the top.
    parent: usize,
    /// A file's bytes: the whole buffer is its capacity, `len` of it is its content.
    data: Option<&'a mut [u8]>,
    len: usize,
}

impl Node<'_> {
    const EMPTY: Node<'static> = Node {
        used: false,
        kind: Kind::File,
        name: [0; MAX_NAME],
        name_len: 0,
        parent: 0,
        data: None,
        len: 0,
    };

    fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

/// A filesystem of at most `NODES` files and directories.
pub struct MemFs<'a, const NODES: usize> {
    nodes: [Node<'a>; NODES],
}

impl<const NODES: usize> Default for MemFs<'_, NODES> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, const NODES: usize> MemFs<'a, NODES> {
    /// An empty filesystem: a root directory and nothing in it.
    pub fn new() -> Self {
        let mut fs = MemFs {
            nodes: [const { Node::EMPTY }; NODES],
        };
        fs.nodes[ROOT as usize] = Node {
            used: true,
            kind: Kind::Dir,
            ..Node::EMPTY
        };
        fs
    }

    fn slot(&self, node: NodeId) -> Result<usize, Error> {
        let index = usize::try_from(node).map_err(|_| Error::NotFound)?;
        match self.nodes.get(index) {
            Some(n) if n.used => Ok(index),
            _ => Err(Error::NotFound),
        }
    }

    /// Check `name` and `parent`, and take a free slot for a new node.
    fn make(&mut self, parent: NodeId, name: &[u8], kind: Kind) -> Result<usize, Error> {
        if name.is_empty() || name.len() > MAX_NAME || name.contains(&b'/') {
            return Err(Error::BadPath);
        }
        let parent = self.slot(parent)?;
        if self.nodes[parent].kind != Kind::Dir {
            return Err(Error::NotADirectory);
        }
        if self.find(parent, name).is_some() {
            return Err(Error::Full);
        }
        let index = self.nodes.iter().position(|n| !n.used).ok_or(Error::Full)?;
        let mut bytes = [0u8; MAX_NAME];
        bytes[..name.len()].copy_from_slice(name);
        self.nodes[index] = Node {
            used: true,
            kind,
            name: bytes,
            name_len: name.len(),
            parent,
            data: None,
            len: 0,
        };
        Ok(index)
    }

    /// Create a directory in `parent`.
    pub fn create_dir(&mut self, parent: NodeId, name: &[u8]) -> Result<NodeId, Error> {
        self.make(parent, name, Kind::Dir).map(|i| i as NodeId)
    }

    /// Create a file in `parent` whose bytes live in `storage`, of which the first `len`
    /// are its content. The rest is room to grow: a write past `storage.len()` is refused
    /// rather than served short, because a file that silently stops growing is worse than
    /// one that says it is full.
    pub fn create_file(
        &mut self,
        parent: NodeId,
        name: &[u8],
        storage: &'a mut [u8],
        len: usize,
    ) -> Result<NodeId, Error> {
        if len > storage.len() {
            return Err(Error::OutOfRange);
        }
        let index = self.make(parent, name, Kind::File)?;
        self.nodes[index].data = Some(storage);
        self.nodes[index].len = len;
        Ok(index as NodeId)
    }

    /// Free a node: a directory only once it is empty, and never the root.
    fn remove(&mut self, index: usize) -> Result<(), Error> {
        if index == ROOT as usize {
            return Err(Error::BadPath);
        }
        let has_children = self
            .nodes
            .iter()
            .enumerate()
            .any(|(i, n)| i != index && n.used && n.parent == index);
        if self.nodes[index].kind == Kind::Dir && has_children {
            return Err(Error::NotEmpty);
        }
        self.nodes[index] = Node::EMPTY;
        Ok(())
    }

    fn find(&self, parent: usize, name: &[u8]) -> Option<usize> {
        self.nodes
            .iter()
            .enumerate()
            .position(|(i, n)| i != parent && n.used && n.parent == parent && n.name() == name)
    }
}

impl<const NODES: usize> FileSystem for MemFs<'_, NODES> {
    fn root(&self) -> NodeId {
        ROOT
    }

    fn lookup(&mut self, dir: NodeId, name: &[u8]) -> Result<NodeId, Error> {
        let dir = self.slot(dir)?;
        if self.nodes[dir].kind != Kind::Dir {
            return Err(Error::NotADirectory);
        }
        self.find(dir, name)
            .map(|i| i as NodeId)
            .ok_or(Error::NotFound)
    }

    fn stat(&mut self, node: NodeId) -> Result<Stat, Error> {
        let index = self.slot(node)?;
        let n = &self.nodes[index];
        Ok(Stat {
            kind: n.kind,
            len: match n.kind {
                Kind::File => n.len as u64,
                Kind::Dir => 0,
            },
        })
    }

    fn read_at(&mut self, node: NodeId, offset: u64, into: &mut [u8]) -> Result<usize, Error> {
        let index = self.slot(node)?;
        let n = &self.nodes[index];
        if n.kind != Kind::File {
            return Err(Error::IsADirectory);
        }
        let Ok(at) = usize::try_from(offset) else {
            return Ok(0);
        };
        if at >= n.len {
            return Ok(0);
        }
        let data = n
            .data
            .as_ref()
            .ok_or(Error::Corrupt("a file with no storage"))?;
        let take = (n.len - at).min(into.len());
        into[..take].copy_from_slice(&data[at..at + take]);
        Ok(take)
    }

    fn write_at(&mut self, node: NodeId, offset: u64, from: &[u8]) -> Result<usize, Error> {
        let index = self.slot(node)?;
        let n = &mut self.nodes[index];
        if n.kind != Kind::File {
            return Err(Error::IsADirectory);
        }
        let at = usize::try_from(offset).map_err(|_| Error::OutOfRange)?;
        // A file made by `create` has no storage lent to it, so it has no room.
        let data = n.data.as_mut().ok_or(Error::Full)?;
        if at > n.len {
            // Writing past the end would leave a hole whose contents nobody decided on.
            return Err(Error::OutOfRange);
        }
        let end = at.checked_add(from.len()).ok_or(Error::OutOfRange)?;
        if end > data.len() {
            return Err(Error::Full);
        }
        data[at..end].copy_from_slice(from);
        n.len = n.len.max(end);
        Ok(from.len())
    }

    fn create(&mut self, dir: NodeId, name: &[u8], kind: Kind) -> Result<NodeId, Error> {
        let parent = self.slot(dir)?;
        if self.nodes[parent].kind == Kind::Dir && self.find(parent, name).is_some() {
            return Err(Error::Exists);
        }
        self.make(dir, name, kind).map(|i| i as NodeId)
    }

    fn truncate(&mut self, node: NodeId, len: u64) -> Result<(), Error> {
        let index = self.slot(node)?;
        let n = &mut self.nodes[index];
        if n.kind != Kind::File {
            return Err(Error::IsADirectory);
        }
        let len = usize::try_from(len).map_err(|_| Error::Full)?;
        if len > n.len {
            let data = n.data.as_mut().ok_or(Error::Full)?;
            if len > data.len() {
                return Err(Error::Full);
            }
            data[n.len..len].fill(0);
        }
        n.len = len;
        Ok(())
    }

    fn unlink(&mut self, dir: NodeId, name: &[u8]) -> Result<(), Error> {
        let dir = self.slot(dir)?;
        if self.nodes[dir].kind != Kind::Dir {
            return Err(Error::NotADirectory);
        }
        let victim = self.find(dir, name).ok_or(Error::NotFound)?;
        self.remove(victim)
    }

    fn rename(&mut self, dir: NodeId, from: &[u8], to: &[u8]) -> Result<(), Error> {
        let dir = self.slot(dir)?;
        if self.nodes[dir].kind != Kind::Dir {
            return Err(Error::NotADirectory);
        }
        if to.is_empty() || to.len() > MAX_NAME || to.contains(&b'/') {
            return Err(Error::BadPath);
        }
        let source = self.find(dir, from).ok_or(Error::NotFound)?;
        if let Some(target) = self.find(dir, to) {
            if target != source {
                match (self.nodes[source].kind, self.nodes[target].kind) {
                    (Kind::File, Kind::Dir) => return Err(Error::IsADirectory),
                    (Kind::Dir, Kind::File) => return Err(Error::NotADirectory),
                    _ => {}
                }
                self.remove(target)?;
            }
        }
        let n = &mut self.nodes[source];
        n.name = [0; MAX_NAME];
        n.name[..to.len()].copy_from_slice(to);
        n.name_len = to.len();
        Ok(())
    }

    fn readdir(&mut self, dir: NodeId, index: usize) -> Result<Option<Entry>, Error> {
        let dir = self.slot(dir)?;
        if self.nodes[dir].kind != Kind::Dir {
            return Err(Error::NotADirectory);
        }
        let found = self
            .nodes
            .iter()
            .enumerate()
            .filter(|(i, n)| *i != dir && n.used && n.parent == dir)
            .nth(index);
        match found {
            Some((i, n)) => Entry::new(n.name(), i as NodeId, n.kind).map(Some),
            None => Ok(None),
        }
    }
}
