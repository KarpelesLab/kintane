//! Evaluating AML: methods, expressions, stores, and field access.

use core::cmp::Ordering;

use super::load::{Code, NameString, is_name_lead};
use super::*;

const MAX_ARGS: usize = 7;
const MAX_LOCALS: usize = 8;
/// Expression nesting. QEMU's deepest is under ten.
const MAX_NESTING: u16 = 48;
/// Method calls in progress at once, recursion included.
const MAX_CALLS: u8 = 12;
/// What `Revision` evaluates to: the interpreter's own version.
const REVISION: u64 = 1;

/// A method's arguments and locals, and where its names resolve.
struct Frame<'t> {
    code: Code<'t>,
    wide: bool,
    scope: NodeId,
    args: [Object; MAX_ARGS],
    locals: [Object; MAX_LOCALS],
}

impl<'t> Frame<'t> {
    fn new(code: Code<'t>, wide: bool, scope: NodeId) -> Frame<'t> {
        Frame {
            code,
            wide,
            scope,
            args: [Object::Uninitialized; MAX_ARGS],
            locals: [Object::Uninitialized; MAX_LOCALS],
        }
    }

    fn ones(&self) -> u64 {
        if self.wide {
            u64::MAX
        } else {
            u64::from(u32::MAX)
        }
    }
}

/// How a term list finished.
enum Flow {
    Next,
    Return(Object),
    Break,
    Continue,
}

/// Where a store goes.
#[derive(Clone, Copy)]
enum Place {
    Null,
    Local(usize),
    Arg(usize),
    Node(NodeId),
    Element(Container, usize),
}

/// What an `Index` used as a store target indexes.
#[derive(Clone, Copy)]
enum Container {
    Local(usize),
    Arg(usize),
    Node(NodeId),
}

impl<'t, 's, H: Host> Interpreter<'t, 's, H> {
    /// Evaluate `node` with `args`: call it if it is a method, read it if it is a name or a
    /// field, and otherwise return a reference to it. Starts a fresh step budget.
    pub fn evaluate(&mut self, node: NodeId, args: &[Object]) -> Result<Object, Error> {
        self.fresh();
        self.value_of(node, args)
    }

    /// Evaluate the child of `parent` named `name`, or `None` when there is no such child.
    pub fn evaluate_child(
        &mut self,
        parent: NodeId,
        name: &NameSeg,
        args: &[Object],
    ) -> Result<Option<Object>, Error> {
        match self.child(parent, name) {
            Some(node) => self.evaluate(node, args).map(Some),
            None => Ok(None),
        }
    }

    /// How many elements a package has.
    pub fn package_len(&self, object: Object) -> Result<usize, Error> {
        match object {
            Object::Package(Package::Table { table, at, .. }) => {
                let (code, _) = self.code(table)?;
                let (_, p) = code.pkg_end(at as usize + 1, code.bytes.len())?;
                Ok(usize::from(code.byte(p)?))
            }
            Object::Package(Package::Heap { len, .. }) => Ok(len as usize),
            _ => Err(Error::WrongType),
        }
    }

    /// Element `index` of a package, or byte `index` of a buffer or string as an integer.
    pub fn element(&mut self, object: Object, index: usize) -> Result<Object, Error> {
        self.fresh();
        self.element_of(object, index)
    }

    pub(super) fn fresh(&mut self) {
        self.budget = self.limit;
        self.nest = 0;
        self.calls = 0;
    }

    fn step(&mut self) -> Result<(), Error> {
        self.budget = self.budget.checked_sub(1).ok_or(Error::Budget)?;
        Ok(())
    }

    fn code(&self, table: u8) -> Result<(Code<'t>, bool), Error> {
        let index = usize::from(table);
        if index >= self.n_tables {
            return Err(Error::NotFound);
        }
        let (bytes, wide) = self.tables[index];
        Ok((Code { bytes, table }, wide))
    }

    fn value_of(&mut self, node: NodeId, args: &[Object]) -> Result<Object, Error> {
        match self.kind(node)? {
            Kind::Method { .. } => self.call(node, args),
            _ if !args.is_empty() => Err(Error::WrongType),
            Kind::Name { .. } | Kind::Value => self.name_value(node),
            Kind::Field { .. } => self.read_field(node).map(Object::Integer),
            Kind::BufferField { .. } => self.read_buffer_field(node).map(Object::Integer),
            Kind::OtherField => Err(Error::Unsupported {
                table: self.nodes[node.index()].table,
                offset: 0,
            }),
            _ => Ok(Object::Reference(node)),
        }
    }

    /// A name's value, evaluating its data object the first time.
    fn name_value(&mut self, node: NodeId) -> Result<Object, Error> {
        let n = self.nodes[node.index()];
        match n.kind {
            Kind::Value => Ok(n.value),
            Kind::Name { at } => {
                let (code, wide) = self.code(n.table)?;
                let mut frame = Frame::new(code, wide, NodeId(n.parent));
                let (value, _) = self.eval(&mut frame, at as usize)?;
                let slot = &mut self.nodes[node.index()];
                slot.kind = Kind::Value;
                slot.value = value;
                Ok(value)
            }
            _ => Err(Error::WrongType),
        }
    }

    fn call(&mut self, method: NodeId, args: &[Object]) -> Result<Object, Error> {
        let n = self.nodes[method.index()];
        let Kind::Method { at, end, flags } = n.kind else {
            return Err(Error::WrongType);
        };
        let argc = usize::from(flags & 7);
        if args.len() != argc {
            return Err(Error::WrongType);
        }
        if self.calls >= MAX_CALLS {
            return Err(Error::TooDeep);
        }
        let (code, wide) = self.code(n.table)?;
        let mut frame = Frame::new(code, wide, method);
        frame.args[..argc].copy_from_slice(args);
        // What the method declares lives while it runs.
        let mark = self.n_nodes;
        self.calls += 1;
        let flow = self.exec(&mut frame, at as usize, end as usize);
        self.calls -= 1;
        self.n_nodes = mark;
        match flow? {
            Flow::Return(v) => Ok(v),
            _ => Ok(Object::Integer(0)),
        }
    }

    fn exec(&mut self, frame: &mut Frame<'t>, mut at: usize, end: usize) -> Result<Flow, Error> {
        let code = frame.code;
        while at < end {
            self.step()?;
            let next = match code.byte(at)? {
                // If, with the Else that may follow it.
                0xa0 => {
                    let (body_end, p) = code.pkg_end(at + 1, end)?;
                    let (predicate, p) = self.eval(frame, p)?;
                    let taken = self.integer(predicate)? != 0;
                    let otherwise = if body_end < end && code.byte(body_end)? == 0xa1 {
                        let (e, q) = code.pkg_end(body_end + 1, end)?;
                        Some((q, e))
                    } else {
                        None
                    };
                    let flow = if taken {
                        self.exec(frame, p, body_end)?
                    } else if let Some((q, e)) = otherwise {
                        self.exec(frame, q, e)?
                    } else {
                        Flow::Next
                    };
                    if !matches!(flow, Flow::Next) {
                        return Ok(flow);
                    }
                    otherwise.map_or(body_end, |(_, e)| e)
                }
                // An Else with no If before it.
                0xa1 => code.pkg_end(at + 1, end)?.0,
                // While
                0xa2 => {
                    let (body_end, p) = code.pkg_end(at + 1, end)?;
                    loop {
                        self.step()?;
                        let (predicate, q) = self.eval(frame, p)?;
                        if self.integer(predicate)? == 0 {
                            break;
                        }
                        match self.exec(frame, q, body_end)? {
                            Flow::Break => break,
                            Flow::Return(v) => return Ok(Flow::Return(v)),
                            Flow::Next | Flow::Continue => {}
                        }
                    }
                    body_end
                }
                0xa4 => {
                    let (v, _) = self.eval(frame, at + 1)?;
                    return Ok(Flow::Return(v));
                }
                0xa5 => return Ok(Flow::Break),
                0x9f => return Ok(Flow::Continue),
                0xa3 => at + 1,
                // Name, in a method: a new object each time the method runs.
                0x08 => {
                    let (name, p) = code.name_string(at + 1)?;
                    let (value, next) = self.eval(frame, p)?;
                    let value = self.copy(value)?;
                    self.create(code, at, frame.scope, &name, Kind::Value, value)?;
                    next
                }
                // CreateDWordField, CreateWordField, CreateByteField, CreateBitField,
                // CreateQWordField.
                op @ (0x8a | 0x8b | 0x8c | 0x8d | 0x8f) => {
                    let (source, p) = self.eval(frame, at + 1)?;
                    let (index, p) = self.eval(frame, p)?;
                    let index = self.integer(index)?;
                    let (name, p) = code.name_string(p)?;
                    let (bit_offset, bits) = match op {
                        0x8a => (index.checked_mul(8), 32),
                        0x8b => (index.checked_mul(8), 16),
                        0x8c => (index.checked_mul(8), 8),
                        0x8d => (Some(index), 1),
                        _ => (index.checked_mul(8), 64),
                    };
                    let bit_offset = bit_offset.ok_or(Error::BadIndex)?;
                    self.create_buffer_field(frame, at, &name, source, bit_offset, bits)?;
                    p
                }
                // CreateField
                0x5b if code.byte(at + 1)? == 0x13 => {
                    let (source, p) = self.eval(frame, at + 2)?;
                    let (index, p) = self.eval(frame, p)?;
                    let index = self.integer(index)?;
                    let (bits, p) = self.eval(frame, p)?;
                    let bits = u32::try_from(self.integer(bits)?).map_err(|_| Error::BadIndex)?;
                    let (name, p) = code.name_string(p)?;
                    self.create_buffer_field(frame, at, &name, source, index, bits)?;
                    p
                }
                _ => self.eval(frame, at)?.1,
            };
            at = next;
        }
        Ok(Flow::Next)
    }

    fn create_buffer_field(
        &mut self,
        frame: &Frame<'t>,
        at: usize,
        name: &NameString,
        source: Object,
        bit_offset: u64,
        bit_width: u32,
    ) -> Result<(), Error> {
        let Object::Buffer(Bytes::Heap { len, .. }) = source else {
            return Err(Error::WrongType);
        };
        let bits = u64::from(len) * 8;
        if bit_width == 0
            || bit_width > 64
            || bit_offset.saturating_add(u64::from(bit_width)) > bits
        {
            return Err(Error::BadIndex);
        }
        let kind = Kind::BufferField {
            bit_offset,
            bit_width,
        };
        self.create(frame.code, at, frame.scope, name, kind, source)?;
        Ok(())
    }

    fn eval(&mut self, frame: &mut Frame<'t>, at: usize) -> Result<(Object, usize), Error> {
        if self.nest >= MAX_NESTING {
            return Err(Error::TooDeep);
        }
        self.nest += 1;
        let result = self.eval_term(frame, at);
        self.nest -= 1;
        result
    }

    fn eval_term(&mut self, frame: &mut Frame<'t>, at: usize) -> Result<(Object, usize), Error> {
        self.step()?;
        let code = frame.code;
        let ones = frame.ones();
        if let Some((v, next)) = code.integer_const(at, ones)? {
            return Ok((Object::Integer(v), next));
        }
        let op = code.byte(at)?;
        let int = |v: u64| Object::Integer(v & ones);
        let truth = |b: bool| Object::Integer(if b { ones } else { 0 });
        match op {
            // String
            0x0d => {
                let end = code.skip_data(at, code.bytes.len())?;
                let bytes = Bytes::Table {
                    table: code.table,
                    start: (at + 1) as u32,
                    len: (end - at - 2) as u32,
                };
                Ok((Object::String(bytes), end))
            }
            // Buffer
            0x11 => {
                let (end, p) = code.pkg_end(at + 1, code.bytes.len())?;
                let (size, p) = self.eval(frame, p)?;
                let size = usize::try_from(self.integer(size)?).map_err(|_| Error::NoMemory)?;
                if p > end {
                    return Err(code.truncated(at));
                }
                let init = code.slice(p, end - p)?;
                let heap = self.alloc_bytes(size.max(init.len()))?;
                if let Bytes::Heap { start, .. } = heap {
                    let start = start as usize;
                    self.bytes[start..start + init.len()].copy_from_slice(init);
                }
                Ok((Object::Buffer(heap), end))
            }
            // Package
            0x12 => {
                let (end, _) = code.pkg_end(at + 1, code.bytes.len())?;
                let package = Package::Table {
                    table: code.table,
                    at: at as u32,
                    scope: frame.scope,
                };
                Ok((Object::Package(package), end))
            }
            // VarPackage: its length is computed, so its cells are made now.
            0x13 => {
                let (end, p) = code.pkg_end(at + 1, code.bytes.len())?;
                let (count, mut q) = self.eval(frame, p)?;
                let count = usize::try_from(self.integer(count)?).map_err(|_| Error::NoMemory)?;
                let (start, len) = self.alloc_cells(count)?;
                let mut i = 0;
                while q < end && i < count {
                    let (v, next) = self.decode_element(code, frame.wide, frame.scope, q, end)?;
                    self.cells[start + i] = v;
                    q = next;
                    i += 1;
                }
                let package = Package::Heap {
                    start: start as u32,
                    len,
                };
                Ok((Object::Package(package), end))
            }
            0x60..=0x67 => Ok((frame.locals[usize::from(op - 0x60)], at + 1)),
            0x68..=0x6e => Ok((frame.args[usize::from(op - 0x68)], at + 1)),
            // Store
            0x70 => {
                let (v, p) = self.eval(frame, at + 1)?;
                let (place, p) = self.target(frame, p)?;
                self.store(frame, place, v)?;
                Ok((v, p))
            }
            // Add, Subtract, Multiply, ShiftLeft, ShiftRight, And, Nand, Or, Nor, Xor, Mod
            0x72 | 0x74 | 0x77 | 0x79..=0x7f | 0x85 => {
                let (a, p) = self.eval(frame, at + 1)?;
                let a = self.integer(a)?;
                let (b, p) = self.eval(frame, p)?;
                let b = self.integer(b)?;
                let r = match op {
                    0x72 => a.wrapping_add(b),
                    0x74 => a.wrapping_sub(b),
                    0x77 => a.wrapping_mul(b),
                    0x79 => a.checked_shl(u32::try_from(b).unwrap_or(64)).unwrap_or(0),
                    0x7a => a.checked_shr(u32::try_from(b).unwrap_or(64)).unwrap_or(0),
                    0x7b => a & b,
                    0x7c => !(a & b),
                    0x7d => a | b,
                    0x7e => !(a | b),
                    0x7f => a ^ b,
                    _ => a.checked_rem(b).ok_or(Error::DivideByZero)?,
                };
                let (place, p) = self.target(frame, p)?;
                self.store(frame, place, int(r))?;
                Ok((int(r), p))
            }
            // Divide: dividend, divisor, remainder target, quotient target.
            0x78 => {
                let (a, p) = self.eval(frame, at + 1)?;
                let a = self.integer(a)?;
                let (b, p) = self.eval(frame, p)?;
                let b = self.integer(b)?;
                let quotient = a.checked_div(b).ok_or(Error::DivideByZero)?;
                let (remainder_place, p) = self.target(frame, p)?;
                self.store(frame, remainder_place, int(a % b))?;
                let (quotient_place, p) = self.target(frame, p)?;
                self.store(frame, quotient_place, int(quotient))?;
                Ok((int(quotient), p))
            }
            // Not
            0x80 => {
                let (a, p) = self.eval(frame, at + 1)?;
                let r = !self.integer(a)?;
                let (place, p) = self.target(frame, p)?;
                self.store(frame, place, int(r))?;
                Ok((int(r), p))
            }
            // Increment, Decrement
            0x75 | 0x76 => {
                let (place, p) = self.target(frame, at + 1)?;
                let v = self.read_place(frame, place)?;
                let v = self.integer(v)?;
                let r = if op == 0x75 {
                    v.wrapping_add(1)
                } else {
                    v.wrapping_sub(1)
                };
                self.store(frame, place, int(r))?;
                Ok((int(r), p))
            }
            // LAnd, LOr
            0x90 | 0x91 => {
                let (a, p) = self.eval(frame, at + 1)?;
                let a = self.integer(a)? != 0;
                let (b, p) = self.eval(frame, p)?;
                let b = self.integer(b)? != 0;
                Ok((truth(if op == 0x90 { a && b } else { a || b }), p))
            }
            // LNot, and the LNotEqual, LLessEqual and LGreaterEqual it prefixes.
            0x92 => match code.byte(at + 1)? {
                sub @ 0x93..=0x95 => {
                    let (ord, p) = self.compare(frame, at + 2)?;
                    let r = match sub {
                        0x93 => ord != Ordering::Equal,
                        0x94 => ord != Ordering::Greater,
                        _ => ord != Ordering::Less,
                    };
                    Ok((truth(r), p))
                }
                _ => {
                    let (a, p) = self.eval(frame, at + 1)?;
                    Ok((truth(self.integer(a)? == 0), p))
                }
            },
            // LEqual, LGreater, LLess
            0x93..=0x95 => {
                let (ord, p) = self.compare(frame, at + 1)?;
                let r = match op {
                    0x93 => ord == Ordering::Equal,
                    0x94 => ord == Ordering::Greater,
                    _ => ord == Ordering::Less,
                };
                Ok((truth(r), p))
            }
            // DerefOf
            0x83 => {
                let (v, p) = self.eval(frame, at + 1)?;
                match v {
                    Object::Reference(node) => Ok((self.value_of(node, &[])?, p)),
                    _ => Ok((v, p)),
                }
            }
            // Index: its value is the element itself, which is what DerefOf of it reads.
            0x88 => {
                let (source, p) = self.eval(frame, at + 1)?;
                let (index, p) = self.eval(frame, p)?;
                let index = usize::try_from(self.integer(index)?).map_err(|_| Error::BadIndex)?;
                let (place, p) = self.target(frame, p)?;
                let v = self.element_of(source, index)?;
                self.store(frame, place, v)?;
                Ok((v, p))
            }
            // SizeOf
            0x87 => {
                let (place, p) = self.target(frame, at + 1)?;
                let v = self.read_place(frame, place)?;
                let size = match v {
                    Object::Package(_) => self.package_len(v)?,
                    _ => self.buffer(v)?.len(),
                };
                Ok((int(size as u64), p))
            }
            // Notify: nobody is listening.
            0x86 => {
                let (_, p) = self.target(frame, at + 1)?;
                let (_, p) = self.eval(frame, p)?;
                Ok((Object::Uninitialized, p))
            }
            0x5b => match code.byte(at + 1)? {
                // Acquire always succeeds: nothing else runs AML while this does.
                0x23 => {
                    let (_, p) = self.target(frame, at + 2)?;
                    code.slice(p, 2)?;
                    Ok((Object::Integer(0), p + 2))
                }
                // Release
                0x27 => {
                    let (_, p) = self.target(frame, at + 2)?;
                    Ok((Object::Uninitialized, p))
                }
                0x30 => Ok((Object::Integer(REVISION), at + 2)),
                // Debug
                0x31 => Ok((Object::Uninitialized, at + 2)),
                ext => Err(code.unknown(at, 0x5b00 | u16::from(ext))),
            },
            b if is_name_lead(b) => self.name_term(frame, at),
            _ => Err(code.unknown(at, u16::from(op))),
        }
    }

    /// A name in an expression: a method call with its arguments, or the named object's value.
    fn name_term(&mut self, frame: &mut Frame<'t>, at: usize) -> Result<(Object, usize), Error> {
        let (name, p) = frame.code.name_string(at)?;
        let node = self.resolve(frame.scope, &name).ok_or(Error::NotFound)?;
        if let Some(argc) = self.method_args(node) {
            let mut args = [Object::Uninitialized; MAX_ARGS];
            let mut q = p;
            for arg in args.iter_mut().take(argc) {
                let (v, next) = self.eval(frame, q)?;
                *arg = v;
                q = next;
            }
            return Ok((self.call(node, &args[..argc])?, q));
        }
        Ok((self.value_of(node, &[])?, p))
    }

    fn compare(&mut self, frame: &mut Frame<'t>, at: usize) -> Result<(Ordering, usize), Error> {
        let (a, p) = self.eval(frame, at)?;
        let (b, p) = self.eval(frame, p)?;
        let ord = match (a, b) {
            (Object::String(_) | Object::Buffer(_), Object::String(_) | Object::Buffer(_)) => {
                self.buffer(a)?.cmp(self.buffer(b)?)
            }
            _ => self.integer(a)?.cmp(&self.integer(b)?),
        };
        Ok((ord, p))
    }

    /// A SuperName, as the target of a store.
    fn target(&mut self, frame: &mut Frame<'t>, at: usize) -> Result<(Place, usize), Error> {
        let code = frame.code;
        Ok(match code.byte(at)? {
            0x00 => (Place::Null, at + 1),
            op @ 0x60..=0x67 => (Place::Local(usize::from(op - 0x60)), at + 1),
            op @ 0x68..=0x6e => (Place::Arg(usize::from(op - 0x68)), at + 1),
            0x5b if code.byte(at + 1)? == 0x31 => (Place::Null, at + 2),
            0x88 => {
                let (container, p) = match code.byte(at + 1)? {
                    op @ 0x60..=0x67 => (Container::Local(usize::from(op - 0x60)), at + 2),
                    op @ 0x68..=0x6e => (Container::Arg(usize::from(op - 0x68)), at + 2),
                    b if is_name_lead(b) => {
                        let (name, p) = code.name_string(at + 1)?;
                        let node = self.resolve(frame.scope, &name).ok_or(Error::NotFound)?;
                        (Container::Node(node), p)
                    }
                    _ => return Err(code.unsupported(at)),
                };
                let (index, p) = self.eval(frame, p)?;
                let index = usize::try_from(self.integer(index)?).map_err(|_| Error::BadIndex)?;
                let (inner, p) = self.target(frame, p)?;
                if !matches!(inner, Place::Null) {
                    return Err(code.unsupported(at));
                }
                (Place::Element(container, index), p)
            }
            b if is_name_lead(b) => {
                let (name, p) = code.name_string(at)?;
                let node = self.resolve(frame.scope, &name).ok_or(Error::NotFound)?;
                (Place::Node(node), p)
            }
            _ => return Err(code.unsupported(at)),
        })
    }

    fn read_place(&mut self, frame: &Frame<'t>, place: Place) -> Result<Object, Error> {
        match place {
            Place::Null => Ok(Object::Uninitialized),
            Place::Local(i) => Ok(frame.locals[i]),
            Place::Arg(i) => Ok(frame.args[i]),
            Place::Node(node) => self.value_of(node, &[]),
            Place::Element(container, index) => {
                let c = self.container(frame, container)?;
                self.element_of(c, index)
            }
        }
    }

    fn container(&mut self, frame: &Frame<'t>, container: Container) -> Result<Object, Error> {
        match container {
            Container::Local(i) => Ok(frame.locals[i]),
            Container::Arg(i) => Ok(frame.args[i]),
            Container::Node(node) => match self.kind(node)? {
                Kind::Name { .. } | Kind::Value => self.name_value(node),
                _ => Err(Error::WrongType),
            },
        }
    }

    fn store(&mut self, frame: &mut Frame<'t>, place: Place, value: Object) -> Result<(), Error> {
        match place {
            Place::Null => Ok(()),
            Place::Local(i) => {
                frame.locals[i] = self.copy(value)?;
                Ok(())
            }
            Place::Arg(i) => {
                frame.args[i] = self.copy(value)?;
                Ok(())
            }
            Place::Node(node) => self.store_node(node, value),
            Place::Element(container, index) => {
                let object = self.container(frame, container)?;
                match object {
                    Object::Package(package) => {
                        let (start, len) = match package {
                            Package::Heap { start, len } => (start as usize, len as usize),
                            Package::Table { .. } => {
                                // A literal is written into for the first time: copy it into
                                // cells, and make the copy what the container holds.
                                let heap = self.materialize(package)?;
                                let o = Object::Package(heap);
                                match container {
                                    Container::Local(i) => frame.locals[i] = o,
                                    Container::Arg(i) => frame.args[i] = o,
                                    Container::Node(node) => {
                                        let slot = &mut self.nodes[node.index()];
                                        slot.kind = Kind::Value;
                                        slot.value = o;
                                    }
                                }
                                match heap {
                                    Package::Heap { start, len } => (start as usize, len as usize),
                                    Package::Table { .. } => return Err(Error::WrongType),
                                }
                            }
                        };
                        if index >= len {
                            return Err(Error::BadIndex);
                        }
                        let value = self.copy(value)?;
                        self.cells[start + index] = value;
                        Ok(())
                    }
                    Object::Buffer(Bytes::Heap { start, len }) => {
                        if index >= len as usize {
                            return Err(Error::BadIndex);
                        }
                        let byte = self.integer(value)? as u8;
                        self.bytes[start as usize + index] = byte;
                        Ok(())
                    }
                    _ => Err(Error::WrongType),
                }
            }
        }
    }

    fn store_node(&mut self, node: NodeId, value: Object) -> Result<(), Error> {
        match self.kind(node)? {
            Kind::Field { .. } => {
                let v = self.integer(value)?;
                self.write_field(node, v)
            }
            Kind::BufferField { .. } => {
                let v = self.integer(value)?;
                self.write_buffer_field(node, v)
            }
            Kind::Name { .. } | Kind::Value => {
                let current = self.name_value(node)?;
                let new = match (current, value) {
                    // A store converts to the type of what is already there.
                    (Object::Integer(_), _) => Object::Integer(self.integer(value)?),
                    (Object::Buffer(Bytes::Heap { start, len }), Object::Integer(v)) => {
                        let bytes = &mut self.bytes[start as usize..(start + len) as usize];
                        for (i, b) in bytes.iter_mut().enumerate() {
                            *b = if i < 8 { (v >> (8 * i)) as u8 } else { 0 };
                        }
                        current
                    }
                    _ => self.copy(value)?,
                };
                let slot = &mut self.nodes[node.index()];
                slot.kind = Kind::Value;
                slot.value = new;
                Ok(())
            }
            _ => Err(Error::WrongType),
        }
    }

    /// A copy of `object` for a store: buffers and package cells are duplicated, so writing
    /// into the copy does not change the original.
    fn copy(&mut self, object: Object) -> Result<Object, Error> {
        match object {
            Object::Buffer(Bytes::Heap { start, len }) => {
                let heap = self.alloc_bytes(len as usize)?;
                if let Bytes::Heap { start: to, .. } = heap {
                    self.bytes
                        .copy_within(start as usize..(start + len) as usize, to as usize);
                }
                Ok(Object::Buffer(heap))
            }
            Object::Package(Package::Heap { start, len }) => {
                let (to, len) = self.alloc_cells(len as usize)?;
                self.cells
                    .copy_within(start as usize..start as usize + len as usize, to);
                Ok(Object::Package(Package::Heap {
                    start: to as u32,
                    len,
                }))
            }
            _ => Ok(object),
        }
    }

    /// A package literal's elements, copied into cells.
    fn materialize(&mut self, package: Package) -> Result<Package, Error> {
        let Package::Table { table, at, scope } = package else {
            return Ok(package);
        };
        let count = self.package_len(Object::Package(package))?;
        let (code, wide) = self.code(table)?;
        let (end, p) = code.pkg_end(at as usize + 1, code.bytes.len())?;
        let (start, len) = self.alloc_cells(count)?;
        let mut q = p + 1;
        let mut i = 0;
        while q < end && i < count {
            let (v, next) = self.decode_element(code, wide, scope, q, end)?;
            self.cells[start + i] = v;
            q = next;
            i += 1;
        }
        Ok(Package::Heap {
            start: start as u32,
            len,
        })
    }

    fn element_of(&mut self, object: Object, index: usize) -> Result<Object, Error> {
        match object {
            Object::Package(Package::Table { table, at, scope }) => {
                let count = self.package_len(object)?;
                if index >= count {
                    return Err(Error::BadIndex);
                }
                let (code, wide) = self.code(table)?;
                let (end, p) = code.pkg_end(at as usize + 1, code.bytes.len())?;
                let mut q = p + 1;
                let mut i = 0;
                while q < end {
                    self.step()?;
                    if i == index {
                        return Ok(self.decode_element(code, wide, scope, q, end)?.0);
                    }
                    q = code.skip_data(q, end)?;
                    i += 1;
                }
                // Declared, and not listed: uninitialized (ACPI 6.5 §19.6.101).
                Ok(Object::Uninitialized)
            }
            Object::Package(Package::Heap { start, len }) => {
                if index >= len as usize {
                    return Err(Error::BadIndex);
                }
                Ok(self.cells[start as usize + index])
            }
            Object::Buffer(_) | Object::String(_) => self
                .buffer(object)?
                .get(index)
                .map(|&b| Object::Integer(u64::from(b)))
                .ok_or(Error::BadIndex),
            _ => Err(Error::WrongType),
        }
    }

    /// One package element. A name is a reference to what it names, or the name itself as a
    /// string when it names nothing, and is never evaluated.
    fn decode_element(
        &mut self,
        code: Code<'t>,
        wide: bool,
        scope: NodeId,
        at: usize,
        end: usize,
    ) -> Result<(Object, usize), Error> {
        if is_name_lead(code.byte(at)?) {
            let (name, p) = code.name_string(at)?;
            let object = match self.resolve(scope, &name) {
                Some(node) => Object::Reference(node),
                None => Object::String(Bytes::Table {
                    table: code.table,
                    start: at as u32,
                    len: (p - at) as u32,
                }),
            };
            return Ok((object, p));
        }
        let mut frame = Frame::new(code, wide, scope);
        let (v, p) = self.eval(&mut frame, at)?;
        if p > end {
            return Err(code.truncated(at));
        }
        Ok((v, p))
    }

    // ---- fields -----------------------------------------------------------------------

    /// The region a field is in, where it is, and how it is accessed: `(space, base, len,
    /// bit_offset, bit_width, access bits, flags)`.
    fn field_layout(
        &mut self,
        node: NodeId,
    ) -> Result<(Space, u64, u64, u32, u32, u32, u8), Error> {
        let Kind::Field {
            region,
            bit_offset,
            bit_width,
            flags,
        } = self.kind(node)?
        else {
            return Err(Error::WrongType);
        };
        let region = NodeId(region);
        let Kind::Region { space, offset, len } = self.kind(region)? else {
            return Err(Error::WrongType);
        };
        if bit_width == 0 || bit_width > 64 {
            return Err(Error::Unsupported {
                table: self.nodes[node.index()].table,
                offset: 0,
            });
        }
        let space = match space {
            0 => Space::Memory,
            1 => Space::Io,
            2 => {
                let device = self.enclosing_device(region).ok_or(Error::NotFound)?;
                let (bus, device, function) = self.pci_address(device)?;
                Space::PciConfig {
                    bus,
                    device,
                    function,
                }
            }
            _ => {
                return Err(Error::Unsupported {
                    table: self.nodes[region.index()].table,
                    offset: 0,
                });
            }
        };
        let access = match flags & 0x0f {
            2 => 16,
            3 => 32,
            4 => 64,
            // AnyAcc, ByteAcc and BufferAcc: a byte at a time.
            _ => 8,
        };
        Ok((space, offset, len, bit_offset, bit_width, access, flags))
    }

    fn read_field(&mut self, node: NodeId) -> Result<u64, Error> {
        let (space, base, len, bit_offset, bit_width, access, _) = self.field_layout(node)?;
        let mut value = 0u64;
        let mut done = 0u32;
        while done < bit_width {
            let bit = bit_offset + done;
            let unit = bit / access * access;
            let shift = bit - unit;
            let take = (access - shift).min(bit_width - done);
            let address = region_address(base, len, unit, access)?;
            let raw = self
                .host
                .read(space, address, access as u8)
                .ok_or(Error::Host)?;
            value |= ((raw >> shift) & mask(take)) << done;
            done += take;
        }
        Ok(value)
    }

    fn write_field(&mut self, node: NodeId, value: u64) -> Result<(), Error> {
        let (space, base, len, bit_offset, bit_width, access, flags) = self.field_layout(node)?;
        let mut done = 0u32;
        while done < bit_width {
            let bit = bit_offset + done;
            let unit = bit / access * access;
            let shift = bit - unit;
            let take = (access - shift).min(bit_width - done);
            let address = region_address(base, len, unit, access)?;
            let whole = take == access;
            // The update rule says what the bits of the unit outside the field become.
            let around = match (flags >> 5) & 3 {
                _ if whole => 0,
                1 => mask(access),
                2 => 0,
                _ => self
                    .host
                    .read(space, address, access as u8)
                    .ok_or(Error::Host)?,
            };
            let field_mask = mask(take) << shift;
            let raw = (around & !field_mask) | (((value >> done) & mask(take)) << shift);
            self.host
                .write(space, address, access as u8, raw)
                .ok_or(Error::Host)?;
            done += take;
        }
        Ok(())
    }

    fn buffer_field(&self, node: NodeId) -> Result<(usize, usize, u64, u32), Error> {
        let n = self.nodes[node.index()];
        match (n.kind, n.value) {
            (
                Kind::BufferField {
                    bit_offset,
                    bit_width,
                },
                Object::Buffer(Bytes::Heap { start, len }),
            ) => Ok((start as usize, len as usize, bit_offset, bit_width)),
            _ => Err(Error::WrongType),
        }
    }

    fn read_buffer_field(&self, node: NodeId) -> Result<u64, Error> {
        let (start, len, bit_offset, bit_width) = self.buffer_field(node)?;
        let bytes = &self.bytes[start..start + len];
        let mut value = 0u64;
        for i in 0..u64::from(bit_width) {
            let bit = bit_offset + i;
            let byte = bytes.get((bit / 8) as usize).ok_or(Error::BadIndex)?;
            value |= u64::from((byte >> (bit % 8)) & 1) << i;
        }
        Ok(value)
    }

    fn write_buffer_field(&mut self, node: NodeId, value: u64) -> Result<(), Error> {
        let (start, len, bit_offset, bit_width) = self.buffer_field(node)?;
        let bytes = &mut self.bytes[start..start + len];
        for i in 0..u64::from(bit_width) {
            let bit = bit_offset + i;
            let byte = bytes.get_mut((bit / 8) as usize).ok_or(Error::BadIndex)?;
            let m = 1u8 << (bit % 8);
            if (value >> i) & 1 != 0 {
                *byte |= m;
            } else {
                *byte &= !m;
            }
        }
        Ok(())
    }

    /// The nearest device enclosing `node`.
    pub(super) fn enclosing_device(&self, node: NodeId) -> Option<NodeId> {
        let mut n = self.parent(node)?;
        loop {
            if self.is_device(n) {
                return Some(n);
            }
            n = self.parent(n)?;
        }
    }

    /// A PCI device node's bus, device and function: device and function from its `_ADR`;
    /// the bus from its host bridge's `_BBN` (zero without one), or from the secondary bus
    /// register of the bridge it is behind.
    pub(super) fn pci_address(&mut self, device: NodeId) -> Result<(u8, u8, u8), Error> {
        let adr = self.child(device, b"_ADR").ok_or(Error::NotFound)?;
        let adr = self.value_of(adr, &[])?;
        let adr = self.integer(adr)?;
        let (dev, function) = (((adr >> 16) & 0x1f) as u8, (adr & 0x7) as u8);
        let bus = match self.enclosing_device(device) {
            None => 0,
            Some(parent) if self.is_host_bridge(parent)? => match self.child(parent, b"_BBN") {
                Some(bbn) => {
                    let v = self.value_of(bbn, &[])?;
                    self.integer(v)? as u8
                }
                None => 0,
            },
            Some(parent) => {
                if self.calls >= MAX_CALLS {
                    return Err(Error::TooDeep);
                }
                self.calls += 1;
                let bridge = self.pci_address(parent);
                self.calls -= 1;
                let (bus, device, function) = bridge?;
                let space = Space::PciConfig {
                    bus,
                    device,
                    function,
                };
                // Type 1 header: the secondary bus number.
                self.host.read(space, 0x19, 8).ok_or(Error::Host)? as u8
            }
        };
        Ok((bus, dev, function))
    }

    /// Whether `device` is a PCI host bridge: a `_HID` or `_CID` of `PNP0A03` or `PNP0A08`.
    pub(super) fn is_host_bridge(&mut self, device: NodeId) -> Result<bool, Error> {
        for id in [b"_HID", b"_CID"] {
            let Some(node) = self.child(device, id) else {
                continue;
            };
            let v = self.value_of(node, &[])?;
            let matched = match v {
                Object::Integer(v) => {
                    v == u64::from(eisa_id(b"PNP0A03")) || v == u64::from(eisa_id(b"PNP0A08"))
                }
                Object::String(_) => matches!(self.buffer(v)?, b"PNP0A03" | b"PNP0A08"),
                _ => false,
            };
            if matched {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn mask(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

/// The address of the `access`-bit unit at bit `unit` of a region at `base` of `len` bytes.
fn region_address(base: u64, len: u64, unit: u32, access: u32) -> Result<u64, Error> {
    let offset = u64::from(unit / 8);
    if offset + u64::from(access / 8) > len {
        return Err(Error::BadIndex);
    }
    base.checked_add(offset).ok_or(Error::BadIndex)
}
