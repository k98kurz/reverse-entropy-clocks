# Reverse Entropy Clock

This module uses sha256 to implement a reverse entropy logical clock; i.e. a
hash lock clock. This is a generalization of the hashlock used in Bitcoin UTXO
locking scripts and logical clocks as invented by Leslie Lamport.

## Overview

The idea is that a message digest can form a lock that is opened by the preimage
key. These can be chained by using digests as preimages for the next digest.
This can be used to create a logical clock where the final digest becomes the
lock state; each next preimage released is verified and added to the state; the
time of the clock is the number of state items minus 1. Thus, as causally prior
states are revealed, the timer increases; hence, it is a Reverse Entropy Clock
(aka HashClock).

This simple library uses sha256 as the hash algorithm to generate HashClocks
that can provably terminate if default options are used. Clocks that do not
provably terminate can be setup with `hc.setup(n, root_size=32)`. Whether a
clock has provably terminated can be determined with `hc.has_terminated()`; the
inverse, whether a clock can possibly receive updates, can be determined with
`hc.can_be_updated()`.

The `setup(lock_count: int, root_size: int = 16) -> list[bytes]` method will set
up the hash lock chain, set the final digest as the state, and return the rest.
This list of bytes is then used to advance the clock by combining the state with
a bytes value popped off the end of the list; this new list becomes the update.
It is technically a state-based CRDT counter and can be thought of as a
permissioned CRDT since only those who know the locks can advance the clock.

## Status

- [x] Readme
- [x] Tests
- [x] Interfaces
- [x] Classes

## Installation

Currently, this project is still in development, so the best way to install is
to clone the repo. There are no dependencies.

These instructions will change once development is complete and the module is
published as a package.

## Classes and Interfaces

### Interfaces

- HashClockProtocol(Protocol)

### Classes

- HashClock(HashClockProtocol)

## Examples

```python
from hashclock import HashClock
hc = HashClock()
hc_keys = hc.setup(3)

print(hc.read())
print(repr(hc))
hc = hc.update([*hc.state, hc_keys.pop()])
print(hc.read())
print(repr(hc))

packed = hc.pack()
hc = HashClock.unpack(packed)
print('verified' if hc.verify() else 'unverified')
print(repr(hc))
```

## Tests

Open a terminal in the root directory and run the following:

```
cd tests/
python -m unittest
```

The tests are the interface contract that the code follows. Examples of intended
behaviors are contained in that short file. Reading through them may be helpful
when reasoning about the clock mechanism.

## Bugs

If you encounter a bug, please submit an issue on GitHub.

## ISC License

Copyleft (c) 2022 k98kurz

Permission to use, copy, modify, and/or distribute this software
for any purpose with or without fee is hereby granted, provided
that the above copyleft notice and this permission notice appear in
all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
