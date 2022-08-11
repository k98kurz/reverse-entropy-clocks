# Reverse Entropy Clock

This module uses sha256 to implement reverse entropy logical clocks; i.e. hash
lock clocks. This is a generalization of the hashlock used in Bitcoin UTXO
locking scripts and logical clocks as invented by Leslie Lamport. A given hash
clock can only be updated by the node that created it or any nodes with which it
shares the root and max_time values, and it can be used in a distributed system
to order events.

## Overview

The idea is that a message digest can form a lock that is opened by the preimage
key. These can be chained by using digests as preimages for the next digest.
This can be used to create a logical clock where the final digest becomes the
clock state; each next preimage released is verified and added to the state; the
time of the clock is the number of state items minus 1. Thus, as causally prior
states are revealed, the timer increases; hence, it is a Reverse Entropy Clock
(aka HashClock).

This simple library uses sha256 as the hash algorithm to generate HashClocks
that can provably terminate if default options are used. Clocks that do not
provably terminate can be setup with `hc.setup(n, root_size=32)`. Whether a
clock has provably terminated can be determined with `hc.has_terminated()`; the
inverse, whether a clock can possibly receive updates, can be determined with
`hc.can_be_updated()`.

The `setup(max_time: int, root_size: int = 16) -> HashClockUpdater` method will
set up the hash lock chain, set the final digest as the state, and return a
HashClockUpdater. This HashClockUpdater is then used to advance the clock by
recursively hashing the root `max_time - time` times and returning a tuple of
`(time, state)`. It is technically a state-based CRDT counter and can be thought
of as a permissioned CRDT since only those who know the root and max_time can
advance the clock.

The VectorHashClock class can be used to create vector clocks using the
HashClock mechanism underneath. Additionally, a MapHashClock class will extend
the VectorHashClock idea to not require all node IDs to be included in the
setup; i.e. new nodes will be able to join the MapHashClock after setup by
issuing an update referencing the clock's uuid, the node id, and the node's
HashLock state tuple. A further optimization will be created in a ChainHashClock
class to implement the chain clock as described by Agarwal and Garg in their
paper "Efficient Dependency Tracking for Relevant Events in Concurrent Systems".

## Status

- [x] Readme
- [x] Tests
- [x] Interfaces
- [x] Classes
- [x] Optimization refactor
- [x] VectorHashClock
- [ ] MapHashClock
- [ ] ChainHashClock

## Installation

Currently, this project is still in development, so the best way to install is
to clone the repo. There are no dependencies.

These instructions will change once development is complete and the module is
published as a package.

## Classes and Interfaces

### Interfaces

- HashClockProtocol(Protocol)
- HashClockUpdaterProtocol(Protocol)
- VectorHashClockProtocol(Protocol)

### Classes

- HashClock(HashClockProtocol)
- HashClockUpdater(HashClockUpdaterProtocol)
- VectorHashClock(VectorHashClockProtocol)

## Examples

### HashClock and HashClockUpdater

```python
from hashclock import HashClock
hc = HashClock()
hcu = hc.setup(2)

print(hc.read())
print(repr(hc))
hc = hc.update(hcu.advance(1))
print(repr(hc))
hc = hc.update(hcu.advance(2))
print(repr(hc))

packed = hc.pack()
hc = HashClock.unpack(packed)
print('verified' if hc.verify() else 'unverified')
print(repr(hc))
```

### VectorHashClock

```python
from hashclock import HashClock, VectorHashClock
from hashclock.misc import hexify
node_ids = [b'node0', b'node1']
vhc0 = VectorHashClock().setup(node_ids)
hc0, hc1 = HashClock(), HashClock()
hcu0, hcu1 = hc0.setup(1), hc1.setup(3)

# initial timestamp where both are time=-1
tsneg1 = vhc0.read()
print(hexify(tsneg1))

# setup each HashClock at initial state
vhc0 = vhc0.update(vhc0.advance(node_ids[0], hcu0.advance(0)))
vhc0 = vhc0.update(vhc0.advance(node_ids[1], hcu1.advance(0)))

# next timestamp where both are time=0
ts0 = vhc0.read()
print(hexify(ts0))

# advance the clocks separately
update0 = vhc0.advance(node_ids[0], hcu0.advance(1))
update1 = vhc0.advance(node_ids[1], hcu1.advance(1))
packed = vhc0.pack()
vhc1 = VectorHashClock.unpack(packed)

vhc0 = vhc0.update(update0)
vhc1 = vhc1.update(update1)

print(hexify(vhc0.read()))
print(hexify(vhc1.read()))

# converge by swapping updates
vhc1 = vhc1.update(update0)
vhc0 = vhc0.update(update1)
print(hexify(vhc0.read()))
print(hexify(vhc1.read()))
```

## Tests

Open a terminal in the root directory and run the following:

```
python tests/test_classes.py
```

The tests are the interface contract that the code follows. Examples of intended
behaviors are contained in that file. Reading through them may be helpful when
reasoning about the clock mechanism.

## Bugs

If you encounter a bug, please submit an issue on GitHub.

## ISC License

Copyleft (c) 2022 k98kurz

Permission to use, copy, modify, and/or distribute this software
for any purpose with or without fee is hereby granted, provided
that the above copyleft notice and this permission notice appear in
all copies.

Exceptions: this permission is not granted to Alphabet/Google, Amazon,
Apple, Microsoft, Netflix, Meta/Facebook, Twitter, or Disney; nor is
permission granted to any company that contracts to supply weapons or
logistics to any national military; nor is permission granted to any
national government or governmental agency; nor is permission granted to
any employees, associates, or affiliates of these designated entities.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
