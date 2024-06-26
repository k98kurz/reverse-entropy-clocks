# Reverse Entropy Clocks

A reverse entropy clock is a logical clock that uses one-way functions to
pre-compute a causality chain that is revealed in reverse order, thus enabling
later timestamps to be verified using just the public UUID of the clock, the
integer timestamp, and a 32 byte proof. It is "reverse entropy" in the sense
that the causal chain of events within the clock mechanism is reversed compared
to other logical clocks using one-way functions, e.g. blockchains.

This package provides two types of reverse entropy logical clocks:
- Hash-based, in which a seed value is recursively hashed to produce the UUID
- Ed25519-based, in which a seed secret value is used as the seed for a private
key, then the public key is recursively hashed and added to a point derived from
that hash (as a scalar) using Ed25519 point addition to produce the UUID

This module uses sha256 from hashlib to implement reverse entropy hash clocks;
i.e. hash lock clocks. This is a generalization of the hash lock used in Bitcoin
UTXO locking scripts and logical clocks as invented by Leslie Lamport. A given
hash clock can only be updated by the node that created it or any nodes with
which it shares the seed and max_time values, and it can be used in a
distributed system to order events.

This module uses sha256 from hashlib and ed25519 via the PyNaCl package to
implement reverse entropy signature clocks. This takes advantage of a
combination of Ed25519's homomorphic one-way feature of point derivation and
sha256's one-way feature, and it can produce verifiable attestations. The clock
owner needs only to keep a 32 byte seed value and the lifetime; clock observers
need the 32 byte uuid.

To the author's knowledge, these are novel constructions.

## Status

- [x] Readme
- [x] Interfaces
- [x] HashClock and HashClockUpdater
- [x] Optimization refactor
- [x] VectorHashClock
- [x] PointClock and PointClockUpdater
- [x] VectorPointClock

## Installation

```bash
pip install reclocks
```

## Overview

In general, a reverse entropy clock uses a cryptographic one-way function to
pre-compute a causality chain. Intermediate states are then revealed in reverse
order to move the clock forward. The causal chains have finite length, and so
the clocks have a finite life span. Because the functions are one-way, they
cannot be reversed, so only the holder of the seed value can issue updates.

Full documentation can be found
[here](https://github.com/k98kurz/reverse-entropy-clocks/blob/main/dox.md). Dox
were automagically generated by [autodox](https://pypi.org/project/autodox/).

### Reverse Entropy Hash Clock

The idea is that a message digest can form a lock that is opened by the preimage
key. These can be chained by using digests as preimages for the next digest.
This can be used to create a logical clock where the final digest becomes the
clock state; each next preimage released is verified and added to the state; the
time of the clock is the number of state items minus 1. Thus, as causally prior
states are revealed, the timer increases; hence, it is a Reverse Entropy Clock
(aka HashClock).

This library uses sha256 as the hash algorithm to generate `HashClock`s that can
provably terminate if default options are used. Clocks that do not provably
terminate can be setup with `clock.setup(n, seed_size=32)`.

The `setup(max_time: int, seed_size: int = 16) -> HashClockUpdater` method will
set up the hash lock chain, set the final digest as the state, and return a
HashClockUpdater. This HashClockUpdater is then used to advance the clock by
recursively hashing the seed `max_time - time` times and returning a tuple of
`(time, state)`. It is technically a state-based CRDT counter and can be thought
of as a permissioned CRDT since only those who know the seed and max_time can
advance the clock.

The VectorHashClock class can be used to create vector clocks using the
HashClock mechanism underneath.Additionally, a VectorPointClock class can be
used to create vector clocks using the PointClock mechanism underneath.

If there is sufficient interest, perhaps I will make a MapHashClock class to
extend the VectorHashClock idea to not require all node IDs to be included in
the setup; i.e. new nodes would be able to join the MapHashClock after setup by
issuing an update referencing the clock's uuid, the node id, and the node's
HashLock state tuple. A further optimization could be made in a ChainHashClock
class to implement the chain clock as described by Agarwal and Garg in their
paper "Efficient Dependency Tracking for Relevant Events in Concurrent Systems".

### Reverse Entropy Ed25519 Clock

Similarly, we can construct a reverse entropy clock by generating a secret seed
value, generating an ed25519 private key from it, then using the public key as
the base of the causality chain. The chain is then constructed by recursively
multiplying the public key point by its sha256 digest clamped to the ed22519
scalar field.

This library uses the ed25519 bindings from the PyNaCl package to create
`PointClock`s. Unlike the `HachClock`, the `PointClock` does not provably
terminate, regardless of the seed size.

The mechanism is as follows: given `derive(scalar) -> G * scalar` for generating
ed25519 points from scalars, `add(scalar) -> scalar + scalar` for adding ed25519
private key scalars, `mult(point, scalar) -> point + derive(scalar)` for adding
an ed25519 public key point with the point dervied from an ed25519 scalar,
`next_p(point) -> mult(point, hash(point))` for generating the next point in the
chain, `next_s(scalar) -> scalar + hash(derive(scalar))` for generating the next
(secret) scalar value in the chain,
`recursive_next_p(pnt, cnt) -> pnt if cnt is 0 else recursive_next_p(next_p(pnt, pnt), cnt-1)`
for recursively calling `next_p` to get the point for a given time step, and
`recursive_next_s(sclr, cnt) -> sclr if cnt is 0 else recursive_next_s(next_s(sclr, pnt), cnt-1)`
for recursively calling `next_s` to get the scalar for a given time step,
we can set `clock.uuid = recursive_next_p(pubkey, clock.lifetime)`, and have
timestamp tuple `(ts, state = recursive_next_p(pubkey, clock.lifetime - ts), msg, sig)`
where the signature `sig` is made using `recursive_next_s(prvkey, clock.lifetime - ts)`
as the signing key. Verification is then
`verify(ts, state, msg, sig) -> recursive_next_p(state, ts) == clock.uuid and ed25519_verify(msg, sig, state)`.

## Classes and Interfaces

### Interfaces

- ClockProtocol(Protocol)
- ClockUpdaterProtocol(Protocol)
- VectorClockProtocol(Protocol)

### Classes

- HashClock(ClockProtocol)
- HashClockUpdater(ClockUpdaterProtocol)
- VectorHashClock(VectorClockProtocol)
- PointClock(ClockProtocol)
- PointClockUpdater(ClockUpdaterProtocol)
- VectorPointClock(VectorClockProtocol)

## Usage Examples

### HashClock and HashClockUpdater

```python
from reclocks import HashClock, HashClockUpdater

max_clock_life = 420 # arbitrary but meaningful choice

# setup clock
hclock = HashClock()
hc_updater = hclock.setup(420)

# simulate sending public data elsewhere
hclock2 = HashClock(uuid=hclock.uuid)
ts1 = hclock2.read()

# advance the clock
hcu1 = hc_updater.advance(68)
hclock.update(hcu1)

# verify update and synchronize
assert hclock2.verify_timestamp(hcu1)
hclock2.update(hcu1)
ts2 = hclock2.read()

# prove causality
assert hclock2.happens_before(ts1, ts2)

# serialize, deserialize, and verify internal state
packed = hclock2.pack()
unpacked = HashClock.unpack(packed)
assert unpacked.verify()

# serialiaze and deserialize updater
packed = hc_updater.pack()
unpacked = HashClockUpdater.unpack(packed)
```

### PointClock and PointClockUpdater

```python
from reclocks import PointClock, PointClockUpdater

max_clock_life = 420 # arbitrary but meaningful choice

# setup clock
pclock = PointClock()
pc_updater = pclock.setup(420)

# simulate sending public data elsewhere
pclock2 = PointClock(uuid=pclock.uuid)
ts1 = pclock2.read()

# advance the clock
pcu1 = pc_updater.advance(68)
pclock.update(pcu1)

# verify and synchronize
assert pclock2.verify_timestamp(pcu1)
pclock2.update(pcu1)
ts2 = pclock2.read()

# additional signature feature of the PointClock
pcu2 = pc_updater.advance_and_sign(69, b'nice')
pclock.update(pcu2)

# verify before synchronizing
assert pclock2.verify_signed_timestamp(pcu2, b'nice')
pclock2.update(pcu2)
ts3 = pclock2.read()

# prove causality
assert pclock2.happens_before(ts1, ts2)
assert pclock2.happens_before(ts2, ts3)
assert pclock2.happens_before(ts1, ts3) # transitive

# serialize, deserialize, and verify internal state
packed = pclock2.pack()
unpacked = PointClock.unpack(packed)
assert unpacked.verify()

# serialiaze and deserialize updater
packed = pc_updater.pack()
unpacked = PointClockUpdater.unpack(packed)
```

### VectorHashClock

```python
from reclocks import HashClock, VectorHashClock
from reclocks.misc import hexify
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

ts0, ts1 = vhc0.read(), vhc1.read()

print(hexify(ts0))
print(hexify(ts1))
print(f'{VectorHashClock.are_concurrent(ts0, ts1)=}')

# converge by swapping updates
vhc1 = vhc1.update(update0)
vhc0 = vhc0.update(update1)
print(hexify(vhc0.read()))
print(hexify(vhc1.read()))

for c in vhc0.clocks:
    print(repr(vhc0.clocks[c]))
```

### VectorPointClock

E2e example from the test suite:

```python
from hashlib import sha256
from reclocks import PointClock, VectorPointClock

# simulate setting up clocks independently
clocks = [PointClock() for _ in range(5)]
updaters = [clock.setup(256) for clock in clocks]

# compile the ids
node_ids = [clock.uuid for clock in clocks]
uuids = { nid: nid for nid in node_ids }
root_uuid = sha256(b''.join(node_ids)).digest()

# simulate creating a vector clock at each node
vectorclocks = [
    VectorPointClock(root_uuid).setup(node_ids, uuids)
    for _ in node_ids
]

# make timestamps
ts0 = [vc.read() for vc in vectorclocks]
assert all([ts0[0] == ts for ts in ts0]), 'timestamps should be the same'

# create some updates
message = b'hello world'
updates = [
    vectorclocks[i].advance(
        updaters[i].uuid,
        updaters[i].advance_and_sign(1, message)
    )
    for i in range(len(node_ids))
]

# verify every update at each node and then update
for u in updates:
    for vc in vectorclocks:
        assert vc.verify_signed_timestamp(u, message)
        _ = vc.update(u)

# check timestamps are all the same
ts1 = [vc.read() for vc in vectorclocks]
assert all([ts1[0] == ts for ts in ts1]), 'timestamps should be the same'

# ensure that time moved forward
assert vectorclocks[0].happens_before(ts0[0], ts1[0]), 'time should move forward'
```

Note: in theory, an application should advance its own clock after receiving
updates for other clocks in the vector; each receipt of a message that updates
one of the clocks should represent a causal happens-before relationship to any
updates that occur after. However, allowing the clocks to tick independently may
be useful for some applications where synchronization/desynchronization levels
need to be tracked and managed.

## Tests

To setup, clone the repository and run the following in the seed directory:

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Then to run the tests:

```bash
python tests/test_classes.py
```

There are 75 tests ensuring algorithmic correctness. Examples of intended and
disallowed behaviors are contained in the tests. Reading through them may be
helpful when reasoning about the clocks' mechanisms.

## Bugs and Contributions

If you encounter a bug, please submit an issue on GitHub. If you would like to
contribute to any of my projects, discuss new projects, or collaborate on
experiments, join the [Pycelium discord server](https://discord.gg/b2QFEJDX69).

## ISC License

Copyleft (c) 2024 Jonathan Voss

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
