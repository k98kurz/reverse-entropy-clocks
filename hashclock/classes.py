from __future__ import annotations
from dataclasses import dataclass, field
from hashclock.misc import (
    bytes_are_same,
    derive_point_from_scalar,
    recursive_hash,
    recursive_next_point,
    recursive_next_scalar,
    derive_key_from_seed,
    sign_with_scalar,
    H_small,
    SigningKey,
    VerifyKey,
    tert,
    vert,
    sert,
)
from secrets import token_bytes
from uuid import uuid4
import json
import struct


@dataclass
class HashClockUpdater:
    """Implementation of the ClockUpdaterProtocol."""
    root: bytes
    uuid: bytes
    max_time: int

    @classmethod
    def setup(cls, root: bytes, max_time: int) -> HashClockUpdater:
        """Set up a new instance."""
        state = recursive_hash(root, max_time)

        return cls(root=root, uuid=state, max_time=max_time)

    def advance(self, time: int) -> tuple[int, bytes]:
        """Create an update that advances the clock to the given time."""
        assert type(time) is int, 'time must be int <= max_time'
        assert time <= self.max_time, 'time must be int <= max_time'

        state = recursive_hash(self.root, self.max_time - time)

        return (time, state)

    def pack(self) -> bytes:
        """Pack the clock updater into bytes."""
        return struct.pack(
            f'!I{len(self.root)}s',
            self.max_time,
            self.root
        )

    @classmethod
    def unpack(cls, data: bytes) -> HashClockUpdater:
        """Unpack a clock updater from bytes."""
        assert type(data) is bytes, 'data must be bytes with len > 6'
        assert len(data) > 6, 'data must be bytes with len > 6'

        max_time, root = struct.unpack(f'!I{len(data)-4}s', data)

        return cls.setup(root, max_time)


@dataclass
class HashClock:
    """Implementation of the Reverse Entropy Clock."""
    uuid: bytes = field(default_factory=bytes)
    state: tuple[int, bytes] = field(default=None)
    updater: HashClockUpdater = field(default=None)

    def setup(self, max_time: int, root_size: int = 16) -> HashClockUpdater|None:
        """Set up the instance if it hasn't been setup yet and return
            the updater for the clock. If it has been setup (i.e. has a
            uuid), return the updater if there is one or None.
        """
        if self.uuid:
            if not self.state:
                self.state = (0, self.uuid)
            return self.updater

        self.updater = HashClockUpdater.setup(token_bytes(root_size), max_time)

        self.uuid = self.updater.uuid
        self.state = (0, self.uuid)

        return self.updater

    def read(self) -> int:
        """Read the current state of the clock."""
        return self.state[0] if self.state is not None else -1

    def can_be_updated(self) -> bool:
        """Determines if the clock can possibly receive further updates."""
        return not (self.state is None or self.state[1] is None or len(self.state[-1]) != 32)

    def has_terminated(self) -> bool:
        """Determines if the clock has provably terminated."""
        return self.state is not None and len(self.state[-1]) != 32

    def update(self, state: tuple[int, bytes]) -> HashClock:
        """Update the clock if the state verifies."""
        assert type(state) in (tuple, list), \
            'states must be tuple or list of (int, bytes)'
        assert self.uuid is not None, 'cannot update clock without valid uuid'

        # ignore old updates
        if self.state and self.state[0] is not None and state[0] <= self.state[0]:
            return self

        # verify the update maps back to the most recent state
        calc_state = recursive_hash(state[1], state[0] - self.state[0])

        if bytes_are_same(calc_state, self.state[1]):
            self.state = tuple(state)

        return self

    def verify(self) -> bool:
        """Verifies the state."""
        if self.state is None:
            return True

        calc_state = recursive_hash(self.state[1], self.state[0])

        return bytes_are_same(calc_state, self.uuid)

    def verify_timestamp(self, timestamp: tuple[int, bytes]) -> bool:
        """Verifies the timestamp is valid for this clock."""
        if type(timestamp) is not tuple or len(timestamp) < 2:
            return False
        if type(timestamp[1]) is not bytes or len(timestamp[1]) == 0:
            return False

        calc_state = recursive_hash(timestamp[1], timestamp[0])

        return bytes_are_same(calc_state, self.uuid)

    def pack(self) -> bytes:
        """Pack the clock down to bytes."""
        return struct.pack(
            f'!I{len(self.state[1])}s',
            self.state[0],
            self.state[1]
        )

    @classmethod
    def unpack(cls, data: bytes) -> HashClock:
        """Unpack a clock from bytes."""
        assert type(data) is bytes, 'data must be bytes with len > 4'
        assert len(data) > 4, 'data must be bytes with len > 4'

        time, state = struct.unpack(f'!I{len(data)-4}s', data)
        calc_state = recursive_hash(state, time)

        return cls(uuid=calc_state, state=(time, state))

    def __repr__(self) -> str:
        return f'time={self.read()}; uuid={self.uuid.hex()}; ' + \
            f'state={self.state[1].hex()}; {self.has_terminated()=}'


@dataclass
class VectorHashClock:
    uuid: bytes = field(default_factory=lambda: uuid4().bytes)
    node_ids: list[bytes] = field(default=None)
    clocks: dict[bytes, HashClock] = field(default_factory=dict)

    def setup(self, node_ids: list[bytes] = None) -> VectorHashClock:
        """Set up the vector clock."""
        assert type(node_ids) is list or node_ids is None, \
            'node_ids must be list of bytes or None'
        if node_ids is not None:
            for nid in node_ids:
                assert type(nid) is bytes, 'node_ids must be list of bytes or None'
        assert self.clocks == {}, 'clock has already been setup'

        if node_ids is not None:
            self.node_ids = [*node_ids]

        for nid in self.node_ids:
            self.clocks[nid] = HashClock()

        return self

    @classmethod
    def create(cls, uuid: bytes, node_ids: list[bytes]) -> VectorHashClock:
        """Create a vector clock."""
        assert type(uuid) is bytes, 'uuid must be bytes'
        assert type(node_ids) is list, 'node_ids must be list of bytes'
        for nid in node_ids:
            assert type(nid) is bytes, 'node_ids must be list of bytes'

        return cls(uuid, node_ids).setup()

    def read(self) -> dict:
        """Read the clock as dict mapping node_id to tuple[int, bytes]."""
        result = {b'uuid': self.uuid}

        for id in self.node_ids:
            result[id] = self.clocks[id].state
            result[id] = (-1, None) if result[id] is None else result[id]

        return result

    def advance(self, node_id: bytes, state: tuple[int, bytes]) -> dict:
        """Create an update to advance the clock."""
        assert self.clocks != {}, 'cannot advance clock that has not been setup'
        assert type(node_id) is bytes, 'node_id must be bytes'
        assert node_id in self.node_ids, 'node_id not part of this clock'

        if self.clocks[node_id].state is None:
            uuid = recursive_hash(state[1], state[0])
            self.clocks[node_id].uuid = uuid
            self.clocks[node_id].state = state

        update = {b'uuid': self.uuid}
        for nid in self.node_ids:
            clock_state = self.clocks[nid].state
            if clock_state and clock_state[1]:
                update[nid] = clock_state
        update[node_id] = state

        return update

    def update(self, state: dict) -> VectorHashClock:
        """Update the clock using a dict mapping node_id to tuple[int, bytes]."""
        assert type(state) is dict, 'state must be a dict mapping node_id to tuple[int, bytes]'
        assert b'uuid' in state, 'state must include uuid of clock to update'
        assert bytes_are_same(state[b'uuid'], self.uuid), 'uuid of update must match clock uuid'

        for id in state:
            assert id in self.node_ids or id == b'uuid', 'state includes invalid node_id'

        for id in state:
            if id == b'uuid' or state[id][1] is None:
                continue

            if self.clocks[id].state is None:
                uuid = recursive_hash(state[id][1], state[id][0])
                self.clocks[id].uuid = uuid
                self.clocks[id].state = (0, uuid)

            self.clocks[id].update(state[id])

        return self

    def verify(self) -> bool:
        """Verify that all underlying HashClocks are valid."""
        for id in self.node_ids:
            if not self.clocks[id].verify():
                return False

        return True

    def verify_timestamp(self, timestamp: dict[bytes, bytes|tuple]) -> bool:
        """Verify that the timestamp is valid."""
        if b'uuid' not in timestamp or timestamp[b'uuid'] != self.uuid:
            return False

        for id in [id for id in timestamp if id != b'uuid']:
            if id not in self.node_ids:
                return False

            if not self.clocks[id].verify_timestamp(timestamp[id]):
                return False

        return True

    @staticmethod
    def happens_before(ts1: dict, ts2: dict) -> bool:
        """Determine if ts1 happens before ts2. As long as at least
            one node_id contained in both timestamps has a higher value
            in ts1 and no node_id shared by both has a higher value in
            ts2, ts1 happened-before ts2.
        """
        assert not VectorHashClock.are_incomparable(ts1, ts2), \
            'incomparable timestamps cannot be compared for happens-before relation'

        reverse_causality = False
        at_least_one_earlier = False

        for id in [id for id in ts1 if id in ts2 and id != b'uuid']:
            if ts1[id][0] > ts2[id][0]:
                reverse_causality = True
            if ts1[id][0] < ts2[id][0]:
                at_least_one_earlier = True

        return at_least_one_earlier and not reverse_causality

    @staticmethod
    def are_incomparable(ts1: dict, ts2: dict) -> bool:
        """Determine if ts1 and ts2 are incomparable. As long as the
            two timestamps share one node_id in common, they are
            comparable.
        """
        assert type(ts1) is dict, 'ts1 must be dict mapping node_id to tuple[int, bytes]'
        assert type(ts2) is dict, 'ts2 must be dict mapping node_id to tuple[int, bytes]'
        assert b'uuid' in ts1 and b'uuid' in ts2, 'ts1 and ts2 must have both have uuids'

        if not bytes_are_same(ts1[b'uuid'], ts2[b'uuid']):
            return True

        for id in ts1:
            if id in ts2:
                return False

        for id in ts2:
            if id in ts1:
                return False

        return True

    @staticmethod
    def are_concurrent(ts1: dict, ts2: dict) -> bool:
        """Determine if ts1 and ts2 are concurrent."""
        assert not VectorHashClock.are_incomparable(ts1, ts2), \
            'incomparable timestamps cannot be compared for concurrency'

        return not VectorHashClock.happens_before(ts1, ts2) and \
            not VectorHashClock.happens_before(ts2, ts1)

    def pack(self) -> bytes:
        """Pack the clock into bytes."""
        jsonified = {'uuid': self.uuid.hex()}

        for id in self.node_ids:
            if self.clocks[id].state is not None and self.clocks[id].state[1] is not None:
                jsonified[id.hex()] = self.clocks[id].pack().hex()
            else:
                jsonified[id.hex()] = None

        return bytes(json.dumps(jsonified, sort_keys=True, separators=(',', ':')), 'utf-8')

    @classmethod
    def unpack(cls, data: bytes) -> VectorHashClock:
        """Unpack a clock from bytes."""
        assert type(data) is bytes, 'data must be bytes'

        data = json.loads(str(data, 'utf-8'))
        uuid = bytes.fromhex(data['uuid'])
        clocks = {}

        for key in data:
            if key == 'uuid':
                continue

            node_id = bytes.fromhex(key)

            if data[key] is None:
                clocks[node_id] = HashClock()
            else:
                clocks[node_id] = HashClock.unpack(bytes.fromhex(data[key]))

        node_ids = clocks.keys()

        return cls(uuid, node_ids, clocks)


@dataclass
class PointClockUpdater:
    """Implementation of the ClockUpdaterProtocol."""
    root: bytes
    uuid: bytes
    max_time: int

    @classmethod
    def setup(cls, root: bytes, max_time: int) -> PointClockUpdater:
        """Set up a new instance."""
        skey = SigningKey(H_small(root))
        state = recursive_next_point(bytes(skey.verify_key), max_time)

        return cls(root=root, uuid=state, max_time=max_time)

    def advance(self, time: int) -> tuple[int, bytes]:
        """Create an update that advances the clock to the given time."""
        tert(type(time) is int, 'time must be int <= max_time')
        vert(time <= self.max_time, 'time must be int <= max_time')

        skey = SigningKey(H_small(self.root))
        state = recursive_next_point(bytes(skey.verify_key), self.max_time - time)

        return (time, state)

    def advance_and_sign(self, time: int, message: bytes) -> tuple[int, bytes, bytes]:
        """Create an update that advances the clock to the given time
            and provide a signature that verifies for the public key.
            Return format is (ts, pubkey, signature).
        """
        tert(type(time) is int, 'time must be int <= max_time')
        vert(time <= self.max_time, 'time must be int <= max_time')
        tert(type(message) is bytes, 'message must be bytes')
        vert(len(message) > 0, 'message must not be empty')

        x = derive_key_from_seed(H_small(self.root))
        x = recursive_next_scalar(x, self.max_time - time)
        X = derive_point_from_scalar(x)
        sig = sign_with_scalar(x, message, self.root)
        return (time, X, sig)

    def pack(self) -> bytes:
        """Pack the clock updater into bytes."""
        return struct.pack(
            f'!I{len(self.root)}s',
            self.max_time,
            self.root
        )

    @classmethod
    def unpack(cls, data: bytes) -> PointClockUpdater:
        """Unpack a clock updater from bytes."""
        assert type(data) is bytes, 'data must be bytes with len > 6'
        assert len(data) > 6, 'data must be bytes with len > 6'

        max_time, root = struct.unpack(f'!I{len(data)-4}s', data)

        return cls.setup(root, max_time)


@dataclass
class PointClock:
    """Implementation of the Ed25519 Reverse Entropy Clock."""
    uuid: bytes = field(default_factory=bytes)
    state: tuple[int, bytes] = field(default=None)
    updater: PointClockUpdater = field(default=None)

    def setup(self, max_time: int, root_size: int = 32) -> PointClockUpdater|None:
        """Set up the instance if it hasn't been setup yet and return
            the updater for the clock. If it has been setup (i.e. has a
            uuid), return the updater if there is one or None.
        """
        if self.uuid:
            if not self.state:
                self.state = (0, self.uuid)
            return self.updater

        self.updater = PointClockUpdater.setup(token_bytes(root_size), max_time)

        self.uuid = self.updater.uuid
        self.state = (0, self.uuid)

        return self.updater

    def read(self) -> int:
        """Read the current state of the clock."""
        return self.state[0] if self.state is not None else -1

    def update(self, state: tuple[int, bytes]) -> PointClock:
        """Update the clock if the state verifies."""
        assert type(state) in (tuple, list), \
            'states must be tuple or list of (int, bytes)'
        assert self.uuid is not None, 'cannot update clock without valid uuid'

        # ignore old updates
        if self.state and self.state[0] is not None and state[0] <= self.state[0]:
            return self

        time, calc_state = state[0], state[1]

        # verify the update maps back to the most recent state
        calc_state = recursive_next_point(calc_state, time - self.state[0])

        if bytes_are_same(calc_state, self.state[1]):
            self.state = tuple(state)

        return self

    def verify(self) -> bool:
        """Verifies the state."""
        if self.state is None:
            return True

        try:
            calc_state = recursive_next_point(self.state[1], self.state[0])
            return bytes_are_same(calc_state, self.uuid)
        except:
            return False

    def verify_timestamp(self, timestamp: tuple) -> bool:
        """Verify a timestamp."""
        if type(timestamp) is not tuple or len(timestamp) < 2:
            return False
        if type(timestamp[1]) is not bytes or len(timestamp[1]) == 0:
            return False

        # check that it is a valid point for the entropy clock
        time, point = timestamp[0], timestamp[1]
        try:
            calc_point = recursive_next_point(point, time)
            return bytes_are_same(calc_point, self.uuid)
        except:
            return False

    def verify_signed_timestamp(self, timestamp: tuple, message: bytes) -> bool:
        """Verify a signed timestamp contains both a valid timestamp and
            a valid signature from the pubkey in the timestamp.
        """
        tert(type(timestamp) is tuple, 'timestamp must be tuple of (int, bytes, bytes)')
        vert(len(timestamp) >= 3, 'timestamp must be tuple of (int, bytes, bytes)')

        if not self.verify_timestamp(timestamp[:2]):
            return False

        # verify the signature
        _, point, signature = timestamp
        try:
            vkey = VerifyKey(point)
            vkey.verify(message, signature)
            return True
        except:
            return False

    def pack(self) -> bytes:
        """Pack the clock down to bytes."""
        return struct.pack(
            f'!I{len(self.state[1])}s',
            self.state[0],
            self.state[1]
        )

    @classmethod
    def unpack(cls, data: bytes) -> PointClock:
        """Unpack a clock from bytes."""
        assert type(data) is bytes, 'data must be bytes with len > 4'
        assert len(data) > 4, 'data must be bytes with len > 4'

        time, state = struct.unpack(f'!I{len(data)-4}s', data)
        calc_state = recursive_next_point(state, time)

        return cls(uuid=calc_state, state=(time, state))

    def __repr__(self) -> str:
        return f'time={self.read()}; uuid={self.uuid.hex()}; ' + \
            f'state={self.state[1].hex()}; {self.has_terminated()=}'


@dataclass
class VectorPointClock:
    uuid: bytes = field(default_factory=lambda: uuid4().bytes)
    node_ids: list[bytes] = field(default=None)
    clocks: dict[bytes, PointClock] = field(default_factory=dict)

    def setup(self, node_ids: list[bytes] = None) -> VectorPointClock:
        """Set up the vector clock."""
        assert type(node_ids) is list or node_ids is None, \
            'node_ids must be list of bytes or None'
        if node_ids is not None:
            for nid in node_ids:
                assert type(nid) is bytes, 'node_ids must be list of bytes or None'
        assert self.clocks == {}, 'clock has already been setup'

        if node_ids is not None:
            self.node_ids = [*node_ids]

        for nid in self.node_ids:
            self.clocks[nid] = PointClock()

        return self

    @classmethod
    def create(cls, uuid: bytes, node_ids: list[bytes]) -> VectorPointClock:
        """Create a vector clock."""
        assert type(uuid) is bytes, 'uuid must be bytes'
        assert type(node_ids) is list, 'node_ids must be list of bytes'
        for nid in node_ids:
            assert type(nid) is bytes, 'node_ids must be list of bytes'

        return cls(uuid, node_ids).setup()

    def read(self) -> dict:
        """Read the clock as dict mapping node_id to tuple[int, bytes]."""
        result = {b'uuid': self.uuid}

        for id in self.node_ids:
            result[id] = self.clocks[id].state
            result[id] = (-1, None) if result[id] is None else result[id]

        return result

    def advance(self, node_id: bytes, state: tuple[int, bytes]) -> dict:
        """Create an update to advance the clock."""
        assert self.clocks != {}, 'cannot advance clock that has not been setup'
        assert type(node_id) is bytes, 'node_id must be bytes'
        assert node_id in self.node_ids, 'node_id not part of this clock'

        if self.clocks[node_id].state is None:
            uuid = recursive_next_point(state[1], state[0])
            self.clocks[node_id].uuid = uuid
            self.clocks[node_id].state = state

        update = {b'uuid': self.uuid}
        for nid in self.node_ids:
            clock_state = self.clocks[nid].state
            if clock_state and clock_state[1]:
                update[nid] = clock_state
        update[node_id] = state

        return update

    def update(self, state: dict[bytes, tuple]) -> VectorPointClock:
        """Update the clock using a dict mapping node_id to
            tuple[int, bytes] or tuple[int, bytes, bytes].
        """
        assert type(state) is dict, 'state must be a dict mapping node_id to tuple[int, bytes]'
        assert b'uuid' in state, 'state must include uuid of clock to update'
        assert bytes_are_same(state[b'uuid'], self.uuid), 'uuid of update must match clock uuid'

        for id in state:
            assert id in self.node_ids or id == b'uuid', 'state includes invalid node_id'

        for id in state:
            if id == b'uuid' or state[id][1] is None:
                continue

            if self.clocks[id].state is None:
                uuid = recursive_next_point(state[id][1], state[id][0])
                self.clocks[id].uuid = uuid
                self.clocks[id].state = (0, uuid)

            self.clocks[id].update(state[id])

        return self

    def verify(self) -> bool:
        """Verify that all underlying PointClocks are valid."""
        for id in self.node_ids:
            if not self.clocks[id].verify():
                return False

        return True

    def verify_timestamp(self, timestamp: dict[bytes, bytes|tuple]) -> bool:
        """Verify that the timestamp is valid."""
        if b'uuid' not in timestamp or timestamp[b'uuid'] != self.uuid:
            return False

        for id in [id for id in timestamp if id != b'uuid']:
            if id not in self.node_ids:
                return False

            if not self.clocks[id].verify_timestamp(timestamp[id]):
                return False

        return True

    @staticmethod
    def happens_before(ts1: dict, ts2: dict) -> bool:
        """Determine if ts1 happens before ts2. As long as at least
            one node_id contained in both timestamps has a higher value
            in ts1 and no node_id shared by both has a higher value in
            ts2, ts1 happened-before ts2.
        """
        assert not VectorPointClock.are_incomparable(ts1, ts2), \
            'incomparable timestamps cannot be compared for happens-before relation'

        reverse_causality = False
        at_least_one_earlier = False

        for id in [id for id in ts1 if id in ts2 and id != b'uuid']:
            if ts1[id][0] > ts2[id][0]:
                reverse_causality = True
            if ts1[id][0] < ts2[id][0]:
                at_least_one_earlier = True

        return at_least_one_earlier and not reverse_causality

    @staticmethod
    def are_incomparable(ts1: dict, ts2: dict) -> bool:
        """Determine if ts1 and ts2 are incomparable. As long as the
            two timestamps share one node_id in common, they are
            comparable.
        """
        assert type(ts1) is dict, 'ts1 must be dict mapping node_id to tuple[int, bytes]'
        assert type(ts2) is dict, 'ts2 must be dict mapping node_id to tuple[int, bytes]'
        assert b'uuid' in ts1 and b'uuid' in ts2, 'ts1 and ts2 must have both have uuids'

        if not bytes_are_same(ts1[b'uuid'], ts2[b'uuid']):
            return True

        for id in ts1:
            if id in ts2:
                return False

        for id in ts2:
            if id in ts1:
                return False

        return True

    @staticmethod
    def are_concurrent(ts1: dict, ts2: dict) -> bool:
        """Determine if ts1 and ts2 are concurrent."""
        assert not VectorPointClock.are_incomparable(ts1, ts2), \
            'incomparable timestamps cannot be compared for concurrency'

        return not VectorPointClock.happens_before(ts1, ts2) and \
            not VectorPointClock.happens_before(ts2, ts1)

    def pack(self) -> bytes:
        """Pack the clock into bytes."""
        jsonified = {'uuid': self.uuid.hex()}

        for id in self.node_ids:
            if self.clocks[id].state is not None and self.clocks[id].state[1] is not None:
                jsonified[id.hex()] = self.clocks[id].pack().hex()
            else:
                jsonified[id.hex()] = None

        return bytes(json.dumps(jsonified, sort_keys=True, separators=(',', ':')), 'utf-8')

    @classmethod
    def unpack(cls, data: bytes) -> VectorPointClock:
        """Unpack a clock from bytes."""
        assert type(data) is bytes, 'data must be bytes'

        data = json.loads(str(data, 'utf-8'))
        uuid = bytes.fromhex(data['uuid'])
        clocks = {}

        for key in data:
            if key == 'uuid':
                continue

            node_id = bytes.fromhex(key)

            if data[key] is None:
                clocks[node_id] = PointClock()
            else:
                clocks[node_id] = PointClock.unpack(bytes.fromhex(data[key]))

        node_ids = clocks.keys()

        return cls(uuid, node_ids, clocks)
