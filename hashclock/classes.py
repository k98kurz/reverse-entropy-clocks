from __future__ import annotations
from dataclasses import dataclass, field
from hashclock.misc import bytes_are_same, recursive_hash
from secrets import token_bytes
from uuid import uuid1
import json
import struct


@dataclass
class HashClockUpdater:
    """Implementation of the HashClockUpdaterProtocol."""
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

    def setup(self, max_time: int, root_size: int = 16) -> HashClockUpdater:
        """Set up the instance if it hasn't been setup yet and return
            the updater for the clock.
        """
        if self.uuid and self.state and self.updater:
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
        return not (self.state is None or len(self.state[-1]) != 32)

    def has_terminated(self) -> bool:
        """Determines if the clock has provably terminated."""
        return self.state is not None and len(self.state[-1]) != 32

    def update(self, state: tuple[int, bytes]) -> HashClock:
        """Update the clock if the state verifies."""
        assert type(state) in (tuple, list), \
            'states must be tuple or list of (int, bytes)'
        assert self.state is not None, 'cannot update unsetup clock'

        # ignore if we cannot update
        if not self.can_be_updated():
            return self

        # ignore old updates
        if state[0] <= self.state[0]:
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
    uuid: bytes = field(default_factory=lambda: uuid1().bytes)
    node_ids: list[bytes] = field(default=None)
    hash_clocks: dict = field(default_factory=dict)

    def setup(self, node_ids: list[bytes] = None) -> VectorHashClock:
        """Set up the vector clock."""
        assert type(node_ids) is list or node_ids is None, \
            'node_ids must be list of bytes or None'
        if node_ids is not None:
            for nid in node_ids:
                assert type(nid) is bytes, 'node_ids must be list of bytes or None'
        assert self.hash_clocks == {}, 'clock has already been setup'

        if node_ids is not None:
            self.node_ids = [*node_ids]

        for nid in self.node_ids:
            self.hash_clocks[nid] = HashClock()

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
            result[id] = self.hash_clocks[id].state
            result[id] = (-1, None) if result[id] is None else result[id]

        return result

    def advance(self, node_id: bytes, state: tuple[int, bytes]) -> dict:
        """Create an update to advance the clock."""
        assert self.hash_clocks != {}, 'cannot advance clock that has not been setup'
        assert type(node_id) is bytes, 'node_id must be bytes'
        assert node_id in self.node_ids, 'node_id not part of this clock'

        if self.hash_clocks[node_id].state is None:
            uuid = recursive_hash(state[1], state[0])
            self.hash_clocks[node_id].uuid = uuid
            self.hash_clocks[node_id].state = state

        update = {b'uuid': self.uuid}
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
            if id != b'uuid':
                if self.hash_clocks[id].state is None:
                    uuid = recursive_hash(state[id][1], state[id][0])
                    self.hash_clocks[id].uuid = uuid
                    self.hash_clocks[id].state = (0, uuid)

                self.hash_clocks[id].update(state[id])

        return self

    def verify(self) -> bool:
        """Verify that all underlying HashClocks are valid."""
        valid = True

        for id in self.node_ids:
            valid = valid and self.hash_clocks[id].verify()

        return valid

    @staticmethod
    def happens_before(ts1: dict, ts2: dict) -> bool:
        """Determine if ts1 happens before ts2."""
        assert not VectorHashClock.are_incomparable(ts1, ts2), \
            'incomparable timestamps cannot be compared for happens-before relation'

        reverse_causality = False
        at_least_one_earlier = False

        for id in ts1:
            if ts1[id][0] > ts2[id][0]:
                reverse_causality = True
            if ts1[id][0] < ts2[id][0]:
                at_least_one_earlier = True

        return at_least_one_earlier and not reverse_causality

    @staticmethod
    def are_incomparable(ts1: dict, ts2: dict) -> bool:
        """Determine if ts1 and ts2 are incomparable."""
        assert type(ts1) is dict, 'ts1 must be dict mapping node_id to tuple[int, bytes]'
        assert type(ts2) is dict, 'ts2 must be dict mapping node_id to tuple[int, bytes]'
        assert b'uuid' in ts1 and b'uuid' in ts2, 'ts1 and ts2 must have both have uuids'

        if not bytes_are_same(ts1[b'uuid'], ts2[b'uuid']):
            return True

        incomparable = False

        for id in ts1:
            if id not in ts2:
                incomparable = True

        for id in ts2:
            if id not in ts1:
                incomparable = True

        return incomparable

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
            if self.hash_clocks[id].state is not None:
                jsonified[id.hex()] = self.hash_clocks[id].pack().hex()
            else:
                jsonified[id.hex()] = None

        return bytes(json.dumps(jsonified, sort_keys=True, separators=(',', ':')), 'utf-8')

    @classmethod
    def unpack(cls, data: bytes) -> VectorHashClock:
        """Unpack a clock from bytes."""
        assert type(data) is bytes, 'data must be bytes'

        data = json.loads(str(data, 'utf-8'))
        uuid = bytes.fromhex(data['uuid'])
        hash_clocks = {}

        for key in data:
            if key == 'uuid':
                continue

            node_id = bytes.fromhex(key)

            if data[key] is None:
                hash_clocks[node_id] = HashClock()
            else:
                hash_clocks[node_id] = HashClock.unpack(bytes.fromhex(data[key]))

        node_ids = hash_clocks.keys()

        return cls(uuid, node_ids, hash_clocks)
