from __future__ import annotations
from dataclasses import dataclass, field
from hashlib import sha256
from secrets import token_bytes
import struct



# helper functions
def xor(b1: bytes, b2: bytes) -> bytes:
    """XOR two equal-length byte strings together."""
    b3 = bytearray()
    for i in range(len(b1)):
        b3.append(b1[i] ^ b2[i])

    return bytes(b3)

def bytes_are_same(b1: bytes, b2: bytes) -> bool:
    """Timing-attack safe bytes comparison."""
    return len(b1) == len(b2) and int.from_bytes(xor(b1, b2), 'little') == 0


@dataclass
class HashClockUpdater:
    """Implementation of the HashClockUpdaterProtocol."""
    root: bytes
    uuid: bytes
    max_time: int

    @classmethod
    def setup(cls, root: bytes, max_time: int) -> HashClockUpdater:
        """Set up a new instance."""
        state = root
        for _ in range(max_time):
            state = sha256(state).digest()

        return cls(root=root, uuid=state, max_time=max_time)

    def advance(self, time: int) -> tuple[int, bytes]:
        """Create an update that advances the clock to the given time."""
        assert type(time) is int, 'time must be int <= max_time'
        assert time <= self.max_time, 'time must be int <= max_time'

        state = self.root

        for _ in range(self.max_time - time):
            state = sha256(state).digest()

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

    def setup(self, max_time: int, root_size: int = 16) -> HashClockUpdater:
        """Set up the instance if it hasn't been setup yet and return
            the updater for the clock.
        """
        assert self.state is None, 'clock has already been setup'

        updater = HashClockUpdater.setup(token_bytes(root_size), max_time)

        self.uuid = updater.uuid
        self.state = (0, self.uuid)

        return updater

    def read(self) -> int:
        """Read the current state of the clock."""
        return self.state[0] if self.state is not None else -1

    def can_be_updated(self) -> bool:
        """Determines if the clock can possibly receive further updates."""
        return False if self.state is None or len(self.state[-1]) != 32 else True

    def has_terminated(self) -> bool:
        """Determines if the clock has provably terminated."""
        return self.state is not None and not self.can_be_updated()

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

        # verify the update maps back to the uuid
        calc_state = state[1]
        for _ in range(state[0]):
            calc_state = sha256(calc_state).digest()

        if bytes_are_same(calc_state, self.uuid):
            self.state = tuple(state)

        return self

    def verify(self) -> bool:
        """Verifies the state."""
        if self.state is None:
            return True

        calc_state = self.state[1]
        for _ in range(self.state[0]):
            calc_state = sha256(calc_state).digest()

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
        calc_state = state
        for _ in range(time):
            calc_state = sha256(calc_state).digest()

        return cls(uuid=calc_state, state=(time, state))

    def __repr__(self) -> str:
        return f'time={self.read()}; uuid={self.uuid.hex()}; ' + \
            f'state={self.state[1].hex()}; {self.has_terminated()=}'
