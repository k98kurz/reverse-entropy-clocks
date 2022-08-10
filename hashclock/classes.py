from __future__ import annotations
from dataclasses import dataclass, field
from hashlib import sha256
from secrets import token_bytes


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
class HashClock:
    state: list[bytes] = field(default_factory=list)

    def setup(self, lock_count: int, root_size: int = 16) -> list[bytes]:
        """Set up the instance if it hasn't been setup yet and return
            the chain of hashlock keys.
        """
        assert len(self.state) == 0, 'lock has already been setup'

        root = token_bytes(root_size)
        states = [root]

        while len(states) < lock_count + 1:
            states.append(sha256(states[-1]).digest())

        self.state = [states.pop()]

        return states

    def read(self) -> int:
        """Read the current state of the clock."""
        return len(self.state) - 1

    def can_be_updated(self) -> bool:
        """Determines if the clock can possibly receive further updates."""
        return False if len(self.state[-1]) != 32 else True

    def has_terminated(self) -> bool:
        """Determines if the clock has provably terminated."""
        return not self.can_be_updated()

    def update(self, states: list[bytes]) -> HashClock:
        """Update the clock if the states verify."""
        assert type(states) in (tuple, list), \
            'states must be tuple or list of bytes'

        # ignore old updates
        if len(states) <= len(self.state):
            return self

        # ignore updates that diverge from current state
        for i, v in enumerate(self.state):
            if not bytes_are_same(states[i], v):
                return self

        # check remaining hash locks
        states = states[len(self.state):]
        states.reverse()

        while len(states):
            lockkey = states.pop()
            if sha256(lockkey).digest() == self.state[-1]:
                self.state.append(lockkey)
            else:
                break

        return self

    def verify(self) -> bool:
        """Verifies the state."""
        for i, v in enumerate(self.state):
            if i > 0:
                if not bytes_are_same(sha256(v).digest(), self.state[i-1]):
                    return False

        return True

    def pack(self) -> bytes:
        """Pack the clock down to bytes."""
        return b''.join(self.state)

    @classmethod
    def unpack(cls, data: bytes) -> HashClock:
        """Unpack a clock from bytes."""
        assert type(data) in (bytes, bytearray), 'data must be bytes or bytearray'

        # split off every 32 bytes and save remainder
        data = data if type(data) is bytearray else bytearray(data)
        states = []
        while len(data) > 32:
            states.append(bytes(data[:32]))
            data = data[32:]
        states.append(bytes(data))

        return cls(states)

    def __repr__(self) -> str:
        return f'{self.read()}: {self.pack().hex()}'
