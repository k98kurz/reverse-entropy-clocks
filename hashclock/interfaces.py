from __future__ import annotations
from typing import Protocol, runtime_checkable


@runtime_checkable
class HashClockProtocol(Protocol):
    def setup(self, lock_count: int, preimage_size: int = 16) -> tuple[bytes]:
        """Set up the instance if it hasn't been setup yet and return
            the chain of hashlock keys.
        """
        ...

    def read(self) -> int:
        """Read the current state of the clock."""
        ...

    def can_be_updated(self) -> bool:
        """Determines if the clock can possibly receive further updates."""
        ...

    def update(self, states: list[bytes]) -> HashClockProtocol:
        """Update the clock if the states verify."""
        ...

    def verify(self) -> bool:
        """Verifies the state."""
        ...

    def pack(self) -> bytes:
        """Pack the clock down to bytes."""
        ...

    @classmethod
    def unpack(cls, data: bytes) -> HashClockProtocol:
        """Unpack a clock from bytes."""
        ...
