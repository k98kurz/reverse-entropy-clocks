from __future__ import annotations
from typing import Protocol, runtime_checkable


@runtime_checkable
class HashClockUpdaterProtocol(Protocol):
    """Duck typed Protocol showing what a HashClockUpdater must do."""
    @classmethod
    def setup(cls, root: bytes, max_time: int) -> HashClockUpdaterProtocol:
        """Set up a new instance."""
        ...

    def advance(self, time: int) -> tuple[int, bytes]:
        """Create an update that advances the clock to the given time."""
        ...

    def pack(self) -> bytes:
        """Pack the clock updater into bytes."""
        ...

    @classmethod
    def unpack(cls, data: bytes) -> HashClockUpdaterProtocol:
        """Unpack a clock updater from bytes."""
        ...


@runtime_checkable
class HashClockProtocol(Protocol):
    def setup(self, max_time: int, preimage_size: int = 16) -> HashClockUpdaterProtocol:
        """Set up the instance if it hasn't been setup yet and return
            the updater for the clock.
        """
        ...

    def read(self) -> int:
        """Read the current state of the clock."""
        ...

    def can_be_updated(self) -> bool:
        """Determines if the clock can possibly receive further updates."""
        ...

    def has_terminated(self) -> bool:
        """Determines if the clock has provably terminated."""
        ...

    def update(self, state: tuple[int, bytes]) -> HashClockProtocol:
        """Update the clock if the state verifies."""
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


@runtime_checkable
class VectorHashClockProtocol(Protocol):
    def setup(self, node_ids: list[bytes] = None) -> VectorHashClockProtocol:
        """Set up the vector clock."""
        ...

    @classmethod
    def create(cls, uuid: bytes, node_ids: list[bytes]) -> VectorHashClockProtocol:
        """Create a vector clock."""
        ...

    def read(self) -> dict:
        """Read the clock as dict mapping node_id to tuple[int, bytes]."""
        ...

    def advance(self, node_id: bytes, state: tuple[int, bytes]) -> dict:
        """Create an update to advance the clock."""
        ...

    def update(self, state: dict) -> VectorHashClockProtocol:
        """Update the clock using a dict mapping node_id to tuple[int, bytes]."""
        ...

    def verify(self) -> bool:
        """Verify that all underlying HashClocks are valid."""
        ...

    @staticmethod
    def happens_before(ts1: dict, ts2: dict) -> bool:
        """Determine if ts1 happens before ts2."""
        ...

    @staticmethod
    def are_incomparable(ts1: dict, ts2: dict) -> bool:
        """Determine if ts1 and ts2 are incomparable."""
        ...

    @staticmethod
    def are_concurrent(ts1: dict, ts2: dict) -> bool:
        """Determine if ts1 and ts2 are concurrent."""
        ...

    def pack(self) -> bytes:
        """Pack the clock into bytes."""
        ...

    @classmethod
    def unpack(cls, data: bytes) -> VectorHashClockProtocol:
        """Unpack a clock from bytes."""
        ...
