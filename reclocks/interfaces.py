from __future__ import annotations
from typing import Protocol, runtime_checkable


@runtime_checkable
class ClockUpdaterProtocol(Protocol):
    """Duck typed Protocol showing what a HashClockUpdater must do."""
    @classmethod
    def setup(cls, root: bytes, max_time: int) -> ClockUpdaterProtocol:
        """Set up a new instance."""
        ...

    def advance(self, time: int) -> tuple[int, bytes]:
        """Create a timestamp that advances the clock to the given time."""
        ...

    def pack(self) -> bytes:
        """Pack the clock updater into bytes."""
        ...

    @classmethod
    def unpack(cls, data: bytes) -> ClockUpdaterProtocol:
        """Unpack a clock updater from bytes."""
        ...


@runtime_checkable
class ClockProtocol(Protocol):
    def setup(self, max_time: int, preimage_size: int = 16) -> ClockUpdaterProtocol|None:
        """Set up the instance if it hasn't been setup yet and return
            the updater for the clock. If it has been setup (i.e. has a
            uuid), return the updater if there is one or None.
        """
        ...

    def read(self) -> tuple[int, bytes]:
        """Read the current state of the clock."""
        ...

    @staticmethod
    def happens_before(ts1: tuple, ts2: tuple) -> bool:
        """Determine if ts1 happens before ts2."""
        ...

    @staticmethod
    def are_incomparable(ts1: dict, ts2: dict) -> bool:
        """Determine if ts1 and ts2 are incomparable."""
        ...

    def update(self, state: tuple[int, bytes]) -> ClockProtocol:
        """Update the clock if the state verifies."""
        ...

    def verify(self) -> bool:
        """Verifies the state."""
        ...

    def verify_timestamp(self, timestamp: tuple[int, bytes]) -> bool:
        """Verify that the timestamp is valid."""
        ...

    def pack(self) -> bytes:
        """Pack the clock down to bytes."""
        ...

    @classmethod
    def unpack(cls, data: bytes) -> ClockProtocol:
        """Unpack a clock from bytes."""
        ...


@runtime_checkable
class VectorClockProtocol(Protocol):
    def setup(self, node_ids: list[bytes] = None,
              clock_uuids: dict[bytes, bytes] = {}) -> VectorClockProtocol:
        """Set up the vector clock."""
        ...

    @classmethod
    def create(cls, uuid: bytes, node_ids: list[bytes],
              clock_uuids: dict[bytes, bytes] = {}) -> VectorClockProtocol:
        """Create a vector clock."""
        ...

    def read(self) -> dict:
        """Read the clock as dict mapping node_id to tuple[int, bytes]."""
        ...

    def advance(self, node_id: bytes, state: tuple[int, bytes]) -> dict:
        """Create a timestamp to advance the clock."""
        ...

    def update(self, state: dict[bytes, tuple]) -> VectorClockProtocol:
        """Update the clock using a dict mapping node_id to tuple[int, bytes]."""
        ...

    def verify(self) -> bool:
        """Verify that all underlying HashClocks are valid."""
        ...

    def verify_timestamp(self, timestamp: dict[bytes, bytes|tuple]) -> bool:
        """Verify that the timestamp is valid."""
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
    def unpack(cls, data: bytes) -> VectorClockProtocol:
        """Unpack a clock from bytes."""
        ...
