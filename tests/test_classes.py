from hashlib import sha256
from unittest.mock import patch
from context import classes, interfaces
import unittest


class TestClasses(unittest.TestCase):
    """Test suite for classes."""
    def test_imports_without_error(self):
        pass

    # HashClock tests
    def test_HashClock_implements_HashClockProtocol(self):
        assert issubclass(classes.HashClock, interfaces.HashClockProtocol), \
            'HashClock must implement HashClockProtocol'

    def test_HashClock_setup_creates_random_preimage(self):
        hc1 = classes.HashClock()
        hc1_vals = hc1.setup(1)
        hc2 = classes.HashClock()
        hc2_vals = hc2.setup(1)

        assert type(hc1_vals[0]) is bytes, 'preimage should be bytes'
        assert type(hc2_vals[0]) is bytes, 'preimage should be bytes'
        assert len(hc1_vals[0]) == 16, 'preimage should be 16 bytes'
        assert len(hc2_vals[0]) == 16, 'preimage should be 16 bytes'
        assert hc1_vals[0] != hc2_vals[0], 'preimages should be uncorrelated'

        assert hc1.read() == 0, 'clock should be at time 0 after setup'
        assert hc1.state[0] == sha256(hc1_vals[-1]).digest(), \
            'clock state should be the hash of the final value returned by setup'

    def test_HashClock_setup_can_be_updated(self):
        hc1 = classes.HashClock()
        hc1_vals = hc1.setup(1)

        assert hc1.can_be_updated(), 'can_be_updated() should be True after setup'

    def test_HashClock_update_increases_read_output(self):
        hc1 = classes.HashClock()
        hc1_vals = hc1.setup(3)

        assert hc1.read() == 0
        hc1.update([*hc1.state, hc1_vals.pop()])
        assert hc1.read() == 1
        hc1.update([*hc1.state, hc1_vals.pop()])
        assert hc1.read() == 2
        hc1.update([*hc1.state, hc1_vals.pop()])
        assert hc1.read() == 3

    def test_HashClock_update_is_idempotent(self):
        hc1 = classes.HashClock()
        hc1_vals = hc1.setup(3)

        assert hc1.read() == 0
        update1 = [*hc1.state, hc1_vals.pop()]
        hc1.update(update1)
        assert hc1.read() == 1
        hc1.update(update1)
        hc1.update(update1)
        assert hc1.read() == 1, 'no change after update applied many times'

        update2 = [*hc1.state, hc1_vals.pop()]
        hc1.update(update2)
        assert hc1.read() == 2, 'change after next update'
        hc1.update(update1)
        assert hc1.read() == 2, 'no change after reapplying old update'

    def test_HashClock_update_rejects_invalid_updates(self):
        hc1, hc2 = classes.HashClock(), classes.HashClock()
        hc1_vals = hc1.setup(2)
        hc2_vals = hc2.setup(2)

        assert hc1.read() == 0
        hc1.update([*hc2.state, hc1_vals[-1]])
        assert hc1.read() == 0

        assert hc2.read() == 0
        hc2.update([*hc2.state, hc1_vals[-1]])
        assert hc2.read() == 0

    def test_HashClock_can_be_updated_returns_False_for_terminated_clock(self):
        hc1 = classes.HashClock()
        hc1_vals = hc1.setup(1)

        assert hc1.read() == 0, 'read() starts at 0'
        hc1.update([*hc1.state, hc1_vals.pop()])
        assert hc1.read() == 1, 'read() increments after update'
        assert not hc1.can_be_updated(), 'can_be_updated() should return False'

    def test_HashClock_pack_returns_bytes(self):
        hc1 = classes.HashClock()
        hc1_vals = hc1.setup(1)

        packed = hc1.pack()
        assert type(packed) is bytes, 'pack() should return bytes'
        packed_len_0 = len(packed)

        hc1.update([*hc1.state, hc1_vals.pop()])
        packed = hc1.pack()
        assert type(packed) is bytes, 'pack() should return bytes'
        assert len(packed) > packed_len_0, 'pack() result should grow with state'

    def test_HashClock_unpack_works_with_pack_output(self):
        hc1 = classes.HashClock()
        hc1_vals = hc1.setup(1)

        packed = hc1.pack()
        unpacked = classes.HashClock.unpack(packed)
        assert type(unpacked) is classes.HashClock, 'unpack() should return HashClock instance'

        for i, v in enumerate(hc1.state):
            assert v == unpacked.state[i], 'all state items should match'

    def test_HashClock_verify_returns_True_for_valid_state(self):
        hc1 = classes.HashClock()
        assert hc1.verify(), 'verify() should return True for valid state'

        hc1_vals = hc1.setup(1)
        assert hc1.verify(), 'verify() should return True for valid state'

        hc1.update([*hc1.state, hc1_vals.pop()])

        assert hc1.verify(), 'verify() should return True for valid state'

    def test_HashClock_verify_returns_False_for_invalid_state(self):
        hc1 = classes.HashClock()
        hc1_vals = hc1.setup(1)
        hc1.update([*hc1.state, hc1_vals.pop()])
        hc1.state[-1] = hc1.state[-1] + b'1'

        assert not hc1.verify(), 'verify() should return False for invalid state'


if __name__ == '__main__':
    unittest.main()