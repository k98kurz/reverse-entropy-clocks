from hashlib import sha256
from secrets import token_bytes
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

    def test_HashClock_setup_returns_HashClockUpdater_with_random_root(self):
        hc1 = classes.HashClock()
        hcu1 = hc1.setup(1)
        hc2 = classes.HashClock()
        hcu2 = hc2.setup(1)

        assert isinstance(hcu1, interfaces.HashClockUpdaterProtocol), \
            'setup() output should implement HashClockUpdaterProtocol'
        assert isinstance(hcu2, interfaces.HashClockUpdaterProtocol), \
            'setup() output should implement HashClockUpdaterProtocol'
        assert type(hcu1.root) is bytes, 'HCU root should be bytes'
        assert type(hcu2.root) is bytes, 'HCU root should be bytes'
        assert len(hcu1.root) == 16, 'root should be 16 bytes'
        assert len(hcu2.root) == 16, 'root should be 16 bytes'
        assert hcu1.root != hcu2.root, 'locks should be uncorrelated'

        assert hc1.read() == 0, 'clock should be at time 0 after setup'
        assert hc1.uuid == hcu1.uuid, \
            'clock uuid should match updater uuid'
        assert hc1.uuid == sha256(hcu1.advance(1)[1]).digest(), \
            'clock uuid should be hash of state at time=1'

    def test_HashClock_setup_can_be_updated(self):
        hc1 = classes.HashClock()
        _ = hc1.setup(1)

        assert hc1.can_be_updated(), 'can_be_updated() should be True after setup'
        assert not hc1.has_terminated(), 'has_terminated() should return False after setup'

    def test_HashClock_update_increases_read_output(self):
        hc1 = classes.HashClock()
        hcu1 = hc1.setup(3)

        assert hc1.read() == 0
        hc1.update(hcu1.advance(1))
        assert hc1.read() == 1
        hc1.update(hcu1.advance(2))
        assert hc1.read() == 2
        hc1.update(hcu1.advance(3))
        assert hc1.read() == 3

    def test_HashClock_update_is_idempotent(self):
        hc1 = classes.HashClock()
        hcu1 = hc1.setup(3)

        assert hc1.read() == 0, 'clock should be at time 0 after setup'
        update1 = hcu1.advance(1)
        hc1.update(update1)
        assert hc1.read() == 1, 'clock should be at time 1 after update1'
        hc1.update(update1)
        hc1.update(update1)
        assert hc1.read() == 1, 'no change after update applied many times'

        update2 = hcu1.advance(2)
        hc1.update(update2)
        assert hc1.read() == 2, 'change after next update'
        hc1.update(update1)
        assert hc1.read() == 2, 'no change after reapplying old update'

    def test_HashClock_update_rejects_invalid_updates(self):
        hc1, hc2 = classes.HashClock(), classes.HashClock()
        hcu1 = hc1.setup(2)
        hcu2 = hc2.setup(2)

        assert hc1.read() == 0
        hc1.update(hcu2.advance(1))
        assert hc1.read() == 0

        assert hc2.read() == 0
        hc2.update(hcu1.advance(1))
        assert hc2.read() == 0

    def test_HashClock_can_be_updated_and_has_terminated_return_False_for_unsetup_clock(self):
        hc1 = classes.HashClock()

        assert not hc1.can_be_updated()
        assert not hc1.has_terminated()

    def test_HashClock_can_be_updated_returns_False_for_terminated_clock(self):
        hc1 = classes.HashClock()
        hcu1 = hc1.setup(1)

        assert hc1.read() == 0, 'read() starts at 0'
        hc1.update(hcu1.advance(1))
        assert hc1.read() == 1, 'read() increments after update'
        assert not hc1.can_be_updated(), 'can_be_updated() should return False'
        assert hc1.has_terminated(), 'has_terminated() should return True'

    def test_HashClock_pack_returns_bytes(self):
        hc1 = classes.HashClock()
        hcu1 = hc1.setup(2)

        packed = hc1.pack()
        assert type(packed) is bytes, 'pack() should return bytes'
        packed_len_0 = len(packed)

        hc1.update(hcu1.advance(1))
        packed = hc1.pack()
        assert type(packed) is bytes, 'pack() should return bytes'
        assert len(packed) == packed_len_0, 'pack() result length should not change'
        hc1.update(hcu1.advance(2))
        packed = hc1.pack()
        assert type(packed) is bytes, 'pack() should return bytes'
        assert len(packed) < packed_len_0, \
            'pack() result length should be shorted for terminated clock'

    def test_HashClock_unpack_works_with_pack_output(self):
        hc1 = classes.HashClock()
        _ = hc1.setup(1)

        packed = hc1.pack()
        unpacked = classes.HashClock.unpack(packed)
        assert type(unpacked) is classes.HashClock, 'unpack() should return HashClock instance'

        assert unpacked.uuid == hc1.uuid, 'uuids should match'
        assert unpacked.read() == hc1.read(), 'read() calls should match'

        for i, v in enumerate(hc1.state):
            assert v == unpacked.state[i], 'all state items should match'

    def test_HashClock_verify_returns_True_for_valid_state(self):
        hc1 = classes.HashClock()
        assert hc1.verify(), 'verify() should return True for valid state'

        hcu1 = hc1.setup(1)
        assert hc1.verify(), 'verify() should return True for valid state'

        hc1.update(hcu1.advance(1))

        assert hc1.verify(), 'verify() should return True for valid state'

    def test_HashClock_verify_returns_False_for_invalid_state(self):
        hc1 = classes.HashClock()
        hcu1 = hc1.setup(1)
        hc1.update(hcu1.advance(1))
        hc1.state = (hc1.state[0], hc1.state[1] + b'1')

        assert not hc1.verify(), 'verify() should return False for invalid state'

    def test_HashClock_can_be_updated_returns_True_for_terminated_clock_with_setup_root_32(self):
        hc1 = classes.HashClock()
        hcu1 = hc1.setup(1, root_size=32)
        assert hc1.verify()
        assert hc1.can_be_updated()
        assert not hc1.has_terminated()
        hc1.update(hcu1.advance(1))
        assert hc1.verify()
        assert hc1.can_be_updated()
        assert not hc1.has_terminated()

    # HashClockUpdater tests
    def test_HashClockUpdater_implements_HashClockUpdater_Protocol(self):
        assert issubclass(classes.HashClockUpdater, interfaces.HashClockUpdaterProtocol), \
            'HashClockUpdater must implement HashClockUpdaterProtocol'

    def test_HashClockUpdater_setup_returns_HashClockUpdater_instance(self):
        hcu = classes.HashClockUpdater.setup(token_bytes(16), 3)

        assert isinstance(hcu, classes.HashClockUpdater)

    def test_HashClockUpdater_can_advance_to_max_time_but_no_further(self):
        hcu = classes.HashClockUpdater.setup(token_bytes(16), 3)

        assert type(hcu.advance(3)) is tuple, 'must advance up to time=3'

        with self.assertRaises(AssertionError) as e:
            hcu.advance(4)
        assert str(e.exception) == 'time must be int <= max_time', \
            'advance(n) where n > max_time should throw exception with matching str'

    def test_HashClockUpdater_advance_returns_chained_hash_from_root(self):
        hcu = classes.HashClockUpdater.setup(token_bytes(16), 2)

        assert sha256(hcu.advance(1)[1]).digest() == hcu.uuid, \
            'hcu.uuid must be hash of hcu.advance(1)[1]'
        assert hcu.advance(1)[1] == sha256(hcu.root).digest(), \
            'advance(1)[1] must be hash of root for setup(root, 2)'
        assert hcu.advance(2)[1] == hcu.root, \
            'advance(2)[1] must be root for setup(root, 2)'

        hcu = classes.HashClockUpdater.setup(token_bytes(16), 3)

        assert sha256(hcu.advance(1)[1]).digest() == hcu.uuid, \
            'hcu.uuid must be hash of hcu.advance(1)[1]'
        assert hcu.advance(1)[1] == sha256(sha256(hcu.root).digest()).digest(), \
            'hcu.advance(1)[1] must be hash of hash of root for setup(root, 3)'
        assert hcu.advance(2)[1] == sha256(hcu.root).digest(), \
            'advance(2)[1] must be hash of root for setup(root, 3)'
        assert hcu.advance(3)[1] == hcu.root, \
            'advance(3)[1] must be root for setup(root, 3)'

        hcu = classes.HashClockUpdater.setup(token_bytes(16), 100)

        assert sha256(hcu.advance(1)[1]).digest() == hcu.uuid, \
            'hcu.uuid must be hash of hcu.advance(1)[1]'
        assert hcu.advance(100)[1] == hcu.root, \
            'advance(100)[1] must be root for setup(root, 100)'

    def test_HashClockUpdater_pack_returns_bytes(self):
        hcu = classes.HashClockUpdater.setup(token_bytes(16), 3)
        packed = hcu.pack()

        assert type(packed) is bytes, 'pack() must return bytes'

    def test_HashClockUpdater_unpack_returns_instance_with_same_values(self):
        hcu = classes.HashClockUpdater.setup(token_bytes(16), 3)
        packed = hcu.pack()
        unpacked = classes.HashClockUpdater.unpack(packed)

        assert isinstance(unpacked, classes.HashClockUpdater)
        assert hcu.uuid == unpacked.uuid
        assert hcu.root == unpacked.root
        assert hcu.max_time == unpacked.max_time


if __name__ == '__main__':
    unittest.main()