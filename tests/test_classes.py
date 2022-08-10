from hashlib import sha256
from secrets import token_bytes
from context import classes, interfaces
import unittest

from hashclock.classes import HashClock


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

    # VectorHashClock tess
    def test_VectorHashClock_implements_VectorHashClockProtocol(self):
        assert issubclass(classes.VectorHashClock, interfaces.VectorHashClockProtocol), \
            'VectorHashClock must implement VectorHashClockProtocol'

    def test_VectorHashClock_initializes_empty(self):
        vhc = classes.VectorHashClock()

        assert vhc.node_ids is None
        assert vhc.hash_clocks == {}

    def test_VectorHashClock_setup_sets_node_ids_and_unsetup_hash_clocks(self):
        node_ids = [b'123', b'321']
        vhc = classes.VectorHashClock().setup(node_ids)

        assert vhc.node_ids == node_ids
        assert len(vhc.hash_clocks.keys()) == len(node_ids)

        for id in vhc.hash_clocks:
            assert id in node_ids
            assert isinstance(vhc.hash_clocks[id], classes.HashClock)
            assert not vhc.hash_clocks[id].can_be_updated()
            assert not vhc.hash_clocks[id].has_terminated()

    def test_VectorHashClock_read_returns_all_negative_ones_after_setup(self):
        node_ids = [b'123', b'321']
        vhc = classes.VectorHashClock().setup(node_ids)

        ts = vhc.read()
        for id in ts:
            assert id in node_ids or id == b'uuid'
            if id != b'uuid':
                assert type(ts[id]) is tuple, 'each node\'s ts should be tuple[int, bytes|None]'
                assert ts[id][0] == -1, 'each time must be -1'
                assert ts[id][1] is None, 'each state must be empty'
            if id == b'uuid':
                assert type(ts[id]) is bytes, 'uuid must be bytes'
                assert ts[id] == vhc.uuid

    def test_VectorHashClock_advance_returns_dict_with_proper_form(self):
        node_ids = [b'123', b'321']
        vhc = classes.VectorHashClock().setup(node_ids)
        hc = vhc.hash_clocks[node_ids[0]]
        hcu = hc.setup(3)
        update = vhc.advance(node_ids[0], hcu.advance(1))

        assert type(update) is dict, 'advance(node_id, update) must return dict'
        assert node_ids[0] in update, 'advance() dict must map node_id to tuple[int, bytes'
        assert b'uuid' in update, 'advance() dict must include uuid'
        assert type(update[b'uuid']) is bytes, 'advance() dict[uuid] must be bytes'
        assert type(update[node_ids[0]]) is tuple, \
            'advance() dict must map node_id to tuple[int, bytes'
        assert type(update[node_ids[0]][0]) is int, \
            'advance() dict must map node_id to tuple[int, bytes'
        assert type(update[node_ids[0]][1]) is bytes, \
            'advance() dict must map node_id to tuple[int, bytes'

    def test_VectorHashClock_update_accepts_advance_output_and_advances_clock(self):
        node_ids = [b'123', b'321']
        vhc = classes.VectorHashClock().setup(node_ids)
        hc = classes.HashClock()
        hcu = hc.setup(3)
        vhc.hash_clocks[node_ids[0]] = hc
        update = vhc.advance(node_ids[0], hcu.advance(1))

        before = vhc.read()
        updated = vhc.update(update)
        after = vhc.read()

        assert isinstance(updated, classes.VectorHashClock), \
            'vhc.update() must return a VectorHashClock'
        assert updated is vhc, 'vhc.update() must return vhc (monad pattern)'
        assert before != after, 'read() output should change after update'

        diff = 0
        for id in node_ids:
            diff += 1 if before[id] != after[id] else 0
        assert diff == 1, 'read() output should change by exactly 1 after update'

    def test_VectorHashClock_can_update_with_initial_states_of_HashClocks(self):
        node_ids = [b'123', b'321']
        vhc = classes.VectorHashClock().setup(node_ids)
        hc1 = classes.HashClock()
        hc2 = classes.HashClock()
        hcu1 = hc1.setup(2)
        hcu2 = hc2.setup(2)

        ts1 = vhc.read()
        update = vhc.advance(node_ids[0], hcu1.advance(0))
        vhc.update(update)
        ts2 = vhc.read()
        update = vhc.advance(node_ids[1], hcu2.advance(0))
        vhc.update(update)
        ts3 = vhc.read()

        assert vhc.happens_before(ts1, ts2), 'time moves forward'
        assert vhc.happens_before(ts2, ts3), 'time moves forward'
        assert vhc.happens_before(ts1, ts3), 'time moves forward transitively'

    def test_VectorHashClock_verify_returns_True_if_all_clocks_valid(self):
        node_ids = [b'123', b'321']
        vhc = classes.VectorHashClock().setup(node_ids)

        assert vhc.verify(), 'empty clock should verify'

        hc = classes.HashClock()
        hcu = hc.setup(3)
        vhc.hash_clocks[node_ids[0]] = hc
        update = vhc.advance(node_ids[0], hcu.advance(1))

        assert vhc.verify(), 'clock should verify if all underlying clocks verify'

        hc.state = [hc.state[0], hc.state[1] + b'1']

        assert not vhc.verify(), 'clock should not verify if underlying clock fails verification'

    def test_VectorHashClock_happens_before_returns_correct_bool(self):
        node_ids = [b'123', b'321']
        vhc = classes.VectorHashClock().setup(node_ids)
        hc = classes.HashClock()
        hcu = hc.setup(3)
        vhc.hash_clocks[node_ids[0]] = hc
        update = vhc.advance(node_ids[0], hcu.advance(1))

        before = vhc.read()
        updated = vhc.update(update)
        after = vhc.read()

        assert type(vhc.happens_before(before, after)) is bool, \
            'happens_before() must return bool'
        assert type(vhc.happens_before(after, before)) is bool, \
            'happens_before() must return bool'
        assert classes.VectorHashClock.happens_before(before, after), \
            'happens_before(before, after) must return True for valid timestamps'
        assert not classes.VectorHashClock.happens_before(after, before), \
            'happens_before(before, after) must return False for valid timestamps'
        assert not classes.VectorHashClock.happens_before(after, after), \
            'happens_before(after, after) must return False for valid timestamps'

    def test_VectorHashClock_are_incomparable_returns_correct_bool(self):
        node_ids = [b'123', b'321']
        vhc1 = classes.VectorHashClock().setup(node_ids)
        vhc2 = classes.VectorHashClock().setup([*node_ids, b'abc'])
        hc = classes.HashClock()
        hcu = hc.setup(3)
        vhc1.hash_clocks[node_ids[0]] = hc
        update = vhc1.advance(node_ids[0], hcu.advance(1))

        ts1 = vhc1.read()
        ts2 = vhc2.read()

        assert type(vhc1.are_incomparable(ts1, ts2)) is bool, \
            'are_incomparable() must return bool'
        assert classes.VectorHashClock.are_incomparable(ts1, ts2), \
            'are_incomparable() must return True for incomparable timestamps'
        assert not vhc1.are_incomparable(ts1, ts1), \
            'are_incomparable() must return False for comparable timestamps'
        assert vhc1.are_incomparable(ts1, {**ts1, b'diverge': (-1, None)}), \
            'are_incomparable() must return True for incomparable timestamps'

        vhc1.update(update)
        ts2 = vhc1.read()

        assert not vhc2.are_incomparable(ts1, ts2), \
            'are_incomparable() must return False for comparable timestamps'

        vhc2 = classes.VectorHashClock(vhc1.uuid).setup(node_ids)
        hc2 = classes.HashClock()
        hcu2 = hc2.setup(2)
        vhc2.hash_clocks[node_ids[1]] = hc2
        update2 = vhc2.advance(node_ids[1], hcu2.advance(1))
        vhc2.update(update2)
        ts2 = vhc2.read()

        assert vhc2.are_incomparable(ts1, ts2), 'timestamps should be incomparable'

    def test_VectorHashClock_are_concurrent_returns_correct_bool(self):
        node_ids = [b'123', b'321']
        vhc1 = classes.VectorHashClock().setup(node_ids)
        hc1 = classes.HashClock()
        hcu1 = hc1.setup(2)
        vhc1.hash_clocks[node_ids[0]] = hc1
        ts1 = vhc1.read()
        update1 = vhc1.advance(node_ids[0], hcu1.advance(1))
        vhc1.update(update1)
        ts2 = vhc1.read()

        assert type(classes.VectorHashClock.are_concurrent(ts1, ts1)) is bool, \
            'are_concurrent() must return a bool'
        assert vhc1.are_concurrent(ts1, ts1), \
            'are_concurrent() must return True for concurrent timestamps'
        assert not vhc1.are_concurrent(ts1, ts2), \
            'are_concurrent() must return False for sequential timestamps'
        assert not vhc1.are_concurrent(ts2, ts1), \
            'are_concurrent() must return False for sequential timestamps'

    def test_VectorHashClock_pack_returns_bytes_that_change_with_state(self):
        node_ids = [b'123', b'321']
        vhc = classes.VectorHashClock().setup(node_ids)
        hc = classes.HashClock()
        hcu = hc.setup(2)
        vhc.hash_clocks[node_ids[0]] = hc
        packed1 = vhc.pack()
        packed2 = vhc.pack()

        assert type(packed1) is bytes, 'pack() must return bytes'
        assert packed1 == packed2, \
            'pack() output must not change without underlying state change'

        update = vhc.advance(node_ids[0], hcu.advance(1))
        vhc.update(update)
        packed2 = vhc.pack()

        assert type(packed2) is bytes, 'pack() must return bytes'
        assert packed1 != packed2, \
            'pack() output must change with underlying state change'

    def test_VectorHashClock_unpack_returns_valid_instance(self):
        node_ids = [b'123', b'321']
        vhc = classes.VectorHashClock().setup(node_ids)
        hc = classes.HashClock()
        hcu = hc.setup(2)
        vhc.hash_clocks[node_ids[0]] = hc
        packed = vhc.pack()
        unpacked = classes.VectorHashClock.unpack(packed)

        assert isinstance(unpacked, classes.VectorHashClock), \
            'unpack() must return a VectorHashClock'
        assert unpacked.uuid == vhc.uuid, 'unpacked must have same uuid as source VHC'
        assert vhc.are_concurrent(vhc.read(), unpacked.read()), \
            'timestamps must be concurrent between unpacked and source VHC'


if __name__ == '__main__':
    unittest.main()