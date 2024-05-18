from hashlib import sha256
from secrets import token_bytes
from context import classes, interfaces, misc
import unittest


class TestHashClock(unittest.TestCase):
    """Test suite for HashClock."""
    def test_implements_ClockProtocol(self):
        assert issubclass(classes.HashClock, interfaces.ClockProtocol), \
            'HashClock must implement ClockProtocol'

    def test_setup_returns_HashClockUpdater_with_random_seed(self):
        clock1 = classes.HashClock()
        clockupdater1 = clock1.setup(5)
        clock2 = classes.HashClock()
        clockupdater2 = clock2.setup(5)

        assert isinstance(clockupdater1, interfaces.ClockUpdaterProtocol), \
            'setup() output should implement ClockUpdaterProtocol'
        assert isinstance(clockupdater2, interfaces.ClockUpdaterProtocol), \
            'setup() output should implement ClockUpdaterProtocol'
        assert type(clockupdater1.seed) is bytes, 'clockupdater seed should be bytes'
        assert type(clockupdater2.seed) is bytes, 'clockupdater seed should be bytes'
        assert len(clockupdater1.seed) == 16, 'seed should be 16 bytes'
        assert len(clockupdater2.seed) == 16, 'seed should be 16 bytes'
        assert clockupdater1.seed != clockupdater2.seed, 'locks should be uncorrelated'

        assert clock1.read()[0] == 0, 'clock should be at time 0 after setup'
        assert clock1.uuid == clockupdater1.uuid, \
            'clock uuid should match updater uuid'
        assert clock1.uuid == sha256(clockupdater1.advance(1)[1]).digest(), \
            'clock uuid should be hash of state at time=1'

    def test_created_from_uuid_returns_None_from_setup(self):
        clock1 = classes.HashClock()
        _ = clock1.setup(5)
        clock2 = classes.HashClock(clock1.uuid)
        assert clock2.setup(5) is None

    def test_setup_can_be_updated(self):
        clock1 = classes.HashClock()
        _ = clock1.setup(5)

        assert clock1.can_be_updated(), 'can_be_updated() should be True after setup'
        assert not clock1.has_terminated(), 'has_terminated() should return False after setup'

    def test_happens_before_and_are_incomparable_work_correctly(self):
        clock1 = classes.HashClock()
        clock2 = classes.HashClock()
        updater1 = clock1.setup(12)
        _ = clock2.setup(12)
        ts1 = clock1.read()
        clock1.update(updater1.advance(2))
        ts2 = clock1.read()
        assert classes.HashClock.are_incomparable(ts1, clock2.read())
        assert not classes.HashClock.are_incomparable(ts1, ts2)
        assert classes.HashClock.happens_before(ts1, ts2)
        assert not classes.HashClock.happens_before(ts2, ts1)
        assert not classes.HashClock.happens_before(ts1, ts1)

    def test_update_increases_read_output(self):
        clock1 = classes.HashClock()
        clockupdater1 = clock1.setup(3)

        assert clock1.read()[0] == 0
        clock1.update(clockupdater1.advance(1))
        assert clock1.read()[0] == 1
        clock1.update(clockupdater1.advance(2))
        assert clock1.read()[0] == 2
        clock1.update(clockupdater1.advance(3))
        assert clock1.read()[0] == 3

    def test_update_is_idempotent(self):
        clock1 = classes.HashClock()
        clockupdater1 = clock1.setup(3)

        assert clock1.read()[0] == 0, 'clock should be at time 0 after setup'
        update1 = clockupdater1.advance(1)
        clock1.update(update1)
        assert clock1.read()[0] == 1, 'clock should be at time 1 after update1'
        clock1.update(update1)
        clock1.update(update1)
        assert clock1.read()[0] == 1, 'no change after update applied many times'

        update2 = clockupdater1.advance(2)
        clock1.update(update2)
        assert clock1.read()[0] == 2, 'change after next update'
        clock1.update(update1)
        assert clock1.read()[0] == 2, 'no change after reapplying old update'

    def test_update_rejects_invalid_updates(self):
        clock1, clock2 = classes.HashClock(), classes.HashClock()
        clockupdater1 = clock1.setup(2)
        clockupdater2 = clock2.setup(2)

        assert clock1.read()[0] == 0
        clock1.update(clockupdater2.advance(1))
        assert clock1.read()[0] == 0

        assert clock2.read()[0] == 0
        clock2.update(clockupdater1.advance(1))
        assert clock2.read()[0] == 0

    def test_can_be_updated_and_has_terminated_return_False_for_unsetup_clock(self):
        clock1 = classes.HashClock()

        assert not clock1.can_be_updated()
        assert not clock1.has_terminated()

    def test_can_be_updated_returns_False_for_terminated_clock(self):
        clock1 = classes.HashClock()
        clockupdater1 = clock1.setup(5)

        assert clock1.read()[0] == 0, 'read() starts at 0'
        clock1.update(clockupdater1.advance(5))
        assert clock1.read()[0] == 5, 'read() increases after update'
        assert not clock1.can_be_updated(), 'can_be_updated() should return False'
        assert clock1.has_terminated(), 'has_terminated() should return True'

    def test_pack_returns_bytes(self):
        clock1 = classes.HashClock()
        clockupdater1 = clock1.setup(2)

        packed = clock1.pack()
        assert type(packed) is bytes, 'pack() should return bytes'
        packed_len_0 = len(packed)

        clock1.update(clockupdater1.advance(1))
        packed = clock1.pack()
        assert type(packed) is bytes, 'pack() should return bytes'
        assert len(packed) == packed_len_0, 'pack() result length should not change'
        clock1.update(clockupdater1.advance(2))
        packed = clock1.pack()
        assert type(packed) is bytes, 'pack() should return bytes'
        assert len(packed) < packed_len_0, \
            'pack() result length should be shorted for terminated clock'

    def test_unpack_works_with_pack_output(self):
        clock1 = classes.HashClock()
        _ = clock1.setup(5)

        packed = clock1.pack()
        unpacked = classes.HashClock.unpack(packed)
        assert type(unpacked) is classes.HashClock, 'unpack() should return HashClock instance'

        assert unpacked.uuid == clock1.uuid, 'uuids should match'
        assert unpacked.read() == clock1.read(), 'read() calls should match'

        for i, v in enumerate(clock1.state):
            assert v == unpacked.state[i], 'all state items should match'

    def test_verify_returns_True_for_valid_state(self):
        clock1 = classes.HashClock()
        assert clock1.verify(), 'verify() should return True for valid state'

        clockupdater1 = clock1.setup(5)
        assert clock1.verify(), 'verify() should return True for valid state'

        clock1.update(clockupdater1.advance(1))

        assert clock1.verify(), 'verify() should return True for valid state'

    def test_verify_returns_False_for_invalid_state(self):
        clock1 = classes.HashClock()
        clockupdater1 = clock1.setup(5)
        clock1.update(clockupdater1.advance(1))
        clock1.state = (clock1.state[0], clock1.state[1] + b'1')

        assert not clock1.verify(), 'verify() should return False for invalid state'

    def test_verify_timestamp_returns_True_for_valid_and_False_for_invalid_ts(self):
        clock1 = classes.HashClock()
        clockupdater1 = clock1.setup(5)
        ts = clockupdater1.advance(1)
        assert clock1.verify_timestamp(ts)
        assert not clock1.verify_timestamp((1, token_bytes(32)))

    def test_can_be_updated_returns_True_for_terminated_clock_with_setup_seed_32(self):
        clock1 = classes.HashClock()
        clockupdater1 = clock1.setup(1, seed_size=32)
        assert clock1.verify()
        assert clock1.can_be_updated()
        assert not clock1.has_terminated()
        clock1.update(clockupdater1.advance(1))
        assert clock1.verify()
        assert clock1.can_be_updated()
        assert not clock1.has_terminated()


class TestHashClockUpdater(unittest.TestCase):
    """Test suite for HashClockUpdater."""
    def test_HashClockUpdater_implements_ClockUpdaterProtocol(self):
        assert issubclass(classes.HashClockUpdater, interfaces.ClockUpdaterProtocol), \
            'HashClockUpdater must implement ClockUpdaterProtocol'

    def test_HashClockUpdater_setup_returns_HashClockUpdater_instance(self):
        clockupdater = classes.HashClockUpdater.setup(token_bytes(16), 3)

        assert isinstance(clockupdater, classes.HashClockUpdater)

    def test_HashClockUpdater_can_advance_to_max_time_but_no_further(self):
        clockupdater = classes.HashClockUpdater.setup(token_bytes(16), 3)

        assert type(clockupdater.advance(3)) is tuple, 'must advance up to time=3'

        with self.assertRaises(ValueError) as e:
            clockupdater.advance(4)
        assert str(e.exception) == 'time must be int <= max_time', \
            'advance(n) where n > max_time should throw exception with matching str'

    def test_HashClockUpdater_advance_returns_chained_hash_from_seed(self):
        clockupdater = classes.HashClockUpdater.setup(token_bytes(16), 2)

        assert sha256(clockupdater.advance(1)[1]).digest() == clockupdater.uuid, \
            'clockupdater.uuid must be hash of clockupdater.advance(1)[1]'
        assert clockupdater.advance(1)[1] == sha256(clockupdater.seed).digest(), \
            'advance(1)[1] must be hash of seed for setup(seed, 2)'
        assert clockupdater.advance(2)[1] == clockupdater.seed, \
            'advance(2)[1] must be seed for setup(seed, 2)'

        clockupdater = classes.HashClockUpdater.setup(token_bytes(16), 3)

        assert sha256(clockupdater.advance(1)[1]).digest() == clockupdater.uuid, \
            'clockupdater.uuid must be hash of clockupdater.advance(1)[1]'
        assert clockupdater.advance(1)[1] == sha256(sha256(clockupdater.seed).digest()).digest(), \
            'clockupdater.advance(1)[1] must be hash of hash of seed for setup(seed, 3)'
        assert clockupdater.advance(2)[1] == sha256(clockupdater.seed).digest(), \
            'advance(2)[1] must be hash of seed for setup(seed, 3)'
        assert clockupdater.advance(3)[1] == clockupdater.seed, \
            'advance(3)[1] must be seed for setup(seed, 3)'

        clockupdater = classes.HashClockUpdater.setup(token_bytes(16), 100)

        assert sha256(clockupdater.advance(1)[1]).digest() == clockupdater.uuid, \
            'clockupdater.uuid must be hash of clockupdater.advance(1)[1]'
        assert clockupdater.advance(100)[1] == clockupdater.seed, \
            'advance(100)[1] must be seed for setup(seed, 100)'

    def test_HashClockUpdater_pack_returns_bytes(self):
        clockupdater = classes.HashClockUpdater.setup(token_bytes(16), 3)
        packed = clockupdater.pack()

        assert type(packed) is bytes, 'pack() must return bytes'

    def test_HashClockUpdater_unpack_returns_instance_with_same_values(self):
        clockupdater = classes.HashClockUpdater.setup(token_bytes(16), 3)
        packed = clockupdater.pack()
        unpacked = classes.HashClockUpdater.unpack(packed)

        assert isinstance(unpacked, classes.HashClockUpdater)
        assert clockupdater.uuid == unpacked.uuid
        assert clockupdater.seed == unpacked.seed
        assert clockupdater.max_time == unpacked.max_time


class TestVectorHashClock(unittest.TestCase):
    """Test suite for VectorHashClock."""
    def test_implements_VectorClockProtocol(self):
        assert issubclass(classes.VectorHashClock, interfaces.VectorClockProtocol), \
            'VectorHashClock must implement VectorClockProtocol'

    def test_initializes_empty(self):
        vectorclock = classes.VectorHashClock()

        assert vectorclock.node_ids is None
        assert vectorclock.clocks == {}

    def test_setup_sets_node_ids_and_unsetup_clocks(self):
        node_ids = [b'123', b'321']
        vectorclock = classes.VectorHashClock().setup(node_ids)

        assert vectorclock.node_ids == node_ids
        assert len(vectorclock.clocks.keys()) == len(node_ids)

        for id in vectorclock.clocks:
            assert id in node_ids
            assert isinstance(vectorclock.clocks[id], classes.HashClock)
            assert not vectorclock.clocks[id].can_be_updated()
            assert not vectorclock.clocks[id].has_terminated()

    def test_setup_with_uuids_sets_nodes(self):
        node_ids = [b'123', b'321']
        clock1 = classes.HashClock()
        _ = clock1.setup(3)
        clock2 = classes.HashClock()
        _ = clock2.setup(3)
        uuids = {
            node_ids[0]: clock1.uuid,
            node_ids[1]: clock2.uuid,
        }

        vectorclock = classes.VectorHashClock().setup(node_ids, uuids)
        assert vectorclock.verify()
        ts1 = vectorclock.read()
        assert node_ids[0] in ts1
        assert node_ids[1] in ts1
        assert vectorclock.clocks[node_ids[0]] is not clock1
        assert vectorclock.clocks[node_ids[1]] is not clock2

    def test_create_returns_setup_instance(self):
        node_ids = [b'123', b'321']
        clock1 = classes.HashClock()
        _ = clock1.setup(3)
        clock2 = classes.HashClock()
        _ = clock2.setup(3)
        uuids = {
            node_ids[0]: clock1.uuid,
            node_ids[1]: clock2.uuid,
        }

        vectorclock = classes.VectorHashClock.create(b'test', node_ids, uuids)
        assert vectorclock.verify()
        ts1 = vectorclock.read()
        assert node_ids[0] in ts1
        assert node_ids[1] in ts1
        assert vectorclock.clocks[node_ids[0]] is not clock1
        assert vectorclock.clocks[node_ids[1]] is not clock2

    def test_read_returns_all_negative_ones_after_setup(self):
        node_ids = [b'123', b'321']
        vectorclock = classes.VectorHashClock().setup(node_ids)

        ts = vectorclock.read()
        for id in ts:
            assert id in node_ids or id == b'uuid'
            if id != b'uuid':
                assert type(ts[id]) is tuple, 'each node\'s ts should be tuple[int, bytes|None]'
                assert ts[id][0] == -1, 'each time must be -1'
                assert ts[id][1] is None, 'each state must be empty'
            if id == b'uuid':
                assert type(ts[id]) is bytes, 'uuid must be bytes'
                assert ts[id] == vectorclock.uuid

    def test_advance_returns_dict_with_proper_form(self):
        node_ids = [b'123', b'321']
        vectorclock = classes.VectorHashClock().setup(node_ids)
        clock = vectorclock.clocks[node_ids[0]]
        clockupdater = clock.setup(3)
        update = vectorclock.advance(node_ids[0], clockupdater.advance(1))

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

    def test_update_accepts_advance_output_and_advances_clock(self):
        node_ids = [b'123', b'321']
        vectorclock = classes.VectorHashClock().setup(node_ids)
        clock = classes.HashClock()
        clockupdater = clock.setup(3)
        vectorclock.clocks[node_ids[0]] = clock
        update = vectorclock.advance(node_ids[0], clockupdater.advance(1))

        before = vectorclock.read()
        updated = vectorclock.update(update)
        after = vectorclock.read()

        assert isinstance(updated, classes.VectorHashClock), \
            'vectorclock.update() must return a VectorHashClock'
        assert updated is vectorclock, 'vectorclock.update() must return vectorclock (monad pattern)'
        assert before != after, 'read() output should change after update'

        diff = 0
        for id in node_ids:
            if id not in before or id not in after:
                continue
            diff += 1 if before[id] != after[id] else 0
        assert diff == 1, 'read() output should change by exactly 1 after update'

    def test_can_update_with_initial_states_of_HashClocks(self):
        node_ids = [b'123', b'321']
        vectorclock = classes.VectorHashClock().setup(node_ids)
        clock1 = classes.HashClock()
        clock2 = classes.HashClock()
        clockupdater1 = clock1.setup(2)
        clockupdater2 = clock2.setup(2)

        ts1 = vectorclock.read()
        update = vectorclock.advance(node_ids[0], clockupdater1.advance(0))
        vectorclock.update(update)
        ts2 = vectorclock.read()
        update = vectorclock.advance(node_ids[1], clockupdater2.advance(0))
        vectorclock.update(update)
        ts3 = vectorclock.read()

        assert vectorclock.happens_before(ts1, ts2), 'time moves forward'
        assert vectorclock.happens_before(ts2, ts3), 'time moves forward'
        assert vectorclock.happens_before(ts1, ts3), 'time moves forward transitively'

    def test_verify_returns_True_if_all_clocks_valid(self):
        node_ids = [b'123', b'321']
        vectorclock = classes.VectorHashClock().setup(node_ids)

        assert vectorclock.verify(), 'empty clock should verify'

        clock = classes.HashClock()
        clockupdater = clock.setup(3)
        vectorclock.clocks[node_ids[0]] = clock
        vectorclock.advance(node_ids[0], clockupdater.advance(1))

        assert vectorclock.verify(), 'clock should verify if all underlying clocks verify'

        clock.state = [clock.state[0], clock.state[1] + b'1']

        assert not vectorclock.verify(), 'clock should not verify if underlying clock fails verification'

    def test_verify_timestamp_returns_correct_bool(self):
        node_ids = [b'123', b'321']
        vectorclock = classes.VectorHashClock().setup(node_ids)
        clock0 = classes.HashClock()
        clock1 = classes.HashClock()
        clockupdater0 = clock0.setup(3)
        _ = clock1.setup(3)
        vectorclock.clocks[node_ids[0]] = clock0
        vectorclock.clocks[node_ids[1]] = clock1
        update = clockupdater0.advance(1)
        vectorclock.advance(node_ids[0], update)
        good_ts = vectorclock.read()
        bad_ts = {**good_ts, b'321': (1, b'asd')}

        assert vectorclock.verify_timestamp(good_ts)
        assert not vectorclock.verify_timestamp(bad_ts)

    def test_happens_before_returns_correct_bool(self):
        node_ids = [b'123', b'321']
        vectorclock = classes.VectorHashClock().setup(node_ids)
        clock = classes.HashClock()
        clockupdater = clock.setup(3)
        vectorclock.clocks[node_ids[0]] = clock
        update = vectorclock.advance(node_ids[0], clockupdater.advance(1))

        before = vectorclock.read()
        vectorclock.update(update)
        after = vectorclock.read()

        assert type(vectorclock.happens_before(before, after)) is bool, \
            'happens_before() must return bool'
        assert type(vectorclock.happens_before(after, before)) is bool, \
            'happens_before() must return bool'
        assert classes.VectorHashClock.happens_before(before, after), \
            'happens_before(before, after) must return True for valid timestamps'
        assert not classes.VectorHashClock.happens_before(after, before), \
            'happens_before(before, after) must return False for valid timestamps'
        assert not classes.VectorHashClock.happens_before(after, after), \
            'happens_before(after, after) must return False for valid timestamps'

    def test_are_incomparable_returns_correct_bool(self):
        node_ids = [b'123', b'321']
        vclock1 = classes.VectorHashClock().setup(node_ids)
        vclock2 = classes.VectorHashClock().setup([*node_ids, b'abc'])
        clock = classes.HashClock()
        clockupdater = clock.setup(3)
        vclock1.clocks[node_ids[0]] = clock
        update = vclock1.advance(node_ids[0], clockupdater.advance(1))

        ts1 = vclock1.read()
        ts2 = vclock2.read()

        assert type(vclock1.are_incomparable(ts1, ts2)) is bool, \
            'are_incomparable() must return bool'
        assert classes.VectorHashClock.are_incomparable(ts1, ts2), \
            'are_incomparable() must return True for incomparable timestamps'
        assert not vclock1.are_incomparable(ts1, ts1), \
            'are_incomparable() must return False for comparable timestamps'

        vclock1.update(update)
        ts2 = vclock1.read()

        assert not vclock2.are_incomparable(ts1, ts2), \
            'are_incomparable() must return False for comparable timestamps'

        vclock2 = classes.VectorHashClock(vclock1.uuid).setup(node_ids)
        clock2 = classes.HashClock()
        clockupdater2 = clock2.setup(2)
        vclock2.clocks[node_ids[1]] = clock2
        update2 = vclock2.advance(node_ids[1], clockupdater2.advance(1))
        vclock2.update(update2)
        ts2 = vclock2.read()

        assert not vclock2.are_incomparable(ts1, ts2), 'timestamps should not be incomparable'
        assert vclock2.are_concurrent(ts1, ts2), 'timestamps should be concurrent'

    def test_are_concurrent_returns_correct_bool(self):
        node_ids = [b'123', b'321']
        vclock1 = classes.VectorHashClock().setup(node_ids)
        clock1 = classes.HashClock()
        clockupdater1 = clock1.setup(2)
        vclock1.clocks[node_ids[0]] = clock1
        ts1 = vclock1.read()
        update1 = vclock1.advance(node_ids[0], clockupdater1.advance(1))
        vclock1.update(update1)
        ts2 = vclock1.read()

        assert type(classes.VectorHashClock.are_concurrent(ts1, ts1)) is bool, \
            'are_concurrent() must return a bool'
        assert vclock1.are_concurrent(ts1, ts1), \
            'are_concurrent() must return True for concurrent timestamps'
        assert not vclock1.are_concurrent(ts1, ts2), \
            'are_concurrent() must return False for sequential timestamps'
        assert not vclock1.are_concurrent(ts2, ts1), \
            'are_concurrent() must return False for sequential timestamps'

    def test_pack_returns_bytes_that_change_with_state(self):
        node_ids = [b'123', b'321']
        vectorclock = classes.VectorHashClock().setup(node_ids)
        clock = classes.HashClock()
        clockupdater = clock.setup(2)
        vectorclock.clocks[node_ids[0]] = clock
        packed1 = vectorclock.pack()
        packed2 = vectorclock.pack()

        assert type(packed1) is bytes, 'pack() must return bytes'
        assert packed1 == packed2, \
            'pack() output must not change without underlying state change'

        update = vectorclock.advance(node_ids[0], clockupdater.advance(1))
        vectorclock.update(update)
        packed2 = vectorclock.pack()

        assert type(packed2) is bytes, 'pack() must return bytes'
        assert packed1 != packed2, \
            'pack() output must change with underlying state change'

    def test_unpack_returns_valid_instance(self):
        node_ids = [b'123', b'321']
        vectorclock = classes.VectorHashClock().setup(node_ids)
        clock = classes.HashClock()
        clock.setup(2)
        vectorclock.clocks[node_ids[0]] = clock
        packed = vectorclock.pack()
        unpacked = classes.VectorHashClock.unpack(packed)

        assert isinstance(unpacked, classes.VectorHashClock), \
            'unpack() must return a VectorHashClock'
        assert unpacked.uuid == vectorclock.uuid, 'unpacked must have same uuid as source vectorclock'
        assert vectorclock.are_concurrent(vectorclock.read(), unpacked.read()), \
            'timestamps must be concurrent between unpacked and source vectorclock'


class TestPointClockUpdater(unittest.TestCase):
    """Test suite for PointClockUpdater."""
    def test_implements_ClockUpdaterProtocol(self):
        assert issubclass(classes.PointClockUpdater, interfaces.ClockUpdaterProtocol), \
            'PointClockUpdater must implement ClockUpdaterProtocol'

    def test_setup_returns_PointClockUpdater_instance(self):
        clockupdater = classes.PointClockUpdater.setup(token_bytes(16), 3)

        assert isinstance(clockupdater, classes.PointClockUpdater)

    def test_can_advance_to_max_time_but_no_further(self):
        clockupdater = classes.PointClockUpdater.setup(token_bytes(16), 3)

        assert type(clockupdater.advance(3)) is tuple, 'must advance up to time=3'

        with self.assertRaises(ValueError) as e:
            clockupdater.advance(4)
        assert str(e.exception) == 'time must be int <= max_time', \
            'advance(n) where n > max_time should throw exception with matching str'

    def test_advance_returns_chained_point_double_from_seed_vkey(self):
        seed = token_bytes(16)
        skey = misc.derive_key_from_seed(misc.H_small(seed))
        vkey = misc.derive_point_from_scalar(skey)
        clockupdater = classes.PointClockUpdater.setup(seed, 2)

        assert misc.recursive_next_point(clockupdater.advance(1)[1], 1) == clockupdater.uuid, \
            'clockupdater.uuid must be ed25519 point clockupdater.advance(1)[1] * 2'
        assert clockupdater.advance(1)[1] == misc.recursive_next_point(vkey, 1), \
            'advance(1)[1] must be ed25519 recursively squared seed vkey'
        assert clockupdater.advance(2)[1] == vkey, \
            'advance(2)[1] must be seed vkey for setup(seed, 2)'

        clockupdater = classes.PointClockUpdater.setup(seed, 100)

        assert misc.recursive_next_point(clockupdater.advance(1)[1], 1) == clockupdater.uuid, \
            'clockupdater.uuid must be ed25519 point clockupdater.advance(1)[1] * 2'
        assert clockupdater.advance(100)[1] == vkey, \
            'advance(100)[1] must be seed vkey for setup(seed, 100)'

    def test_advance_and_sign_produces_signed_timestamp(self):
        seed = token_bytes(16)
        clockupdater = classes.PointClockUpdater.setup(seed, 2)
        message = b'hello world'
        timestamp = clockupdater.advance_and_sign(1, message)
        assert type(timestamp) is tuple and len(timestamp) == 3
        assert timestamp[0] == 1
        assert type(timestamp[1]) is bytes and len(timestamp[1]) == 32
        assert type(timestamp[2]) is bytes and len(timestamp[2]) == 64

    def test_pack_returns_bytes(self):
        clockupdater = classes.PointClockUpdater.setup(token_bytes(16), 3)
        packed = clockupdater.pack()

        assert type(packed) is bytes, 'pack() must return bytes'

    def test_unpack_returns_instance_with_same_values(self):
        clockupdater = classes.PointClockUpdater.setup(token_bytes(16), 3)
        packed = clockupdater.pack()
        unpacked = classes.PointClockUpdater.unpack(packed)

        assert isinstance(unpacked, classes.PointClockUpdater)
        assert clockupdater.uuid == unpacked.uuid
        assert clockupdater.seed == unpacked.seed
        assert clockupdater.max_time == unpacked.max_time


class TestPointClock(unittest.TestCase):
    """Test suite for PointClock."""
    def test_implements_ClockProtocol(self):
        assert issubclass(classes.PointClock, interfaces.ClockProtocol), \
            'PointClock must implement ClockProtocol'

    def test_setup_returns_PointClockUpdater_with_random_seed(self):
        clock1 = classes.PointClock()
        clockupdater1 = clock1.setup(5)
        clock2 = classes.PointClock()
        clockupdater2 = clock2.setup(5)

        assert isinstance(clockupdater1, interfaces.ClockUpdaterProtocol), \
            'setup() output should implement ClockUpdaterProtocol'
        assert isinstance(clockupdater2, interfaces.ClockUpdaterProtocol), \
            'setup() output should implement ClockUpdaterProtocol'
        assert type(clockupdater1.seed) is bytes, 'clockupdater seed should be bytes'
        assert type(clockupdater2.seed) is bytes, 'clockupdater seed should be bytes'
        assert len(clockupdater1.seed) == 32, 'seed should be 32 bytes'
        assert len(clockupdater2.seed) == 32, 'seed should be 32 bytes'
        assert clockupdater1.seed != clockupdater2.seed, 'clocks should be uncorrelated'
        assert clockupdater1.uuid != clockupdater2.uuid, 'clocks should be uncorrelated'

        assert clock1.read()[0] == 0, 'clock should be at time 0 after setup'
        assert clock1.uuid == clockupdater1.uuid, \
            'clock uuid should match updater uuid'
        assert clock1.uuid == misc.recursive_next_point(clockupdater1.advance(1)[1], 1), \
            'clock uuid should be state + state at time=1'

    def test_created_from_uuid_returns_None_from_setup(self):
        clock1 = classes.PointClock()
        _ = clock1.setup(5)
        clock2 = classes.PointClock(clock1.uuid)
        assert clock2.setup(5) is None

    def test_happens_before_and_are_incomparable_work_correctly(self):
        clock1 = classes.PointClock()
        clock2 = classes.PointClock()
        updater1 = clock1.setup(12)
        _ = clock2.setup(12)
        ts1 = clock1.read()
        clock1.update(updater1.advance(2))
        ts2 = clock1.read()
        assert classes.PointClock.are_incomparable(ts1, clock2.read())
        assert not classes.PointClock.are_incomparable(ts1, ts2)
        assert classes.PointClock.happens_before(ts1, ts2)
        assert not classes.PointClock.happens_before(ts2, ts1)
        assert not classes.PointClock.happens_before(ts1, ts1)

    def test_update_increases_read_output(self):
        clock1 = classes.PointClock()
        clockupdater1 = clock1.setup(4)

        assert clock1.read()[0] == 0
        clock1.update(clockupdater1.advance(1))
        assert clock1.read()[0] == 1
        clock1.update(clockupdater1.advance(2))
        assert clock1.read()[0] == 2
        clock1.update(clockupdater1.advance(3))
        assert clock1.read()[0] == 3

    def test_update_is_idempotent(self):
        clock1 = classes.PointClock()
        clockupdater1 = clock1.setup(3)

        assert clock1.read()[0] == 0, 'clock should be at time 0 after setup'
        timestamp1 = clockupdater1.advance(1)
        clock1.update(timestamp1)
        assert clock1.read()[0] == 1, 'clock should be at time 1 after timestamp1'
        clock1.update(timestamp1)
        clock1.update(timestamp1)
        assert clock1.read()[0] == 1, 'no change after update applied many times'

        timestamp2 = clockupdater1.advance(2)
        clock1.update(timestamp2)
        assert clock1.read()[0] == 2, 'change after next update'
        clock1.update(timestamp1)
        assert clock1.read()[0] == 2, 'no change after reapplying old update'

    def test_update_rejects_invalid_updates(self):
        clock1, clock2 = classes.PointClock(), classes.PointClock()
        clockupdater1 = clock1.setup(2)
        clockupdater2 = clock2.setup(2)

        assert clock1.read()[0] == 0
        clock1.update(clockupdater2.advance(1))
        assert clock1.read()[0] == 0

        assert clock2.read()[0] == 0
        clock2.update(clockupdater1.advance(1))
        assert clock2.read()[0] == 0

    def test_pack_returns_bytes(self):
        clock1 = classes.PointClock()
        clockupdater1 = clock1.setup(2)

        packed = clock1.pack()
        assert type(packed) is bytes, 'pack() should return bytes'
        packed_len_0 = len(packed)

        clock1.update(clockupdater1.advance(1))
        packed = clock1.pack()
        assert type(packed) is bytes, 'pack() should return bytes'
        assert len(packed) == packed_len_0, 'pack() result length should not change'
        clock1.update(clockupdater1.advance(2))
        packed = clock1.pack()
        assert type(packed) is bytes, 'pack() should return bytes'

    def test_unpack_works_with_pack_output(self):
        clock1 = classes.PointClock()
        _ = clock1.setup(5)

        packed = clock1.pack()
        unpacked = classes.PointClock.unpack(packed)
        assert type(unpacked) is classes.PointClock, 'unpack() should return PointClock instance'

        assert unpacked.uuid == clock1.uuid, 'uuids should match'
        assert unpacked.read() == clock1.read(), 'read() calls should match'

        for i, v in enumerate(clock1.state):
            assert v == unpacked.state[i], 'all state items should match'

    def test_verify_returns_True_for_valid_state(self):
        clock1 = classes.PointClock()
        assert clock1.verify(), 'verify() should return True for valid state'

        clockupdater1 = clock1.setup(5)
        assert clock1.verify(), 'verify() should return True for valid state'

        clock1.update(clockupdater1.advance(1))

        assert clock1.verify(), 'verify() should return True for valid state'

    def test_verify_returns_False_for_invalid_state(self):
        clock1 = classes.PointClock()
        clockupdater1 = clock1.setup(5)
        clock1.update(clockupdater1.advance(1))
        clock1.state = (clock1.state[0], clock1.state[1] + b'1')

        assert not clock1.verify(), 'verify() should return False for invalid state'

    def test_verify_timestamp_returns_True_for_valid_and_False_for_invalid_ts(self):
        clock1 = classes.PointClock()
        clockupdater1 = clock1.setup(5)
        ts = clockupdater1.advance(1)
        assert clock1.verify_timestamp(ts)
        assert not clock1.verify_timestamp((1, token_bytes(32)))

    def test_verify_signed_update_returns_True_for_valid_and_False_for_invalid_signed_ts(self):
        clock1 = classes.PointClock()
        clockupdater1 = clock1.setup(5)
        message = b'hello world'
        signedts = clockupdater1.advance_and_sign(1, message)
        assert clock1.verify_signed_timestamp(signedts, message)
        assert not clock1.verify_signed_timestamp(signedts, message + b'123')
        assert not clock1.verify_signed_timestamp(
            (signedts[0], token_bytes(32), signedts[2]),
            message + b'123'
        )


class TestVectorPointClock(unittest.TestCase):
    """Test suite for VectorPointClock."""
    def test_implements_VectorClockProtocol(self):
        assert issubclass(classes.VectorPointClock, interfaces.VectorClockProtocol), \
            'VectorPointClock must implement VectorClockProtocol'

    def test_initializes_empty(self):
        vectorclock = classes.VectorPointClock()

        assert vectorclock.node_ids is None
        assert vectorclock.clocks == {}

    def test_setup_sets_node_ids_and_unsetup_clocks(self):
        node_ids = [b'123', b'321']
        vectorclock = classes.VectorPointClock().setup(node_ids)

        assert vectorclock.node_ids == node_ids
        assert len(vectorclock.clocks.keys()) == len(node_ids)

        for id in vectorclock.clocks:
            assert id in node_ids
            assert isinstance(vectorclock.clocks[id], classes.PointClock)

    def test_setup_with_uuids_sets_nodes(self):
        clock1 = classes.PointClock()
        _ = clock1.setup(3)
        clock2 = classes.PointClock()
        _ = clock2.setup(3)
        node_ids = [clock1.uuid, clock2.uuid]
        clock_uuids = { n: n for n in node_ids }

        vectorclock = classes.VectorPointClock().setup(node_ids, clock_uuids)
        assert vectorclock.verify()
        ts1 = vectorclock.read()
        assert node_ids[0] in ts1
        assert node_ids[1] in ts1
        assert vectorclock.clocks[node_ids[0]] is not clock1
        assert vectorclock.clocks[node_ids[1]] is not clock2

    def test_create_returns_setup_instance(self):
        clock1 = classes.PointClock()
        _ = clock1.setup(3)
        clock2 = classes.PointClock()
        _ = clock2.setup(3)
        node_ids = [clock1.uuid, clock2.uuid]
        clock_uuids = { n: n for n in node_ids }

        vectorclock = classes.VectorPointClock.create(b'test', node_ids, clock_uuids)
        assert vectorclock.verify()
        ts1 = vectorclock.read()
        assert node_ids[0] in ts1
        assert node_ids[1] in ts1
        assert vectorclock.clocks[node_ids[0]] is not clock1
        assert vectorclock.clocks[node_ids[1]] is not clock2

    def test_read_returns_all_negative_ones_after_setup(self):
        node_ids = [b'123', b'321']
        vectorclock = classes.VectorPointClock().setup(node_ids)

        ts = vectorclock.read()
        for id in ts:
            assert id in node_ids or id == b'uuid'
            if id != b'uuid':
                assert type(ts[id]) is tuple, 'each node\'s ts should be tuple[int, bytes|None]'
                assert ts[id][0] == -1, 'each time must be -1'
                assert ts[id][1] is None, 'each state must be empty'
            if id == b'uuid':
                assert type(ts[id]) is bytes, 'uuid must be bytes'
                assert ts[id] == vectorclock.uuid

    def test_advance_returns_dict_with_proper_form(self):
        node_ids = [b'123', b'321']
        vectorclock = classes.VectorPointClock().setup(node_ids)
        clock = vectorclock.clocks[node_ids[0]]
        clockupdater = clock.setup(3)
        timestamp = vectorclock.advance(node_ids[0], clockupdater.advance(1))

        assert type(timestamp) is dict, 'advance(node_id, timestamp) must return dict'
        assert node_ids[0] in timestamp, 'advance() dict must map node_id to tuple[int, bytes'
        assert b'uuid' in timestamp, 'advance() dict must include uuid'
        assert type(timestamp[b'uuid']) is bytes, 'advance() dict[uuid] must be bytes'
        assert type(timestamp[node_ids[0]]) is tuple, \
            'advance() dict must map node_id to tuple[int, bytes'
        assert type(timestamp[node_ids[0]][0]) is int, \
            'advance() dict must map node_id to tuple[int, bytes'
        assert type(timestamp[node_ids[0]][1]) is bytes, \
            'advance() dict must map node_id to tuple[int, bytes'

    def test_update_accepts_advance_output_and_advances_clock(self):
        node_ids = [b'123', b'321']
        vectorclock = classes.VectorPointClock().setup(node_ids)
        clock = classes.PointClock()
        clockupdater = clock.setup(3)
        vectorclock.clocks[node_ids[0]] = clock
        timestamp = vectorclock.advance(node_ids[0], clockupdater.advance(1))

        before = vectorclock.read()
        updated = vectorclock.update(timestamp)
        after = vectorclock.read()

        assert isinstance(updated, classes.VectorPointClock), \
            'vectorclock.update() must return a VectorPointClock'
        assert updated is vectorclock, 'vectorclock.update() must return vectorclock (monad pattern)'
        assert before != after, 'read() output should change after update'

        diff = 0
        for id in node_ids:
            if id not in before or id not in after:
                continue
            diff += 1 if before[id] != after[id] else 0
        assert diff == 1, 'read() output should change by exactly 1 after update'

    def test_can_update_with_initial_states_of_PointClocks(self):
        node_ids = [b'123', b'321']
        vectorclock = classes.VectorPointClock().setup(node_ids)
        clock1 = classes.PointClock()
        clock2 = classes.PointClock()
        clockupdater1 = clock1.setup(2)
        clockupdater2 = clock2.setup(2)

        ts1 = vectorclock.read()
        timestamp = vectorclock.advance(node_ids[0], clockupdater1.advance(0))
        vectorclock.update(timestamp)
        ts2 = vectorclock.read()
        timestamp = vectorclock.advance(node_ids[1], clockupdater2.advance(0))
        vectorclock.update(timestamp)
        ts3 = vectorclock.read()

        assert vectorclock.happens_before(ts1, ts2), 'time moves forward'
        assert vectorclock.happens_before(ts2, ts3), 'time moves forward'
        assert vectorclock.happens_before(ts1, ts3), 'time moves forward transitively'

    def test_verify_returns_True_if_all_clocks_valid(self):
        node_ids = [b'123', b'321']
        vectorclock = classes.VectorPointClock().setup(node_ids)

        assert vectorclock.verify(), 'empty clock should verify'

        clock = classes.PointClock()
        clockupdater = clock.setup(3)
        vectorclock.clocks[node_ids[0]] = clock
        vectorclock.advance(node_ids[0], clockupdater.advance(1))

        assert vectorclock.verify(), 'clock should verify if all underlying clocks verify'

        clock.state = [clock.state[0], clock.state[1] + b'1']

        assert not vectorclock.verify(), 'clock should not verify if underlying clock fails verification'

    def test_verify_timestamp_returns_correct_bool(self):
        node_ids = [b'123', b'321']
        vectorclock = classes.VectorPointClock().setup(node_ids)
        clock0 = classes.PointClock()
        clock1 = classes.PointClock()
        clockupdater0 = clock0.setup(3)
        _ = clock1.setup(3)
        vectorclock.clocks[node_ids[0]] = clock0
        vectorclock.clocks[node_ids[1]] = clock1
        update = clockupdater0.advance(1)
        vectorclock.advance(node_ids[0], update)
        good_ts = vectorclock.read()
        bad_ts = {**good_ts, b'321': (1, b'asd')}

        assert vectorclock.verify_timestamp(good_ts)
        assert not vectorclock.verify_timestamp(bad_ts)

    def test_happens_before_returns_correct_bool(self):
        node_ids = [b'123', b'321']
        vectorclock = classes.VectorPointClock().setup(node_ids)
        clock = classes.PointClock()
        clockupdater = clock.setup(3)
        vectorclock.clocks[node_ids[0]] = clock
        timestamp = vectorclock.advance(node_ids[0], clockupdater.advance(1))

        before = vectorclock.read()
        vectorclock.update(timestamp)
        after = vectorclock.read()

        assert type(vectorclock.happens_before(before, after)) is bool, \
            'happens_before() must return bool'
        assert type(vectorclock.happens_before(after, before)) is bool, \
            'happens_before() must return bool'
        assert classes.VectorPointClock.happens_before(before, after), \
            'happens_before(before, after) must return True for valid timestamps'
        assert not classes.VectorPointClock.happens_before(after, before), \
            'happens_before(before, after) must return False for valid timestamps'
        assert not classes.VectorPointClock.happens_before(after, after), \
            'happens_before(after, after) must return False for valid timestamps'

    def test_are_incomparable_returns_correct_bool(self):
        node_ids = [b'123', b'321']
        vectorclock1 = classes.VectorPointClock().setup(node_ids)
        vectorclock2 = classes.VectorPointClock().setup([*node_ids, b'abc'])
        clock = classes.PointClock()
        clockupdater = clock.setup(3)
        vectorclock1.clocks[node_ids[0]] = clock
        update = vectorclock1.advance(node_ids[0], clockupdater.advance(1))

        ts1 = vectorclock1.read()
        ts2 = vectorclock2.read()

        assert type(vectorclock1.are_incomparable(ts1, ts2)) is bool, \
            'are_incomparable() must return bool'
        assert classes.VectorPointClock.are_incomparable(ts1, ts2), \
            'are_incomparable() must return True for incomparable timestamps'
        assert not vectorclock1.are_incomparable(ts1, ts1), \
            'are_incomparable() must return False for comparable timestamps'

        vectorclock1.update(update)
        ts2 = vectorclock1.read()

        assert not vectorclock2.are_incomparable(ts1, ts2), \
            'are_incomparable() must return False for comparable timestamps'

        vectorclock2 = classes.VectorPointClock(vectorclock1.uuid).setup(node_ids)
        clock2 = classes.PointClock()
        clockupdater2 = clock2.setup(2)
        vectorclock2.clocks[node_ids[1]] = clock2
        update2 = vectorclock2.advance(node_ids[1], clockupdater2.advance(1))
        vectorclock2.update(update2)
        ts2 = vectorclock2.read()

        assert not vectorclock2.are_incomparable(ts1, ts2), 'timestamps should not be incomparable'
        assert vectorclock2.are_concurrent(ts1, ts2), 'timestamps should be concurrent'

    def test_are_concurrent_returns_correct_bool(self):
        node_ids = [b'123', b'321']
        vectorclock1 = classes.VectorPointClock().setup(node_ids)
        clock1 = classes.PointClock()
        clockupdater1 = clock1.setup(2)
        vectorclock1.clocks[node_ids[0]] = clock1
        ts1 = vectorclock1.read()
        update1 = vectorclock1.advance(node_ids[0], clockupdater1.advance(1))
        vectorclock1.update(update1)
        ts2 = vectorclock1.read()

        assert type(classes.VectorPointClock.are_concurrent(ts1, ts1)) is bool, \
            'are_concurrent() must return a bool'
        assert vectorclock1.are_concurrent(ts1, ts1), \
            'are_concurrent() must return True for concurrent timestamps'
        assert not vectorclock1.are_concurrent(ts1, ts2), \
            'are_concurrent() must return False for sequential timestamps'
        assert not vectorclock1.are_concurrent(ts2, ts1), \
            'are_concurrent() must return False for sequential timestamps'

    def test_pack_returns_bytes_that_change_with_state(self):
        node_ids = [b'123', b'321']
        vectorclock = classes.VectorPointClock().setup(node_ids)
        clock = classes.PointClock()
        clockupdater = clock.setup(2)
        vectorclock.clocks[node_ids[0]] = clock
        packed1 = vectorclock.pack()
        packed2 = vectorclock.pack()

        assert type(packed1) is bytes, 'pack() must return bytes'
        assert packed1 == packed2, \
            'pack() output must not change without underlying state change'

        update = vectorclock.advance(node_ids[0], clockupdater.advance(1))
        vectorclock.update(update)
        packed2 = vectorclock.pack()

        assert type(packed2) is bytes, 'pack() must return bytes'
        assert packed1 != packed2, \
            'pack() output must change with underlying state change'

    def test_unpack_returns_valid_instance(self):
        node_ids = [b'123', b'321']
        vectorclock = classes.VectorPointClock().setup(node_ids)
        clock = classes.PointClock()
        clock.setup(2)
        vectorclock.clocks[node_ids[0]] = clock
        packed = vectorclock.pack()
        unpacked = classes.VectorPointClock.unpack(packed)

        assert isinstance(unpacked, classes.VectorPointClock), \
            'unpack() must return a VectorPointClock'
        assert unpacked.uuid == vectorclock.uuid, 'unpacked must have same uuid as source vectorclock'
        assert vectorclock.are_concurrent(vectorclock.read(), unpacked.read()), \
            'timestamps must be concurrent between unpacked and source vectorclock'

    def test_e2e_with_signatures(self):
        """This demonstrates a decent way to use this in practice."""
        # simulate setting up clocks independently
        clocks = [classes.PointClock() for _ in range(5)]
        updaters = [clock.setup(256) for clock in clocks]

        # compile the ids
        node_ids = [clock.uuid for clock in clocks]
        uuids = { nid: nid for nid in node_ids }
        root_uuid = sha256(b''.join(node_ids)).digest()

        # simulate creating a vector clock at each node
        vectorclocks = [
            classes.VectorPointClock(root_uuid).setup(node_ids, uuids)
            for _ in node_ids
        ]

        # make timestamps
        ts0 = [vc.read() for vc in vectorclocks]
        assert all([ts0[0] == ts for ts in ts0]), 'timestamps should be the same'

        # create some updates
        message = b'hello world'
        updates = [
            vectorclocks[i].advance(
                updaters[i].uuid,
                updaters[i].advance_and_sign(1, message)
            )
            for i in range(len(node_ids))
        ]

        # verify every update at each node and then update
        for u in updates:
            for vc in vectorclocks:
                assert vc.verify_signed_timestamp(u, message)
                vc.update(u)

        # check timestamps are all the same
        ts1 = [vc.read() for vc in vectorclocks]
        assert all([ts1[0] == ts for ts in ts1]), 'timestamps should be the same'

        # ensure that time moved forward
        assert vectorclocks[0].happens_before(ts0[0], ts1[0]), 'time should move forward'


if __name__ == '__main__':
    unittest.main()