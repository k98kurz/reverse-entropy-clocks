from hashlib import sha256
from secrets import token_bytes
from context import misc
import nacl.bindings
import unittest


class RunMathematicalProofs(unittest.TestCase):
    """Prove some maths to demonstrate insecurity of constructions."""
    def test_prove_point_can_be_divided_by_two(self):
        """Proves that doubling a point is not a one-way function."""
        seed = token_bytes(32)
        x = misc.derive_key_from_seed(seed)
        Y = misc.derive_point_from_scalar(x)
        Y2 = recursive_add_point(Y, 1)
        Y_2 = divide_point_by_two(Y2)
        assert Y == Y_2, f'\n{Y.hex()}\n{Y_2.hex()}'


def recursive_add_point(point: bytes, count: int) -> bytes:
    """Function to recursively add an ed25519 point to itself."""
    misc.tert(type(point) is bytes, 'point must be bytes')
    misc.tert(type(count) is int, 'count must be int >= 0')
    misc.vert(count >= 0, 'count must be int >= 0')

    misc.vert(nacl.bindings.crypto_core_ed25519_is_valid_point(point),
         'point must be a valid ed25519 point')

    for _ in range(count):
        point = nacl.bindings.crypto_core_ed25519_add(point, point)

    return point

def recursive_add_scalar(scalar: bytes, count: int) -> bytes:
    """Function to recursively add an ed25519 scalar to itself."""
    misc.tert(type(scalar) is bytes, 'scalar must be bytes')
    misc.tert(type(count) is int, 'count must be int >= 0')
    misc.vert(count >= 0, 'count must be int >= 0')

    misc.vert(nacl.bindings.crypto_core_ed25519_SCALARBYTES == len(scalar),
         'scalar must be a valid ed25519 scalar')

    for _ in range(count):
        scalar = nacl.bindings.crypto_core_ed25519_scalar_add(scalar, scalar)

    return scalar

def divide_point_by_two(point: bytes) -> bytes:
    """Divides a point by the scalar equivalent of 2.
        x * x^-1 = 1
        (x * x^-1) + (x * x^-1) = 2
        [(x * x^-1) + (x * x^-1)]^-1 = 1/2
        let s := [(x * x^-1) + (x * x^-1)]^-1
        let P2 := P1 + P1
        P2 * s == P1
    """
    x = misc.clamp_scalar(misc.H_small(b'one'))
    scalar1 = nacl.bindings.crypto_core_ed25519_scalar_mul(
        x,
        nacl.bindings.crypto_core_ed25519_scalar_invert(x)
    )
    scalar2 = nacl.bindings.crypto_core_ed25519_scalar_add(scalar1, scalar1)
    scalarhalf = nacl.bindings.crypto_core_ed25519_scalar_invert(scalar2)
    return nacl.bindings.crypto_scalarmult_ed25519_noclamp(scalarhalf, point)


if __name__ == '__main__':
    unittest.main()