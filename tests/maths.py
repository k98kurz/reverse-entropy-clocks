from hashlib import sha256
from secrets import token_bytes
from context import classes, interfaces, misc
import nacl.bindings
import unittest


class RunMathematicalProofs(unittest.TestCase):
    """Prove some maths to demonstrate insecurity of constructions."""
    def test_prove_point_can_be_divided_by_two(self):
        """Proves that doubling a point is not a one-way function."""
        seed = token_bytes(32)
        x = misc.derive_key_from_seed(seed)
        Y = misc.derive_point_from_scalar(x)
        Y2 = misc.recursive_add_point(Y, 1)
        Y_2 = divide_point_by_two(Y2)
        assert Y == Y_2, f'\n{Y.hex()}\n{Y_2.hex()}'


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