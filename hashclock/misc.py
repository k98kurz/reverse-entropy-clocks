from hashlib import sha256, sha512
from nacl.signing import SigningKey, VerifyKey
import nacl.bindings

# error raising checks
def tert(condition: bool, message: str) -> None:
    """Raises TypeError with the given message if condition is False."""
    if not condition:
        raise TypeError(message)

def vert(condition: bool, message: str) -> None:
    """Raises ValueError with the given message if condition is False."""
    if not condition:
        raise ValueError(message)

# cryptography
def clamp_scalar(scalar: bytes, from_private_key: bool = False) -> bytes:
    """Make a clamped ed25519 scalar by setting specific bits."""
    if type(scalar) is bytes and len(scalar) >= 32:
        x_i = bytearray(scalar[:32])
    elif type(scalar) is SigningKey:
        x_i = bytearray(sha512(bytes(scalar)).digest()[:32])
        from_private_key = True
    else:
        raise ValueError('not a SigningKey and not 32+ bytes scalar')

    if from_private_key:
        # set bits 0, 1, and 2 to 0
        # nb: lsb is right-indexed
        x_i[0] &= 0b11111000
        # set bit 254 to 1
        x_i[31] |= 0b01000000

    # set bit 255 to 0
    x_i[31] &= 0b01111111

    return bytes(x_i)

def H_big(*parts) -> bytes:
    """The big, 64-byte hash function."""
    return sha512(b''.join(parts)).digest()

def H_small(*parts) -> bytes:
    """The small, 32-byte hash function."""
    return nacl.bindings.crypto_core_ed25519_scalar_reduce(H_big(*parts))

def derive_key_from_seed(seed: bytes) -> bytes:
    """Derive the scalar used for signing from a seed."""
    return clamp_scalar(H_big(seed)[:32], True)

def derive_point_from_scalar(scalar: bytes) -> bytes:
    """Derives an ed25519 point from a scalar."""
    return nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(scalar)

def recursive_hash(preimage: bytes, count: int) -> bytes:
    """Function to recursively hash a preimage."""
    state = preimage
    for _ in range(count):
        state = sha256(state).digest()

    return state

def recursive_add_point(point: bytes, count: int) -> bytes:
    """Function to recursively add an ed25519 point to itself."""
    tert(type(point) is bytes, 'point must be bytes')
    tert(type(count) is int, 'count must be int >= 0')
    vert(count >= 0, 'count must be int >= 0')

    vert(nacl.bindings.crypto_core_ed25519_is_valid_point(point),
         'point must be a valid ed25519 point')

    for _ in range(count):
        point = nacl.bindings.crypto_core_ed25519_add(point, point)

    return point

def recursive_add_scalar(scalar: bytes, count: int) -> bytes:
    """Function to recursively add an ed25519 scalar to itself."""
    tert(type(scalar) is bytes, 'scalar must be bytes')
    tert(type(count) is int, 'count must be int >= 0')
    vert(count >= 0, 'count must be int >= 0')

    vert(nacl.bindings.crypto_core_ed25519_SCALARBYTES == len(scalar),
         'scalar must be a valid ed25519 scalar')

    for _ in range(count):
        scalar = nacl.bindings.crypto_core_ed25519_scalar_add(scalar, scalar)

    return scalar

def sign_with_scalar(scalar: bytes, message: bytes, seed: bytes = None) -> bytes:
    """Creates a valid signature given an ed25519 scalar that validates
        with the corresponding point.
    """
    tert(type(scalar) is bytes, 'scalar must be bytes')
    tert(type(message) is bytes, 'message must be bytes')

    vert(nacl.bindings.crypto_core_ed25519_SCALARBYTES == len(scalar),
         'scalar must be a valid ed25519 scalar')

    seed = seed or H_small(scalar + message)
    x, m = scalar, message
    X = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(x) # G^x
    nonce = H_big(seed)[32:]
    r = clamp_scalar(H_small(H_big(nonce, m))) # H(nonce || m)
    R = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(r) # G^r
    c = clamp_scalar(H_small(R, X, m)) # H(R + T || X || m)
    s = nacl.bindings.crypto_core_ed25519_scalar_add(
        r, nacl.bindings.crypto_core_ed25519_scalar_mul(c, x)
    ) # r + H(R || X || m) * x
    return R + s

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

def all_ascii(data: bytes) -> bool:
    """Determine if all bytes are displayable ascii chars."""
    for c in data:
        if c < 32 or c > 126:
            return False

    return True

def hexify(data) -> dict:
    """Convert bytes to hex."""

    if type(data) is bytes and not all_ascii(data):
        return data.hex()

    if type(data) in (tuple, list):
        result = []
        for v in data:
            result.append(hexify(v))

        return result if type(data) is list else tuple(result)

    if type(data) is dict:
        result = {}

        for key in data:
            name = hexify(key)
            result[name] = hexify(data[key])

        return result

    return data
