from hashlib import sha256

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

def recursive_hash(preimage: bytes, count: int) -> bytes:
    """Function to recursively hash a preimage."""
    state = preimage
    for _ in range(count):
        state = sha256(state).digest()

    return state

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
