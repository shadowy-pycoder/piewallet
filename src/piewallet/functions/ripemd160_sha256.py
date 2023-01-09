from functions.sha256 import sha256
from functions.ripemd160 import ripemd160


def ripemd160_sha256(b: bytes) -> bytes:
    return ripemd160(sha256(b))
