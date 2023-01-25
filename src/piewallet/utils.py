import hashlib

from ripemd.ripemd160 import ripemd160  # type: ignore


def double_sha256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def ripemd160_sha256(b: bytes) -> bytes:
    return ripemd160(hashlib.sha256(b).digest())
