from functions.sha256 import sha256


def double_sha256(b: bytes) -> bytes:
    return sha256(sha256(b))
