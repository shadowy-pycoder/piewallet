import hmac
from hashlib import sha256


def bits_to_int(b: bytes, qlen: int):
    # https://www.rfc-editor.org/rfc/rfc6979 section 2.3.2.
    blen = len(b) * 8
    b_int = int.from_bytes(b, 'big')
    if blen > qlen:
        b_int = b_int >> blen - qlen
    return b_int


def int_to_oct(x: int, rolen: int) -> bytes:
    # https://www.rfc-editor.org/rfc/rfc6979 section 2.3.3.
    xolen = x.bit_length() >> 3
    x_hex = f'{x:x}'
    if xolen < rolen:
        x_hex = f'{x:0>{rolen*2}x}'
    elif xolen > rolen:
        x_hex = x_hex[(xolen - rolen)*2:]
    return bytes.fromhex(x_hex)


def bits_to_oct(b: bytes, q: int, qlen: int, rolen: int) -> bytes:
    # https://www.rfc-editor.org/rfc/rfc6979 section 2.3.4.
    z1 = bits_to_int(b, qlen)
    z2 = z1 - q
    if z2 < 0:
        z2 = z1
    return int_to_oct(z2, rolen)


def rfc_sign(x: int, m: int, q: int):
    qlen = q.bit_length()
    qolen = qlen >> 3
    rolen = qlen + 7 >> 3
    h1 = m.to_bytes(32, 'big')
    V = b'\x01' * 32
    K = b'\x00' * 32
    m1 = b'\x00' + int_to_oct(x, rolen) + bits_to_oct(h1, q, qlen, rolen)
    m2 = b'\x01' + int_to_oct(x, rolen) + bits_to_oct(h1, q, qlen, rolen)

    K_ = hmac.new(K, digestmod=sha256)
    K_.update(V + m1)
    K = K_.digest()
    V = hmac.new(K, V, digestmod=sha256).digest()
    K_ = hmac.new(K, digestmod=sha256)
    K_.update(V + m2)
    K = K_.digest()
    V = hmac.new(K, V, digestmod=sha256).digest()
    while True:
        T = b''
        while len(T) < qolen:
            V = hmac.new(K, V, digestmod=sha256).digest()
            T = T + V
        k = bits_to_int(T, qlen)
        if 0 < k < q:
            return k
        K_ = hmac.new(K, digestmod=sha256)
        K_.update(V + b'\x00')
        K = K_.digest()
        V = hmac.new(K, V, digestmod=sha256).digest()


if __name__ == '__main__':
    h1 = int(sha256(b'sample').hexdigest(), 16)
    q = 0x4000000000000000000020108A2E0CC0D99F8A5EF
    x = 0x09A4D6792295A7F730FC3F2B49CBC0F62E862272F
    qlen = q.bit_length()
    rolen = (qlen + 7) >> 3
    rlen = rolen * 8
    print(hex(rfc_sign(x, h1, q)))
