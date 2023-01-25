import hmac
# from functions.sha256 import sha256
from hashlib import sha256

h1 = sha256('sample'.encode('utf-8'))
q = 0x4000000000000000000020108A2E0CC0D99F8A5EF
x = 0x09A4D6792295A7F730FC3F2B49CBC0F62E862272F
qlen = q.bit_length()
rolen = (qlen + 7) >> 3
rlen = rolen * 8


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

# H(m) - hash of the message


def rfc_sign(x: int, m, q: int):
    qlen = q.bit_length()
    qolen = qlen >> 3
    rolen = (qlen + 7) >> 3
    h1 = sha256()
    h1.update(b'sample')
    h1 = h1.digest()
    V = b'\x01' * 32
    K = b'\x00' * 32
    m1 = b'\x00' + int_to_oct(x, rolen) + bits_to_oct(h1, q, qlen, rolen)
    m2 = b'\x01' + int_to_oct(x, rolen) + bits_to_oct(h1, q, qlen, rolen)

    K = hmac.new(K, digestmod=sha256)
    K.update(V + m1)
    K = K.digest()
    V = hmac.new(K, V, digestmod=sha256).digest()
    K = hmac.new(K, digestmod=sha256)
    K.update(V + m2)
    K = K.digest()
    V = hmac.new(K, V, digestmod=sha256).digest()
    print(V)
    while True:
        T = b''
        while len(T) < qolen:
            V = hmac.new(K, V, digestmod=sha256).digest()
            T = T + V
        k = bits_to_int(T, qlen)
        # if (sig := self._signed(x, m, k)) is not None:
        # return sig
        if 0 < k < q:
            return k
        K = hmac.new(K, digestmod=sha256)
        K.update(V + b'\x00')
        K = K.digest()
        V = hmac.new(K, V, digestmod=sha256).digest()


# q = (q.bit_length() + 7) >> 3
print(rfc_sign(x, 's', q))
# print(sha256('sample'.encode('utf-8')).hex())
