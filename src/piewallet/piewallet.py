import base64
from secrets import randbelow
import sys
from time import perf_counter

import base58
import bech32  # type: ignore

from curve_params import secp256k1, JacobianPoint, Point, Signature, IDENTITY_POINT, POW_2_256_M1
from functions.double_sha256 import double_sha256
from functions.ripemd160_sha256 import ripemd160_sha256
from functions.sha256 import sha256


class PieWalletException(Exception):
    '''Base exception for PieWallet'''


class PrivateKeyError(PieWalletException):
    '''Private key is out of allowed range'''


class PointError(PieWalletException):
    '''Point is not on an elliptic curve'''


class SignatureError(PieWalletException):
    '''Invalid ECDSA signature parameters'''


class PrivateKey:

    def __init__(self, privkey: int | None = None, /, *, uncompressed: bool = False) -> None:
        if privkey is None:
            privkey = self._generate()

        if not self.valid_key(privkey):
            raise PrivateKeyError('Invalid scalar/private key')

        self.__private_key = privkey
        self.__wif_private_key: str | None = None
        self.uncompressed = uncompressed

    @property
    def private_key(self):
        '''Returns private key (generated or user-supplied)'''
        return self.__private_key

    @property
    def hex_private_key(self) -> str:
        '''Returns private key in HEX format'''
        return f'0x{self.private_key:0>64x}'

    @property
    def wif_private_key(self) -> str:
        '''Returns private key in WIF format'''
        if self.__wif_private_key is None:
            self.__wif_private_key = self.to_wif(self.private_key, uncompressed=self.uncompressed)
        return self.__wif_private_key

    def __repr__(self) -> str:
        cls_name = self.__class__.__name__
        key = self.hex_private_key
        return f'{cls_name}({key[:4]}...{key[-4:]}, uncompressed={self.uncompressed})'

    def _generate(self) -> int:
        '''Generates cryptographically-secure random integer'''
        return randbelow(secp256k1.n_curve)

    @staticmethod
    def valid_key(scalar: int, /) -> bool:
        '''Checks if an integer is within allowed range'''
        return isinstance(scalar, int) and not (scalar <= 0 or scalar >= secp256k1.n_curve)

    @staticmethod
    def valid_checksum(version: bytes, privkey: bytes, checksum: bytes, /) -> bool:
        return double_sha256(version + privkey)[:4] == checksum

    @staticmethod
    def to_bytes(wif: str, /) -> tuple[bytes, bytes, bytes]:
        '''Converts WIF private key to bytes'''
        if not isinstance(wif, str):
            raise PrivateKeyError('must be in WIF format')

        privkey = base58.b58decode(wif)
        return privkey[:1], privkey[1:-4], privkey[-4:]

    @staticmethod
    def to_int(wif: str, /, *, hexlify: bool = False) -> int | str:
        '''Converts WIF private key to integer'''
        if not isinstance(wif, str):
            raise PrivateKeyError('must be in WIF format')

        version, privkey, checksum = PrivateKey.to_bytes(wif)
        if not PrivateKey.valid_checksum(version, privkey, checksum):
            raise PrivateKeyError('invalid WIF checksum')

        privkey_int = int.from_bytes(
            privkey[:-1], 'big') if len(privkey) == 33 else int.from_bytes(privkey, 'big')
        if PrivateKey.valid_key(privkey_int):
            if hexlify:
                return f'0x{privkey_int:0>64x}'
            return privkey_int
        return -1

    @staticmethod
    def to_wif(privkey: int, /, *, uncompressed: bool = False) -> str:
        '''Converts private key from integer to WIF format'''
        if not PrivateKey.valid_key(privkey):
            raise PrivateKeyError('Invalid scalar/private key')

        suffix = b'' if uncompressed else b'\x01'
        privkey_bytes = b'\x80' + privkey.to_bytes(32, 'big') + suffix
        return base58.b58encode_check(privkey_bytes).decode('UTF-8')


class PublicKey(PrivateKey):

    __precomputes: list[JacobianPoint] = []
    __headers = [[b'\x1b', b'\x1c', b'\x1d', b'\x1e'],
                 [b'\x1f', b'\x1f', b'\x20', b'\x22'],
                 [b'\x23', b'\x24', b'\x25', b'\x26'],
                 [b'\x27', b'\x29', b'\x28', b'\x2a'],
                 [b'\x2b', b'\x2c', b'\x2d', b'\x2e']]

    def __init__(self, privkey: int | None = None, /, *, uncompressed: bool = False) -> None:
        super().__init__(privkey, uncompressed=uncompressed)
        self.__raw_public_key: Point | None = None
        self.__public_key: bytes | None = None
        self.__address: str | None = None
        self.__nested_segwit_address: str | None = None
        self.__native_segwit_address: str | None = None
        if not PublicKey.__precomputes:
            self.__get_precomputes()

    @property
    def address(self) -> str:
        '''Returns Legacy bitcoin address (P2PKH)'''
        if self.__address is None:
            self.__address = self._create_address(self.public_key_bytes)
        return self.__address

    @property
    def nested_segwit_address(self) -> str | None:
        '''
        Returns nested Segwit bitcoin address (P2WPKH-P2SH),

        Returns None for uncompressed public keys
        '''
        if not self.uncompressed and self.__nested_segwit_address is None:
            self.__nested_segwit_address = self._create_nested_segwit(self.public_key_bytes)
        return self.__nested_segwit_address

    @property
    def native_segwit_address(self) -> str | None:
        '''
        Returns native SegWit bitcoin address (P2WPKH),

        Returns None for uncompressed public keys
        '''
        if not self.uncompressed and self.__native_segwit_address is None:
            self.__native_segwit_address = self._create_native_segwit(self.public_key_bytes)
        return self.__native_segwit_address

    @property
    def raw_public_key(self) -> Point:
        if self.__raw_public_key is None:
            self.__raw_public_key = self._raw_pubkey()
        return self.__raw_public_key

    @property
    def public_key_bytes(self) -> bytes:
        '''Returns public key in bytes format'''
        if self.__public_key is None:
            self.__public_key = self._create_pubkey(self.raw_public_key, uncompressed=self.uncompressed)
        return self.__public_key

    @property
    def public_key(self) -> str:
        '''Returns public key in HEX format'''
        return f'{self.public_key_bytes.hex()}'

    def _ec_dbl(self, q: JacobianPoint, /) -> JacobianPoint:
        # Fast Prime Field Elliptic Curve Cryptography with 256 Bit Primes
        # Shay Gueron, Vlad Krasnov
        # https://eprint.iacr.org/2013/816.pdf page 4
        if q.x == secp256k1.p_curve:
            return q
        Y2 = q.y * q.y
        S = (4 * q.x * Y2) % secp256k1.p_curve
        M = 3 * q.x * q.x
        x = (M * M - 2 * S) % secp256k1.p_curve
        y = (M * (S - x) - 8 * Y2 * Y2) % secp256k1.p_curve
        z = (2 * q.y * q.z) % secp256k1.p_curve
        return JacobianPoint(x, y, z)

    def _ec_add(self, p: JacobianPoint, q: JacobianPoint, /) -> JacobianPoint:
        # Fast Prime Field Elliptic Curve Cryptography with 256 Bit Primes
        # Shay Gueron, Vlad Krasnov
        # https://eprint.iacr.org/2013/816.pdf page 4
        if p.x == secp256k1.p_curve:
            return q
        if q.x == secp256k1.p_curve:
            return p

        PZ2 = p.z * p.z
        QZ2 = q.z * q.z
        U1 = (p.x * QZ2) % secp256k1.p_curve
        U2 = (q.x * PZ2) % secp256k1.p_curve
        S1 = (p.y * QZ2 * q.z) % secp256k1.p_curve
        S2 = (q.y * PZ2 * p.z) % secp256k1.p_curve

        if U1 == U2:
            if S1 == S2:  # double point
                return self._ec_dbl(p)
            else:  # return POINT_AT_INFINITY
                return IDENTITY_POINT

        H = (U2 - U1) % secp256k1.p_curve
        R = (S2 - S1) % secp256k1.p_curve
        H2 = (H * H) % secp256k1.p_curve
        H3 = (H2 * H) % secp256k1.p_curve
        x = (R * R - H3 - 2 * U1 * H2) % secp256k1.p_curve
        y = (R * (U1 * H2 - x) - S1 * H3) % secp256k1.p_curve
        z = (H * p.z * q.z) % secp256k1.p_curve
        return JacobianPoint(x, y, z)

    def __get_precomputes(self) -> None:
        dbl: JacobianPoint = secp256k1.gen_point
        for _ in range(256):
            PublicKey.__precomputes.append(dbl)
            dbl = self._ec_dbl(dbl)

    def _ec_mul(self, scalar: int, point: Point | JacobianPoint | None = None, /) -> JacobianPoint:
        # https://paulmillr.com/posts/noble-secp256k1-fast-ecc/#fighting-timing-attacks
        n = scalar
        p = IDENTITY_POINT
        if point is None:  # no point specified, which means standard multiplication
            fake_p = p
            fake_n = POW_2_256_M1 ^ n
            for precomp in PublicKey.__precomputes:
                q = precomp
                if n & 1:
                    p = self._ec_add(p, q)
                else:
                    fake_p = self._ec_add(fake_p, q)
                n >>= 1
                fake_n >>= 1
        else:  # unsafe multiplication for signature verification
            if isinstance(point, Point):
                point = self.to_jacobian(point)
            q = point
            while n > 0:
                if n & 1:
                    p = self._ec_add(p, q)
                n >>= 1
                q = self._ec_dbl(q)
        return JacobianPoint(p.x, p.y, p.z)

    def _raw_pubkey(self) -> Point:
        raw_pubkey = self.to_affine(self._ec_mul(self.private_key))
        if not self.valid_point(raw_pubkey):
            raise PointError('Point is not on curve')
        return raw_pubkey

    def _create_pubkey(self, raw_pubkey: Point, /, *, uncompressed: bool = False) -> bytes:
        if uncompressed:
            return b'\x04' + raw_pubkey.x.to_bytes(32, 'big') + raw_pubkey.y.to_bytes(32, 'big')

        prefix = b'\x03' if self._is_odd(raw_pubkey.y) else b'\x02'
        return prefix + raw_pubkey.x.to_bytes(32, 'big')

    def _create_address(self, pubkey: bytes, /) -> str:
        address = b'\x00' + ripemd160_sha256(pubkey)
        return base58.b58encode_check(address).decode('UTF-8')

    def _create_nested_segwit(self, pubkey: bytes, /) -> str:
        address = b'\x05' + ripemd160_sha256(b'\x00\x14' + ripemd160_sha256(pubkey))
        return base58.b58encode_check(address).decode('UTF-8')

    def _create_native_segwit(self, pubkey: bytes, /) -> str:
        return bech32.encode('bc', 0x00, ripemd160_sha256(pubkey))

    def _is_odd(self, n: int) -> bool:
        return bool(n & 1)

    @staticmethod
    def mod_inverse(n: int, /, mod: int) -> int:
        return pow(n, -1, mod)

    @staticmethod
    def to_affine(p: JacobianPoint, /) -> Point:
        '''Converts jacobian point to affine point'''
        inv_z = PublicKey.mod_inverse(p.z, secp256k1.p_curve)
        inv_z2 = inv_z ** 2
        x = (p.x * inv_z2) % secp256k1.p_curve
        y = (p.y * inv_z2 * inv_z) % secp256k1.p_curve
        return Point(x, y)

    @staticmethod
    def to_jacobian(p: Point, /) -> JacobianPoint:
        '''Converts affine point to jacobian point'''
        return JacobianPoint(p.x, p.y, z=1)

    @staticmethod
    def valid_point(p: Point | tuple[int, int], /) -> bool:
        '''Checks if a given point belongs to secp256k1 elliptic curve'''
        try:
            return (all(isinstance(i, int) for i in p) and
                    pow(p[1], 2) % secp256k1.p_curve == (pow(p[0], 3) + secp256k1.b_curve) % secp256k1.p_curve)
        except (TypeError, IndexError):  # Exception is raised when given arguments are invalid (non-integers)
            return False  # which also means point is not on curve

    def msg_magic(self, message: str) -> str:
        return "\x18Bitcoin Signed Message:\n" + chr(len(message)) + message

    def _sign(self, privkey: int, mhash: int, /) -> Signature:
        # https://learnmeabitcoin.com/technical/ecdsa#sign
        while True:
            k = self._generate()
            if not self.valid_key(k):
                continue
            # when working with private keys, standard multiplication is used
            point = self.to_affine(self._ec_mul(k))
            r = point.x % secp256k1.n_curve
            if r == 0 or point == IDENTITY_POINT:
                continue
            s = self.mod_inverse(k, secp256k1.n_curve) * (mhash + privkey * r) % secp256k1.n_curve
            if s == 0:
                continue
            if s > secp256k1.n_curve // 2:  # https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
                s = secp256k1.n_curve - s
            break
        return Signature(r, s)

    def _verify(self, pubkey: Point, sig: Signature, mhash: int, /) -> bool:
        # https://learnmeabitcoin.com/technical/ecdsa#verify
        # when working with public keys, unsafe multiplication is used
        p = self._ec_mul(self.mod_inverse(sig.s, secp256k1.n_curve) * mhash, secp256k1.gen_point)
        q = self._ec_mul(self.mod_inverse(sig.s, secp256k1.n_curve) * sig.r, pubkey)
        pq = self.to_affine(self._ec_add(p, q))
        return pq.x == sig.r

    def _sign_message(self, address: str, message: str) -> str:
        m_bytes = self.msg_magic(message).encode('ascii')
        m_hash = int.from_bytes(double_sha256(m_bytes), 'big')
        sig = self._sign(self.private_key, m_hash)

        if address.startswith('bc'):
            ver = 3
        else:
            if self.uncompressed:
                ver = 0
            else:
                addr_bytes = base58.b58decode_check(address)
                if addr_bytes.startswith(b'\x00'):
                    ver = 1
                else:
                    ver = 2
        r = sig.r.to_bytes(32, 'big')
        s = sig.s.to_bytes(32, 'big')
        for header in self.__headers[ver]:
            sig = base64.b64encode(header + r + s).decode('ascii')
            verified = self.verify_message(address, message, sig)
            if verified:
                return sig

    def bitcoin_message(self, address: str, message: str) -> None:
        print('-----BEGIN BITCOIN SIGNED MESSAGE-----')
        print(message)
        print('-----BEGIN BITCOIN SIGNATURE-----')
        print(address)
        print()
        print(self._sign_message(address, message))
        print('-----END BITCOIN SIGNATURE-----')

    def verify_message(self, address: str, message: str, sig: str):
        dsig = base64.b64decode(sig)
        if len(dsig) != 65:
            raise SignatureError("Signature must be 65 bytes long:", len(dsig))
        ver = dsig[:1]
        m_bytes = self.msg_magic(message).encode('ascii')
        z = int.from_bytes(double_sha256(m_bytes), 'big')
        header, r, s = dsig[0], int.from_bytes(dsig[1:33], 'big'), int.from_bytes(dsig[33:], 'big')
        if header < 27 or header > 42:
            raise SignatureError("Header byte out of range:", header)
        if header >= 39:
            header -= 12
        elif header >= 35:
            header -= 8
        elif header >= 31:
            header -= 4
        recid = header - 27
        x = r + secp256k1.n_curve * (recid // 2)
        alpha = (pow(x, 3) + secp256k1.b_curve) % secp256k1.p_curve
        beta = pow(alpha, (secp256k1.p_curve + 1) // 4, secp256k1.p_curve)
        if (beta - recid) % 2 == 0:
            y = beta
        else:
            y = secp256k1.p_curve - beta
        R = Point(x, y)
        e = (-z) % secp256k1.n_curve
        inv_r = self.mod_inverse(r, secp256k1.n_curve)
        p = self._ec_mul(s, R)
        q = self._ec_mul(e, secp256k1.gen_point)
        Q = self._ec_add(p, q)
        raw_pubkey = self.to_affine(self._ec_mul(inv_r, Q))
        if ver in self.__headers[0]:
            pubkey = self._create_pubkey(raw_pubkey, uncompressed=True)
            addr = self._create_address(pubkey)
        elif ver in self.__headers[1]:
            pubkey = self._create_pubkey(raw_pubkey)
            addr = self._create_address(pubkey)
        elif ver in self.__headers[2]:
            pubkey = self._create_pubkey(raw_pubkey)
            addr = self._create_nested_segwit(pubkey)
        elif ver in self.__headers[3]:
            pubkey = self._create_pubkey(raw_pubkey)
            addr = self._create_native_segwit(pubkey)
        elif ver in self.__headers[4]:
            raise NotImplementedError()
        else:
            raise SignatureError("Header byte out of range:", header)
        return addr == address


class PieWallet(PublicKey):
    def __init__(self):
        super().__init__()


if __name__ == '__main__':
    my_key = PublicKey(112757557418114203588093402336452206775565751179231977388358956335153294300646)
    print(my_key.wif_private_key)
    privkey = my_key.private_key
    pubkey = my_key.raw_public_key
    message = 'ECDSA is the most fun I have ever experienced'
    m_hash = int.from_bytes(sha256(message.encode('ascii')), 'big')
    nonce = 12345
    address = my_key.native_segwit_address
    sig, odd = my_key._sign(privkey, m_hash)
    sig_real = 'G0PUXl2I51DzDEkTZJqWZZFf67X8ipazXLLgLhW28PYrFHMhsVrDzuDJtLbAcMUDFrz5uu7XSdXghDdIVw0P/W0='
    decoded = base64.b64decode(sig_real).hex()
    print(int(decoded[:2], 16), int(decoded[2:66], 16), int(decoded[66:], 16))
    print(my_key.verify_message(address, message, sig_real))
    my_key.bitcoin_message(address, message)
