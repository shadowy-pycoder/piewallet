from secrets import randbelow
from time import perf_counter

import base58
import bech32  # type: ignore

from curve_params import secp256k1, JacobianPoint, Point, IDENTITY_POINT, POW_2_256_M1
from functions.double_sha256 import double_sha256
from functions.ripemd160_sha256 import ripemd160_sha256


class PieWalletException(Exception):
    '''Base exception for PieWallet'''


class PrivateKeyError(PieWalletException):
    '''Private key is out of allowed range'''


class PointError(PieWalletException):
    '''Point is not on an elliptic curve'''


class PrivateKey:

    def __init__(self, privkey: int | None = None, /, *, uncompressed: bool = False) -> None:
        if privkey is None:
            privkey = randbelow(secp256k1.n_curve)

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

    @staticmethod
    def valid_key(scalar: int, /) -> bool:
        '''Checks if an integer is within allowed range'''
        return isinstance(scalar, int) and not (scalar <= 0 or scalar >= secp256k1.n_curve)

    @staticmethod
    def valid_checksum(version: bytes, privkey: bytes, checksum: bytes) -> bool:
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

    def __init__(self, privkey: int | None = None, /, *, uncompressed: bool = False) -> None:
        super().__init__(privkey, uncompressed=uncompressed)
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
            self.__address = self.__create_address(self.public_key_bytes)
        return self.__address

    @property
    def nested_segwit_address(self) -> str | None:
        '''
        Returns nested Segwit bitcoin address (P2WPKH-P2SH),

        Returns None for uncompressed public keys
        '''
        if not self.uncompressed and self.__nested_segwit_address is None:
            self.__nested_segwit_address = self.__create_nested_segwit(self.public_key_bytes)
        return self.__nested_segwit_address

    @property
    def native_segwit_address(self) -> str | None:
        '''
        Returns native SegWit bitcoin address (P2WPKH),

        Returns None for uncompressed public keys
        '''
        if not self.uncompressed and self.__native_segwit_address is None:
            self.__native_segwit_address = self.__create_native_segwit(self.public_key_bytes)
        return self.__native_segwit_address

    @property
    def public_key_bytes(self) -> bytes:
        '''Returns public key in bytes format'''
        if self.__public_key is None:
            self.__public_key = self.__create_pubkey(uncompressed=self.uncompressed)
        return self.__public_key

    @property
    def public_key(self) -> str:
        '''Returns public key in HEX format'''
        return f'{self.public_key_bytes.hex()}'

    def __ec_dbl(self, q: JacobianPoint) -> JacobianPoint:
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

    def __ec_add(self, p: JacobianPoint, q: JacobianPoint) -> JacobianPoint:
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
                return self.__ec_dbl(p)
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
            dbl = self.__ec_dbl(dbl)

    def __ec_mul(self, scalar: int) -> JacobianPoint:
        # https://paulmillr.com/posts/noble-secp256k1-fast-ecc/#fighting-timing-attacks
        n = scalar
        p = IDENTITY_POINT
        fake_p = IDENTITY_POINT
        fake_n = POW_2_256_M1 ^ n

        for point in PublicKey.__precomputes:
            q = point
            if n & 1:
                p = self.__ec_add(p, q)
            else:
                fake_p = self.__ec_add(fake_p, q)
            n >>= 1
            fake_n >>= 1
        return JacobianPoint(p.x, p.y, p.z)

    def __create_pubkey(self, *, uncompressed: bool = False) -> bytes:
        raw_pubkey: Point = self.to_affine(self.__ec_mul(self.private_key))
        if not self.valid_point(raw_pubkey):
            raise PointError('Point is not on curve')

        if uncompressed:
            return b'\x04' + raw_pubkey.x.to_bytes(32, 'big') + raw_pubkey.y.to_bytes(32, 'big')

        prefix = b'\x03' if raw_pubkey.y & 1 else b'\x02'
        return prefix + raw_pubkey.x.to_bytes(32, 'big')

    def __create_address(self, pubkey: bytes) -> str:
        address = b'\x00' + ripemd160_sha256(pubkey)
        return base58.b58encode_check(address).decode('UTF-8')

    def __create_nested_segwit(self, pubkey: bytes) -> str:
        address = b'\x05' + ripemd160_sha256(b'\x00\x14' + ripemd160_sha256(pubkey))
        return base58.b58encode_check(address).decode('UTF-8')

    def __create_native_segwit(self, pubkey: bytes) -> str:
        return bech32.encode('bc', 0x00, ripemd160_sha256(pubkey))

    @staticmethod
    def modulo_inverse(n: int) -> int:
        return pow(n, -1, secp256k1.p_curve)

    @staticmethod
    def to_affine(p: JacobianPoint) -> Point:
        '''Converts jacobian point to affine point'''
        inv_z = PublicKey.modulo_inverse(p.z)
        inv_z2 = inv_z ** 2
        x = (p.x * inv_z2) % secp256k1.p_curve
        y = (p.y * inv_z2 * inv_z) % secp256k1.p_curve
        return Point(x, y)

    @staticmethod
    def valid_point(p: Point | tuple[int, int], /) -> bool:
        '''Checks if a given point belongs to secp256k1 elliptic curve'''
        try:
            return (all(isinstance(i, int) for i in p) and
                    pow(p[1], 2) % secp256k1.p_curve == (pow(p[0], 3) + secp256k1.b_curve) % secp256k1.p_curve)
        except (TypeError, IndexError):  # Exception is raised when given arguments are invalid (non-integers)
            return False  # which also means point is not on curve


class Address(PublicKey):
    pass


if __name__ == '__main__':
    # print(__ec_mul(0xFF) == (12312385769684547396095365029355369071957339694349689622296638024179682296192,
    #       29045073188889159330506972844502087256824914692696728592611344825524969277689))
    # print(__ec_mul(0xEE31862668ECD0EC1B3538B04FBF21A59965B51C5648F5CE97C613B48610FA7B) == (
    #     49414738088508426605940350615969154033259972709128027173379136589046972286596, 113066049041265251152881802696276066009952852537138792323892337668336798103501))
    my_key = PublicKey(0xFF, uncompressed=False)
    # assert my_key.public_key == '031B38903A43F7F114ED4500B4EAC7083FDEFECE1CF29C63528D563446F972C180'.lower()
    # assert my_key.public_key == '041B38903A43F7F114ED4500B4EAC7083FDEFECE1CF29C63528D563446F972C1804036EDC931A60AE889353F77FD53DE4A2708B26B6F5DA72AD3394119DAF408F9'.lower()

    print(my_key._PublicKey__precomputes[1])
    print(my_key.wif_private_key)
    print(PrivateKey.to_wif(0xFF, uncompressed=True))

    print(my_key.native_segwit_address)
    print(my_key.nested_segwit_address)
    print(my_key.address)
    my_privkey = PrivateKey(0xFF)
    print(my_privkey.wif_private_key)
    print(PrivateKey.valid_key(0xC0FEE))
    b = (12312385769684547396095365029355369071957339694349689622296638024179682296192,
         29045073188889159330506972844502087256824914692696728592611344825524969277689)
    print(my_key.valid_point(b))
    c = Point(x=12312385769684547396095365029355369071957339694349689622296638024179682296192,
              y=29045073188889159330506972844502087256824914692696728592611344825524969277689)
    print(my_key.valid_point((c.x, c.y)))
    # print(getattr(my_key, 'address', []))
    # print(hasattr(my_key, 'generate'))
    # try:
    #     setattr(my_key, 'private_key', 'hack_bitcoin')
    # except AttributeError:
    #     print('Sorry, can\'t hack bitcoin')
    # print(vars(my_key))
    # print(vars())
    # print([(key, value) for key, value in my_key.__dict__.items()])
    my_key2 = PublicKey(0xFF, uncompressed=True)
    print(my_key2.hex_private_key)
    print(my_key2.private_key)
    print(my_key2.wif_private_key)
    print(my_key2.public_key)
    print(my_key2.native_segwit_address)
    print(my_key2)
