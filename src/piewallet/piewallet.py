from secrets import randbelow

import base58
import bech32  # type: ignore

from curve_params import secp256k1, Point
from functions.double_sha256 import double_sha256
from functions.ripemd160_sha256 import ripemd160_sha256


class PieWalletException(Exception):
    '''Base exception for PieWallet'''


class PrivateKeyError(PieWalletException):
    '''Private key is out of allowed range'''


class PointError(PieWalletException):
    '''Point is not on an elliptic curve'''


class PrivateKey:

    def __init__(self, private_key: int | None = None) -> None:
        if private_key is None:
            private_key = randbelow(secp256k1.n_curve)
        if not self.valid_key(private_key):
            raise PrivateKeyError('Invalid scalar/private key')
        self.__generate = private_key
        self.__wif_private_key: str | None = None

    @property
    def generate(self):
        return self.__generate

    @property
    def wif_private_key(self) -> str:
        '''Returns private key in WIF format'''
        if self.__wif_private_key is None:
            self.__wif_private_key = self.to_wif(self.generate)
        return self.__wif_private_key

    @staticmethod
    def valid_key(key: int) -> bool:
        try:
            return not (key <= 0 or key >= secp256k1.n_curve)
        except TypeError:
            return False

    def __repr__(self):
        return f"PrivateKey({hex(self.generate)[:4]}...)"

    @staticmethod
    def valid_checksum(version: bytes, private_key: bytes, checksum: bytes) -> bool:
        return double_sha256(version + private_key)[:4] == checksum

    @staticmethod
    def to_bytes(wif: str) -> tuple[bytes, bytes, bytes]:
        if not isinstance(wif, str):
            raise PrivateKeyError('must be in WIF format')
        private_key = base58.b58decode(wif)
        return private_key[:1], private_key[1:-4], private_key[-4:]

    @staticmethod
    def to_int(wif: str, *, hexlify: bool = False) -> int | str:
        # https://en.bitcoin.it/wiki/Wallet_import_format
        if not isinstance(wif, str):
            raise PrivateKeyError('must be in WIF format')
        version, private_key, checksum = PrivateKey.to_bytes(wif)
        if not PrivateKey.valid_checksum(version, private_key, checksum):
            raise PrivateKeyError('invalid WIF checksum')
        private_key_int = int.from_bytes(
            private_key[:-1], 'big') if len(private_key) == 33 else int.from_bytes(private_key, 'big')
        if PrivateKey.valid_key(private_key_int):
            if hexlify:
                return f'0x{private_key_int:0>64x}'
            return private_key_int
        return

    @staticmethod
    def to_wif(key: int, *, uncompressed: bool = False):
        '''Returns private key in WIF format'''
        if not PrivateKey.valid_key(key):
            raise PrivateKeyError('Invalid scalar/private key')
        privkey = bytes.fromhex(f"80{key:0>64x}" if uncompressed else f"80{key:0>64x}01")
        return base58.b58encode_check(privkey).decode("UTF-8")


class PublicKey:

    def __init__(self, private_key: int | None = None, *, uncompressed: bool = False) -> None:
        self.__private_key: int = PrivateKey(private_key).generate
        self.__wif_private_key: str | None = None
        self.__public_key: bytes | None = None
        self.__address: str | None = None
        self.__nested_segwit_address: str | None = None
        self.__native_segwit_address: str | None = None
        self.__uncompressed: bool = uncompressed

    @property
    def address(self) -> str:
        '''Returns Legacy bitcoin address (P2PKH)'''
        if self.__address is None:
            self.__address = self.__create_address(bytes.fromhex(self.public_key))
        return self.__address

    @property
    def nested_segwit_address(self) -> str | None:
        '''
        Returns nested Segwit bitcoin address (P2WPKH-P2SH),

        Returns None for uncompressed public keys
        '''
        if not self.__uncompressed and self.__nested_segwit_address is None:
            self.__nested_segwit_address = self.__create_nested_segwit(bytes.fromhex(self.public_key))
        return self.__nested_segwit_address

    @property
    def native_segwit_address(self) -> str | None:
        '''
        Returns native SegWit bitcoin address (P2WPKH),

        Returns None for uncompressed public keys
        '''
        if not self.__uncompressed and self.__native_segwit_address is None:
            self.__native_segwit_address = self.__create_native_segwit(bytes.fromhex(self.public_key))
        return self.__native_segwit_address

    @property
    def public_key(self) -> str:
        '''Returns public key in HEX format'''
        if self.__public_key is None:
            self.__public_key = self.__create_pubkey(uncompressed=self.__uncompressed)
        return f'{self.__public_key.hex()}'

    @property
    def private_key(self) -> str:
        '''Returns private key in HEX format'''
        return f'0x{self.__private_key:0>64x}'

    @property
    def wif_private_key(self) -> str:
        '''Returns private key in WIF format'''
        if self.__wif_private_key is None:
            self.__wif_private_key = self.__to_wif(uncompressed=self.__uncompressed)
        return self.__wif_private_key

    def __repr__(self):
        return f"PublicKey({self.private_key[:4]}..., uncompressed={self.__uncompressed})"

    def __reciprocal(self, n: int) -> int:
        return pow(n, -1, secp256k1.p_curve)

    def __ec_add(self, p: Point) -> Point:
        slope = (p.y - secp256k1.gen_point.y) * self.__reciprocal(p.x - secp256k1.gen_point.x)
        x = pow(slope, 2) - p.x - secp256k1.gen_point.x
        y = slope * (p.x - x) - p.y
        return Point(x % secp256k1.p_curve, y % secp256k1.p_curve)

    def __ec_dup(self, p: Point) -> Point:
        slope = (3 * pow(p.x, 2) + secp256k1.a_curve) * self.__reciprocal(2 * p.y)
        x = pow(slope, 2) - 2 * p.x
        y = slope * (p.x - x) - p.y
        return Point(x % secp256k1.p_curve, y % secp256k1.p_curve)

    def __ec_mul(self, scalar: int) -> Point:
        scalarbin = bin(scalar)[2:]
        q = secp256k1.gen_point
        for i in range(1, len(scalarbin)):
            q = self.__ec_add(self.__ec_dup(q)) if scalarbin[i] == "1" else self.__ec_dup(q)
        return Point(q.x, q.y)

    def __create_pubkey(self, *, uncompressed: bool = False) -> bytes:
        raw_pubkey = self.__ec_mul(self.__private_key)
        if not self.valid_point(raw_pubkey):
            raise PointError('Point is not on curve')
        if uncompressed:
            return bytes.fromhex(f"04{raw_pubkey.x:0>64x}{raw_pubkey.y:0>64x}")
        odd = raw_pubkey.y & 1
        return (bytes.fromhex(f"03{raw_pubkey.x:0>64x}") if odd
                else bytes.fromhex(f"02{raw_pubkey.x:0>64x}"))

    def __create_address(self, key: bytes) -> str:
        address = b'\x00' + ripemd160_sha256(key)
        return base58.b58encode_check(address).decode("UTF-8")

    def __create_nested_segwit(self, key: bytes) -> str:
        address = b'\x05' + ripemd160_sha256(b'\x00\x14' + ripemd160_sha256(key))
        return base58.b58encode_check(address).decode("UTF-8")

    def __create_native_segwit(self, key: bytes) -> str:
        return bech32.encode('bc', 0x00, ripemd160_sha256(key))

    def __to_wif(self, *, uncompressed: bool = False) -> str:
        privkey = bytes.fromhex(
            f"80{self.private_key[2:]:0>64}" if uncompressed else f"80{self.private_key[2:]:0>64}01")
        return base58.b58encode_check(privkey).decode("UTF-8")

    @staticmethod
    def valid_point(p: Point | tuple[int, int]) -> bool:
        '''Checks if a given point belongs to secp256k1 elliptic curve'''
        try:
            return (pow(p[1], 2) % secp256k1.p_curve ==
                    (pow(p[0], 3) + p[0] * secp256k1.a_curve + secp256k1.b_curve) % secp256k1.p_curve)
        except TypeError:  # Exception is raised when given arguments are invalid (non-integers)
            return False  # which also means point is not on curve


if __name__ == '__main__':
    # print(__ec_mul(0xFF) == (12312385769684547396095365029355369071957339694349689622296638024179682296192,
    #       29045073188889159330506972844502087256824914692696728592611344825524969277689))
    # print(__ec_mul(0xEE31862668ECD0EC1B3538B04FBF21A59965B51C5648F5CE97C613B48610FA7B) == (
    #     49414738088508426605940350615969154033259972709128027173379136589046972286596, 113066049041265251152881802696276066009952852537138792323892337668336798103501))
    my_key = PublicKey(0xFF)
    print(my_key.private_key)
    print(my_key.wif_private_key)
    print(my_key.public_key)
    print(my_key.native_segwit_address)
    print(my_key.address)
    my_privkey = PrivateKey()
    # wif_key = my_privkey.to_wif()
    # print(my_privkey.to_wif())
    # print(my_privkey.to_bytes(wif_key))
    b = (12312385769684547396095365029355369071957339694349689622296638024179682296192,
         29045073188889159330506972844502087256824914692696728592611344825524969277689)
    print(my_key.valid_point(b))
    c = Point(x=12312385769684547396095365029355369071957339694349689622296638024179682296192,
              y=29045073188889159330506972844502087256824914692696728592611344825524969277689)
    print(my_key.valid_point((c.x, c.y)))
    print(my_key.address)
    print(my_key.address)
    # my_key.address = 'B'
    # print(my_key.__private_key) #error
    print(my_key.nested_segwit_address)
    my_key._PublicKey__uncompressed = False
    my_key2 = PublicKey(0xAA)
    print(PublicKey.address.__doc__)
    print(my_key2.address)
    print(my_key.address)
    print(*[i for i in dir(my_key) if not i.startswith('_')], sep='\n')
    print(getattr(my_key, 'address', []))
    print(hasattr(my_key, 'generate'))
    try:
        setattr(my_key, 'private_key', 'hack_bitcoin')
    except AttributeError:
        print('Sorry, can\'t hack bitcoin')
    print(vars(my_key))
    print(vars())
    print([(key, value) for key, value in my_key.__dict__.items()])
    print(vars(my_privkey))
    my_key3 = PrivateKey(0xAA)
    my_key3.__generate = 2
    my_key.__address = 1
    print(my_key.address)
    print(vars(my_key3))
    my_key4 = PrivateKey()
    print(my_key4.wif_private_key)
    print(my_key4)
    print(my_key)
    print(PrivateKey().to_wif(0xff))
    print(my_key.valid_point(c))
    print(pow(0xFF, 1))
