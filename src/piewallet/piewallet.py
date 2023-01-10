from secrets import randbelow

import base58

from curve_params import secp256k1
from functions.double_sha256 import double_sha256
from functions.ripemd160_sha256 import ripemd160_sha256


UNCOMPRESSED = False


class PublicKey:

    def __init__(self, private_key: int | None = None) -> None:
        if private_key is None:
            private_key = randbelow(secp256k1.n_curve)
        if not self.valid_key(private_key):
            raise Exception('Invalid scalar/private key')
        self._private_key: int = private_key
        self._address: str | None = None
        self._public_key: bytes | None = None

    @property
    def address(self) -> str:
        if self._address is None:
            self._address = self.__address(bytes.fromhex(self.public_key[2:]))
        return self._address

    @property
    def public_key(self) -> str:
        if self._public_key is None:
            self._public_key = self.__compute_pubkey(uncompressed=UNCOMPRESSED)
        return f'0x{self._public_key.hex()}'

    @property
    def private_key(self) -> str:
        return f'0x{self._private_key:0>64x}'

    def __reciprocal(self, n: int) -> int:
        return pow(n, -1, secp256k1.p_curve)

    def __ec_add(self, p: tuple[int, int]) -> tuple[int, int]:
        slope = ((p[1] - secp256k1.gen_point[1]) *
                 self.__reciprocal(p[0] - secp256k1.gen_point[0]))
        x = pow(slope, 2) - p[0] - secp256k1.gen_point[0]
        y = slope * (p[0] - x) - p[1]
        return x % secp256k1.p_curve, y % secp256k1.p_curve

    def __ec_dup(self, p: tuple[int, int]) -> tuple[int, int]:
        slope = ((3 * pow(p[0], 2) + secp256k1.a_curve)
                 * self.__reciprocal(2 * p[1]))
        x = pow(slope, 2) - 2 * p[0]
        y = slope * (p[0] - x) - p[1]
        return x % secp256k1.p_curve, y % secp256k1.p_curve

    def __ec_mul(self, scalar: int) -> tuple[int, int]:
        scalarbin = bin(scalar)[2:]
        q = secp256k1.gen_point
        for i in range(1, len(scalarbin)):
            q = (self.__ec_add(self.__ec_dup(q))
                 if scalarbin[i] == "1" else self.__ec_dup(q))
        return q

    def __pubkey(self) -> tuple[int, int]:
        return self.__ec_mul(self._private_key)

    def __compute_pubkey(self, *, uncompressed: bool = UNCOMPRESSED) -> bytes:
        if uncompressed:
            return bytes.fromhex(f"04{self.__pubkey()[0]:0>64x}{self.__pubkey()[1]:0>64x}")
        odd = self.__pubkey()[1] % 2 == 1
        return bytes.fromhex(f"03{self.__pubkey()[0]:0>64x}") if odd else bytes.fromhex(f"02{self.__pubkey()[0]:0>64x}")

    def __address(self, key: bytes) -> str:
        address = b'\x00' + ripemd160_sha256(key)
        return base58.b58encode(address + double_sha256(address)[:4]).decode("UTF-8")

    def wif(self, *, uncompressed: bool = UNCOMPRESSED) -> str:
        '''
        Reveals a WIF-version of the generated private key
        '''
        privkey = bytes.fromhex(
            f"80{self.private_key[2:]:0>64}" if uncompressed else f"80{self.private_key[2:]:0>64}01")
        return base58.b58encode(privkey + double_sha256(privkey)[:4]).decode("UTF-8")

    @staticmethod
    def valid_key(key: int) -> bool:
        try:
            key_h = int(key)
        except (ValueError, TypeError):
            return False
        return not (key_h <= 0 or key_h >= secp256k1.n_curve)


class Address(PublicKey):
    pass


# print(__ec_mul(0xFF) == (12312385769684547396095365029355369071957339694349689622296638024179682296192,
#       29045073188889159330506972844502087256824914692696728592611344825524969277689))
# print(__ec_mul(0xEE31862668ECD0EC1B3538B04FBF21A59965B51C5648F5CE97C613B48610FA7B) == (
#     49414738088508426605940350615969154033259972709128027173379136589046972286596, 113066049041265251152881802696276066009952852537138792323892337668336798103501))
my_key = PublicKey(
    0xFF)
print(my_key.private_key)
print(my_key.wif(uncompressed=True))
print(my_key.public_key)
print(my_key.address)
print(PublicKey.valid_key(
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F))
