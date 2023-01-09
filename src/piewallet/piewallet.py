from curve_params import secp256k1
from secrets import randbelow
from functions.sha256 import sha256
from functions.ripemd160 import ripemd160


class PublicKey:

    def __init__(self, private_key=None):
        if private_key is None:
            private_key = randbelow(secp256k1.n_curve)
        if not valid_key(private_key):
            raise Exception('Invalid scalar/private key')
        self.private_key = private_key

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

    def __public_key(self):
        return self.__ec_mul(self.private_key)

    def public_key(self, *, uncompressed=False):
        if uncompressed:
            return f"04{self.__public_key()[0]:0>64x}{self.__public_key()[1]:0>64x}"
        odd = self.__public_key()[1] % 2 == 1
        return f"03{self.__public_key()[0]:0>64x}" if odd else f"02{self.__public_key()[0]:0>64x}"


class Address(PublicKey):
    pass


def valid_key(key: int) -> bool:
    try:
        key_h = int(key)
    except (ValueError, TypeError):
        return False
    return not (key_h <= 0 or key_h >= secp256k1.n_curve)


# print(__ec_mul(0xFF) == (12312385769684547396095365029355369071957339694349689622296638024179682296192,
#       29045073188889159330506972844502087256824914692696728592611344825524969277689))
# print(__ec_mul(0xEE31862668ECD0EC1B3538B04FBF21A59965B51C5648F5CE97C613B48610FA7B) == (
#     49414738088508426605940350615969154033259972709128027173379136589046972286596, 113066049041265251152881802696276066009952852537138792323892337668336798103501))
my_key = PublicKey(0xFF)
private = my_key.private_key
print(hex(private))
print(my_key.public_key(uncompressed=True))
print(Address.mro())
