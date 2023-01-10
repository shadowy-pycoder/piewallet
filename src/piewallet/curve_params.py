from typing import NamedTuple


P_CURVE = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N_CURVE = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A_CURVE = 0
B_CURVE = 7
GEN_POINT = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
             0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


class Point(NamedTuple):
    x: int
    y: int


G = Point(x=GEN_POINT[0], y=GEN_POINT[1])


class EllipticCurve(NamedTuple):
    p_curve: int
    n_curve: int
    a_curve: int
    b_curve: int
    gen_point: Point


secp256k1 = EllipticCurve(p_curve=P_CURVE, n_curve=N_CURVE,
                          a_curve=A_CURVE, b_curve=B_CURVE, gen_point=G)
