from typing import NamedTuple


P_CURVE = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N_CURVE = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A_CURVE = 0
B_CURVE = 7
GEN_POINT = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
             0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


class Point(NamedTuple):
    '''Point on an elliptic curve'''
    x: int
    y: int


class JacobianPoint(NamedTuple):
    x: int
    y: int
    z: int


class EllipticCurve(NamedTuple):
    '''
    Elliptic curve with all the parameters to define it.
    '''
    p_curve: int
    n_curve: int
    a_curve: int
    b_curve: int
    gen_point: JacobianPoint


class Signature(NamedTuple):
    r: int
    s: int


secp256k1 = EllipticCurve(p_curve=P_CURVE, n_curve=N_CURVE,
                          a_curve=A_CURVE, b_curve=B_CURVE, gen_point=JacobianPoint(x=GEN_POINT[0], y=GEN_POINT[1], z=1))

IDENTITY_POINT = JacobianPoint(x=P_CURVE, y=0, z=1)
POW_2_256_M1 = 2 ** 256 - 1
