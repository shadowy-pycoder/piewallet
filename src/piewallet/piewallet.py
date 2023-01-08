from curve_params import secp256k1


def reciprocal(n: int) -> int:
    return pow(n, -1, secp256k1.p_curve)


def ec_add(p: tuple[int, int], q: tuple[int, int]) -> tuple[int, int]:
    slope = (p[1] - q[1]) * reciprocal(p[0] - q[0])
    x = pow(slope, 2) - p[0] - q[0]
    y = slope * (p[0] - x) - p[1]
    return x % secp256k1.p_curve, y % secp256k1.p_curve


def ec_dup(p: tuple[int, int]) -> tuple[int, int]:
    slope = ((3 * pow(p[0], 2) + secp256k1.a_curve) * reciprocal(2 * p[1]))
    x = pow(slope, 2) - 2 * p[0]
    y = slope * (p[0] - x) - p[1]
    return x % secp256k1.p_curve, y % secp256k1.p_curve


def ec_mul(scalar: int) -> tuple[int, int]:
    scalarbin = bin(scalar)[2:]
    current = secp256k1.gen_point
    for i in range(1, len(scalarbin)):
        current = ec_dup(current)
        if scalarbin[i] == "1":
            current = ec_add(current, secp256k1.gen_point)
    return current


print(ec_mul(0xFF) == (12312385769684547396095365029355369071957339694349689622296638024179682296192,
      29045073188889159330506972844502087256824914692696728592611344825524969277689))
