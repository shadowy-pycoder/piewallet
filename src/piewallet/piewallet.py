from curve_params import secp256k1


def reciprocal(n: int) -> int:
    return pow(n, -1, secp256k1.p_curve)


def ec_add(p: tuple[int, int]) -> tuple[int, int]:
    slope = ((p[1] - secp256k1.gen_point[1]) *
             reciprocal(p[0] - secp256k1.gen_point[0]))
    x = pow(slope, 2) - p[0] - secp256k1.gen_point[0]
    y = slope * (p[0] - x) - p[1]
    return x % secp256k1.p_curve, y % secp256k1.p_curve


def ec_dup(p: tuple[int, int]) -> tuple[int, int]:
    slope = ((3 * pow(p[0], 2) + secp256k1.a_curve) * reciprocal(2 * p[1]))
    x = pow(slope, 2) - 2 * p[0]
    y = slope * (p[0] - x) - p[1]
    return x % secp256k1.p_curve, y % secp256k1.p_curve


def ec_mul(scalar: int) -> tuple[int, int]:
    scalarbin = bin(scalar)[2:]
    q = secp256k1.gen_point
    for i in range(1, len(scalarbin)):
        q = ec_add(ec_dup(q)) if scalarbin[i] == "1" else ec_dup(q)
    return q


print(ec_mul(0xFF) == (12312385769684547396095365029355369071957339694349689622296638024179682296192,
      29045073188889159330506972844502087256824914692696728592611344825524969277689))
print(ec_mul(0xEE31862668ECD0EC1B3538B04FBF21A59965B51C5648F5CE97C613B48610FA7B) == (
    49414738088508426605940350615969154033259972709128027173379136589046972286596, 113066049041265251152881802696276066009952852537138792323892337668336798103501))
