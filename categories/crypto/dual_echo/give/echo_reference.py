import json


with open("params.json") as f:
    prm = json.load(f)

p = int(prm["p"], 16)
a = int(prm["a"], 16)
b = int(prm["b"], 16)
P = (int(prm["P"][0], 16), int(prm["P"][1], 16))
Q = (int(prm["Q"][0], 16), int(prm["Q"][1], 16))

OUTLEN = 30
KEEP = OUTLEN * 8


def inv(x, m):
    return pow(x, -1, m)


def add(A, B):
    if A is None:
        return B
    if B is None:
        return A
    x1, y1 = A
    x2, y2 = B
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if A == B:
        m = (3 * x1 * x1 + a) * inv(2 * y1 % p, p) % p
    else:
        m = (y2 - y1) * inv((x2 - x1) % p, p) % p
    x3 = (m * m - x1 - x2) % p
    return (x3, (m * (x1 - x3) - y1) % p)


def mul(n, A):
    R = None
    Qq = A
    n %= p
    while n > 0:
        if n & 1:
            R = add(R, Qq)
        Qq = add(Qq, Qq)
        n >>= 1
    return R


def drbg_step(s):
    """One step of echo256-DRBG. Returns (new_state, beacon_bytes)."""
    s = mul(s, P)[0]
    r = mul(s, Q)[0]
    beacon = (r % (1 << KEEP)).to_bytes(OUTLEN, "big")
    return s, beacon


if __name__ == "__main__":
    s = 1234567890
    for _ in range(3):
        s, beacon = drbg_step(s)
        print(beacon.hex(), "->", int.from_bytes(beacon, "big") % 37)
