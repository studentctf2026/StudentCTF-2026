import json

with open("feistel_data.json", "r") as f:
    data = json.load(f)

SBOX = data["sbox"]
ROUND_KEYS = data["round_keys"]
PERM = data["perm"]
TARGET = data["target"]


def f_function(block, key, rnd):
    result = block[:]

    for i in range(16):
        result[i] ^= key[i]

    for i in range(16):
        result[i] = SBOX[result[i]]

    tmp = [0] * 16
    for i in range(16):
        tmp[i] = result[PERM[i]]
    result = tmp

    c = (rnd * 37 + 19) & 0xff
    for i in range(16):
        result[i] ^= c

    return result


def decrypt(cipher):
    L = list(cipher[:16])
    R = list(cipher[16:])

    for rnd in reversed(range(16)):
        old_R = L

        f = f_function(old_R, ROUND_KEYS[rnd], rnd)

        old_L = []
        for i in range(16):
            old_L.append(R[i] ^ f[i])

        L = old_L
        R = old_R

    return bytes(L + R)


plain = decrypt(TARGET)

print(plain.rstrip(b"\x00").decode())