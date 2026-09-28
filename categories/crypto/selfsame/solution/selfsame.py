import numpy as np
ROUNDS = 32
SBOX = np.array([99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22], dtype=np.uint8)
INV_SBOX = np.zeros(256, dtype=np.uint8)
INV_SBOX[SBOX] = np.arange(256, dtype=np.uint8)

def _gf_mul_table(c):
    t = np.zeros(256, dtype=np.uint8)
    for x in range(256):
        a, b, r = (c, x, 0)
        while a:
            if a & 1:
                r ^= b
            b = (b << 1 ^ 27) & 255 if b & 128 else b << 1 & 255
            a >>= 1
        t[x] = r
    return t
MUL = {c: _gf_mul_table(c) for c in (1, 2, 3, 9, 11, 13, 14)}

def _split(w):
    return ((w >> 24 & 255).astype(np.uint8), (w >> 16 & 255).astype(np.uint8), (w >> 8 & 255).astype(np.uint8), (w & 255).astype(np.uint8))

def _join(b0, b1, b2, b3):
    return b0.astype(np.uint32) << 24 | b1.astype(np.uint32) << 16 | b2.astype(np.uint32) << 8 | b3.astype(np.uint32)

def _mix_columns(b0, b1, b2, b3):
    m2, m3 = (MUL[2], MUL[3])
    c0 = m2[b0] ^ m3[b1] ^ b2 ^ b3
    c1 = b0 ^ m2[b1] ^ m3[b2] ^ b3
    c2 = b0 ^ b1 ^ m2[b2] ^ m3[b3]
    c3 = m3[b0] ^ b1 ^ b2 ^ m2[b3]
    return (c0, c1, c2, c3)

def _inv_mix_columns(c0, c1, c2, c3):
    m9, mb, md, me = (MUL[9], MUL[11], MUL[13], MUL[14])
    b0 = me[c0] ^ mb[c1] ^ md[c2] ^ m9[c3]
    b1 = m9[c0] ^ me[c1] ^ mb[c2] ^ md[c3]
    b2 = md[c0] ^ m9[c1] ^ me[c2] ^ mb[c3]
    b3 = mb[c0] ^ md[c1] ^ m9[c2] ^ me[c3]
    return (b0, b1, b2, b3)

def F(x, ka, kb):
    x = np.asarray(x, dtype=np.uint32) ^ np.uint32(ka)
    b0, b1, b2, b3 = _split(x)
    b0, b1, b2, b3 = (SBOX[b0], SBOX[b1], SBOX[b2], SBOX[b3])
    b0, b1, b2, b3 = _mix_columns(b0, b1, b2, b3)
    return _join(b0, b1, b2, b3) ^ np.uint32(kb)

def F_inverse(y, ka, kb):
    y = np.asarray(y, dtype=np.uint32) ^ np.uint32(kb)
    c0, c1, c2, c3 = _split(y)
    c0, c1, c2, c3 = _inv_mix_columns(c0, c1, c2, c3)
    return _join(INV_SBOX[c0], INV_SBOX[c1], INV_SBOX[c2], INV_SBOX[c3]) ^ np.uint32(ka)

def encrypt_blocks(L, R, ka, kb, rounds=ROUNDS):
    L = L.astype(np.uint32, copy=True)
    R = R.astype(np.uint32, copy=True)
    for _ in range(rounds):
        L, R = (R, L ^ F(R, ka, kb))
    return (L, R)

def decrypt_blocks(L, R, ka, kb, rounds=ROUNDS):
    L = L.astype(np.uint32, copy=True)
    R = R.astype(np.uint32, copy=True)
    for _ in range(rounds):
        L, R = (R ^ F(L, ka, kb), L)
    return (L, R)

def _unpack(data: bytes):
    arr = np.frombuffer(data, dtype='>u4').astype(np.uint32)
    return (arr[0::2].copy(), arr[1::2].copy())

def _pack(L, R) -> bytes:
    out = np.empty(L.size * 2, dtype='>u4')
    out[0::2] = L
    out[1::2] = R
    return out.tobytes()

def encrypt_ecb(data: bytes, key: bytes) -> bytes:
    if len(data) % 8:
        raise ValueError('length must be a multiple of 8')
    ka, kb = (int.from_bytes(key[:4], 'big'), int.from_bytes(key[4:], 'big'))
    if not data:
        return b''
    return _pack(*encrypt_blocks(*_unpack(data), ka, kb))

def decrypt_ecb(data: bytes, key: bytes) -> bytes:
    if len(data) % 8:
        raise ValueError('length must be a multiple of 8')
    ka, kb = (int.from_bytes(key[:4], 'big'), int.from_bytes(key[4:], 'big'))
    if not data:
        return b''
    return _pack(*decrypt_blocks(*_unpack(data), ka, kb))
