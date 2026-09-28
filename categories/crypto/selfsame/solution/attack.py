import numpy as np
from selfsame import SBOX, MUL, _split, _join, _mix_columns, _inv_mix_columns

def build_ddt_solutions():
    sol = [[[] for _ in range(256)] for _ in range(256)]
    S = SBOX.tolist()
    for delta in range(256):
        for z in range(256):
            sol[delta][S[z] ^ S[z ^ delta]].append(z)
    return [[tuple(c) for c in row] for row in sol]
DDT_SOL = build_ddt_solutions()
_S = SBOX.tolist()
_M2, _M3 = (MUL[2].tolist(), MUL[3].tolist())
_M9, _MB, _MD, _ME = (MUL[9].tolist(), MUL[11].tolist(), MUL[13].tolist(), MUL[14].tolist())

def _mc32(w):
    b0, b1 = (w >> 24 & 255, w >> 16 & 255)
    b2, b3 = (w >> 8 & 255, w & 255)
    return (_M2[b0] ^ _M3[b1] ^ b2 ^ b3) << 24 | (b0 ^ _M2[b1] ^ _M3[b2] ^ b3) << 16 | (b0 ^ b1 ^ _M2[b2] ^ _M3[b3]) << 8 | _M3[b0] ^ b1 ^ b2 ^ _M2[b3]

def _inv_mc32(w):
    c0, c1 = (w >> 24 & 255, w >> 16 & 255)
    c2, c3 = (w >> 8 & 255, w & 255)
    return (_ME[c0] ^ _MB[c1] ^ _MD[c2] ^ _M9[c3]) << 24 | (_M9[c0] ^ _ME[c1] ^ _MB[c2] ^ _MD[c3]) << 16 | (_MD[c0] ^ _M9[c1] ^ _ME[c2] ^ _MB[c3]) << 8 | _MB[c0] ^ _MD[c1] ^ _M9[c2] ^ _ME[c3]

def _sb32(w):
    return _S[w >> 24 & 255] << 24 | _S[w >> 16 & 255] << 16 | _S[w >> 8 & 255] << 8 | _S[w & 255]

def _encrypt_scalar(L, R, ka, kb, rounds=32):
    for _ in range(rounds):
        L, R = (R, L ^ _mc32(_sb32(R ^ ka)) ^ kb)
    return (L, R)

def keys_from_two_F_pairs(u1, v1, u2, v2, max_keys=4096):
    if u1 == u2:
        return []
    diff = _inv_mc32(v1 ^ v2)
    du = u1 ^ u2
    per_byte = []
    for k in range(4):
        sh = 24 - 8 * k
        delta = du >> sh & 255
        Delta = diff >> sh & 255
        u1b = u1 >> sh & 255
        if delta == 0:
            if Delta != 0:
                return []
            cand = tuple((z ^ u1b for z in range(256)))
        else:
            zs = DDT_SOL[delta][Delta]
            if not zs:
                return []
            cand = tuple((z ^ u1b for z in zs))
        per_byte.append(cand)
    total = 1
    for c in per_byte:
        total *= len(c)
    if total > max_keys:
        return []
    out = []
    for k0 in per_byte[0]:
        for k1 in per_byte[1]:
            for k2 in per_byte[2]:
                for k3 in per_byte[3]:
                    ka = k0 << 24 | k1 << 16 | k2 << 8 | k3
                    kb = v1 ^ _mc32(_sb32(u1 ^ ka))
                    out.append((ka, kb))
    return out

def recover_key(oracle, a=None, log_n=18, rng=None, verbose=True):
    rng = rng or np.random.default_rng()
    if a is None:
        a = int(rng.integers(0, 1 << 32))
    n = 1 << log_n
    xs = np.unique(rng.integers(0, 1 << 32, size=n, dtype=np.uint64)).astype(np.uint32)
    ys = np.unique(rng.integers(0, 1 << 32, size=n, dtype=np.uint64)).astype(np.uint32)
    n = min(xs.size, ys.size)
    xs, ys = (xs[:n], ys[:n])

    def pack(L, R):
        buf = np.empty(L.size * 2, dtype='>u4')
        buf[0::2] = L
        buf[1::2] = R
        return buf.tobytes()

    def unpack(b):
        arr = np.frombuffer(b, dtype='>u4')
        return (arr[0::2].astype(np.uint32), arr[1::2].astype(np.uint32))
    av = np.full(n, a, dtype=np.uint32)
    if verbose:
        print(f'[*] a = {a:#010x}, structures of 2^{log_n} blocks ({2 * n * 8 / 2 ** 20:.1f} MiB total)')
    LcA, RcA = unpack(oracle(pack(xs, av)))
    LcB, RcB = unpack(oracle(pack(av, ys)))
    table = {}
    for j, lc in enumerate(LcB.tolist()):
        table.setdefault(lc, []).append(j)
    xs_l, ys_l = (xs.tolist(), ys.tolist())
    LcA_l, RcA_l, RcB_l = (LcA.tolist(), RcA.tolist(), RcB.tolist())
    cands = 0
    known_pt, known_ct = ((xs_l[0], a), (LcA_l[0], RcA_l[0]))
    for i, rc in enumerate(RcA_l):
        for j in table.get(rc, ()):
            cands += 1
            u1, v1 = (a, xs_l[i] ^ ys_l[j])
            u2, v2 = (rc, LcA_l[i] ^ RcB_l[j])
            for ka, kb in keys_from_two_F_pairs(u1, v1, u2, v2):
                if _encrypt_scalar(known_pt[0], known_pt[1], ka, kb) == known_ct:
                    if verbose:
                        print(f'[+] filtered pairs examined: {cands}')
                        print(f'[+] Ka = {ka:#010x}  Kb = {kb:#010x}')
                    return (ka, kb)
    if verbose:
        print(f'[-] failed ({cands} filtered pairs examined)')
    return None
