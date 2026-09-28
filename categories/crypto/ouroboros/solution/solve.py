import hashlib
import struct
import sys
import random

from fpylll import IntegerMatrix, LLL

NCONST = 256
BCLEN = 128
BLOBLEN = 64


def rotl32(x, n):
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def chacha_block(key, ctr):
    st = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    st += list(struct.unpack("<8I", key))
    st += [ctr, 0, 0, 0]
    x = list(st)

    def qr(a, b, c, d):
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF
        x[d] = rotl32(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF
        x[b] = rotl32(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF
        x[d] = rotl32(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF
        x[b] = rotl32(x[b] ^ x[c], 7)

    for _ in range(10):
        qr(0, 4, 8, 12)
        qr(1, 5, 9, 13)
        qr(2, 6, 10, 14)
        qr(3, 7, 11, 15)
        qr(0, 5, 10, 15)
        qr(1, 6, 11, 12)
        qr(2, 7, 8, 13)
        qr(3, 4, 9, 14)
    return struct.pack("<16I", *[(x[i] + st[i]) & 0xFFFFFFFF for i in range(16)])


def chacha_stream(key, n):
    out = b""
    ctr = 0
    while len(out) < n:
        out += chacha_block(key, ctr)
        ctr += 1
    return out[:n]


def chacha_xor(key, data):
    return bytes(a ^ b for a, b in zip(data, chacha_stream(key, len(data))))


def elf_load_segments(blob):
    phoff, = struct.unpack_from("<Q", blob, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", blob, 0x36)
    out = []
    for i in range(phnum):
        base = phoff + i * phentsize
        p_type, = struct.unpack_from("<I", blob, base)
        p_offset, p_vaddr = struct.unpack_from("<QQ", blob, base + 0x08)
        p_filesz, = struct.unpack_from("<Q", blob, base + 0x20)
        if p_type == 1:
            out.append((p_vaddr, p_offset, p_filesz))
    return out


def v2o(blob, vaddr):
    for va, off, fsz in elf_load_segments(blob):
        if va <= vaddr < va + fsz:
            return off + (vaddr - va)
    raise ValueError(hex(vaddr))


def elf_symbols(blob):
    shoff, = struct.unpack_from("<Q", blob, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", blob, 0x3A)
    sh = []
    for i in range(shnum):
        base = shoff + i * shentsize
        name, stype = struct.unpack_from("<II", blob, base)
        off, = struct.unpack_from("<Q", blob, base + 0x18)
        size, = struct.unpack_from("<Q", blob, base + 0x20)
        link, = struct.unpack_from("<I", blob, base + 0x28)
        entsize, = struct.unpack_from("<Q", blob, base + 0x38)
        sh.append((name, stype, off, size, link, entsize))
    syms = {}
    for name, stype, off, size, link, entsize in sh:
        if stype != 2:
            continue
        stroff = sh[link][2]
        for k in range(size // entsize):
            b = off + k * entsize
            nm, = struct.unpack_from("<I", blob, b)
            val, = struct.unpack_from("<Q", blob, b + 8)
            end = blob.index(b"\x00", stroff + nm)
            syms[blob[stroff + nm:end].decode()] = val
    return syms


def extract(path):
    blob = open(path, "rb").read()
    syms = elf_symbols(blob)
    start, etext = syms["__executable_start"], syms["__etext"]
    o = v2o(blob, start)
    tk = hashlib.sha256(blob[o:o + (etext - start)]).digest()

    def grab(name, n):
        b = v2o(blob, syms[name])
        return blob[b:b + n]

    bc = chacha_xor(tk, grab("d0", BCLEN))
    p = int.from_bytes(grab("d1", 80), "little")
    target = int.from_bytes(grab("d2", 80), "little")
    cipher = grab("d3", BLOBLEN)
    stream = chacha_stream(hashlib.sha256(bc).digest(), NCONST * 75)
    M = []
    for i in range(NCONST):
        v = int.from_bytes(stream[i * 75:(i + 1) * 75], "little")
        if v >= p:
            v -= p
        M.append(v)
    return p, target, cipher, M


def brent(n):
    if n % 2 == 0:
        return 2
    while True:
        y = random.randrange(1, n)
        c = random.randrange(1, n)
        m = 128
        g = q = r = 1
        while g == 1:
            x = y
            for _ in range(r):
                y = (y * y + c) % n
            k = 0
            while k < r and g == 1:
                ys = y
                for _ in range(min(m, r - k)):
                    y = (y * y + c) % n
                    q = q * abs(x - y) % n
                g = gcd(q, n)
                k += m
            r *= 2
        if g == n:
            g = 1
            y = ys
            while g == 1:
                y = (y * y + c) % n
                g = gcd(abs(x - y), n)
        if g != n:
            return g


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def is_prime(n):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def factor(n):
    out = []
    stack = [n]
    while stack:
        v = stack.pop()
        if v == 1:
            continue
        if is_prime(v):
            out.append(v)
            continue
        d = brent(v)
        stack.append(d)
        stack.append(v // d)
    return sorted(out)


def crt(rs, ms):
    x, m = 0, 1
    for r, mi in zip(rs, ms):
        g = pow(m % mi, -1, mi)
        t = (r - x) % mi * g % mi
        x += m * t
        m *= mi
    return x % m


def build_tables(g, p, qs):
    n = p - 1
    tabs = []
    for q in qs:
        gq = pow(g, n // q, p)
        m = int(q ** 0.5) + 1
        tab = {}
        cur = 1
        for j in range(m):
            tab.setdefault(cur, j)
            cur = cur * gq % p
        factor_ = pow(pow(gq, m, p), -1, p)
        tabs.append((q, gq, m, tab, factor_))
    return tabs


def dlog(h, p, tabs):
    rs, ms = [], []
    n = p - 1
    for q, gq, m, tab, fac in tabs:
        hq = pow(h, n // q, p)
        cur = hq
        for i in range(m + 1):
            if cur in tab:
                rs.append((i * m + tab[cur]) % q)
                break
            cur = cur * fac % p
        else:
            raise ValueError("no dlog")
        ms.append(q)
    return crt(rs, ms)


def solve_subset_sum(e, E, n):
    k = len(e)
    N = 1 << 90
    A = IntegerMatrix(k + 2, k + 2)
    for i in range(k):
        A[i, i] = 2
        A[i, k] = N * e[i]
    A[k, k] = N * n
    for i in range(k):
        A[k + 1, i] = 1
    A[k + 1, k] = N * E
    A[k + 1, k + 1] = 1
    LLL.reduction(A)
    for r in range(k + 2):
        row = [A[r, c] for c in range(k + 2)]
        if row[k] != 0 or abs(row[k + 1]) != 1:
            continue
        if any(abs(v) != 1 for v in row[:k]):
            continue
        s = -1 if row[k + 1] == -1 else 1
        bits = [(1 - s * v) // 2 for v in row[:k]]
        if all(b in (0, 1) for b in bits):
            yield bits


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "ouroboros"
    p, target, cipher, M = extract(path)
    n = p - 1
    print("[*] p     = %d bits" % p.bit_length())

    qs = factor(n)
    print("[*] p-1 factors: %d primes, max %d bits" % (len(qs), max(qs).bit_length()))

    g = 2
    while any(pow(g, n // q, p) == 1 for q in qs):
        g += 1
    print("[*] g = %d" % g)

    base = 1
    for i in range(128):
        base = base * M[2 * i] % p
    c = [M[2 * i + 1] * pow(M[2 * i], -1, p) % p for i in range(128)]
    tprime = target * pow(base, -1, p) % p

    tabs = build_tables(g, p, qs)
    print("[*] baby-step tables ready")
    e = [dlog(x, p, tabs) for x in c]
    E = dlog(tprime, p, tabs)
    print("[*] discrete logs done")

    for bits in solve_subset_sum(e, E, n):
        key = sum(b << i for i, b in enumerate(bits))
        acc = 1
        for i in range(128):
            acc = acc * M[2 * i + ((key >> i) & 1)] % p
        if acc != target:
            continue
        print("[+] key = %032x" % key)
        k = hashlib.sha256(acc.to_bytes(80, "little")).digest()
        out = chacha_xor(k, cipher)
        print("[+] " + out.split(b"\x00")[0].decode().strip())
        return
    print("[-] no solution found")


main()
