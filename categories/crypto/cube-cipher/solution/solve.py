import json
import sys
from itertools import permutations

sys.path.insert(0, ".")

FACES = ("U", "D", "F", "B", "L", "R")
OFFSET = {f: i * 9 for i, f in enumerate(FACES)}
CW = (6, 3, 0, 7, 4, 1, 8, 5, 2)
CCW = (2, 5, 8, 1, 4, 7, 0, 3, 6)
RINGS = {
    "U": ((("F", 0), ("F", 1), ("F", 2)), (("L", 0), ("L", 1), ("L", 2)),
          (("B", 0), ("B", 1), ("B", 2)), (("R", 0), ("R", 1), ("R", 2))),
    "D": ((("F", 6), ("F", 7), ("F", 8)), (("R", 6), ("R", 7), ("R", 8)),
          (("B", 6), ("B", 7), ("B", 8)), (("L", 6), ("L", 7), ("L", 8))),
    "R": ((("F", 2), ("F", 5), ("F", 8)), (("U", 2), ("U", 5), ("U", 8)),
          (("B", 6), ("B", 3), ("B", 0)), (("D", 2), ("D", 5), ("D", 8))),
    "L": ((("F", 0), ("F", 3), ("F", 6)), (("D", 0), ("D", 3), ("D", 6)),
          (("B", 8), ("B", 5), ("B", 2)), (("U", 0), ("U", 3), ("U", 6))),
    "F": ((("U", 6), ("U", 7), ("U", 8)), (("R", 0), ("R", 3), ("R", 6)),
          (("D", 2), ("D", 1), ("D", 0)), (("L", 8), ("L", 5), ("L", 2))),
    "B": ((("U", 0), ("U", 1), ("U", 2)), (("L", 6), ("L", 3), ("L", 0)),
          (("D", 8), ("D", 7), ("D", 6)), (("R", 2), ("R", 5), ("R", 8))),
}
MOVES = ["F", "F'", "F2", "B", "B'", "B2", "U", "U'", "U2", "D", "D'", "D2",
         "L", "L'", "L2", "R", "R'", "R2", "x", "x'", "y", "y'", "z", "z'"]
VIS = [OFFSET[f] + i for f in ("U", "F", "R") for i in range(9)]
MASK = 0xFFFFFFFF


def idx(f, i):
    return OFFSET[f] + i


def spin(s, f, cw):
    o = s[:]
    t = CW if cw else CCW
    for i in range(9):
        s[idx(f, i)] = o[idx(f, t[i])]


def turn(s, f, cw):
    spin(s, f, cw)
    ring = RINGS[f]
    order = (0, 1, 2, 3) if cw else (3, 2, 1, 0)
    buf = [s[idx(g, i)] for g, i in ring[order[3]]]
    for k in (3, 2, 1):
        src, dst = ring[order[k - 1]], ring[order[k]]
        for j in range(3):
            s[idx(dst[j][0], dst[j][1])] = s[idx(src[j][0], src[j][1])]
    dst = ring[order[0]]
    for j in range(3):
        s[idx(dst[j][0], dst[j][1])] = buf[j]


def rot_x(s):
    o = s[:]
    for i in range(9):
        s[idx("U", i)] = o[idx("F", i)]
        s[idx("B", i)] = o[idx("U", 8 - i)]
        s[idx("D", i)] = o[idx("B", 8 - i)]
        s[idx("F", i)] = o[idx("D", i)]
        s[idx("R", i)] = o[idx("R", CW[i])]
        s[idx("L", i)] = o[idx("L", CCW[i])]


def rot_y(s):
    o = s[:]
    for i in range(9):
        s[idx("L", i)] = o[idx("F", i)]
        s[idx("B", i)] = o[idx("L", i)]
        s[idx("R", i)] = o[idx("B", i)]
        s[idx("F", i)] = o[idx("R", i)]
        s[idx("U", i)] = o[idx("U", CW[i])]
        s[idx("D", i)] = o[idx("D", CCW[i])]


def rot_z(s):
    o = s[:]
    for i in range(9):
        s[idx("R", i)] = o[idx("U", CW[i])]
        s[idx("D", i)] = o[idx("R", CW[i])]
        s[idx("L", i)] = o[idx("D", CW[i])]
        s[idx("U", i)] = o[idx("L", CW[i])]
        s[idx("F", i)] = o[idx("F", CW[i])]
        s[idx("B", i)] = o[idx("B", CCW[i])]


def move(s, m):
    base, mod = m[0], m[1:]
    if base in "UDFBLR":
        if mod == "2":
            turn(s, base, True)
            turn(s, base, True)
        else:
            turn(s, base, mod != "'")
    else:
        fn = {"x": rot_x, "y": rot_y, "z": rot_z}[base]
        for _ in range({"": 1, "2": 2, "'": 3}[mod]):
            fn(s)
    return s


def value_triple(v):
    return (MOVES[v // 576], MOVES[(v // 24) % 24], MOVES[v % 24])


def build_tables():
    perm = [None] * 13824
    for v in range(13824):
        perm[v] = tuple(move(move(move(list(range(54)), value_triple(v)[0]),
                                   value_triple(v)[1]), value_triple(v)[2]))
    canon_of = {}
    canon_value = [0] * 13824
    for v in range(13824):
        canon_of.setdefault(perm[v], v)
        canon_value[v] = canon_of[perm[v]]
    canon_list = [v for v in range(13824) if canon_value[v] == v]
    vis_src = {v: tuple(perm[v][k] for k in VIS) for v in canon_list}
    return perm, canon_value, canon_list, vis_src


def fnv1a(text):
    h = 0x811C9DC5
    for ch in text:
        h ^= ord(ch)
        h = (h * 0x01000193) & MASK
    return h


def gamma(seed, count):
    s = fnv1a(seed) or 0x9E3779B9
    out = []
    for _ in range(count):
        s ^= (s << 13) & MASK
        s &= MASK
        s ^= s >> 17
        s ^= (s << 5) & MASK
        s &= MASK
        out.append(s & 0xFF)
    return out


def frame_vis(frame):
    return tuple(frame[f][i] for f in ("U", "F", "R") for i in range(9))


def recover(frames, start, canon_list, vis_src, perm):
    state = start[:]
    values = []
    for k in range(1, len(frames)):
        target = frame_vis(frames[k])
        found = None
        for v in canon_list:
            src = vis_src[v]
            if all(state[src[j]] == target[j] for j in range(27)):
                if found is not None:
                    return None
                found = v
        if found is None:
            return None
        state = [state[p] for p in perm[found]]
        values.append(found)
    return values


def main(path):
    frames = json.load(open(path))
    perm, canon_value, canon_list, vis_src = build_tables()

    palette = []
    for fr in frames:
        for face in ("U", "F", "R"):
            for c in fr[face]:
                if c not in palette:
                    palette.append(c)
    front = {f: frames[0][f][0] for f in ("U", "F", "R")}
    hidden = [c for c in palette if c not in front.values()]
    print("[*] цветов на ленте: %d" % len(palette))
    print("[*] видно на старте: U=%s F=%s R=%s" % (front["U"], front["F"], front["R"]))
    print("[*] скрытые грани, кандидаты: %s" % ", ".join(hidden))

    for order in permutations(hidden):
        colors = dict(front)
        colors["D"], colors["B"], colors["L"] = order
        start = [colors[f] for f in FACES for _ in range(9)]
        values = recover(frames, start, canon_list, vis_src, perm)
        if values is None:
            continue
        seed = "".join(colors[f].lower() for f in FACES) + "|"
        g = gamma(seed, 2 * len(values))
        out = bytes((canon_value[v] % 256) ^ g[2 * i] for i, v in enumerate(values))
        try:
            text = out.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if all(32 <= b <= 126 for b in out):
            print("[+] D=%s B=%s L=%s" % order)
            print("[+] ходов восстановлено: %d" % (3 * len(values)))
            print("[+] %s" % text)
            return
    print("[-] не решилось")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "frames.json")
