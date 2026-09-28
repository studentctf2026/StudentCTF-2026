from __future__ import annotations

import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

MASK64 = (1 << 64) - 1
MASK63 = (1 << 63) - 1
DELTA = 0x7FFFFFFFFFFFFFFE
ROUNDS = 5

@dataclass(frozen=True)
class PairState:
    plain_left: int
    plain_right: int
    left: int
    right: int

def reverse_bits64(x: int) -> int:
    x &= MASK64
    x = ((x >> 1) & 0x5555555555555555) | ((x & 0x5555555555555555) << 1)
    x = ((x >> 2) & 0x3333333333333333) | ((x & 0x3333333333333333) << 2)
    x = ((x >> 4) & 0x0F0F0F0F0F0F0F0F) | ((x & 0x0F0F0F0F0F0F0F0F) << 4)
    x = ((x >> 8) & 0x00FF00FF00FF00FF) | ((x & 0x00FF00FF00FF00FF) << 8)
    x = ((x >> 16) & 0x0000FFFF0000FFFF) | ((x & 0x0000FFFF0000FFFF) << 16)
    x = ((x >> 32) | (x << 32)) & MASK64
    return x

def parse_parameters(path: Path):
    pairs = []
    verify = []

    for raw_line in path.read_text(encoding="ascii").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split()

        if parts[0] == "PAIR" and len(parts) == 5:
            plain_left, left, plain_right, right = (
                int(value, 16) for value in parts[1:]
            )
            pairs.append(
                PairState(plain_left, plain_right, left, right)
            )

        elif parts[0] == "VERIFY" and len(parts) == 3:
            verify.append((int(parts[1], 16), int(parts[2], 16)))

    if len(pairs) != 128:
        raise ValueError(f"expected 128 PAIR records, got {len(pairs)}")
    if len(verify) != 10:
        raise ValueError(f"expected 10 VERIFY records, got {len(verify)}")

    return pairs, verify

HALF_DELTA = DELTA >> 1
INVERSE_HALF_DELTA = pow(HALF_DELTA, -1, 1 << 63)

def strongest_multipliers(pairs):
    votes = Counter()

    for pair in pairs:
        total = (pair.left + pair.right) & MASK64
        if total & 1:
            continue

        multiplier = (
            ((total >> 1) * INVERSE_HALF_DELTA) & MASK63
        )

        if multiplier & 1:
            votes[multiplier] += 1

    if not votes:
        return []

    strongest = max(votes.values())
    if strongest < 2:
        return []

    return [
        value for value, count in votes.items()
        if count == strongest
    ]

def possible_round_keys(multiplier_without_msb):
    low = multiplier_without_msb
    high = multiplier_without_msb | (1 << 63)
    return low, low ^ 1, high, high ^ 1

def decrypt_one_round(pairs, round_key):
    inverse = pow(round_key | 1, -1, 1 << 64)
    previous = []

    for pair in pairs:
        left = reverse_bits64(
            (pair.left * inverse) & MASK64
        ) ^ round_key

        right = reverse_bits64(
            (pair.right * inverse) & MASK64
        ) ^ round_key

        previous.append(
            PairState(
                pair.plain_left,
                pair.plain_right,
                left,
                right,
            )
        )

    return previous

def reached_plaintexts(pairs):
    return all(
        pair.left == pair.plain_left
        and pair.right == pair.plain_right
        for pair in pairs
    )

def recover_round_keys(encrypted_pairs):
    recovered = [0] * ROUNDS

    def search(round_index, states):
        if round_index < 0:
            return reached_plaintexts(states)

        for multiplier in strongest_multipliers(states):
            for round_key in possible_round_keys(multiplier):
                recovered[round_index] = round_key

                previous = decrypt_one_round(states, round_key)
                if search(round_index - 1, previous):
                    return True

        return False

    if not search(ROUNDS - 1, encrypted_pairs):
        raise RuntimeError(
            "attack failed: no consistent round keys found"
        )

    return recovered

def encrypt_block(block, round_keys):
    x = block & MASK64

    for round_key in round_keys:
        x = reverse_bits64(x ^ round_key)
        x = (x * (round_key | 1)) & MASK64

    return x

def main():
    if len(sys.argv) != 2:
        raise SystemExit(
            f"usage: {Path(sys.argv[0]).name} "
            "Nimbus_parameters_public.txt"
        )

    pairs, verify = parse_parameters(Path(sys.argv[1]))
    round_keys = recover_round_keys(pairs)

    print("Recovered round keys:")
    for index, key in enumerate(round_keys):
        print(f"  K{index} = {key:016X}")

    matches = sum(
        encrypt_block(plain, round_keys) == expected
        for plain, expected in verify
    )

    password = f"{round_keys[0]:016X}{round_keys[1]:016X}"

    print(f"VERIFY: {matches}/{len(verify)}")
    print(f"Password: {password}")

if __name__ == "__main__":
    main()
