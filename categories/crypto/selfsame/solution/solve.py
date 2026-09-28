import sys
import urllib.request
import numpy as np
import selfsame as S
from attack import recover_key

def make_oracle(base):

    def oracle(pt: bytes) -> bytes:
        req = urllib.request.Request(base.rstrip('/') + '/upload', data=pt, method='POST', headers={'Content-Type': 'application/octet-stream'})
        with urllib.request.urlopen(req, timeout=180) as r:
            return r.read()
    return oracle

def get_flag_ct(base) -> bytes:
    import json
    with urllib.request.urlopen(base.rstrip('/') + '/flag', timeout=30) as r:
        return bytes.fromhex(json.load(r)['ciphertext'])

def main():
    base = sys.argv[1] if len(sys.argv) > 1 else 'http://127.0.0.1:8001'
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else None
    res = recover_key(make_oracle(base), log_n=18, rng=np.random.default_rng(seed))
    if res is None:
        return 1
    ka, kb = res
    key = ka.to_bytes(4, 'big') + kb.to_bytes(4, 'big')
    print(f'[+] master key = {key.hex()}')
    pt = S.decrypt_ecb(get_flag_ct(base), key)
    print('[+] flag =', pt.rstrip(b'\x00').decode())
    return 0
if __name__ == '__main__':
    sys.exit(main())
